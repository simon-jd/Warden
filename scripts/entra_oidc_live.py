#!/usr/bin/env python3
"""Task 6 live check: the real warden-api binary against Microsoft Entra ID.

Builds controlplane/cmd/warden-api from this checkout, runs it with
WARDEN_OIDC_{ISSUER,AUDIENCE,JWKS_URL} set to the signed-in tenant's real v2
issuer and JWKS, on a throwaway postgres:18-alpine container (as
scripts/test-postgres.sh does), and sends it real delegated access tokens from
the Azure CLI. The user is provisioned through Warden's own SCIM endpoint with
a one-off static token; that is not Entra's provisioning service.

  run      no token, unprovisioned, provisioned POST/GET, another resource's
           token, tampered payload/signature, alg=none, SCIM deactivate -> 401,
           and a second server whose audience is another app ID.
  expired  the token kept by `run --keep-token` after it expired, next to a
           fresh token as the control. The kept token file is deleted.
  unassign removes the signed-in user's assignment to warden-lab-api, polls
           Entra for new tokens (scripts/entra_token_probe.py, no cache) and
           Warden with the token issued before, deactivates by hand through
           Warden's SCIM endpoint, then assigns the user again.

Nothing secret is written: tokens and their segments, the tenant ID, the
user's object ID, sub and profile claims, the SCIM token and the database
password are replaced before output, and the output is checked for leftovers
(including anything shaped like a JWT). Uses only the standard library.

  python3 -I -B scripts/entra_oidc_live.py run --audience <client id> --out <json> [--keep-token <file>]
  python3 -I -B scripts/entra_oidc_live.py expired --audience <client id> --keep-token <file> --out <json>
  python3 -I -B scripts/entra_oidc_live.py unassign --audience <client id> --sp-object-id <id> --out <json>
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets as random_secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTHORITY = "https://login.microsoftonline.com/"
JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
# Claims whose values are kept in evidence. Everything else is listed by name only.
SHAPE_CLAIMS = ("aud", "iss", "ver", "scp", "azp", "appid", "idtyp", "tid", "oid", "iat", "nbf", "exp")
RUN_BODY = json.dumps({"image_digest": "sha256:" + "a" * 64, "cmd": ["/bin/true"]})
SCIM_TENANT = "tenant-entra-lab"


class Leak(Exception):
    """Evidence still contains a secret or a JWT-shaped string."""


def _b64decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def header(token):
    return json.loads(_b64decode(token.split(".")[0]))


def payload(token):
    return json.loads(_b64decode(token.split(".")[1]))


def _iso(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def claims_summary(token):
    """Header and claim shape of a token without identifying values."""
    h, c = header(token), payload(token)
    tenant = c.get("tid", "")
    kept = {}
    for name in SHAPE_CLAIMS:
        if name not in c:
            continue
        value = c[name]
        if name == "tid":
            value = "<tenant-id>"
        elif name == "oid":
            value = "<user-oid>"
        elif name == "iss" and tenant:
            value = str(value).replace(tenant, "<tenant-id>")
        elif name in ("iat", "nbf", "exp"):
            value = _iso(value)
        kept[name] = value
    lifetime = c["exp"] - c["iat"] if isinstance(c.get("exp"), int) and isinstance(c.get("iat"), int) else None
    return {
        "header": {k: h[k] for k in ("alg", "typ", "kid") if k in h},
        "header_names": sorted(h),
        "claims": kept,
        "claim_names": sorted(c),
        "lifetime_s": lifetime,
        "signature_bytes": len(_b64decode(token.split(".")[2])),
    }


def seconds_until_expiry(token, now=None):
    return payload(token)["exp"] - int(time.time() if now is None else now)


def tamper_payload(token):
    """Same header and signature, payload with exp pushed out by an hour."""
    h, _, s = token.split(".")
    c = payload(token)
    c["exp"] = c["exp"] + 3600
    return ".".join([h, _b64encode(json.dumps(c, separators=(",", ":")).encode()), s])


def tamper_signature(token):
    """Flip one bit in the middle of the signature; still canonical base64url."""
    h, p, s = token.split(".")
    raw = bytearray(_b64decode(s))
    raw[len(raw) // 2] ^= 0x01
    return ".".join([h, p, _b64encode(bytes(raw))])


def unsigned(token):
    """alg=none and no signature, payload unchanged."""
    h = header(token)
    h["alg"] = "none"
    return ".".join([_b64encode(json.dumps(h, separators=(",", ":")).encode()), token.split(".")[1], ""])


def secrets_of(*tokens, extra=None):
    """(value, placeholder) pairs, longest first so tokens go before their parts."""
    pairs = {}
    for token in tokens:
        if not token:
            continue
        pairs[token] = "<token>"
        for segment in token.split(".")[1:]:
            if len(segment) >= 8:
                pairs[segment] = "<token-segment>"
        c = payload(token)
        if c.get("tid"):
            pairs[c["tid"]] = "<tenant-id>"
        if c.get("oid"):
            pairs[c["oid"]] = "<user-oid>"
        for name in ("sub", "name", "given_name", "family_name", "upn", "unique_name", "preferred_username",
                     "email", "ipaddr", "uti", "rh", "sid", "xms_ftd", "puid", "onprem_sid"):
            value = c.get(name)
            if isinstance(value, str) and len(value) >= 3:
                pairs.setdefault(value, "<redacted>")
    for value, placeholder in (extra or {}).items():
        if value:
            pairs[value] = placeholder
    return sorted(pairs.items(), key=lambda item: -len(item[0]))


def redact(text, secrets):
    for value, placeholder in secrets:
        text = text.replace(value, placeholder)
    return text


def assert_clean(text, secrets):
    for value, _ in secrets:
        if value in text:
            raise Leak("secret value left in evidence")
    if JWT_SHAPE.search(text):
        raise Leak("JWT-shaped string left in evidence")


def aadsts_codes(text):
    return sorted(set(re.findall(r"AADSTS\d+", text or "")))


# Entra's answer that the user is not assigned to the app. Only this counts as
# a refusal; a probe that crashed or timed out, an unusable token cache or any
# other error says nothing about the assignment and is inconclusive.
REFUSAL_CODES = frozenset({"AADSTS50105"})


def probe_outcome(result):
    """'ok', 'refused' (Entra answered AADSTS50105) or 'inconclusive'."""
    if result.get("ok"):
        return "ok"
    if REFUSAL_CODES & set(result.get("aadsts") or []):
        return "refused"
    return "inconclusive"


def first_stable_refusal(samples, run=3):
    """t_s of the first refusal followed by run-1 more, among conclusive samples.

    As in respond/azurelab, an inconclusive sample neither counts nor restarts
    the run; a token restarts it."""
    conclusive = [sample for sample in samples if sample["outcome"] in ("ok", "refused")]
    for i in range(len(conclusive) - run + 1):
        if all(sample["outcome"] == "refused" for sample in conclusive[i:i + run]):
            return conclusive[i]["t_s"]
    return None


def scim_user(object_id):
    return json.dumps({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                       "userName": "warden-lab-user", "externalId": object_id, "active": True})


# ---- live helpers (not used by the offline tests) ----

def az_json(*args):
    out = subprocess.run(["az", *args, "-o", "json"], capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        # stderr can carry AADSTS codes; it never carries tokens.
        raise RuntimeError(f"az {args[0]} {args[1] if len(args) > 1 else ''} failed: {out.stderr.strip()[:600]}")
    return json.loads(out.stdout)


def token_for(scope=None, resource=None):
    args = ["account", "get-access-token", "--query", "{t:accessToken}"]
    args += ["--scope", scope] if scope else ["--resource", resource]
    return az_json(*args)["t"]


def fresh_probe(tenant, username, scope):
    """One real token request through scripts/entra_token_probe.py, with its outcome.

    A probe that times out, exits non-zero or prints something other than its
    JSON summary is inconclusive, whatever its stderr mentions."""
    try:
        out = subprocess.run(["/opt/az/bin/python3", "-I", "-B", str(ROOT / "scripts" / "entra_token_probe.py"),
                              "--tenant", tenant, "--username", username, "--scope", scope],
                             capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"ok": False, "ms": None, "aadsts": [], "error": "probe timed out", "outcome": "inconclusive"}
    try:
        result = json.loads(out.stdout)
        if not isinstance(result, dict):
            raise ValueError("not an object")
    except ValueError:
        return {"ok": False, "ms": None, "aadsts": aadsts_codes(out.stderr),
                "error": f"probe failed (exit {out.returncode})", "outcome": "inconclusive"}
    result["outcome"] = probe_outcome(result) if out.returncode == 0 else "inconclusive"
    return result


def graph(method, url, body=None):
    args = ["az", "rest", "--method", method, "--uri", url, "-o", "json"]
    if body is not None:
        args += ["--headers", "Content-Type=application/json", "--body", json.dumps(body)]
    out = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"graph {method} failed: {out.stderr.strip()[:600]}")
    return json.loads(out.stdout) if out.stdout.strip() else None


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Postgres:
    def __init__(self, log):
        self.name = f"warden-task6-entra-pg-{os.getuid()}-{os.getpid()}"
        self.password = random_secrets.token_hex(24)
        self.log = log

    def __enter__(self):
        subprocess.run(["docker", "run", "-d", "--name", self.name, "--label", "warden.test=task6",
                        "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "128", "--cpus", "2",
                        "-p", "127.0.0.1::5432", "-e", f"POSTGRES_PASSWORD={self.password}",
                        "-e", "POSTGRES_DB=warden_test", "postgres:18-alpine"],
                       check=True, capture_output=True, timeout=120)
        for _ in range(240):
            ready = subprocess.run(["docker", "exec", self.name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres",
                                    "-d", "warden_test"], capture_output=True, timeout=30)
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Postgres failed to start")
        port = subprocess.run(["docker", "port", self.name, "5432/tcp"], check=True, capture_output=True,
                              text=True).stdout.split(":")[-1].strip()
        self.url = f"postgres://postgres:{self.password}@127.0.0.1:{port}/warden_test?sslmode=disable"
        image = subprocess.run(["docker", "inspect", "-f", "{{.Image}}", self.name], capture_output=True,
                               text=True).stdout.strip()
        self.log["postgres"] = {"image": "postgres:18-alpine", "image_id": image, "container": self.name}
        return self

    def __exit__(self, *exc):
        subprocess.run(["docker", "rm", "-f", "-v", self.name], capture_output=True, timeout=120)
        gone = subprocess.run(["docker", "ps", "-a", "-q", "--filter", f"name=^{self.name}$"], capture_output=True,
                              text=True).stdout.strip() == ""
        self.log.setdefault("postgres", {"container": self.name})["removed"] = gone


def build(bin_dir):
    bin_dir.mkdir(parents=True, exist_ok=True)
    out = bin_dir / "warden-api"
    cache = ROOT / ".cache"
    env = {"PATH": "/usr/bin:/bin", "GOTOOLCHAIN": "local", "GOPROXY": "off",
           "GOFLAGS": "-mod=readonly -buildvcs=false", "GOCACHE": str(cache / "go-build"),
           "GOMODCACHE": str(cache / "go-mod"), "GOPATH": str(cache / "go"), "HOME": str(cache / "home"),
           "TMPDIR": str(cache / "t"), "CGO_ENABLED": "0"}
    (cache / "t").mkdir(mode=0o700, exist_ok=True)
    subprocess.run([str(ROOT / ".tools/go/bin/go"), "build", "-o", str(out), "./controlplane/cmd/warden-api"],
                   cwd=ROOT, env=env, check=True, capture_output=True, timeout=600)
    return out, hashlib.sha256(out.read_bytes()).hexdigest()


class Server:
    """One warden-api process; stderr goes to a private log read back redacted."""

    def __init__(self, binary, db_url, tenant, audience, digests, log_path):
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.env = {"PATH": "/usr/bin:/bin", "DATABASE_URL": db_url, "WARDEN_LISTEN_ADDR": f"127.0.0.1:{self.port}",
                    "WARDEN_OIDC_ISSUER": f"{AUTHORITY}{tenant}/v2.0", "WARDEN_OIDC_AUDIENCE": audience,
                    "WARDEN_OIDC_JWKS_URL": f"{AUTHORITY}{tenant}/discovery/v2.0/keys"}
        if digests:
            self.env["WARDEN_SCIM_TOKEN_DIGESTS"] = str(digests)
        self.binary, self.log_path = binary, log_path

    def __enter__(self):
        self.log_file = open(self.log_path, "wb")
        self.proc = subprocess.Popen([str(self.binary)], env=self.env, stdout=self.log_file, stderr=self.log_file)
        for _ in range(200):
            try:
                request(self.base, "GET", "/v1/runs/x")
                return self
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError("warden-api exited during startup")
                time.sleep(0.05)
        raise RuntimeError("warden-api did not start listening")

    def __exit__(self, *exc):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log_file.close()


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(base, method, path, bearer=None, body=None, key=None):
    data = body.encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method)
    if bearer is not None:
        r.add_header("Authorization", "Bearer " + bearer)
    if key:
        r.add_header("Idempotency-Key", key)
    if data is not None:
        r.add_header("Content-Type", "application/scim+json" if path.startswith("/scim/") else "application/json")
    start = time.perf_counter()
    try:
        with _OPENER.open(r, timeout=15) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read()
    ms = round((time.perf_counter() - start) * 1000, 2)
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode(errors="replace")[:200]
    return status, ms, parsed


def seconds_to_ms(seconds):
    """A check's "ms" field is milliseconds; the *_s fields stay in seconds."""
    return None if seconds is None else round(seconds * 1000, 1)


def check(log, name, want, got, ms, body=None, note=None):
    entry = {"name": name, "want": want, "got": got, "ms": ms, "pass": got == want}
    if body is not None:
        entry["body"] = body
    if note:
        entry["note"] = note
    log["checks"].append(entry)
    return got == want


def source_state(root=None):
    """HEAD, changed tracked files and untracked files of the checkout the run builds.

    Untracked files count: a driver script that is not committed yet is part
    of the source (as respond/azurelab's SourceState). Raises if git cannot
    tell."""
    root = ROOT if root is None else root

    def git(*args):
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"git {args[0]}: {out.stderr.strip()[:200]}")
        return out.stdout

    head = git("rev-parse", "--verify", "HEAD").strip()
    tracked, untracked = [], []
    for line in git("status", "--porcelain=v1", "--untracked-files=all").splitlines():
        if line.startswith("?? "):
            untracked.append(line[3:])
        elif line:
            tracked.append(line)
    return {"commit": head, "tracked_changes": tracked, "untracked": untracked}


def scim_setup(work):
    token = random_secrets.token_urlsafe(32)
    digests = work / "scim-digests.json"
    digests.write_text(json.dumps({hashlib.sha256(token.encode()).hexdigest(): SCIM_TENANT}))
    digests.chmod(0o600)
    return token, digests


def run_live(args, log, work, secrets):
    audience = args.audience
    scope = args.scope or f"api://{audience}/warden.access"
    tenant = az_json("account", "show", "--query", "{t:tenantId}")["t"]
    secrets += [(tenant, "<tenant-id>")]
    token = token_for(scope=scope)
    secrets += secrets_of(token)
    arm = token_for(resource="https://management.azure.com/")
    secrets += secrets_of(arm)
    scim_token, digests = scim_setup(work)
    secrets += [(scim_token, "<scim-token>")]
    oid = payload(token).get("oid", "")
    log["token"] = claims_summary(token)
    log["other_resource_token"] = claims_summary(arm)
    log["oidc"] = {"issuer": f"{AUTHORITY}{tenant}/v2.0", "jwks_url": f"{AUTHORITY}{tenant}/discovery/v2.0/keys",
                   "audience": audience, "scope": scope}
    binary, digest = build(work / "bin")
    log["control_plane"] = {"binary": "controlplane/cmd/warden-api", "sha256": digest}
    pg = Postgres(log)
    secrets += [(pg.password, "<db-password>")]
    with pg:
        with Server(binary, pg.url, tenant, audience, digests, work / "server-a.log") as a:
            run_id_unknown = "/v1/runs/00000000000000000000000000"
            check(log, "no Authorization header", 401, *request(a.base, "POST", "/v1/runs", body=RUN_BODY, key="n")[:2])
            status, ms, body = request(a.base, "GET", run_id_unknown, token)
            check(log, "real token, user not provisioned (first request, includes JWKS fetch)", 401, status, ms)
            status, ms, body = request(a.base, "POST", "/scim/v2/Users", scim_token, scim_user(oid))
            scim_id = body.get("id") if isinstance(body, dict) else None
            check(log, "SCIM POST /scim/v2/Users externalId=oid (static Warden SCIM token)", 201, status, ms,
                  note="manual provisioning through Warden's endpoint, not Entra's provisioning service")
            status, ms, body = request(a.base, "POST", "/v1/runs", token, RUN_BODY, key="entra-live-1")
            run_id = body.get("run_id") if isinstance(body, dict) else None
            check(log, "real token POST /v1/runs", 201, status, ms, body={"run_id": run_id})
            status, ms, body = request(a.base, "GET", f"/v1/runs/{run_id}", token)
            state = body.get("state") if isinstance(body, dict) else None
            ok = check(log, "real token GET /v1/runs/{id}", 200, status, ms,
                       body={"run_id": body.get("run_id") if isinstance(body, dict) else None, "state": state})
            log["run_read_back"] = ok and state == "queued"
            status, ms, body = request(a.base, "POST", "/v1/runs", token, RUN_BODY, key="entra-live-1")
            check(log, "same Idempotency-Key again", 201, status, ms)
            check(log, "same Idempotency-Key returns the same run_id", True,
                  isinstance(body, dict) and body.get("run_id") == run_id, ms)
            for name, raw in (("token for another resource (Azure Resource Manager)", arm),
                              ("tampered payload (exp +1 h, original signature)", tamper_payload(token)),
                              ("tampered signature (one bit)", tamper_signature(token)),
                              ("alg=none, no signature", unsigned(token)),
                              ("not a JWT", "not-a-token")):
                status, ms, _ = request(a.base, "GET", f"/v1/runs/{run_id}", raw)
                check(log, name, 401, status, ms)
            # Deactivation by hand through Warden's SCIM endpoint, then poll the API with the real token.
            patch = json.dumps({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                "Operations": [{"op": "replace", "path": "active", "value": False}]})
            t0 = time.perf_counter()
            status, ms, _ = request(a.base, "PATCH", f"/scim/v2/Users/{scim_id}", scim_token, patch)
            check(log, "SCIM PATCH active=false", 200, status, ms)
            denied_ms, polls = None, 0
            while time.perf_counter() - t0 < 60:
                polls += 1
                status, _, _ = request(a.base, "GET", f"/v1/runs/{run_id}", token)
                if status == 401:
                    denied_ms = round((time.perf_counter() - t0) * 1000, 2)
                    break
                time.sleep(0.01)
            log["scim_deactivate_to_401_ms"] = denied_ms
            log["scim_deactivate_polls"] = polls
            check(log, "real token after SCIM deactivation", 401, status, denied_ms)
            reactivate = patch.replace("false", "true")
            check(log, "SCIM PATCH active=true", 200, *request(a.base, "PATCH", f"/scim/v2/Users/{scim_id}",
                                                               scim_token, reactivate)[:2])
            check(log, "real token after reactivation", 200, *request(a.base, "GET", f"/v1/runs/{run_id}", token)[:2])
        other = str(uuid.uuid4())
        with Server(binary, pg.url, tenant, other, None, work / "server-b.log") as b:
            log["wrong_audience_server"] = {"audience": other, "note": "random GUID standing for another app"}
            status, ms, _ = request(b.base, "GET", f"/v1/runs/{run_id}", token)
            check(log, "real token at a Warden whose audience is another app", 401, status, ms)
    log["server_logs"] = {p.name: p.read_text(errors="replace").splitlines()[-20:]
                          for p in sorted(work.glob("server-*.log"))}
    if args.keep_token:
        keep = Path(args.keep_token)
        keep.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(keep, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token)
        log["kept_token_expires"] = _iso(payload(token)["exp"])


def run_expired(args, log, work, secrets):
    keep = Path(args.keep_token)
    old = keep.read_text().strip()
    secrets += secrets_of(old)
    left = seconds_until_expiry(old)
    log["expired_token"] = claims_summary(old)
    log["seconds_past_expiry"] = -left
    if left >= 0:
        raise RuntimeError(f"kept token is still valid for {left} s")
    audience = args.audience
    scope = args.scope or f"api://{audience}/warden.access"
    tenant = az_json("account", "show", "--query", "{t:tenantId}")["t"]
    secrets += [(tenant, "<tenant-id>")]
    fresh = token_for(scope=scope)
    secrets += secrets_of(fresh)
    log["token"] = claims_summary(fresh)
    log["oidc"] = {"issuer": f"{AUTHORITY}{tenant}/v2.0", "jwks_url": f"{AUTHORITY}{tenant}/discovery/v2.0/keys",
                   "audience": audience, "scope": scope}
    scim_token, digests = scim_setup(work)
    secrets += [(scim_token, "<scim-token>")]
    binary, digest = build(work / "bin")
    log["control_plane"] = {"binary": "controlplane/cmd/warden-api", "sha256": digest}
    pg = Postgres(log)
    secrets += [(pg.password, "<db-password>")]
    with pg:
        with Server(binary, pg.url, tenant, audience, digests, work / "server-a.log") as a:
            same_user = payload(old).get("oid") == payload(fresh).get("oid")
            log["same_user"] = same_user
            # Otherwise the fresh token is no control for the expired one.
            check(log, "expired token and fresh control token have the same oid", True, same_user, None)
            check(log, "SCIM POST /scim/v2/Users externalId=oid (static Warden SCIM token)", 201,
                  *request(a.base, "POST", "/scim/v2/Users", scim_token, scim_user(payload(fresh)["oid"]))[:2])
            status, ms, body = request(a.base, "POST", "/v1/runs", fresh, RUN_BODY, key="entra-expired-1")
            run_id = body.get("run_id") if isinstance(body, dict) else None
            check(log, "fresh token POST /v1/runs (control)", 201, status, ms)
            check(log, "fresh token GET /v1/runs/{id} (control)", 200,
                  *request(a.base, "GET", f"/v1/runs/{run_id}", fresh)[:2])
            check(log, "expired real token GET /v1/runs/{id}", 401,
                  *request(a.base, "GET", f"/v1/runs/{run_id}", old)[:2])
    log["server_logs"] = {p.name: p.read_text(errors="replace").splitlines()[-20:]
                          for p in sorted(work.glob("server-*.log"))}
    keep.unlink()
    log["kept_token_deleted"] = not keep.exists()


def run_unassign(args, log, work, secrets):
    audience, sp = args.audience, args.sp_object_id
    scope = args.scope or f"api://{audience}/warden.access"
    account = az_json("account", "show", "--query", "{t:tenantId,u:user.name}")
    tenant, username = account["t"], account["u"]
    me = az_json("ad", "signed-in-user", "show", "--query", "{id:id}")["id"]
    secrets += [(tenant, "<tenant-id>"), (me, "<user-oid>"), (username, "<user-upn>")]
    token = token_for(scope=scope)
    secrets += secrets_of(token)
    log["token"] = claims_summary(token)
    if seconds_until_expiry(token) < 900:
        raise RuntimeError("the cached token expires within 15 minutes; run later")
    log["oidc"] = {"issuer": f"{AUTHORITY}{tenant}/v2.0", "jwks_url": f"{AUTHORITY}{tenant}/discovery/v2.0/keys",
                   "audience": audience, "scope": scope}
    scim_token, digests = scim_setup(work)
    secrets += [(scim_token, "<scim-token>")]
    binary, digest = build(work / "bin")
    log["control_plane"] = {"binary": "controlplane/cmd/warden-api", "sha256": digest}
    base = "https://graph.microsoft.com/v1.0/servicePrincipals/" + sp + "/appRoleAssignedTo"
    pg = Postgres(log)
    secrets += [(pg.password, "<db-password>")]
    with pg:
        with Server(binary, pg.url, tenant, audience, digests, work / "server-a.log") as a:
            status, ms, body = request(a.base, "POST", "/scim/v2/Users", scim_token, scim_user(payload(token)["oid"]))
            scim_id = body.get("id") if isinstance(body, dict) else None
            check(log, "SCIM POST /scim/v2/Users externalId=oid (static Warden SCIM token)", 201, status, ms)
            status, ms, body = request(a.base, "POST", "/v1/runs", token, RUN_BODY, key="entra-unassign-1")
            run_id = body.get("run_id") if isinstance(body, dict) else None
            check(log, "token issued while assigned: POST /v1/runs", 201, status, ms)
            before = fresh_probe(tenant, username, scope)
            log["fresh_token_before_unassign"] = before
            check(log, "fresh token from Entra while assigned", True, before["outcome"] == "ok", before["ms"])
            mine = [x for x in graph("GET", base)["value"] if x.get("principalId") == me]
            log["assignments_of_user_before"] = len(mine)
            for x in mine:
                secrets += [(x["id"], "<assignment-id>")]
            if len(mine) != 1:
                raise RuntimeError(f"expected one assignment of the signed-in user, found {len(mine)}")
            t0 = time.perf_counter()
            log["unassigned_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            graph("DELETE", f"{base}/{mine[0]['id']}")
            log["unassign_call_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            samples = []
            while time.perf_counter() - t0 < 600:
                tick = time.perf_counter()
                result = fresh_probe(tenant, username, scope)
                warden, _, _ = request(a.base, "GET", f"/v1/runs/{run_id}", token)
                sample = {"t_s": round(tick - t0, 2), "outcome": result["outcome"], "aadsts": result["aadsts"],
                          "probe_ms": result["ms"], "warden_old_token": warden}
                if result["outcome"] == "inconclusive":
                    sample["probe_error"] = result.get("error")
                samples.append(sample)
                if first_stable_refusal(samples) is not None:
                    break
                time.sleep(max(0.0, 3 - (time.perf_counter() - tick)))
            log["unassign_samples"] = samples
            log["unassign_inconclusive_probes"] = sum(s["outcome"] == "inconclusive" for s in samples)
            refused = first_stable_refusal(samples)
            log["unassign_to_stable_refusal_s"] = refused
            check(log, "Entra refuses new tokens after unassignment (3 in a row)", True, refused is not None,
                  seconds_to_ms(refused))
            status, ms, _ = request(a.base, "GET", f"/v1/runs/{run_id}", token)
            log["old_token_seconds_left"] = seconds_until_expiry(token)
            check(log, "token issued before unassignment still accepted by Warden (nothing tells Warden)", 200,
                  status, ms, note="without SCIM provisioning this lasts until the token's exp")
            patch = json.dumps({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                "Operations": [{"op": "replace", "path": "active", "value": False}]})
            t1 = time.perf_counter()
            check(log, "SCIM PATCH active=false by hand (what Entra provisioning would send)", 200,
                  *request(a.base, "PATCH", f"/scim/v2/Users/{scim_id}", scim_token, patch)[:2])
            status, _, _ = request(a.base, "GET", f"/v1/runs/{run_id}", token)
            check(log, "old token after SCIM deactivation", 401, status, round((time.perf_counter() - t1) * 1000, 2))
        t2 = time.perf_counter()
        log["reassigned_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        created = graph("POST", base, {"principalId": me, "resourceId": sp,
                                       "appRoleId": "00000000-0000-0000-0000-000000000000"})
        secrets += [(created["id"], "<assignment-id>")]
        attempts, ok = 0, False
        while time.perf_counter() - t2 < 300 and not ok:
            attempts += 1
            ok = fresh_probe(tenant, username, scope)["outcome"] == "ok"
            if not ok:
                time.sleep(2)
        log["reassign_to_first_token_s"] = round(time.perf_counter() - t2, 2) if ok else None
        log["reassign_attempts"] = attempts
        check(log, "fresh token from Entra after assigning again", True, ok,
              seconds_to_ms(log["reassign_to_first_token_s"]))
    log["server_logs"] = {p.name: p.read_text(errors="replace").splitlines()[-20:]
                          for p in sorted(work.glob("server-*.log"))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("mode", choices=["run", "expired", "unassign"])
    parser.add_argument("--audience", required=True, help="client ID of warden-lab-api")
    parser.add_argument("--scope", help="default api://<audience>/warden.access")
    parser.add_argument("--out", required=True)
    parser.add_argument("--keep-token", help="run: keep the token (0600) for `expired`; expired: read and delete it")
    parser.add_argument("--sp-object-id", help="unassign: object ID of the warden-lab-api service principal")
    args = parser.parse_args(argv)
    if args.mode == "expired" and not args.keep_token:
        parser.error("expired needs --keep-token")
    if args.mode == "unassign" and not args.sp_object_id:
        parser.error("unassign needs --sp-object-id")
    try:
        source = source_state()
    except RuntimeError as err:
        print(f"cannot read the source state, nothing was done: {err}", file=sys.stderr)
        return 2
    work = ROOT / ".cache" / "task6-idp" / f"work-{args.mode}-{os.getpid()}"
    work.mkdir(parents=True, mode=0o700)
    log = {"schema": "warden.task6.entra-live/v1", "mode": args.mode,
           "started_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "source": source, "host": os.uname().nodename, "checks": []}
    secrets = []
    try:
        {"run": run_live, "expired": run_expired, "unassign": run_unassign}[args.mode](args, log, work, secrets)
    except Exception as err:  # recorded as FAIL with the reason, never swallowed
        log["error"] = f"{type(err).__name__}: {err}"
    secrets.sort(key=lambda item: -len(item[0]))
    log["finished_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log["result"] = "PASS" if log["checks"] and all(c["pass"] for c in log["checks"]) and "error" not in log else "FAIL"
    text = redact(json.dumps(log, indent=2, sort_keys=True), secrets)
    assert_clean(text, secrets)
    Path(args.out).write_text(text + "\n")
    print(f"{log['result']}: {sum(c['pass'] for c in log['checks'])}/{len(log['checks'])} checks -> {args.out}")
    return 0 if log["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
