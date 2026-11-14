"""Offline tests for scripts/entra_oidc_live.py: token handling and redaction.

The live run sends real Entra tokens; these tests use synthetic ones and make
sure nothing identifying or secret can reach the evidence file. The
`unassign` and `expired` modes also run end to end here, with az, Graph,
the token probe, Docker, the Go build and warden-api replaced by fakes and
a fake clock.
"""

import base64
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import entra_oidc_live as live
import entra_token_probe as probe

TENANT = "aaaaaaaa-1111-4111-8111-bbbbbbbbbbbb"
OID = "cccccccc-2222-4222-8222-dddddddddddd"
AUD = "eeeeeeee-3333-4333-8333-ffffffffffff"
OTHER_OID = "99999999-4444-4444-8444-999999999999"
SP = "12121212-5555-4555-8555-121212121212"
NOW = 1762801000  # fake wall clock, inside make_token()'s default iat..exp


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(**extra):
    header = {"typ": "JWT", "alg": "RS256", "kid": "kid-1"}
    claims = {
        "aud": AUD, "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "tid": TENANT,
        "oid": OID, "sub": "subject-value-xyz", "name": "Real Person", "preferred_username": "person@school.example",
        "upn": "person@school.example", "ipaddr": "203.0.113.7", "scp": "warden.access", "ver": "2.0",
        "iat": 1762800000, "nbf": 1762800000, "exp": 1762804500, "uti": "unique-token-id", "rh": "refresh-hint",
        "azp": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "idtyp": "user",
    }
    claims.update(extra)
    signature = bytes(range(256))
    return ".".join([b64(json.dumps(header).encode()), b64(json.dumps(claims).encode()), b64(signature)])


class SummaryTest(unittest.TestCase):
    def test_summary_keeps_shape_not_identity(self):
        token = make_token()
        summary = live.claims_summary(token)
        text = json.dumps(summary)
        for value in (TENANT, OID, "subject-value-xyz", "Real Person", "person@school.example", "203.0.113.7",
                      "unique-token-id", "refresh-hint"):
            self.assertNotIn(value, text)
        self.assertEqual(summary["claims"]["iss"], "https://login.microsoftonline.com/<tenant-id>/v2.0")
        self.assertEqual(summary["claims"]["aud"], AUD)
        self.assertEqual(summary["claims"]["scp"], "warden.access")
        self.assertEqual(summary["claims"]["ver"], "2.0")
        self.assertEqual(summary["claims"]["oid"], "<user-oid>")
        self.assertEqual(summary["lifetime_s"], 4500)
        self.assertEqual(summary["header"], {"alg": "RS256", "typ": "JWT", "kid": "kid-1"})
        self.assertIn("name", summary["claim_names"])
        self.assertEqual(summary["signature_bytes"], 256)

    def test_seconds_until_expiry(self):
        token = make_token(exp=1000)
        self.assertEqual(live.seconds_until_expiry(token, now=900), 100)
        self.assertEqual(live.seconds_until_expiry(token, now=1100), -100)


class TamperTest(unittest.TestCase):
    def test_payload_tamper_keeps_header_and_signature(self):
        token = make_token()
        forged = live.tamper_payload(token)
        h, p, s = token.split(".")
        fh, fp, fs = forged.split(".")
        self.assertEqual((fh, fs), (h, s))
        self.assertNotEqual(fp, p)
        self.assertEqual(live.payload(forged)["exp"], live.payload(token)["exp"] + 3600)
        self.assertEqual(b64(base64.urlsafe_b64decode(fp + "=" * (-len(fp) % 4))), fp, "canonical base64url")

    def test_signature_tamper_changes_only_the_signature(self):
        token = make_token()
        forged = live.tamper_signature(token)
        h, p, s = token.split(".")
        fh, fp, fs = forged.split(".")
        self.assertEqual((fh, fp), (h, p))
        self.assertNotEqual(fs, s)
        raw = base64.urlsafe_b64decode(fs + "=" * (-len(fs) % 4))
        self.assertEqual(len(raw), 256)
        self.assertEqual(b64(raw), fs, "canonical base64url")

    def test_unsigned_variant_has_alg_none(self):
        forged = live.unsigned(make_token())
        header = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
        self.assertEqual(header["alg"], "none")
        self.assertTrue(forged.endswith("."))


class RedactTest(unittest.TestCase):
    def test_redact_tokens_segments_and_ids(self):
        token = make_token()
        secrets = live.secrets_of(token)
        _, payload_segment, signature_segment = token.split(".")
        text = f"t={token} p={payload_segment} s={signature_segment} tid={TENANT} oid={OID} n=Real Person"
        clean = live.redact(text, secrets)
        live.assert_clean(clean, secrets)
        self.assertIn("<tenant-id>", clean)
        self.assertIn("<user-oid>", clean)
        self.assertNotIn("Real Person", clean)

    def test_assert_clean_catches_leftovers(self):
        token = make_token()
        secrets = live.secrets_of(token)
        with self.assertRaises(live.Leak):
            live.assert_clean(f"x {OID}", secrets)
        with self.assertRaises(live.Leak):
            live.assert_clean("eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", [])

    def test_extra_secrets(self):
        secrets = live.secrets_of(make_token(), extra={"scim-token-value": "<scim-token>"})
        self.assertEqual(live.redact("Bearer scim-token-value", secrets), "Bearer <scim-token>")


class ScimBodyTest(unittest.TestCase):
    def test_user_body_maps_oid_without_profile_data(self):
        body = json.loads(live.scim_user(OID))
        self.assertEqual(body["externalId"], OID)
        self.assertEqual(body["schemas"], ["urn:ietf:params:scim:schemas:core:2.0:User"])
        self.assertTrue(body["active"])
        self.assertNotIn("@school.example", body["userName"])


class UnassignHelpersTest(unittest.TestCase):
    def test_aadsts_codes(self):
        text = "ERROR: AADSTS50105: Your administrator ... (AADSTS50105) Trace ID: x"
        self.assertEqual(live.aadsts_codes(text), ["AADSTS50105"])
        self.assertEqual(live.aadsts_codes(""), [])

    def test_first_stable_refusal(self):
        samples = [{"t_s": t, "outcome": o} for t, o in
                   ((1, "ok"), (4, "refused"), (7, "ok"), (10, "refused"), (13, "refused"), (16, "refused"))]
        self.assertEqual(live.first_stable_refusal(samples, run=3), 10)
        self.assertIsNone(live.first_stable_refusal(samples[:5], run=3))
        self.assertIsNone(live.first_stable_refusal([], run=3))

    def test_inconclusive_samples_neither_count_nor_restart(self):
        def samples(*outcomes):
            return [{"t_s": 1 + 3 * i, "outcome": o} for i, o in enumerate(outcomes)]
        self.assertIsNone(live.first_stable_refusal(samples("inconclusive", "inconclusive", "inconclusive")))
        self.assertIsNone(live.first_stable_refusal(samples("refused", "inconclusive", "inconclusive", "refused")))
        self.assertEqual(live.first_stable_refusal(samples("refused", "inconclusive", "refused", "refused")), 1)
        self.assertEqual(live.first_stable_refusal(
            samples("refused", "inconclusive", "ok", "refused", "inconclusive", "refused", "refused")), 10)

    def test_only_the_assignment_refusal_counts_as_refused(self):
        self.assertEqual(live.probe_outcome({"ok": True, "ms": 1, "aadsts": [], "error": None}), "ok")
        self.assertEqual(live.probe_outcome({"ok": False, "ms": 1, "aadsts": ["AADSTS50105"],
                                             "error": "invalid_grant"}), "refused")
        for result in ({"ok": False, "ms": 0, "aadsts": [], "error": "probe failed"},
                       {"ok": False, "ms": 0, "aadsts": [], "error": "2 cached accounts"},
                       {"ok": False, "ms": 5, "aadsts": [], "error": None},
                       {"ok": False, "ms": 5, "aadsts": ["AADSTS90033"], "error": "temporarily_unavailable"}):
            self.assertEqual(live.probe_outcome(result), "inconclusive", result)

    def test_probe_crash_or_timeout_is_inconclusive(self):
        for kind in ("crash", "timeout", "accounts", "garbage", "crash-mentioning-50105"):
            with self.subTest(kind), mock.patch.object(live.subprocess, "run", side_effect=[probe_answer(kind)]):
                result = live.fresh_probe(TENANT, "person@school.example", "api://x/warden.access")
                self.assertFalse(result["ok"])
                self.assertEqual(result["outcome"], "inconclusive")
        for kind, outcome in (("ok", "ok"), ("refused", "refused")):
            with self.subTest(kind), mock.patch.object(live.subprocess, "run", side_effect=[probe_answer(kind)]):
                self.assertEqual(live.fresh_probe(TENANT, "person@school.example", "s")["outcome"], outcome)


class Clock:
    """Fake time for the live loops: sleep advances it, nothing really waits."""

    def __init__(self):
        self.t = 0.0

    def perf_counter(self):
        return self.t

    def time(self):
        return NOW + self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)


def probe_answer(kind):
    """What a run of scripts/entra_token_probe.py gives back for one token request."""
    if kind == "timeout":
        return subprocess.TimeoutExpired(["entra_token_probe.py"], 60)
    if kind == "crash":
        return subprocess.CompletedProcess([], 1, "", "Traceback (most recent call last):\nConnectionResetError\n")
    if kind == "crash-mentioning-50105":
        return subprocess.CompletedProcess([], 1, "", "Traceback (most recent call last):\nValueError: AADSTS50105\n")
    if kind == "garbage":
        return subprocess.CompletedProcess([], 0, "not json\n", "")
    out = {"ok": {"ok": True, "ms": 120.0, "aadsts": [], "error": None},
           "refused": {"ok": False, "ms": 90.0, "aadsts": ["AADSTS50105"], "error": "invalid_grant"},
           "accounts": {"ok": False, "ms": 0, "aadsts": [], "error": "2 cached accounts"}}[kind]
    return subprocess.CompletedProcess([], 2 if kind == "accounts" else 0, json.dumps(out) + "\n", "")


class FakeWarden:
    """warden-api as the live script sees it: SCIM users, runs and the bearer check."""

    def __init__(self, valid_tokens):
        self.valid = set(valid_tokens)
        self.active = True

    def request(self, base, method, path, bearer=None, body=None, key=None):
        if path == "/scim/v2/Users" and method == "POST":
            return 201, 1.0, {"id": "scim-user-1"}
        if path.startswith("/scim/v2/Users/") and method == "PATCH":
            self.active = json.loads(body)["Operations"][0]["value"]
            return 200, 1.0, {}
        if bearer not in self.valid or not self.active:
            return 401, 1.0, None
        if method == "POST":
            return 201, 1.0, {"run_id": "run-1"}
        return 200, 1.0, {"run_id": "run-1", "state": "queued"}


class FakePostgres:
    def __init__(self, log):
        self.log, self.password, self.url = log, "db-password-value", "postgres://fake"

    def __enter__(self):
        self.log["postgres"] = {"container": "fake"}
        return self

    def __exit__(self, *exc):
        self.log["postgres"]["removed"] = True


class FakeServer:
    def __init__(self, binary, db_url, tenant, audience, digests, log_path):
        self.base, self.log_path = "http://127.0.0.1:1", log_path

    def __enter__(self):
        self.log_path.write_text("")
        return self

    def __exit__(self, *exc):
        pass


class OfflineModeTest(unittest.TestCase):
    """`unassign` and `expired` end to end through main(), everything outside replaced."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.clock = Clock()
        self.fresh = make_token()
        self.probes, self.default_probe = [], None
        self.warden = FakeWarden([self.fresh])
        for name, value in (("ROOT", self.dir), ("time", self.clock), ("az_json", self.az_json),
                            ("token_for", lambda scope=None, resource=None: self.fresh),
                            ("build", lambda bin_dir: (bin_dir / "warden-api", "0" * 64)),
                            ("Postgres", FakePostgres), ("Server", FakeServer),
                            ("request", lambda *a, **k: self.warden.request(*a, **k)), ("graph", self.graph),
                            ("source_state", lambda *a, **k: {"commit": "0" * 40, "tracked_changes": [],
                                                              "untracked": []})):
            patcher = mock.patch.object(live, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(live.subprocess, "run", self.run_probe)
        patcher.start()
        self.addCleanup(patcher.stop)

    def az_json(self, *args):
        if args[:2] == ("account", "show"):
            return {"t": TENANT, "u": "person@school.example"}
        if args[:3] == ("ad", "signed-in-user", "show"):
            return {"id": OID}
        raise AssertionError(f"unexpected az {args}")

    def graph(self, method, url, body=None):
        if method == "GET":
            return {"value": [{"id": "assignment-of-user", "principalId": OID},
                              {"id": "assignment-of-someone-else", "principalId": OTHER_OID}]}
        return None if method == "DELETE" else {"id": "assignment-again"}

    def run_probe(self, args, **kwargs):
        self.assertIn(str(live.ROOT / "scripts" / "entra_token_probe.py"), args)
        kind = self.probes.pop(0) if self.probes else self.default_probe
        if kind is None:
            raise AssertionError("more token probes than scripted")
        answer = probe_answer(kind)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def main(self, *args):
        out = self.dir / "out.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = live.main([*args, "--audience", AUD, "--out", str(out)])
        return code, json.loads(out.read_text())

    def test_unassign_counts_only_entra_refusals(self):
        # Assigned: a token. Unassigned: a crash, a timeout and an unusable
        # token cache (all inconclusive), then three refusals. Assigned again:
        # one refusal, then a token.
        self.probes = ["ok", "crash", "timeout", "accounts", "refused", "refused", "refused", "refused", "ok"]
        code, log = self.main("unassign", "--sp-object-id", SP)
        self.assertNotIn("error", log)
        self.assertEqual([s["outcome"] for s in log["unassign_samples"]], ["inconclusive"] * 3 + ["refused"] * 3)
        self.assertEqual(log["unassign_inconclusive_probes"], 3)
        self.assertEqual(log["unassign_to_stable_refusal_s"], 9.0)
        self.assertEqual(log["reassign_attempts"], 2)
        self.assertEqual(log["reassign_to_first_token_s"], 2.0)
        self.assertEqual((code, log["result"]), (0, "PASS"))
        self.assertEqual(self.probes, [])

    def test_check_times_are_milliseconds(self):
        self.probes = ["ok", "ok", "refused", "refused", "refused", "refused", "ok"]
        _, log = self.main("unassign", "--sp-object-id", SP)
        self.assertEqual(log["unassign_to_stable_refusal_s"], 3.0)
        self.assertEqual(log["reassign_to_first_token_s"], 2.0)
        checks = {c["name"]: c for c in log["checks"]}
        self.assertEqual(checks["Entra refuses new tokens after unassignment (3 in a row)"]["ms"], 3000.0)
        self.assertEqual(checks["fresh token from Entra after assigning again"]["ms"], 2000.0)

    def expired(self, oid):
        keep = self.dir / "kept-token"
        keep.write_text(make_token(oid=oid, iat=NOW - 4137, nbf=NOW - 4137, exp=NOW - 57))
        code, log = self.main("expired", "--keep-token", str(keep))
        self.assertFalse(keep.exists())
        return code, log, {c["name"]: c for c in log["checks"]}

    def test_expired_token_of_the_same_user_passes(self):
        code, log, checks = self.expired(OID)
        self.assertTrue(log["same_user"])
        self.assertEqual(checks["expired real token GET /v1/runs/{id}"]["got"], 401)
        self.assertEqual((code, log["result"]), (0, "PASS"))

    def test_expired_token_of_another_user_is_not_a_pass(self):
        # The fresh control then says nothing about the expired token's user.
        code, log, checks = self.expired(OTHER_OID)
        self.assertFalse(log["same_user"])
        self.assertEqual(checks["expired real token GET /v1/runs/{id}"]["got"], 401)
        self.assertEqual((code, log["result"]), (1, "FAIL"))

    def test_unreadable_source_state_stops_before_any_entra_call(self):
        def no_az(*args):
            raise AssertionError(f"az {args} ran without a source state")
        with mock.patch.object(live, "source_state", side_effect=RuntimeError("git rev-parse: not a git repository")), \
                mock.patch.object(live, "az_json", no_az), contextlib.redirect_stderr(io.StringIO()) as err:
            code = live.main(["run", "--audience", AUD, "--out", str(self.dir / "out.json")])
        self.assertEqual(code, 2)
        self.assertIn("source", err.getvalue())
        self.assertFalse((self.dir / "out.json").exists())

    def test_unassign_with_only_failed_probes_is_not_a_refusal(self):
        self.probes, self.default_probe = ["ok"], "crash"
        code, log = self.main("unassign", "--sp-object-id", SP)
        checks = {c["name"]: c for c in log["checks"]}
        self.assertFalse(checks["Entra refuses new tokens after unassignment (3 in a row)"]["pass"])
        self.assertIsNone(log["unassign_to_stable_refusal_s"])
        self.assertTrue(log["unassign_samples"])
        self.assertEqual({s["outcome"] for s in log["unassign_samples"]}, {"inconclusive"})
        self.assertEqual((code, log["result"]), (1, "FAIL"))


class SourceStateTest(unittest.TestCase):
    """The run JSON names the checkout it was built from, untracked files included."""

    def git(self, repo, *args):
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)

    def test_records_commit_tracked_changes_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.git(repo, "init", "-q")
            (repo / "a.txt").write_text("a\n")
            self.git(repo, "add", "a.txt")
            self.git(repo, "commit", "-q", "-m", "a")
            clean = live.source_state(repo)
            self.assertEqual(len(clean["commit"]), 40)
            self.assertEqual((clean["tracked_changes"], clean["untracked"]), ([], []))
            # A driver script that is not committed yet is part of the source.
            (repo / "scripts").mkdir()
            (repo / "scripts" / "driver.py").write_text("print()\n")
            state = live.source_state(repo)
            self.assertEqual(state["commit"], clean["commit"])
            self.assertEqual((state["tracked_changes"], state["untracked"]), ([], ["scripts/driver.py"]))
            (repo / "a.txt").write_text("b\n")
            self.assertEqual(live.source_state(repo)["tracked_changes"], [" M a.txt"])

    def test_outside_a_checkout_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                live.source_state(Path(tmp) / "missing")


class ProbeSummaryTest(unittest.TestCase):
    def test_summary_never_carries_tokens(self):
        token = make_token()
        result = {"access_token": token, "refresh_token": "rt-secret", "id_token": token, "expires_in": 4000,
                  "token_type": "Bearer", "scope": "api://x/warden.access"}
        summary = probe.summarize(result, ms=12.5)
        text = json.dumps(summary)
        self.assertNotIn("rt-secret", text)
        self.assertNotIn(token.split(".")[1], text)
        self.assertEqual(summary, {"ok": True, "ms": 12.5, "aadsts": [], "error": None})

    def test_summary_of_error_keeps_codes_only(self):
        result = {"error": "invalid_grant", "error_description": "AADSTS50105: Your administrator has configured "
                  "... Trace ID: 1 Correlation ID: 2 Timestamp: 3", "error_codes": [50105]}
        summary = probe.summarize(result, ms=80)
        self.assertEqual(summary, {"ok": False, "ms": 80, "aadsts": ["AADSTS50105"], "error": "invalid_grant"})


if __name__ == "__main__":
    unittest.main()
