"""Bound Kyverno rendering and complete Grype v0.121.0 scan assessment.

Parsing is not signature verification. The CI caller must fetch CISA KEV from
the official HTTPS URL and sign the predicate for the same immutable digest.
"""
import argparse
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
REPO = re.compile(r"[a-z0-9_.-]+/[a-z0-9_.-]+\Z")
IMAGE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)+\Z")
ISSUER = "https://token.actions.githubusercontent.com"
REKOR = "https://rekor.sigstore.dev"
SCAN_TYPE = "https://warden.dev/attestations/grype-complete/v1"
SBOM_TYPE = "https://cyclonedx.org/bom"
SLSA_TYPE = "https://slsa.dev/provenance/v0.2"
SLSA_BUILDER = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
CISA_SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_AGE = timedelta(days=7)
MAX_DB_AGE = timedelta(days=5)


def _render_reject(reason):
    return {"status": "rejected", "accepted": False, "reason": reason, "policies": None}


def _scan_reject(reason):
    return {"status": "rejected", "release_allowed": False,
            "block_reasons": [reason], "fixable_critical": [], "kev_cves": [],
            "predicate": None}


def _identity(subject):
    return {"entries": [{"keyless": {"issuer": ISSUER, "subject": subject,
                                     "rekor": {"url": REKOR}}}]}


def _condition(key, value):
    return {"key": "{{ " + key + " }}", "operator": "Equals", "value": value}


def _entry():
    return {"imageReferences": ["*"], "required": True, "verifyDigest": True,
            "mutateDigest": False, "failureAction": "Enforce"}


def _rule(name, namespace, entry):
    return {"name": name, "match": {"any": [{"resources": {
        "kinds": ["Pod"], "namespaces": [namespace]}}]}, "verifyImages": [entry]}


def _policy(name, rules):
    return {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
            "metadata": {"name": name}, "spec": {
                "background": False,
                "webhookConfiguration": {"failurePolicy": "Fail", "timeoutSeconds": 30},
                "rules": rules}}


def render_binding(binding):
    """Render only complete syntactic bindings; caller authenticates GitHub context."""
    if not isinstance(binding, Mapping):
        return _render_reject("binding must be a mapping")
    fields = ("repository", "ref", "image_repository", "image_digest",
              "namespace", "slsa_subject", "slsa_builder_id")
    if any(not isinstance(binding.get(k), str) or not binding[k].strip() for k in fields):
        return _render_reject("repository/ref/image/namespace/SLSA identity required")
    repo, ref = binding["repository"], binding["ref"]
    image, digest, namespace = binding["image_repository"], binding["image_digest"], binding["namespace"]
    if not REPO.fullmatch(repo):
        return _render_reject("invalid repository")
    if not re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+", ref) or ".." in ref:
        return _render_reject("invalid full Git ref")
    if not IMAGE.fullmatch(image) or not DIGEST.fullmatch(digest):
        return _render_reject("invalid immutable image repository/digest")
    if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", namespace):
        return _render_reject("invalid namespace")
    if binding["slsa_subject"] != SLSA_BUILDER:
        return _render_reject("SLSA signer identity unbound")
    if binding["slsa_builder_id"] != SLSA_BUILDER:
        return _render_reject("SLSA builder id unbound")
    workflow = f"https://github.com/{repo}/.github/workflows/build.yml@{ref}"
    # No "type": every check uses Kyverno's default Cosign verifier and the
    # legacy .sig/.att tags. slsa-github-generator v2.1.0 only writes that
    # format, so CI signs with cosign --new-bundle-format=false as well.
    signature = _entry()
    signature["attestors"] = [_identity(workflow)]
    provenance = _entry()
    provenance["attestations"] = [{
        "predicateType": SLSA_TYPE, "attestors": [_identity(binding["slsa_subject"])],
        "conditions": [{"all": [
            _condition("buildType", "https://github.com/slsa-framework/slsa-github-generator/container@v1"),
            _condition("builder.id", binding["slsa_builder_id"]),
            _condition("invocation.configSource.uri", f"git+https://github.com/{repo}@{ref}.git"),
            _condition("invocation.configSource.entryPoint", ".github/workflows/build.yml")]}]}]
    sbom = _entry()
    sbom["attestations"] = [{"predicateType": SBOM_TYPE,
        "attestors": [_identity(workflow)],
        "conditions": [{"all": [_condition("bomFormat", "CycloneDX")]}]}]
    scan = _entry()
    scan["attestations"] = [{"predicateType": SCAN_TYPE,
        "attestors": [_identity(workflow)],
        "conditions": [{"all": [
            _condition("scanComplete", True), _condition("imageRepository", image),
            _condition("imageDigest", digest), _condition("kevCves", []),
            _condition("dbValid", True), _condition("kevCatalogSource", CISA_SOURCE)]}]}]
    verify = _policy("warden-verify-images", [
        _rule("signed-image", namespace, signature),
        _rule("slsa-provenance", namespace, provenance),
        _rule("cyclonedx-sbom", namespace, sbom)])
    block = _policy("warden-block-kev", [_rule("complete-scan-no-kev", namespace, scan)])
    return {"status": "rendered", "accepted": True, "reason": "syntactically bound",
            "policies": {"verify-images.yaml": json.dumps(verify, indent=2) + "\n",
                         "block-kev.yaml": json.dumps(block, indent=2) + "\n"}}


def _time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo else None


def _fresh(value, now):
    return value is not None and timedelta(0) <= now - value <= MAX_AGE


def _cisa_cves(catalog, now):
    if not isinstance(catalog, Mapping):
        return None
    records = catalog.get("vulnerabilities")
    if not _fresh(_time(catalog.get("dateReleased")), now) or not isinstance(records, list):
        return None
    if type(catalog.get("count")) is not int or catalog["count"] != len(records) or not records:
        return None
    result = set()
    for row in records:
        if not isinstance(row, Mapping) or not isinstance(row.get("cveID"), str) or not CVE.fullmatch(row["cveID"]):
            return None
        if row["cveID"] in result:
            return None
        result.add(row["cveID"])
    return result


def assess_scan(report, image_digest, *, image_repository=None, kev_catalog=None, now=None):
    """Gate unignored findings with Grype DB metadata and an independent KEV feed."""
    if not isinstance(image_digest, str) or not DIGEST.fullmatch(image_digest):
        return _scan_reject("invalid image digest")
    if not isinstance(image_repository, str) or not IMAGE.fullmatch(image_repository):
        return _scan_reject("invalid image repository")
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None:
        return _scan_reject("trusted current time required")
    now = now.astimezone(timezone.utc)
    if not isinstance(report, Mapping) or not isinstance(report.get("matches"), list):
        return _scan_reject("complete matches array required")
    # Grype's Document has omitempty on ignoredMatches: absence means zero.
    if report.get("ignoredMatches", []) != []:
        return _scan_reject("ignoredMatches must be empty")
    source = report.get("source")
    if not isinstance(source, Mapping) or source.get("type") != "image":
        return _scan_reject("direct image scan required")
    target = source.get("target")
    if not isinstance(target, Mapping) or not isinstance(target.get("repoDigests"), list):
        return _scan_reject("Grype image digest evidence missing")
    if f"{image_repository}@{image_digest}" not in target["repoDigests"]:
        return _scan_reject("Grype source digest mismatch")
    descriptor = report.get("descriptor")
    if not isinstance(descriptor, Mapping) or descriptor.get("name") != "grype" or descriptor.get("version") != "0.121.0":
        return _scan_reject("pinned Grype version required")
    db = descriptor.get("db")
    status = db.get("status") if isinstance(db, Mapping) else None
    if not isinstance(status, Mapping) or status.get("valid") is not True or status.get("error"):
        return _scan_reject("Grype DB validity evidence missing")
    schema = status.get("schemaVersion")
    if not isinstance(schema, str) or not re.fullmatch(r"v6\.[0-9]+\.[0-9]+", schema):
        return _scan_reject("unsupported Grype DB schema")
    db_built = _time(status.get("built"))
    if db_built is None or not timedelta(0) <= now - db_built <= MAX_DB_AGE:
        return _scan_reject("Grype DB built time missing or stale")
    db_source = status.get("from")
    if not isinstance(db_source, str) or not (
        db_source == "https://grype.anchore.io/databases" or
        db_source.startswith("https://grype.anchore.io/databases/")
    ):
        return _scan_reject("Grype DB source is not the pinned official distribution")
    if not isinstance(db.get("providers"), Mapping) or not db["providers"]:
        return _scan_reject("Grype DB provider provenance missing")
    for provider_name, evidence in db["providers"].items():
        if not isinstance(provider_name, str) or not provider_name or not isinstance(evidence, Mapping):
            return _scan_reject("malformed Grype provider provenance")
        if _time(evidence.get("captured")) is None or not isinstance(evidence.get("input"), str) or not evidence["input"]:
            return _scan_reject("incomplete Grype provider provenance")
    config = descriptor.get("configuration")
    if not isinstance(config, Mapping):
        return _scan_reject("Grype configuration unknown")
    # Pinned Grype v0.121.0's options.Grype JSON tags are hyphenated. Nil
    # Go slices encode as null; explicitly empty slices encode as []. Every
    # field is required so an omitted or partial profile cannot claim a
    # complete scan. Matcher suppressions must be surfaced in ignoredMatches.
    for key in ("only-fixed", "only-notfixed"):
        if config.get(key) is not False:
            return _scan_reject("filtered or incomplete Grype configuration: " + key)
    for key in ("include-matcher-suppressions", "match-upstream-kernel-headers"):
        if config.get(key) is not True:
            return _scan_reject("hidden Grype matches or incomplete profile: " + key)
    if type(config.get("ignore-wontfix")) is not str or config["ignore-wontfix"] != "":
        return _scan_reject("filtered or incomplete Grype configuration: ignore-wontfix")
    for key in ("ignore", "exclude", "vex-documents", "vex-add"):
        if key not in config or config[key] is not None and (
            not isinstance(config[key], list) or config[key] != []
        ):
            return _scan_reject("filtered or incomplete Grype configuration: " + key)
    cisa = _cisa_cves(kev_catalog, now)
    if cisa is None:
        return _scan_reject("fresh complete CISA KEV catalog required")
    critical, kev = set(), set()
    for match in report["matches"]:
        if not isinstance(match, Mapping) or not isinstance(match.get("vulnerability"), Mapping):
            return _scan_reject("malformed match")
        vuln = match["vulnerability"]
        direct, fix = vuln.get("id"), vuln.get("fix")
        if not isinstance(direct, str) or not direct or not isinstance(fix, Mapping):
            return _scan_reject("malformed vulnerability/fix")
        if fix.get("state") not in ("fixed", "not-fixed", "unknown", "wont-fix"):
            return _scan_reject("unknown fix state")
        severity = vuln.get("severity")
        if not isinstance(severity, str) or severity.lower() not in (
            "unknown", "negligible", "low", "medium", "high", "critical"
        ):
            return _scan_reject("invalid vulnerability severity")
        if severity.lower() == "critical" and fix["state"] == "fixed":
            if not isinstance(fix.get("versions"), list) or not fix["versions"]:
                return _scan_reject("fixed critical without fix version")
            critical.add(direct)
        ids = {direct} if CVE.fullmatch(direct) else set()
        related = match.get("relatedVulnerabilities", [])
        if not isinstance(related, list):
            return _scan_reject("malformed related vulnerabilities")
        for relation in related:
            if not isinstance(relation, Mapping) or not isinstance(relation.get("id"), str):
                return _scan_reject("malformed related vulnerability")
            if CVE.fullmatch(relation["id"]):
                ids.add(relation["id"])
        kev.update(ids & cisa)
        for record in [vuln, *related]:
            flags = record.get("knownExploited", [])
            if not isinstance(flags, list):
                return _scan_reject("malformed Grype KEV flags")
            for flag in flags:
                if not isinstance(flag, Mapping) or flag.get("cve") not in cisa:
                    return _scan_reject("Grype KEV claim disagrees with CISA catalog")
                kev.add(flag["cve"])
    reasons = (["fixable-critical"] if critical else []) + (["kev"] if kev else [])
    predicate = {
        "schemaVersion": 1, "scanComplete": True, "scanner": "grype/0.121.0",
        "imageRepository": image_repository, "imageDigest": image_digest,
        "dbValid": True, "dbStatus": dict(status), "dbProviders": dict(db["providers"]),
        "kevCatalogSource": CISA_SOURCE,
        "kevCatalogDateReleased": kev_catalog["dateReleased"],
        "kevCatalogCount": kev_catalog["count"],
        "fixableCritical": sorted(critical), "kevCves": sorted(kev),
        "grypeReport": report}
    return {"status": "assessed", "release_allowed": not reasons,
            "block_reasons": reasons, "fixable_critical": sorted(critical),
            "kev_cves": sorted(kev), "predicate": predicate}


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    render = sub.add_parser("render")
    render.add_argument("--binding", required=True)
    render.add_argument("--output-dir", required=True)
    scan = sub.add_parser("assess")
    scan.add_argument("--report", required=True)
    scan.add_argument("--kev-catalog", required=True)
    scan.add_argument("--image-repository", required=True)
    scan.add_argument("--image-digest", required=True)
    scan.add_argument("--predicate", required=True)
    scan.add_argument("--decision", required=True)
    args = parser.parse_args(argv)
    if args.command == "render":
        result = render_binding(json.loads(Path(args.binding).read_text(encoding="utf-8")))
        if not result["accepted"]:
            print(result["reason"], file=sys.stderr)
            return 2
        output = Path(args.output_dir)
        output.mkdir(parents=True, exist_ok=False)
        for name, body in result["policies"].items():
            (output / name).write_text(body, encoding="utf-8")
        return 0
    raw = Path(args.report).read_bytes()
    catalog_raw = Path(args.kev_catalog).read_bytes()
    result = assess_scan(json.loads(raw), args.image_digest,
                         image_repository=args.image_repository,
                         kev_catalog=json.loads(catalog_raw))
    if result["status"] != "assessed":
        print(result["block_reasons"], file=sys.stderr)
        return 2
    predicate = result["predicate"]
    predicate["grypeReportSha256"] = hashlib.sha256(raw).hexdigest()
    predicate["kevCatalogSha256"] = hashlib.sha256(catalog_raw).hexdigest()
    Path(args.predicate).write_text(json.dumps(predicate, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.decision).write_text(json.dumps(
        {k: v for k, v in result.items() if k != "predicate"}, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if result["release_allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
