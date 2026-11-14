"""Report long-lived Azure credentials from `az` JSON. See longlived_keys_audit.sh."""

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

APPS_SCOPE = ("Entra apps the signed-in user owns (az ad app list --show-mine --all); "
              "apps of the project owned by anyone else are not seen")
STORAGE_SCOPE = "storage accounts of the expected subscription (az storage account list --subscription)"


class ScopeError(ValueError):
    """az is signed in to another subscription than the expected one."""


def guard():
    """scripts/azure_guard.py, for the same expected-subscription file and rules."""
    spec = importlib.util.spec_from_file_location("azure_guard", Path(__file__).resolve().parent / "azure_guard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_time(value: str) -> datetime:
    # Graph returns up to 7 fractional digits; Python accepts at most 6.
    value = value.replace("Z", "+00:00")
    if "." in value:
        head, rest = value.split(".", 1)
        digits = rest[: len(rest) - 6] if rest.endswith("+00:00") else rest
        value = f"{head}.{digits[:6]}+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp without zone: {value}")
    return parsed


def app_project(app: dict):
    """The project=<name> tag of an Entra app (tags are "key=value" strings)."""
    for tag in app.get("tags") or []:
        if isinstance(tag, str) and tag.startswith("project="):
            return tag.split("=", 1)[1]
    return None


def project_group(group: str, project: str) -> bool:
    """rg-<project>-lab (AZURE-BUDGET.md 2.1) or one of its AKS node groups MC_rg-<project>-lab_<cluster>_<region>."""
    group = group.lower()
    return group == f"rg-{project}-lab" or group.startswith(f"mc_rg-{project}-lab_")


def check_account(account, expected: str) -> dict:
    """The scope part of the report: names and states only, no IDs."""
    if not isinstance(account, dict):
        raise ValueError("az account show output must be a JSON object")
    if account.get("id") != expected:
        raise ScopeError("az is signed in to a subscription that is not the expected subscription; nothing audited")
    return {"subscription_matches_expected": True, "subscription_name": account.get("name"),
            "subscription_state": account.get("state"), "tenant": "the expected subscription's tenant (az account show)",
            "apps": APPS_SCOPE, "storage": STORAGE_SCOPE}


def audit(apps: list, storage: list, now: datetime, project: str = None, scope: dict = None,
          allow_empty: bool = False) -> dict:
    """Every finding is listed. With project, only that project's findings count:
    apps tagged project=<project> or not tagged at all (they may be anyone's),
    storage accounts tagged project=<project> or in rg-<project>-lab or its AKS
    node groups. objects_in_scope counts the apps and storage accounts whose
    findings would count; 0 means nothing was audited."""
    if not isinstance(apps, list) or not isinstance(storage, list):
        raise ValueError("az output must be JSON arrays")
    findings, expired, in_scope = [], 0, 0
    for app in apps:
        owner = app_project(app)
        counted = project is None or owner in (project, None)
        in_scope += counted
        for field, kind in (("passwordCredentials", "app_client_secret"), ("keyCredentials", "app_certificate")):
            for cred in app.get(field) or []:
                end = parse_time(cred["endDateTime"])
                if end <= now:
                    expired += 1
                    continue
                start = parse_time(cred["startDateTime"])
                findings.append({"kind": kind, "app": app.get("displayName"), "app_id": app.get("appId"),
                                 "key_id": cred.get("keyId"), "expires": cred["endDateTime"],
                                 "lifetime_days": round((end - start).total_seconds() / 86400),
                                 "owner_project": owner, "counted": counted})
    for account in storage:
        tags = account.get("tags") or {}
        owner = tags.get("project") if isinstance(tags, dict) else None
        group = str(account.get("resourceGroup") or "")
        counted = project is None or owner == project or project_group(group, project)
        in_scope += counted
        # null means the platform default, which allows shared keys.
        if account.get("allowSharedKeyAccess") is not False:
            findings.append({"kind": "storage_shared_key", "account": account.get("name"),
                             "resource_group": account.get("resourceGroup"), "owner_project": owner,
                             "counted": counted})
    scope = dict(scope or {}, objects_in_scope=in_scope, empty=in_scope == 0, empty_allowed=allow_empty)
    report = {"now": now.isoformat(), "scope": scope, "apps_scanned": len(apps), "storage_accounts_scanned": len(storage),
              "long_lived_count": len(findings), "expired_ignored": expired, "findings": findings}
    if project is not None:
        report["project"] = project
        report["project_long_lived_count"] = sum(f["counted"] for f in findings)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="az account show -o json")
    parser.add_argument("--apps", required=True)
    parser.add_argument("--storage", required=True)
    parser.add_argument("--now")
    parser.add_argument("--project", help="count only this project's findings (all are still listed)")
    parser.add_argument("--allow-empty", action="store_true", help="an empty scope exits 0 instead of 3")
    parser.add_argument("--scope-file", help="the expected subscription (default .cache/azure-subscription)")
    args = parser.parse_args()
    if args.project is not None and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", args.project):
        print("longlived_keys_audit: --project must be a lower-case project name", file=sys.stderr)
        return 2
    try:
        g = guard()
        expected = g.read_scope(Path(args.scope_file) if args.scope_file else g.SCOPE_FILE)
        now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
        with open(args.account) as f:
            scope = check_account(json.load(f), expected)
        with open(args.apps) as a, open(args.storage) as s:
            report = audit(json.load(a), json.load(s), now, args.project, scope, args.allow_empty)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as err:
        print(f"longlived_keys_audit: {err}", file=sys.stderr)
        return 2
    json.dump(report, sys.stdout, indent=2)
    print()
    if report["scope"]["empty"] and not args.allow_empty:
        print("longlived_keys_audit: nothing in scope, so nothing was audited; pass --allow-empty if that is expected",
              file=sys.stderr)
        return 3
    count = report["long_lived_count"] if args.project is None else report["project_long_lived_count"]
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
