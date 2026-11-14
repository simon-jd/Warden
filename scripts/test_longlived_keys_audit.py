"""Fixture tests for scripts/longlived_keys_audit.sh (Task 8 TestNoLongLivedKeys)."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "longlived_keys_audit.sh"
NOW = "2026-10-27T12:00:00Z"

CLEAN_APPS = [
    {"appId": "11111111-1111-1111-1111-111111111111", "displayName": "warden-ci",
     "passwordCredentials": [], "keyCredentials": []},
    {"appId": "22222222-2222-2222-2222-222222222222", "displayName": "old-app",
     "passwordCredentials": [{"keyId": "k-expired", "displayName": "gone",
                              "startDateTime": "2025-01-01T00:00:00Z", "endDateTime": "2025-06-01T00:00:00Z"}],
     "keyCredentials": []},
]
DIRTY_APPS = CLEAN_APPS + [
    {"appId": "33333333-3333-3333-3333-333333333333", "displayName": "legacy",
     "passwordCredentials": [{"keyId": "k-secret", "displayName": "ci secret",
                              "startDateTime": "2026-01-01T00:00:00.1234567Z", "endDateTime": "2028-01-01T00:00:00Z"}],
     "keyCredentials": [{"keyId": "k-cert", "displayName": "CN=legacy", "type": "AsymmetricX509Cert",
                         "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2027-01-01T00:00:00Z"}]},
]
CLEAN_STORAGE = [{"name": "wardenlogs", "resourceGroup": "rg-warden-lab", "allowSharedKeyAccess": False}]
DIRTY_STORAGE = CLEAN_STORAGE + [{"name": "wardenold", "resourceGroup": "rg-warden-lab", "allowSharedKeyAccess": None}]
# Made-up IDs. The expected subscription comes from a scope file, as for
# scripts/azure_guard.py (the real one is the untracked .cache/azure-subscription).
SUBSCRIPTION = "11111111-2222-4333-8444-555555555555"
TENANT = "99999999-8888-4777-8666-555555555555"
ACCOUNT = {"id": SUBSCRIPTION, "name": "Azure for Students", "state": "Enabled", "tenantId": TENANT,
           "user": {"name": "someone@example.edu", "type": "user"}}
SCOPE_DIR = tempfile.TemporaryDirectory()
SCOPE = Path(SCOPE_DIR.name, "azure-subscription")
SCOPE.write_text(SUBSCRIPTION + "\n")
SCOPE.chmod(0o600)


def write(directory, apps, storage, account=ACCOUNT):
    Path(directory, "apps.json").write_text(json.dumps(apps))
    Path(directory, "storage.json").write_text(json.dumps(storage))
    Path(directory, "account.json").write_text(json.dumps(account))


def run(*args, env=None, scope=SCOPE):
    proc = subprocess.run(["/bin/bash", str(SCRIPT), *args, "--now", NOW, "--scope-file", str(scope)],
                          capture_output=True, text=True, env=env, timeout=30)
    return proc.returncode, proc.stdout, proc.stderr


class LongLivedKeysAuditTest(unittest.TestCase):
    def test_no_long_lived_keys_passes(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, CLEAN_APPS, CLEAN_STORAGE)
            code, out, err = run("--fixture", d)
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            self.assertEqual(report["long_lived_count"], 0)
            self.assertEqual(report["expired_ignored"], 1)
            self.assertEqual(report["apps_scanned"], 2)

    def test_counts_secret_certificate_and_shared_key(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, DIRTY_APPS, DIRTY_STORAGE)
            code, out, _ = run("--fixture", d)
            self.assertEqual(code, 1)
            report = json.loads(out)
            self.assertEqual(report["long_lived_count"], 3)
            kinds = sorted(f["kind"] for f in report["findings"])
            self.assertEqual(kinds, ["app_certificate", "app_client_secret", "storage_shared_key"])
            secret = next(f for f in report["findings"] if f["kind"] == "app_client_secret")
            self.assertEqual(secret["app"], "legacy")
            self.assertEqual(secret["lifetime_days"], 730)
            self.assertNotIn("secretText", json.dumps(report))

    def test_live_mode_reads_through_az(self):
        with tempfile.TemporaryDirectory() as d:
            bindir = Path(d, "bin")
            bindir.mkdir()
            write(d, DIRTY_APPS, CLEAN_STORAGE)
            fake = bindir / "az"
            fake.write_text(
                "#!/usr/bin/env bash\n"
                f'echo "$*" >> "{d}/calls"\n'
                f'case "$1 $2" in "account show") cat "{d}/account.json";; "ad app") cat "{d}/apps.json";;'
                f' "storage account") cat "{d}/storage.json";; *) exit 9;; esac\n')
            fake.chmod(0o755)
            env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": d}
            code, out, err = run(env=env)
            self.assertEqual(code, 1, err)
            self.assertEqual(json.loads(out)["long_lived_count"], 2)
            calls = Path(d, "calls").read_text().splitlines()
            # University tenant: only apps the signed-in user owns, never the directory.
            self.assertIn("ad app list --show-mine --all -o json", calls)
            self.assertNotIn("ad app list --all -o json", calls)
            # Storage is read from the subscription that was checked, not the CLI default.
            self.assertIn(f"storage account list --subscription {SUBSCRIPTION} -o json", calls)
            self.assertEqual(calls[0], "account show -o json")

    def test_project_scope_lists_other_projects_but_counts_only_its_own(self):
        other_app = {"appId": "44444444-4444-4444-4444-444444444444", "displayName": "otherproj-lab-web",
                     "tags": ["project=otherproj"],
                     "passwordCredentials": [{"keyId": "k-other", "startDateTime": "2026-10-01T00:00:00Z",
                                              "endDateTime": "2026-12-31T00:00:00Z"}], "keyCredentials": []}
        warden_clean = {"appId": "55555555-5555-5555-5555-555555555555", "displayName": "warden-lab-api",
                        "tags": ["project=warden", "owner=warden-lab"],
                        "passwordCredentials": [], "keyCredentials": []}
        other_storage = {"name": "stotherproj", "resourceGroup": "rg-mlinfra-westus", "tags": None,
                         "allowSharedKeyAccess": None}
        with tempfile.TemporaryDirectory() as d:
            write(d, [other_app, warden_clean], [other_storage])
            code, out, err = run("--fixture", d, "--project", "warden")
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            self.assertEqual(report["project"], "warden")
            self.assertEqual(report["long_lived_count"], 2)
            self.assertEqual(report["project_long_lived_count"], 0)
            by_kind = {f["kind"]: f for f in report["findings"]}
            self.assertEqual(by_kind["app_client_secret"]["owner_project"], "otherproj")
            self.assertFalse(by_kind["app_client_secret"]["counted"])
            self.assertIsNone(by_kind["storage_shared_key"]["owner_project"])
            self.assertFalse(by_kind["storage_shared_key"]["counted"])
            # Without a project the whole scanned scope counts.
            code, out, _ = run("--fixture", d)
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)["long_lived_count"], 2)
        # Untagged apps may be anyone's, so they count; so does anything in
        # rg-warden-lab or tagged project=warden.
        untagged = {"appId": "66666666-6666-6666-6666-666666666666", "displayName": "warden-lab-keyprobe",
                    "passwordCredentials": [{"keyId": "k-un", "startDateTime": "2026-11-10T00:00:00Z",
                                             "endDateTime": "2027-11-10T00:00:00Z"}], "keyCredentials": []}
        warden_secret = dict(warden_clean, passwordCredentials=untagged["passwordCredentials"])
        warden_storage = {"name": "wardenlogs", "resourceGroup": "RG-Warden-Lab", "tags": {},
                          "allowSharedKeyAccess": None}
        tagged_elsewhere = {"name": "wardenstray", "resourceGroup": "rg-other", "tags": {"project": "warden"},
                            "allowSharedKeyAccess": True}
        with tempfile.TemporaryDirectory() as d:
            write(d, [other_app, untagged, warden_secret], [other_storage, warden_storage, tagged_elsewhere])
            code, out, _ = run("--fixture", d, "--project", "warden")
            self.assertEqual(code, 1)
            report = json.loads(out)
            self.assertEqual(report["long_lived_count"], 6)
            self.assertEqual(report["project_long_lived_count"], 4)
            counted = sorted((f.get("app") or f.get("account")) for f in report["findings"] if f["counted"])
            self.assertEqual(counted, ["warden-lab-api", "warden-lab-keyprobe", "wardenlogs", "wardenstray"])

    def test_other_subscription_or_missing_scope_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, DIRTY_APPS, CLEAN_STORAGE, account=dict(ACCOUNT, id="22222222-2222-4333-8444-555555555555"))
            code, out, err = run("--fixture", d)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("not the expected subscription", err)
            self.assertNotIn("22222222", err)
            write(d, DIRTY_APPS, CLEAN_STORAGE)
            code, out, err = run("--fixture", d, scope=Path(d, "no-such-file"))
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            Path(d, "account.json").unlink()
            code, out, _ = run("--fixture", d)
            self.assertEqual(code, 2)

    def test_report_records_the_matched_scope_without_ids(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, CLEAN_APPS, CLEAN_STORAGE)
            code, out, err = run("--fixture", d)
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            scope = report["scope"]
            self.assertTrue(scope["subscription_matches_expected"])
            self.assertEqual(scope["subscription_name"], "Azure for Students")
            self.assertIn("--show-mine", scope["apps"])
            self.assertEqual(scope["objects_in_scope"], 3)
            self.assertFalse(scope["empty"])
            self.assertNotIn(SUBSCRIPTION, out)
            self.assertNotIn(TENANT, out)
            self.assertNotIn("someone@example.edu", out)

    def test_empty_scope_is_not_a_pass_unless_expected(self):
        other_app = {"appId": "44444444-4444-4444-4444-444444444444", "displayName": "other-lab-web",
                     "tags": ["project=other"], "passwordCredentials": [], "keyCredentials": []}
        other_storage = {"name": "stother", "resourceGroup": "rg-other", "tags": None, "allowSharedKeyAccess": False}
        for apps, storage, project in (([], [], ()), ([other_app], [other_storage], ("--project", "warden"))):
            with tempfile.TemporaryDirectory() as d:
                write(d, apps, storage)
                code, out, err = run("--fixture", d, *project)
                self.assertEqual(code, 3, err)
                report = json.loads(out)
                self.assertTrue(report["scope"]["empty"])
                self.assertEqual(report["scope"]["objects_in_scope"], 0)
                self.assertIn("--allow-empty", err)
                code, out, err = run("--fixture", d, *project, "--allow-empty")
                self.assertEqual(code, 0, err)
                self.assertTrue(json.loads(out)["scope"]["empty_allowed"])

    def test_aks_node_resource_group_belongs_to_the_project(self):
        node_rg = {"name": "wardennode", "resourceGroup": "MC_rg-warden-lab_warden-aks_westus2", "tags": {},
                   "allowSharedKeyAccess": None}
        lookalike = {"name": "notwarden", "resourceGroup": "MC_rg-warden-lab2_x_westus2", "tags": {},
                     "allowSharedKeyAccess": None}
        with tempfile.TemporaryDirectory() as d:
            write(d, [], [node_rg, lookalike])
            code, out, err = run("--fixture", d, "--project", "warden")
            self.assertEqual(code, 1, err)
            report = json.loads(out)
            counted = [f["account"] for f in report["findings"] if f["counted"]]
            self.assertEqual(counted, ["wardennode"])

    def test_bad_input_is_an_error_not_a_pass(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "apps.json").write_text("{not json")
            Path(d, "storage.json").write_text("[]")
            code, _, err = run("--fixture", d)
            self.assertEqual(code, 2)
            self.assertTrue(err)
        with tempfile.TemporaryDirectory() as d:
            env = {"PATH": "/usr/bin:/bin", "HOME": d}
            code, _, _ = run(env={**env, "PATH": d})  # no az, no python on PATH
            self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
