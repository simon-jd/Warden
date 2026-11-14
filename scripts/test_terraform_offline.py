"""`make test-terraform` must not reach the network or fall back to the registry.

A fake terraform records each call's arguments and the network interfaces it
can see (/proc/net/dev is per network namespace). Every call has to run where
only the loopback exists, init may take providers only from TF_PLUGINS
(-plugin-dir, lock file read-only) and is never retried without it, and a
missing provider fails before terraform runs, with a message that says what
to do.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AZUREAD = Path("registry.terraform.io", "hashicorp", "azuread")


def bwrap_works():
    try:
        return subprocess.run(["/usr/bin/bwrap", "--dev-bind", "/", "/", "--unshare-net", "/bin/true"],
                              capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class TerraformOfflineTest(unittest.TestCase):
    def make(self, plugins=True, init_fails=False):
        d = Path(self.enterContext(tempfile.TemporaryDirectory()))
        log, fail = d / "calls", d / "init-fails"
        if init_fails:
            fail.write_text("1")
        plugin_dir = d / "plugins"
        if plugins:
            (plugin_dir / AZUREAD / "3.10.0" / "linux_amd64").mkdir(parents=True)
        fake = d / "terraform"
        # env -i in the Makefile drops the caller's variables, so paths are baked in.
        fake.write_text(
            "#!/bin/sh\n"
            f"nets=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\\n' ',')\n"
            f"printf '%s | %s\\n' \"$*\" \"$nets\" >> {log}\n"
            f"case \"$*\" in *' init '*) [ -e {fail} ] && exit 1;; esac\n"
            "exit 0\n")
        fake.chmod(0o755)
        env = {k: v for k, v in os.environ.items() if k not in {"MAKEFLAGS", "MAKELEVEL", "MFLAGS", "MAKEOVERRIDES"}}
        proc = subprocess.run(["make", "-s", "-C", str(ROOT), "test-terraform", f"TERRAFORM={fake}",
                               f"TF_PLUGINS={plugin_dir}"], capture_output=True, text=True, env=env, timeout=120)
        calls = []
        for line in (log.read_text().splitlines() if log.exists() else []):
            args, nets = line.split(" | ")
            calls.append((args, [n for n in nets.split(",") if n]))
        return proc, calls, plugin_dir

    def test_every_call_runs_without_network_and_init_uses_only_the_plugin_dir(self):
        proc, calls, plugin_dir = self.make()
        if not bwrap_works():
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("bwrap", proc.stderr)
            self.assertEqual([args for args, _ in calls], [])
            return
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([args.split()[1] for args, _ in calls], ["fmt", "init", "validate"], calls)
        for args, nets in calls:
            self.assertTrue(nets == ["lo"], f"`terraform {args}` saw {len(nets)} network interfaces")
        init = calls[1][0]
        self.assertIn(f"-plugin-dir={plugin_dir}", init)
        self.assertIn("-lockfile=readonly", init)

    def test_failed_offline_init_is_not_retried_with_the_registry(self):
        proc, calls, _ = self.make(init_fails=True)
        self.assertNotEqual(proc.returncode, 0)
        inits = [args for args, _ in calls if " init " in args]
        self.assertEqual(len(inits), 1, inits)
        self.assertIn("-plugin-dir=", inits[0])

    def test_missing_provider_fails_before_terraform_runs(self):
        proc, calls, plugin_dir = self.make(plugins=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual([args for args, _ in calls], [])
        self.assertIn(str(plugin_dir), proc.stderr)
        self.assertIn("make terraform-plugins", proc.stderr)


if __name__ == "__main__":
    unittest.main()
