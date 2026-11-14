"""The Makefile's Go targets, driven with a fake go binary.

A failed `go list` must stop test-go and check instead of leaving an empty
package list, which `go test` and `go vet` read as ".". And no go command may
depend on VCS stamping: Go only recognises a .git directory, so in a git
worktree (where .git is a file) it walks up to whatever .git directory is
above the checkout, and an empty or foreign one there fails the command.

test-go also stops, before any go command, when the Go tests' temp dir or a
directory above it is writable by group or others: runtimes/firecracker's
privateRoot rejects a private directory below such an ancestor, so a clone
made with umask 0002 used to fail there test by test.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOVCS = "-buildvcs=false"


class MakefileGoTargetsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.go = Path(self.dir.name, "go")
        self.calls = Path(self.dir.name, "calls")
        self.kyverno = Path(self.dir.name, "kyverno")
        self.kyverno.write_text("")

    def fake_go(self, list_output, list_code=0):
        listing = Path(self.dir.name, "list-output")
        listing.write_text(list_output)
        self.go.write_text(
            "#!/bin/sh\n"
            f'echo "$*" >> "{self.calls}"\n'
            f'if [ "$1" = list ]; then cat "{listing}"; exit {list_code}; fi\n'
            "exit 0\n")
        self.go.chmod(0o755)

    def make(self, *args, test_tmp=None):
        # A clean environment: no MAKEFLAGS or MAKELEVEL from an outer make.
        # The Go tests' temp dir is in this test's private directory, so the
        # result does not depend on the modes of the checkout's directories.
        env = {"PATH": "/usr/bin:/bin", "HOME": self.dir.name, "LC_ALL": "C"}
        test_tmp = test_tmp or Path(self.dir.name, "test-tmp")
        return subprocess.run(["make", "--no-print-directory", "-C", str(ROOT), *args, f"GO={self.go}",
                               f"KYVERNO={self.kyverno}", f"TEST_TMP={test_tmp}"],
                              env=env, capture_output=True, text=True, timeout=120)

    def invocations(self):
        if not self.calls.exists():
            return []
        return [line.split() for line in self.calls.read_text().splitlines()]

    def test_failed_go_list_stops_test_and_vet(self):
        for target, sub in (("test-go", "test"), ("check", "vet")):
            with self.subTest(target=target):
                self.calls.unlink(missing_ok=True)
                self.fake_go("go: error obtaining VCS status: exit status 128\n", list_code=1)
                proc = self.make(target)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertNotIn(sub, [c[0] for c in self.invocations()], self.invocations())

    def test_no_packages_left_is_a_failure(self):
        self.fake_go("warden/docs/evidence/task-3/snapshot\n")
        proc = self.make("test-go")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("test", [c[0] for c in self.invocations()])

    def test_go_test_gets_listed_packages_without_vcs_stamping(self):
        self.fake_go("warden/a\nwarden/docs/evidence/x\nwarden/b\n")
        proc = self.make("test-go")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.invocations()
        self.assertEqual([c[0] for c in calls], ["list", "test"], calls)
        self.assertIn(NOVCS, calls[0])
        self.assertIn(NOVCS, calls[1])
        self.assertEqual(calls[1][-2:], ["warden/a", "warden/b"])

    def test_writable_ancestor_of_the_test_temp_dir_stops_test_go(self):
        # setUp's directory is private (mkdtemp) and below a root-owned sticky
        # /tmp, which privateRoot accepts; test_go_test_gets_listed_packages_...
        # passes there. Here one directory is group-writable, as git clone
        # and mkdir -p make them with umask 0002.
        for case in ("parent", "itself"):
            with self.subTest(case=case):
                self.calls.unlink(missing_ok=True)
                # Explicit modes: the result must not depend on the umask.
                shared = Path(self.dir.name, case)
                shared.mkdir(mode=0o700)
                test_tmp = shared / "test-tmp"
                if case == "parent":
                    shared.chmod(0o775)
                    bad = shared
                else:
                    test_tmp.mkdir(mode=0o700)
                    test_tmp.chmod(0o770)
                    bad = test_tmp
                self.fake_go("warden/a\n")
                proc = self.make("test-go", test_tmp=test_tmp)
                out = proc.stdout + proc.stderr
                self.assertNotEqual(proc.returncode, 0, out)
                self.assertEqual(self.invocations(), [], "a go command ran")
                self.assertIn("writable private ancestor", out)
                self.assertIn(f"chmod go-w {bad}\n", out)
                self.assertIn("umask 022", out)
                # Only the offending directory is named, not the private ones
                # around it or the sticky /tmp.
                fix = next(line for line in out.splitlines() if "chmod go-w" in line)
                self.assertEqual(fix.split("chmod go-w ", 1)[1], str(bad), out)

    def test_every_go_command_disables_vcs_stamping(self):
        # make -n prints the commands without running them. Each target names
        # the go binary once per go command (live targets pass it to a helper
        # script in $GO), and each of those commands must carry -buildvcs=false.
        self.fake_go("")
        targets = ["test-go", "check", "test-kyverno", "test-postgres", "test-egress", "test-egress-runc",
                   "test-vault", "test-kind", "test-gvisor", "test-identity", "test-cilium", "vuln-feeds",
                   "aks-probe", "test-aks"]
        for target in targets:
            with self.subTest(target=target):
                proc = self.make("-n", target)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                gos = proc.stdout.count(str(self.go))
                self.assertGreater(gos, 0, proc.stdout)
                self.assertEqual(proc.stdout.count(NOVCS), gos, proc.stdout)
        self.assertEqual(self.invocations(), [], "make -n ran go")

    def test_cilium_target_runs_the_live_package_on_a_cilium_lab(self):
        # Tasks 7, 10 and 14's Cilium checks: their own lab mode, torn down
        # after the run unless CILIUM_REUSE=1 names a lab that is already up.
        self.fake_go("")
        # make -n prints the recipe's continuation lines as they are written.
        def command(out):
            return next(l for l in out.replace("\\\n", " ").splitlines() if str(self.go) in l).strip()

        proc = self.make("-n", "test-cilium", "CILIUM_OUT=out/dir", "CILIUM_RUN=TestX")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = command(proc.stdout)
        self.assertTrue(line.startswith("scripts/k3s_gvisor_lab.sh run --cilium scripts/k3s_gvisor_lab.sh env "), line)
        for want in ("WARDEN_LIVE_CILIUM=1", f"CILIUM_OUT={ROOT}/out/dir", "-run 'TestX'",
                     "./controlplane/internal/ciliumlab"):
            self.assertIn(want, line)
        reuse = self.make("-n", "test-cilium", "CILIUM_REUSE=1")
        self.assertEqual(reuse.returncode, 0, reuse.stderr)
        line = command(reuse.stdout)
        self.assertTrue(line.startswith("scripts/k3s_gvisor_lab.sh env "), line)
        self.assertEqual(self.invocations(), [], "make -n ran go")

    def test_aks_target_runs_each_task7_test_through_the_drill(self):
        # Each test is its own go command (two of them share runtimes/conformance
        # and the warden-system namespace), all through `aks_drill.py env`, and
        # one failing does not skip the others.
        self.fake_go("")
        proc = self.make("-n", "test-aks", "AKS_OUT=out/aks")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        text = proc.stdout.replace("\\\n", " ")
        runs = [seg.strip() for seg in text.split(";") if "scripts/aks_drill.py env --" in seg]
        want = [("TestSandboxCannotReachMetadata", "./controlplane/internal/aksdrill"),
                ("TestControlPlaneTokenIsShortLived", "./runtimes/conformance"),
                ("TestSandboxSAHasNoBindings", "./runtimes/conformance")]
        self.assertEqual(len(runs), len(want), text)
        for run, (test, pkg) in zip(runs, want):
            self.assertTrue(run.startswith("python3 -B scripts/aks_drill.py env -- "), run)
            for part in (f"-run '^{test}$'", pkg, f"AKS_OUT={ROOT}/out/aks", f"IDENTITY_OUT={ROOT}/out/aks/identity.jsonl",
                         "AZURE_CONFIG_DIR=", f"{self.go} test", "|| status=1"):
                self.assertIn(part, run)
        self.assertIn("exit $status", text)
        # The probe the tests copy into their pods is built first.
        build = next(l for l in text.splitlines() if f"{self.go} build" in l)
        self.assertIn("-o .cache/aks-drill/warden-probe ./runtimes/conformance/guest", build)
        self.assertLess(text.index(build), text.index(runs[0]))
        self.assertEqual(self.invocations(), [], "make -n ran go")

    def test_gvisor_target_passes_lab_options_and_keeps_its_default(self):
        # GVISOR_LAB_FLAGS goes to the lab's `run` (for example --without-corpus);
        # without it the command is the one test-gvisor always ran.
        self.fake_go("")
        def command(out):
            return next(l for l in out.replace("\\\n", " ").splitlines() if str(self.go) in l).strip()

        default = self.make("-n", "test-gvisor")
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertTrue(command(default.stdout).startswith(
            "scripts/k3s_gvisor_lab.sh run scripts/k3s_gvisor_lab.sh env "), command(default.stdout))
        flagged = self.make("-n", "test-gvisor", "GVISOR_LAB_FLAGS=--without-corpus")
        self.assertEqual(flagged.returncode, 0, flagged.stderr)
        self.assertTrue(command(flagged.stdout).startswith(
            "scripts/k3s_gvisor_lab.sh run --without-corpus scripts/k3s_gvisor_lab.sh env "), command(flagged.stdout))
        reuse = self.make("-n", "test-gvisor", "GVISOR_REUSE=1", "GVISOR_LAB_FLAGS=--without-corpus")
        self.assertTrue(command(reuse.stdout).startswith("scripts/k3s_gvisor_lab.sh env "), command(reuse.stdout))
        self.assertEqual(self.invocations(), [], "make -n ran go")

    def test_detector_targets_run_the_lifecycle_on_the_lab_cpus(self):
        # Task 13's online detector: each target is one detect/falco/detector.py
        # command under taskset on CPUs 0-7,16-31; DRY_RUN=1 only prints the
        # seven-day start.
        for target, sub in (("detect-up", "up"), ("detect-status", "status"), ("detect-down", "down"),
                            ("detect-purge", "purge")):
            with self.subTest(target=target):
                proc = self.make("-n", target)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                lines = [l for l in proc.stdout.splitlines() if "detect/falco/detector.py" in l]
                self.assertEqual(lines, ["taskset -c 0-7,16-31 python3 -I -B detect/falco/detector.py " + sub], proc.stdout)
        engine = self.make("-n", "detect-up", "DETECT_GVISOR_ENGINE=1")
        self.assertIn("detect/falco/detector.py up --gvisor-engine", engine.stdout)
        # The seven-day start runs only with CONFIRM=seven-day and no DRY_RUN
        # (whatever its value); everything else is a dry run.
        start = "taskset -c 0-7,16-31 python3 -I -B detect/falco/detector.py seven-day-start "
        for args, want in (((), "--dry-run"), (("CONFIRM=yes",), "--dry-run"), (("CONFIRM=seven-day", "DRY_RUN=0"), "--dry-run"),
                           (("CONFIRM=seven-day", "DRY_RUN=1"), "--dry-run"), (("CONFIRM=seven-day",), "--confirm seven-day")):
            with self.subTest(args=args):
                proc = self.make("-n", "detect-seven-day-start", *args)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                lines = [l for l in proc.stdout.splitlines() if "detect/falco/detector.py" in l]
                self.assertEqual(lines, [start + want], proc.stdout)
        smoke = self.make("-n", "detect-smoke", "DETECT_OUT=out/smoke")
        self.assertIn(f"taskset -c 0-7,16-31 python3 -I -B detect/falco/smoke.py all --out {ROOT}/out/smoke", smoke.stdout)


if __name__ == "__main__":
    unittest.main()
