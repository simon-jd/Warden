"""detect/falco/benign.py with a fake runner: the commands, CPUs and records of one benign hour."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

try:
    from detect.falco import benign
except ImportError:
    benign = None


def Done(returncode=0, stdout='', stderr='', timed_out=False):
    return returncode, stdout + stderr, timed_out


class Runner:
    def __init__(self, results):
        self.results, self.calls = results, []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return self.results[len(self.calls) - 1]


class Cleanup:
    def __init__(self):
        self.calls = []

    def __call__(self, runtime):
        self.calls.append(runtime)


class BenignTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(benign, 'detect/falco/benign.py missing')
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        base = Path(self.dir.name)
        for name, value in (('STATE', base / 'state'), ('DATA', base / 'data')):
            patcher = mock.patch.object(benign.detector, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        (base / 'state').mkdir()
        self.session = base / 'data' / 'S1'
        self.session.mkdir(parents=True)
        umask = os.umask(0o022)
        self.addCleanup(os.umask, umask)

    def records(self):
        return [json.loads(x) for x in (self.session / 'workloads.jsonl').read_text().splitlines()]

    def test_one_hour_runs_runc_then_gvisor_pinned_to_the_lab_cpus(self):
        benign.detector.save_state({'up': True, 'session': 'S1'})
        runner = Runner([Done(0, '--- PASS: TestConformance (40.1s)\n'), Done(0, '--- PASS: TestGVisorConformance (20s)\n')])
        self.assertEqual(benign.main(['--session', 'S1'], runner), 0)
        (runc, kw1), (gvisor, kw2) = runner.calls
        for argv, kw in ((runc, kw1), (gvisor, kw2)):
            self.assertEqual(argv[:3], ['/usr/bin/taskset', '-c', '0-7,16-31'])
            self.assertEqual(kw['env']['WARDEN_LAB_CPUSET'], '0-7,16-31')
            self.assertEqual(kw['cwd'], benign.ROOT)
        self.assertEqual(runc[3:7], ['/usr/bin/python3', '-B', 'scripts/runtime_lab_docker.py', 'run'])
        self.assertEqual(runc[-2:], ['--other-service-memory-bytes', str(1 << 30)], 'the host instance only')
        self.assertIn('test-gvisor', gvisor)
        self.assertIn('GVISOR_LAB_FLAGS=--without-corpus', gvisor, 'host-level gVisor coverage: no runsc trace mode')
        self.assertFalse([a for a in gvisor if '--falco' in a])
        self.assertEqual(kw1['timeout'], 1200)
        recs = self.records()
        self.assertEqual([(r['runtime'], r['ok']) for r in recs], [('runc', True), ('gvisor', True)])
        for r in recs:
            log = self.session / r['log']
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
            self.assertIn('--- PASS', log.read_text())
            self.assertLessEqual(r['start'], r['end'])

    def test_exit_zero_without_the_pass_line_is_not_ok(self):
        benign.detector.save_state({'up': True, 'session': 'S1'})
        runner = Runner([Done(0, 'ok\n'), Done(2, '--- PASS: TestGVisorConformance\n')])
        self.assertEqual(benign.main(['--session', 'S1'], runner), 1)
        self.assertEqual([r['ok'] for r in self.records()], [False, False])

    def test_a_run_killed_at_its_timeout_cleans_up_its_lab(self):
        benign.detector.save_state({'up': True, 'session': 'S1'})
        runner, cleanup = Runner([Done(0, '--- PASS: TestConformance\n'), Done(-9, 'half', timed_out=True)]), Cleanup()
        self.assertEqual(benign.main(['--session', 'S1'], runner, cleanup), 1)
        self.assertEqual(cleanup.calls, ['gvisor'])
        rec = self.records()[1]
        self.assertEqual((rec['runtime'], rec['ok'], rec['reason']), ('gvisor', False, 'timed out; lab cleaned up'))

    def test_no_detector_no_run(self):
        benign.detector.save_state({'up': False, 'session': 'S1'})
        runner = Runner([])
        self.assertEqual(benign.main(['--session', 'S1', '--only', 'gvisor'], runner), 1)
        self.assertEqual(runner.calls, [])
        rec = self.records()[0]
        self.assertEqual((rec['runtime'], rec['ok']), ('gvisor', False))
        self.assertIn('not up', rec['reason'])

    def test_an_unknown_session_is_refused(self):
        self.assertEqual(benign.main(['--session', 'nope'], Runner([])), 2)


if __name__ == '__main__':
    unittest.main()
