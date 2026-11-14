"""detect/falco/bindings.py: registry records -> the trusted bindings alert_import.py reads.

Synthetic registry records; the container IDs are the ones the host Falco
instance reports for each runtime (the Docker container's for runc, the pod
sandbox's for gVisor, where runsc's sentry runs), as the smoke evidence shows.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    from detect.falco import bindings
except ImportError:
    bindings = None
try:
    from detect.report import alert_import
except ImportError:
    alert_import = None

RUNC = 'a' * 64
POD = 'c' * 64
SANDBOX = 'd' * 64


def docker(event, time, cid=RUNC, run='run-runc'):
    return {'source': 'docker', 'event': event, 'container_id': cid, 'time': time, 'name': 'warden-x',
            'labels': {'project': 'warden', 'warden.dev/run': run}, 'exit_code': '0' if event == 'die' else None}


def k8s(event, observed, cid=POD, run='run-gv', started='2026-11-14T02:00:01Z', finished=None, sandbox=SANDBOX):
    rec = {'source': 'k8s', 'event': event, 'container_id': cid, 'observed_at': observed, 'sandbox_id': sandbox}
    if event != 'gone':
        rec.update({'run_id': run, 'pod': 'p', 'pod_uid': 'u', 'namespace': 'warden-lab', 'created_at': '2026-11-14T02:00:00Z',
                    'started_at': started, 'finished_at': finished, 'exit_code': None})
    return rec


class Base(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(bindings, 'detect/falco/bindings.py missing')


class BindingTest(Base):
    def test_docker_start_to_die_with_nanoseconds(self):
        reg = [docker('start', '2026-11-14T02:00:00.100000000Z'), docker('die', '2026-11-14T02:01:00.200000000Z')]
        b = bindings.binding(reg, run_id='run-runc', execution_id='exec-1')
        self.assertEqual(b, {'execution_id': 'exec-1', 'run_id': 'run-runc', 'container_id': RUNC,
                             'start': '2026-11-14T02:00:00.100000000Z', 'end': '2026-11-14T02:01:00.200000000Z'})

    def test_session_label_names_a_runc_lab_container(self):
        rec = docker('start', '2026-11-14T02:00:00Z')
        rec['labels'] = {'project': 'warden', 'session': 'sess-1'}
        die = dict(rec, event='die', time='2026-11-14T02:05:00Z')
        self.assertEqual(bindings.binding([rec, die], run_id='sess-1', execution_id='e')['container_id'], RUNC)

    def test_runs_sharing_a_lab_container_need_their_own_window_inside_it(self):
        reg = [docker('start', '2026-11-14T02:00:00Z', run='sess'), docker('die', '2026-11-14T02:10:00Z', run='sess')]
        b = bindings.binding(reg, run_id='sess', execution_id='e', start='2026-11-14T02:01:00Z', end='2026-11-14T02:02:00Z')
        self.assertEqual((b['start'], b['end']), ('2026-11-14T02:01:00Z', '2026-11-14T02:02:00Z'))
        for start, end in (('2026-11-14T01:59:00Z', '2026-11-14T02:02:00Z'), ('2026-11-14T02:09:00Z', '2026-11-14T02:11:00Z'),
                           ('2026-11-14T02:03:00Z', '2026-11-14T02:02:00Z')):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                bindings.binding(reg, run_id='sess', execution_id='e', start=start, end=end)

    def test_a_run_that_has_not_ended_has_no_binding(self):
        with self.assertRaises(ValueError):
            bindings.binding([docker('start', '2026-11-14T02:00:00Z')], run_id='run-runc', execution_id='e')
        with self.assertRaises(ValueError):
            bindings.binding([k8s('running', '2026-11-14T02:00:02Z')], run_id='run-gv', execution_id='e')

    def test_unknown_or_ambiguous_runs_fail(self):
        reg = [docker('start', '2026-11-14T02:00:00Z'), docker('die', '2026-11-14T02:01:00Z'),
               docker('start', '2026-11-14T02:02:00Z', cid='b' * 64), docker('die', '2026-11-14T02:03:00Z', cid='b' * 64)]
        with self.assertRaises(ValueError):
            bindings.binding(reg, run_id='nope', execution_id='e')
        with self.assertRaises(ValueError):
            bindings.binding(reg, run_id='run-runc', execution_id='e')
        self.assertEqual(bindings.binding(reg, run_id='run-runc', execution_id='e', container_id='b' * 64)['start'],
                         '2026-11-14T02:02:00Z')

    def test_pod_sandbox_from_creation_to_when_the_pod_was_gone(self):
        # The host instance reports the pod sandbox's ID (runsc's sentry), which
        # exists from before the container starts until after it ends; the ID
        # is unique to this run's pod, so its whole life cannot take in
        # another run's events.
        reg = [k8s('running', '2026-11-14T02:00:02.5Z'),
               k8s('terminated', '2026-11-14T02:00:05.5Z', finished='2026-11-14T02:00:04Z'),
               k8s('gone', '2026-11-14T02:00:06.25Z')]
        self.assertEqual(bindings.binding(reg, run_id='run-gv', execution_id='exec-g'),
                         {'execution_id': 'exec-g', 'run_id': 'run-gv', 'container_id': SANDBOX,
                          'start': '2026-11-14T02:00:00Z', 'end': '2026-11-14T02:00:06.25Z'})
        self.assertEqual(bindings.binding(reg[:2], run_id='run-gv', execution_id='e')['end'], '2026-11-14T02:00:05Z')

    def test_without_a_sandbox_id_there_is_no_host_level_binding(self):
        reg = [k8s('running', '2026-11-14T02:00:02Z', sandbox=None), k8s('gone', '2026-11-14T02:00:09Z', sandbox=None)]
        with self.assertRaises(ValueError):
            bindings.binding(reg, run_id='run-gv', execution_id='e')

    def test_gvisor_engine_binding_uses_the_app_container(self):
        # The opt-in gVisor-engine instance (broken upstream) reports the pod's
        # containers by their own IDs.
        reg = [k8s('running', '2026-11-14T02:00:02.5Z'),
               k8s('terminated', '2026-11-14T02:00:05.5Z', finished='2026-11-14T02:00:04Z')]
        b = bindings.binding(reg, run_id='run-gv', execution_id='exec-g', gvisor_engine=True)
        self.assertEqual((b['container_id'], b['start'], b['end']), (POD, '2026-11-14T02:00:01Z', '2026-11-14T02:00:05Z'))

    def test_binding_is_accepted_by_alert_import(self):
        if alert_import is None:
            self.skipTest('detect/report/alert_import.py missing')
        reg = [k8s('running', '2026-11-14T02:00:02Z'), k8s('terminated', '2026-11-14T02:00:05Z', finished='2026-11-14T02:00:04Z')]
        b = bindings.binding(reg, run_id='run-gv', execution_id='exec-g')
        evt = {'time': '2026-11-14T02:00:00.5Z', 'rule': 'PTRACE attached to process', 'output_fields': {'container.id': SANDBOX[:12]}}
        alerts, _ = alert_import.from_falco([evt], [b], {'exec-g': {'PTRACE attached to process'}})
        self.assertEqual([a['execution_id'] for a in alerts], ['exec-g'])


class CommandTest(Base):
    def test_cli_prints_one_binding_line(self):
        with tempfile.TemporaryDirectory() as d:
            one, two = Path(d, 'host.jsonl'), Path(d, 'gvisor.jsonl')
            one.write_text(''.join(json.dumps(r) + '\n' for r in [docker('start', '2026-11-14T02:00:00Z'), docker('die', '2026-11-14T02:01:00Z')]))
            two.write_text(json.dumps(k8s('running', '2026-11-14T02:00:02Z')) + '\n')
            r = subprocess.run([sys.executable, '-I', '-B', bindings.__file__, '--registry', str(one), '--registry', str(two),
                                '--run-id', 'run-runc', '--execution-id', 'exec-1'], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)['container_id'], RUNC)
            bad = subprocess.run([sys.executable, '-I', '-B', bindings.__file__, '--registry', str(two),
                                  '--run-id', 'run-gv', '--execution-id', 'e'], capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(bad.stdout, '')


if __name__ == '__main__':
    unittest.main()
