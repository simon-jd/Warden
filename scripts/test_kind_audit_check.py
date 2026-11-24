"""scripts/kind_audit_check.py against a fake kubectl: what counts as left
in warden-lab, and its exit codes. No cluster is needed."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts/kind_audit_check.py'
sys.path.insert(0, str(ROOT / 'scripts'))
import kind_audit_check  # noqa: E402

ACTIVE = {'metadata': {'name': 'warden-lab', 'labels': {'project': 'warden', 'owner': 'warden-lab'}}, 'status': {'phase': 'Active'}}
TYPES = 'configmaps\nevents\npods\nserviceaccounts\nevents.events.k8s.io\nroles.rbac.authorization.k8s.io\n'


def item(kind, name):
    return {'kind': kind, 'metadata': {'name': name, 'namespace': 'warden-lab'}}


EMPTY = {'kind': 'List', 'items': [item('ConfigMap', 'kube-root-ca.crt'), item('ServiceAccount', 'default'),
                                   item('Event', 'old-pod.1879a')]}


class LeftoversTest(unittest.TestCase):
    def test_defaults_and_events_are_not_leftovers(self):
        self.assertEqual(kind_audit_check.leftovers(EMPTY), [])
        listing = {'items': EMPTY['items'] + [item('Pod', 'stratus-pod'), item('ServiceAccount', 'stratus-sa'),
                                              item('ConfigMap', 'other')]}
        self.assertEqual(kind_audit_check.leftovers(listing), ['ConfigMap/other', 'Pod/stratus-pod', 'ServiceAccount/stratus-sa'])

    def test_events_are_not_listed(self):
        self.assertEqual(kind_audit_check.resource_types(TYPES.splitlines()),
                         ['configmaps', 'pods', 'roles.rbac.authorization.k8s.io', 'serviceaccounts'])


class CLITest(unittest.TestCase):
    def fake(self, namespace, listing, list_code=0):
        d = Path(self.dir.name)
        (d / 'namespace.json').write_text(json.dumps(namespace))
        (d / 'types.txt').write_text(TYPES)
        (d / 'list.json').write_text(json.dumps(listing))
        kubectl = d / 'kubectl'
        kubectl.write_text('#!/bin/sh\n'
                           f'echo "$*" >> "{d}/calls"\n'
                           'case "$*" in\n'
                           f'  *"get namespace warden-lab"*) cat "{d}/namespace.json" ;;\n'
                           f'  *api-resources*) cat "{d}/types.txt" ;;\n'
                           f'  *"get configmaps,pods,"*) cat "{d}/list.json"; exit {list_code} ;;\n'
                           '  *) exit 3 ;;\n'
                           'esac\n')
        kubectl.chmod(0o755)
        return kubectl

    def run_check(self, kubectl):
        return subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), '--kubectl', str(kubectl), '--kubeconfig', '/x/kubeconfig.json'],
                              capture_output=True, text=True, env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_exit_codes(self):
        result = self.run_check(self.fake(ACTIVE, EMPTY))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['left'], [])
        calls = (Path(self.dir.name) / 'calls').read_text()
        self.assertIn('--context kind-warden-lab', calls)
        self.assertIn('--cache-dir %s' % (ROOT / '.cache/kind-warden-lab/kubectl-cache'), calls)
        self.assertIn('get configmaps,pods,roles.rbac.authorization.k8s.io,serviceaccounts -n warden-lab -o json', calls)
        result = self.run_check(self.fake(ACTIVE, {'items': EMPTY['items'] + [item('Pod', 'left-behind')]}))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['left'], ['Pod/left-behind'])
        terminating = dict(ACTIVE, status={'phase': 'Terminating'})
        self.assertEqual(self.run_check(self.fake(terminating, EMPTY)).returncode, 2)
        self.assertEqual(self.run_check(self.fake(ACTIVE, EMPTY, list_code=1)).returncode, 2)

    def test_lab_and_make_target(self):
        text = (ROOT / 'scripts/kind_lab.sh').read_text()
        self.assertIn('  check-empty) [[ ${2:-} == --audit ]] || usage; audit_check_empty ;;\n', text)
        result = subprocess.run(['make', '--no-print-directory', '-n', '-C', str(ROOT), 'kind-audit-check-empty'],
                                capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scripts/kind_lab.sh check-empty --audit', result.stdout)


if __name__ == '__main__':
    unittest.main()
