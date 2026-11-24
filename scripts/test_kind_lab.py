"""scripts/kind_lab.sh's audit lab mode, offline: the kind configuration it
generates, its names against attacks/stratus/emulate.py's checks, its make
targets, and that the warden-respond cluster's settings are as they were.
No cluster is created."""

import importlib.util
import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts/kind_lab.sh'
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}


def run(*args):
    return subprocess.run(['bash', str(SCRIPT), *args], capture_output=True, text=True, env=ENV, timeout=30)


class AuditConfigTest(unittest.TestCase):
    def setUp(self):
        result = run('config', '--audit')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.config = result.stdout

    def test_api_server_audit_flags(self):
        for flag in ('audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml',
                     'audit-log-path: /var/log/kubernetes/audit/audit.log', 'audit-log-format: json',
                     'audit-log-mode: blocking', 'audit-log-maxsize: "1024"'):
            self.assertIn('        ' + flag + '\n', self.config)
        self.assertNotIn('audit-webhook', self.config, 'the k8saudit instance has no network: no webhook backend')
        self.assertNotIn('audit-log-batch', self.config)

    def test_the_policy_and_the_log_are_this_worktrees(self):
        mounts = re.findall(r'- hostPath: (\S+)\n    containerPath: (\S+)', self.config)
        lab = ROOT / '.cache/kind-warden-lab'
        self.assertEqual(mounts, [(str(lab / 'policy'), '/etc/kubernetes/policies'),
                                  (str(lab / 'audit'), '/var/log/kubernetes/audit')])
        self.assertIn('    readOnly: true\n  - hostPath: %s/audit' % lab, self.config, 'the policy is mounted read-only')
        self.assertEqual(self.config.count('- role:'), 1, 'one node')

    def test_names_pass_the_stratus_wrappers_checks(self):
        text = SCRIPT.read_text()
        self.assertIn('audit_name=warden-lab\n', text)
        self.assertIn('audit_node=warden-lab-control-plane\n', text)
        self.assertIn('--context "kind-$audit_name" config view --raw --minify -o json', text)
        spec = importlib.util.spec_from_file_location('stratus_emulate', ROOT / 'attacks/stratus/emulate.py')
        emulate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emulate)
        emulate.guard_nodes({'items': [{'metadata': {'name': 'warden-lab-control-plane'}}]})
        with self.assertRaises(ValueError):
            emulate.guard_nodes({'items': [{'metadata': {'name': 'warden-respond-control-plane'}}]})
        namespace = json.loads(re.search(r"^audit_namespace='(.*)'$", text, re.M).group(1))
        emulate.guard_namespace(dict(namespace, status={'phase': 'Active'}))
        self.assertIn('wait --for=jsonpath=\'{.status.phase}\'=Active', text)

    def test_node_cpuset_and_pod_image(self):
        text = SCRIPT.read_text()
        self.assertIn('cpuset=${WARDEN_LAB_CPUSET:-0-7,16-31}', text)
        self.assertIn('docker update --cpuset-cpus "$cpuset" "$audit_node"', text)
        self.assertIn("got=$(docker container inspect --format '{{.HostConfig.CpusetCpus}}' \"$audit_node\")", text)
        images = re.findall(r'^  (busybox-[0-9.]+)\.oci\.tar=docker\.io/library/busybox:([0-9.]+)=sha256:[0-9a-f]{64}$', text, re.M)
        self.assertEqual(images, [('busybox-1.37.0', '1.37.0')])
        restore = (ROOT / 'scripts/restore-tools.sh').read_text()
        self.assertIn('  busybox-1.37.0=docker.io/library/busybox:1.37.0@sha256:', restore)


class UnchangedTest(unittest.TestCase):
    def test_warden_respond_settings(self):
        text = SCRIPT.read_text()
        for line in ('name=warden-respond', 'kubeconfig=$root/.cache/kind/kubeconfig', 'pod_images=(python:3.14.4-alpine)',
                     'export KIND_EXPERIMENTAL_DOCKER_NETWORK=warden-kind',
                     'node_image=kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d',
                     '  up) if [[ ${2:-} == --audit ]]; then audit_up; else up; fi ;;',
                     '  down) if [[ ${2:-} == --audit ]]; then audit_down; else down; fi ;;'):
            self.assertIn(line + '\n', text)

    def test_usage(self):
        for args in ((), ('status',), ('config',), ('purge',)):
            with self.subTest(args=args):
                self.assertEqual(run(*args).returncode, 2)
        self.assertEqual(run('run').returncode, 2)


class MakeTargetsTest(unittest.TestCase):
    def test_targets(self):
        for target, command in (('kind-audit-up', 'scripts/kind_lab.sh up --audit'),
                                ('kind-audit-status', 'scripts/kind_lab.sh status --audit'),
                                ('kind-audit-down', 'scripts/kind_lab.sh down --audit')):
            result = subprocess.run(['make', '--no-print-directory', '-n', '-C', str(ROOT), target],
                                    capture_output=True, text=True, env=ENV, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(command, result.stdout)
            self.assertIn('taskset -c 0-7,16-31', result.stdout)


if __name__ == '__main__':
    unittest.main()
