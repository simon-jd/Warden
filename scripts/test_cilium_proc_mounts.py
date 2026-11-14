"""runtimes/gvisor/lab/cilium/readonly_proc_mounts.py: the Cilium chart's
mounts of the node's /proc become read-only.

The lab node is a privileged container on the host's kernel, so the node's
/proc/sys/kernel is the host's. On 2026-11-12 the agent, through its
hostPath mount of /proc/sys/kernel, set the host's kernel.timer_migration
and kernel.unprivileged_bpf_disabled although warden-node-init had made the
node's /proc/sys read-only (docs/evidence/task-10/cilium-lab-20261112).
"""
import json
from pathlib import Path
import subprocess
import sys
import unittest

TRANSFORM = Path(__file__).resolve().parent.parent / 'runtimes/gvisor/lab/cilium/readonly_proc_mounts.py'


def daemonset(name, volumes, containers, init=()):
    return {'apiVersion': 'apps/v1', 'kind': 'DaemonSet', 'metadata': {'name': name, 'namespace': 'kube-system'},
            'spec': {'template': {'spec': {
                'volumes': [{'name': n, 'hostPath': {'path': p}} for n, p in volumes],
                'containers': [{'name': c, 'volumeMounts': [dict(m) for m in ms]} for c, ms in containers],
                'initContainers': [{'name': c, 'volumeMounts': [dict(m) for m in ms]} for c, ms in init]}}}}


# The shape of Cilium 1.20.4's agent DaemonSet, reduced to its volumes.
AGENT = daemonset(
    'cilium',
    [('host-proc-sys-net', '/proc/sys/net'), ('host-proc-sys-kernel', '/proc/sys/kernel'), ('hostproc', '/proc'),
     ('bpf-maps', '/sys/fs/bpf'), ('lib-modules', '/lib/modules')],
    [('cilium-agent', [{'name': 'host-proc-sys-net', 'mountPath': '/host/proc/sys/net'},
                       {'name': 'host-proc-sys-kernel', 'mountPath': '/host/proc/sys/kernel'},
                       {'name': 'bpf-maps', 'mountPath': '/sys/fs/bpf'},
                       {'name': 'lib-modules', 'mountPath': '/lib/modules', 'readOnly': True}])],
    [('mount-cgroup', [{'name': 'hostproc', 'mountPath': '/hostproc'}]),
     ('apply-sysctl-overwrites', [{'name': 'hostproc', 'mountPath': '/hostproc', 'readOnly': False}])])


def chart(*objects):
    return {'apiVersion': 'v1', 'kind': 'List', 'items': [json.loads(json.dumps(o)) for o in objects]}


def mounts(doc, kind, name):
    for it in doc['items']:
        if it['kind'] == kind and it['metadata']['name'] == name:
            spec = it['spec']['template']['spec']
            return {(c['name'], m['name']): m.get('readOnly', False)
                    for c in spec.get('initContainers', []) + spec['containers'] for m in c['volumeMounts']}
    raise KeyError(name)


class ReadOnlyProcMountsTest(unittest.TestCase):
    def transform(self, doc):
        return subprocess.run([sys.executable, '-I', str(TRANSFORM)], input=json.dumps(doc), capture_output=True,
                              text=True, timeout=30)

    def test_the_agents_proc_mounts_become_read_only_except_net(self):
        r = self.transform(chart(AGENT, {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'c'}}))
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(mounts(out, 'DaemonSet', 'cilium'), {
            ('cilium-agent', 'host-proc-sys-net'): False,
            ('cilium-agent', 'host-proc-sys-kernel'): True,
            ('cilium-agent', 'bpf-maps'): False,
            ('cilium-agent', 'lib-modules'): True,
            ('mount-cgroup', 'hostproc'): True,
            ('apply-sysctl-overwrites', 'hostproc'): True,
        })
        self.assertEqual(out['items'][1], {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'c'}})
        # One line per mount it changed, so the run's log shows them.
        self.assertEqual(sorted(r.stderr.splitlines()), [
            'read-only: DaemonSet/cilium apply-sysctl-overwrites hostproc (/proc)',
            'read-only: DaemonSet/cilium cilium-agent host-proc-sys-kernel (/proc/sys/kernel)',
            'read-only: DaemonSet/cilium mount-cgroup hostproc (/proc)',
        ])

    def test_any_workload_and_any_path_under_proc(self):
        other = daemonset('cilium-envoy', [('p', '/proc/'), ('k', '/proc/sys/kernel/'), ('n', '/proc/sys/net/core'),
                                            ('s', '/proc/sysrq-trigger'), ('x', '/procfoo')],
                          [('envoy', [{'name': v, 'mountPath': '/m/' + v} for v in 'pknsx'])])
        r = self.transform(chart(AGENT, other))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(mounts(json.loads(r.stdout), 'DaemonSet', 'cilium-envoy'), {
            ('envoy', 'p'): True, ('envoy', 'k'): True, ('envoy', 'n'): False, ('envoy', 's'): True,
            ('envoy', 'x'): False})

    def test_a_chart_without_the_agents_kernel_mount_is_refused(self):
        # The agent would then write the kernel sysctls some other way, or not
        # at all: either way the chart changed and needs a look.
        agent = json.loads(json.dumps(AGENT))
        spec = agent['spec']['template']['spec']
        spec['volumes'] = [v for v in spec['volumes'] if v['name'] != 'host-proc-sys-kernel']
        spec['containers'][0]['volumeMounts'] = [m for m in spec['containers'][0]['volumeMounts']
                                                 if m['name'] != 'host-proc-sys-kernel']
        for doc in (chart(agent), chart()):
            with self.subTest(items=len(doc['items'])):
                r = self.transform(doc)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, '')
                self.assertIn('/proc/sys/kernel', r.stderr)

    def test_objects_one_after_another_as_kubectl_prints_them(self):
        # kubectl create --dry-run=client -o json prints each object of a
        # multi-document file as its own JSON document, not as a List.
        config = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'c'}}
        text = json.dumps(config, indent=4) + '\n' + json.dumps(AGENT, indent=4) + '\n'
        r = subprocess.run([sys.executable, '-I', str(TRANSFORM)], input=text, capture_output=True, text=True,
                           timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out['kind'], 'List')
        self.assertEqual(out['items'][0], config)
        self.assertTrue(mounts(out, 'DaemonSet', 'cilium')[('cilium-agent', 'host-proc-sys-kernel')])

    def test_input_that_is_not_objects_is_refused(self):
        for text in ('[1, 2]', '{"kind": "List"', 'kind: DaemonSet', ''):
            with self.subTest(text=text):
                r = subprocess.run([sys.executable, '-I', str(TRANSFORM)], input=text, capture_output=True,
                                   text=True, timeout=30)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, '')


if __name__ == '__main__':
    unittest.main()
