"""detect/falco/collector.py: which Falco alerts reach a disk, and which are only counted.

Offline: fake resolvers, a temp FIFO and, for the command itself, a fake
Docker API on a temp unix socket. No Docker daemon, cluster or Falco.
"""
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import queue
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

try:
    from detect.falco import collector
except ImportError:
    collector = None
try:
    from detect.report import alert_import
except ImportError:
    alert_import = None

WARDEN = 'a' * 64
OTHER = 'b' * 64
LAB_POD = 'c' * 64
SECRET = 'other-project-secret-marker'


def event(container_id, rule='Terminal shell in container', extra=None, source='syscall'):
    fields = {'container.id': container_id, 'proc.name': 'sh'}
    fields.update(extra or {})
    return {'time': '2026-11-14T02:00:00.123456789Z', 'rule': rule, 'priority': 'Notice', 'source': source,
            'output': 'A shell was spawned in a container with an attached terminal', 'output_fields': fields,
            'hostname': 'lab', 'tags': ['T1059', 'container']}


def raw(evt):
    return json.dumps(evt).encode()


def metrics(n_evts, n_drops=0, start_ts=1):
    return {'time': '2026-11-14T02:00:30.000000000Z', 'rule': 'Falco internal: metrics snapshot', 'priority': 'Informational',
            'source': 'internal', 'output': 'Falco metrics snapshot',
            'output_fields': {'scap.n_evts': n_evts, 'scap.n_drops': n_drops, 'falco.start_ts': start_ts}}


class FakeResolver:
    def __init__(self, known=None):
        self.known = dict(known or {})
        self.calls = []
        self.failing = {}  # short ID -> exception to raise

    def resolve(self, short):
        self.calls.append(short)
        if short in self.failing:
            raise self.failing[short]
        for full, decision in self.known.items():
            if full.startswith(short):
                return decision
        return None


def decision(warden, full, run='run-1', klass='sandbox'):
    return collector.Decision(warden, 'docker', full, run, {'project': 'warden' if warden else 'other'},
                              klass if warden else None)


class Base(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(collector, 'detect/falco/collector.py missing')


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class ClassifyTest(Base):
    def test_kinds(self):
        self.assertEqual(collector.classify(raw(metrics(5)))[0], 'health')
        self.assertEqual(collector.classify(raw(event('host')))[0], 'host')
        self.assertEqual(collector.classify(raw(event('')))[0], 'host')
        kind, evt, cid = collector.classify(raw(event(WARDEN[:12])))
        self.assertEqual((kind, cid), ('container', WARDEN[:12]))
        for bad in (b'not json', b'[]', raw({'time': 'x', 'output_fields': {}}), raw(event('../etc')),
                    raw(dict(event(WARDEN[:12]), output_fields='x'))):
            with self.subTest(bad=bad):
                self.assertEqual(collector.classify(bad)[0], 'malformed')

    def test_internal_rule_without_source_is_health(self):
        evt = event('host', rule='Falco internal: syscall event drop', source='syscall')
        self.assertEqual(collector.classify(raw(evt))[0], 'health')


class CollectorTest(Base):
    def setUp(self):
        super().setUp()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.out = Path(self.dir.name, 'out')
        self.sink = collector.Sink(str(self.out))
        self.addCleanup(self.sink.close)
        self.clock = Clock()

    def make(self, known=None, deadline=20):
        self.resolver = FakeResolver(known)
        return collector.Collector('host', self.sink, self.resolver, deadline, self.clock)

    def read(self, name):
        path = self.out / name
        return path.read_bytes().splitlines() if path.exists() else []

    def all_bytes(self):
        return b''.join(p.read_bytes() for p in self.out.rglob('*') if p.is_file())

    def test_warden_alert_is_kept_byte_for_byte_with_its_decision(self):
        c = self.make({WARDEN: decision(True, WARDEN)})
        line = raw(event(WARDEN[:12]))
        c.feed(line)
        self.assertEqual(self.read('alerts.jsonl'), [line])
        scoping = [json.loads(x) for x in self.read('scoping.jsonl')]
        self.assertEqual(len(scoping), 1)
        self.assertEqual(scoping[0]['full_container_id'], WARDEN)
        self.assertEqual(scoping[0]['run_id'], 'run-1')
        self.assertEqual(scoping[0]['class'], 'sandbox')
        self.assertEqual(c.snapshot()['warden_alerts'], 1)

    def test_scoping_digest_is_the_one_alert_import_gives(self):
        if alert_import is None:
            self.skipTest('detect/report/alert_import.py missing')
        evt = event(WARDEN[:12])
        c = self.make({WARDEN: decision(True, WARDEN)})
        c.feed(raw(evt))
        binding = {'execution_id': 'exec-1', 'run_id': 'run-1', 'container_id': WARDEN,
                   'start': '2026-11-14T01:59:00Z', 'end': '2026-11-14T02:01:00Z'}
        kept = [json.loads(x) for x in self.read('alerts.jsonl')]
        alerts, provenance = alert_import.from_falco(kept, [binding], {'exec-1': {'Terminal shell in container'}})
        self.assertEqual(len(alerts), 1)
        digest = json.loads(self.read('scoping.jsonl')[0])['raw_event_sha256']
        self.assertEqual(provenance[0]['raw_event_sha256'], digest)

    def test_other_projects_and_host_alerts_are_only_counted(self):
        c = self.make({OTHER: decision(False, OTHER)})
        c.feed(raw(event(OTHER[:12], extra={'proc.cmdline': SECRET})))
        c.feed(raw(event('host', extra={'proc.cmdline': SECRET})))
        c.feed(b'{"broken": "' + SECRET.encode())
        counts = c.snapshot()
        self.assertEqual((counts['dropped_other_container'], counts['dropped_host'], counts['dropped_malformed']), (1, 1, 1))
        self.assertEqual(counts['received'], 3)
        self.assertNotIn(SECRET.encode(), self.all_bytes())
        self.assertEqual(self.read('alerts.jsonl'), [])
        self.assertEqual(self.read('scoping.jsonl'), [])

    def test_dropped_containers_are_counted_by_kind_only(self):
        # Counts only: lab-owned containers that are not Warden workloads (the
        # detector's own Falco containers, the smoke's control), lab pods
        # outside warden-lab, and everyone else's containers.
        lab = collector.Decision(False, 'docker', OTHER, None, {'owner': 'warden-lab', 'name': 'warden-detect-falco-gvisor'})
        pod = collector.Decision(False, 'k8s', LAB_POD, None, {'namespace': 'default', 'pod': 'control'})
        sandbox = collector.Decision(False, 'cgroup-pod', '9' * 64, None, {'namespace': 'default', 'pod': 'control'})
        theirs = collector.Decision(False, 'docker', 'e' * 64, None, {'project': 'theirs', 'name': SECRET})
        c = self.make({OTHER: lab, LAB_POD: pod, '9' * 64: sandbox, 'e' * 64: theirs})
        for cid in (OTHER, LAB_POD, '9' * 64, 'e' * 64, 'e' * 64):
            c.feed(raw(event(cid[:12])))
        counts = c.snapshot()
        self.assertEqual((counts['dropped_other_container'], counts['dropped_other_lab_owned'], counts['dropped_other_lab_pod']),
                         (5, 1, 2))
        self.assertNotIn(SECRET.encode(), self.all_bytes())

    def test_unknown_container_waits_then_is_kept_or_dropped(self):
        c = self.make(deadline=20)
        c.feed(raw(event(WARDEN[:12])))
        c.feed(raw(event(OTHER[:12], extra={'proc.cmdline': SECRET})))
        self.assertEqual(c.snapshot()['pending'], 2)
        self.clock.t = 5
        self.resolver.known[WARDEN] = decision(True, WARDEN)
        c.tick()
        self.assertEqual(len(self.read('alerts.jsonl')), 1)
        self.assertEqual(c.snapshot()['pending'], 1)
        self.clock.t = 20
        c.tick()
        counts = c.snapshot()
        self.assertEqual((counts['pending'], counts['dropped_unresolved']), (0, 1))
        self.assertNotIn(SECRET.encode(), self.all_bytes())

    def test_pending_alerts_of_one_container_are_resolved_once_per_tick(self):
        # Hundreds of alerts of one new sandbox must not mean hundreds of
        # lookups per tick (the lookups then fall behind the sandbox's life).
        c = self.make()
        for i in range(50):
            c.feed(raw(event(WARDEN[:12], extra={'evt.num': i})))
        self.resolver.calls.clear()
        c.tick()
        self.assertEqual(self.resolver.calls, [WARDEN[:12]])
        self.resolver.known[WARDEN] = decision(True, WARDEN)
        c.tick()
        self.assertEqual(len(self.read('alerts.jsonl')), 50)

    def test_final_tick_drops_whatever_is_still_unknown(self):
        c = self.make()
        c.feed(raw(event(OTHER[:12])))
        c.tick(final=True)
        self.assertEqual(c.snapshot()['dropped_unresolved'], 1)

    def test_health_events_are_kept_unchanged(self):
        c = self.make()
        line = raw(metrics(42))
        c.feed(line)
        self.assertEqual(self.read('health.jsonl'), [line])
        self.assertEqual(c.snapshot()['health_events'], 1)

    def test_one_failing_step_is_counted_and_the_loop_goes_on(self):
        # A Docker API error in a heartbeat (or anywhere in a step) must not
        # end the collector: it is counted in collector_errors.
        c = self.make({WARDEN: decision(True, WARDEN)})
        lines = queue.Queue()
        lines.put(raw(event(WARDEN[:12])))
        stop, calls = threading.Event(), []

        def beat():
            calls.append(1)
            if len(calls) == 1:
                raise OSError('docker went away')
            stop.set()
        collector.serve(c, lines, stop, beat, beat_every=0, flush=threading.Event())
        self.assertEqual(c.snapshot()['collector_errors'], 1)
        self.assertEqual(len(self.read('alerts.jsonl')), 1)

    # --- an alert line is never lost silently ---

    def test_a_lookup_error_keeps_the_alert_for_a_retry(self):
        c = self.make({WARDEN: decision(True, WARDEN)})
        self.resolver.failing[WARDEN[:12]] = http.client.BadStatusLine('docker went away')
        c.feed(raw(event(WARDEN[:12])))
        self.assertEqual((self.read('alerts.jsonl'), c.snapshot()['pending'], c.snapshot()['collector_errors']), ([], 1, 1))
        del self.resolver.failing[WARDEN[:12]]
        self.clock.t = 3
        c.tick()
        self.assertEqual(len(self.read('alerts.jsonl')), 1)
        self.assertEqual(c.snapshot()['pending'], 0)

    def test_a_persistent_error_expires_into_a_counted_drop(self):
        c = self.make({WARDEN: decision(True, WARDEN)}, deadline=20)
        self.resolver.failing[WARDEN[:12]] = socket.timeout('timed out')
        c.feed(raw(event(WARDEN[:12])))
        for t in (1, 5, 10, 19.9):
            self.clock.t = t
            c.tick()
        self.assertEqual(c.snapshot()['pending'], 1)
        self.clock.t = 20
        c.tick()
        counts = c.snapshot()
        self.assertEqual((counts['pending'], counts['dropped_error'], counts['warden_alerts']), (0, 1, 0))
        self.assertEqual(self.read('alerts.jsonl'), [])

    def test_a_failing_container_in_a_tick_rewrites_nothing(self):
        c = self.make()
        c.feed(raw(event(WARDEN[:12])))
        c.feed(raw(event(OTHER[:12], extra={'proc.cmdline': 'second'})))
        self.resolver.known[WARDEN] = decision(True, WARDEN)
        self.resolver.failing[OTHER[:12]] = OSError('docker socket')
        for t in range(1, 5):
            self.clock.t = t
            c.tick()
        self.assertEqual(len(self.read('alerts.jsonl')), 1)
        self.assertEqual(len(self.read('scoping.jsonl')), 1)
        self.assertEqual(c.snapshot()['pending'], 1)

    def test_a_failed_write_is_retried_without_duplicating(self):
        c = self.make({WARDEN: decision(True, WARDEN)})
        real = self.sink.write
        failed = []

        def write(name, line):
            if name == 'scoping.jsonl' and not failed:
                failed.append(1)
                raise OSError('disk full')
            return real(name, line)
        self.sink.write = write
        c.feed(raw(event(WARDEN[:12])))
        self.assertEqual(c.snapshot()['collector_errors'], 1)
        self.clock.t = 1
        c.tick()
        self.assertEqual((len(self.read('alerts.jsonl')), len(self.read('scoping.jsonl'))), (1, 1))
        self.assertEqual(c.snapshot()['warden_alerts'], 1)

    def test_writes_are_idempotent_per_alert_id_also_after_a_restart(self):
        c = self.make({WARDEN: decision(True, WARDEN)})
        line = raw(event(WARDEN[:12]))
        c.feed(line)
        c.feed(line)
        self.assertEqual(len(self.read('alerts.jsonl')), 1)
        again = collector.Collector('host', self.sink, self.resolver, 20, self.clock)
        again.load_kept(str(self.out))
        again.feed(line)
        self.assertEqual((len(self.read('alerts.jsonl')), len(self.read('scoping.jsonl'))), (1, 1))

    def test_runscs_start_up_signature_is_platform_not_a_run_alert(self):
        # The sentry ptraces its stubs whenever a sandbox starts: kept and
        # reviewable, but in platform-alerts.jsonl, never in the alerts that
        # are scored against runs. Other rules from the same sandbox are run alerts.
        sandbox = collector.Decision(True, 'cgroup', WARDEN, 'r1', {'namespace': 'warden-lab', 'inside': 'warden-k3s-gvisor'}, 'sandbox')
        c = self.make({WARDEN: sandbox})
        start = raw(event(WARDEN[:12], rule='PTRACE attached to process', extra={'proc.name': 'gvisor_sentry'}))
        other = raw(event(WARDEN[:12], rule='Terminal shell in container', extra={'proc.name': 'sh'}))
        c.feed(start)
        c.feed(other)
        self.assertEqual(self.read('platform-alerts.jsonl'), [start])
        self.assertEqual(self.read('alerts.jsonl'), [other])
        classes = [json.loads(x)['class'] for x in self.read('scoping.jsonl')]
        self.assertEqual(classes, ['platform', 'sandbox'])
        self.assertEqual((c.snapshot()['platform_alerts'], c.snapshot()['warden_alerts']), (1, 1))

    def test_files_are_private(self):
        c = self.make({WARDEN: decision(True, WARDEN)})
        c.feed(raw(event(WARDEN[:12])))
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.out / 'alerts.jsonl').st_mode), 0o600)


class FakeDocker:
    def __init__(self, containers):
        self.containers = containers

    def inspect(self, ident):
        for full, inspect in self.containers.items():
            if full.startswith(ident) or inspect.get('Name', '').lstrip('/') == ident:
                return inspect
        return None


class FakeKube:
    def __init__(self, pods):
        self.items, self.calls = pods, 0

    def pods(self, namespace=None, selector=None):
        self.calls += 1
        return self.items


def uid_of(name):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))


def pod(namespace, name, cid, labels, state=None):
    return {'metadata': {'namespace': namespace, 'name': name, 'uid': uid_of(name), 'labels': labels,
                         'creationTimestamp': '2026-11-14T01:59:58Z'},
            'status': {'containerStatuses': [{'containerID': 'containerd://' + cid,
                                              'state': state or {'running': {'startedAt': '2026-11-14T02:00:00Z'}}}]}}


class ResolverTest(Base):
    def test_docker_label_project_warden_decides(self):
        docker = FakeDocker({WARDEN: {'Id': WARDEN, 'Name': '/warden-x', 'Config': {'Labels': {
            'project': 'warden', 'owner': 'warden-lab', 'warden.dev/run': 'r1', 'secret': 'x'}}},
            OTHER: {'Id': OTHER, 'Name': '/theirs', 'Config': {'Labels': {'project': 'other', 'owner': 'warden-lab'}}}})
        r = collector.Resolver(docker=docker)
        d = r.resolve(WARDEN[:12])
        self.assertTrue(d.warden)
        self.assertEqual((d.full_id, d.run_id, d.resolver), (WARDEN, 'r1', 'docker'))
        self.assertNotIn('secret', d.detail)
        self.assertEqual(d.klass, 'sandbox')
        self.assertFalse(r.resolve(OTHER[:12]).warden, 'owner=warden-lab alone is not a Warden workload')
        self.assertIsNone(r.resolve('d' * 12))

    def test_container_classes(self):
        node, standin, outer = 'd' * 64, 'e' * 64, '1' * 64
        docker = FakeDocker({node: {'Id': node, 'Name': '/warden-k3s-gvisor', 'Config': {'Labels': {'project': 'warden'}}},
                             standin: {'Id': standin, 'Name': '/warden-k3s-dns', 'Config': {'Labels': {'project': 'warden'}}},
                             outer: {'Id': outer, 'Name': '/vibrant_x', 'Config': {'Labels': {
                                 'project': 'warden', 'owner': 'warden-lab', 'session': 's1'}}}})
        r = collector.Resolver(docker=docker)
        self.assertEqual([(r.resolve(c[:12]).klass, r.resolve(c[:12]).run_id) for c in (node, standin, outer)],
                         [('node', None), ('lab', None), ('sandbox', 's1')])

    def test_an_exited_container_is_placed_from_the_registry(self):
        # The runc lab removes its outer container right after the run; an
        # alert the collector reaches later is placed from Docker's start event.
        r = collector.Resolver(docker=FakeDocker({}))
        self.assertIsNone(r.resolve(WARDEN[:12]))
        r.remember_docker({'source': 'docker', 'event': 'start', 'container_id': WARDEN, 'name': 'vibrant_x',
                           'labels': {'project': 'warden', 'owner': 'warden-lab', 'session': 's2'}})
        r.remember_docker({'source': 'docker', 'event': 'start', 'container_id': OTHER, 'name': 'theirs',
                           'labels': {'project': 'other'}})
        d = r.resolve(WARDEN[:12])
        self.assertEqual((d.warden, d.resolver, d.run_id, d.klass), (True, 'registry', 's2', 'sandbox'))
        self.assertFalse(r.resolve(OTHER[:12]).warden)

    def test_lab_pods_in_warden_lab_with_a_run_label_decide(self):
        kube = FakeKube([pod('warden-lab', 'run-a', LAB_POD, {'warden.dev/run': 'r2'}),
                         pod('default', 'control', OTHER, {'warden.dev/run': 'r3'}),
                         pod('warden-lab', 'unlabelled', WARDEN, {})])
        r = collector.Resolver(docker=FakeDocker({}), kube=kube)
        d = r.resolve(LAB_POD[:12])
        self.assertTrue(d.warden)
        self.assertEqual((d.full_id, d.run_id, d.resolver, d.klass), (LAB_POD, 'r2', 'k8s', 'sandbox'))
        self.assertFalse(r.resolve(OTHER[:12]).warden)
        self.assertFalse(r.resolve(WARDEN[:12]).warden)

    def test_nested_cgroups_are_placed_by_their_pod_first(self):
        # runsc's sentry runs in the k3s node's pod-sandbox cgroup, whose ID no
        # API lists; Falco reports that ID. The pod the cgroup belongs to
        # decides (warden-lab with warden.dev/run, or not Warden's); a cgroup
        # of the node that is in no pod is the node's infrastructure.
        node = 'd' * 64
        run_sb, control_sb, infra = '6c918fd05c04' + '0' * 52, '7c918fd05c04' + '1' * 52, '8c918fd05c04' + '2' * 52
        with tempfile.TemporaryDirectory() as root:
            scope = Path(root, 'system.slice', 'docker-%s.scope' % node)
            (scope / 'kubepods' / 'besteffort' / ('pod' + uid_of('run-a')) / run_sb).mkdir(parents=True)
            (scope / 'kubepods' / ('kubepods-pod%s.slice' % uid_of('control').replace('-', '_')) / control_sb).mkdir(parents=True)
            (scope / 'k3s' / infra).mkdir(parents=True)
            (scope / 'kubepods' / ('pod' + uid_of('gone')) / ('9' * 64)).mkdir(parents=True)
            Path(root, 'system.slice', 'docker-%s.scope' % OTHER, 'inner', LAB_POD).mkdir(parents=True)
            docker = FakeDocker({node: {'Id': node, 'Name': '/warden-k3s-gvisor', 'Config': {'Labels': {'project': 'warden'}}},
                                 OTHER: {'Id': OTHER, 'Name': '/theirs', 'Config': {'Labels': {'project': 'other'}}}})
            docker.running = lambda labels: [node] if labels == {'project': 'warden'} else [node, OTHER]
            kube = FakeKube([pod('warden-lab', 'run-a', 'a' * 64, {'warden.dev/run': 'rA'}),
                             pod('default', 'control', 'b' * 64, {'warden.dev/run': 'rB'})])
            r = collector.Resolver(docker=docker, kube=kube, cgroup_root=root)
            d = r.resolve(run_sb[:12])
            self.assertEqual((d.warden, d.resolver, d.full_id, d.run_id, d.klass, d.detail['inside']),
                             (True, 'cgroup', run_sb, 'rA', 'sandbox', 'warden-k3s-gvisor'))
            d = r.resolve(control_sb[:12])
            self.assertEqual((d.warden, d.resolver), (False, 'cgroup-pod'), 'the control pod is not Warden\'s although the node is')
            d = r.resolve(infra[:12])
            self.assertEqual((d.warden, d.klass), (True, 'node'))
            self.assertIsNone(r.resolve('9' * 12), 'a pod no list shows is unknown, so dropped after the deadline')
            d = r.resolve(LAB_POD[:12])
            self.assertEqual((d.warden, d.resolver, d.detail['inside']), (False, 'cgroup-other', 'theirs'),
                             'nested in a container that is not Warden\'s: that container\'s, another\'s')

    def kind_node(self, root, node, inner, labels):
        """A kind node's pod container cgroup, as kubelet's systemd driver names it."""
        uid = uid_of('kind-pod').replace('-', '_')
        Path(root, 'system.slice', 'docker-%s.scope' % node, 'kubelet.slice', 'kubelet-kubepods.slice',
             'kubelet-kubepods-besteffort.slice', 'kubelet-kubepods-besteffort-pod%s.slice' % uid,
             'cri-containerd-%s.scope' % inner).mkdir(parents=True)
        return {'Id': node, 'Name': '/' + labels.pop('name'), 'Config': {'Labels': labels}}

    def test_nested_in_a_container_that_is_not_wardens_is_another_containers(self):
        # The kind audit lab's node, another project's kind node: their pods'
        # containerd IDs are known to no API the collector asks.
        node, inner = 'e' * 64, '5d6e7f809a1b' + '3' * 52
        with tempfile.TemporaryDirectory() as root:
            inspect = self.kind_node(root, node, inner, {'name': 'materialflow-control-plane', 'io.x-k8s.kind.cluster': 'materialflow'})
            docker = FakeDocker({node: inspect})
            docker.running = lambda labels: [] if labels == {'project': 'warden'} else [node]
            r = collector.Resolver(docker=docker, kube=FakeKube([]), cgroup_root=root)
            d = r.resolve(inner[:12])
            self.assertEqual((d.warden, d.resolver, d.full_id, d.run_id, d.detail), (False, 'cgroup-other', inner, None,
                                                                                    {'inside': 'materialflow-control-plane'}))
            with tempfile.TemporaryDirectory() as out:
                sink = collector.Sink(out)
                self.addCleanup(sink.close)
                c = collector.Collector('host', sink, r, 20, Clock())
                c.feed(raw(event(inner[:12], extra={'proc.cmdline': SECRET})))
                counts = c.snapshot()
                self.assertEqual((counts['dropped_other_container'], counts['dropped_other_nested'], counts['pending'],
                                  counts['dropped_unresolved']), (1, 1, 0, 0))
                self.assertFalse(Path(out, 'alerts.jsonl').exists())
                self.assertNotIn(SECRET.encode(), b''.join(p.read_bytes() for p in Path(out).rglob('*') if p.is_file()))

    def test_a_warden_container_comes_first(self):
        # The same cgroup ID below a Warden node and below another container
        # (contrived, but it fixes the order): the Warden node's rules decide,
        # the pod first, then the node; an ID of a Warden pod not listed yet
        # stays unknown (retried) and is never another container's.
        warden_node, theirs = 'd' * 64, 'e' * 64
        infra, unlisted = '8c918fd05c04' + '2' * 52, '4c918fd05c04' + '4' * 52
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'system.slice', 'docker-%s.scope' % warden_node, 'k3s', infra).mkdir(parents=True)
            Path(root, 'system.slice', 'docker-%s.scope' % warden_node, 'kubepods', 'pod' + uid_of('later'), unlisted).mkdir(parents=True)
            for inner in (infra, unlisted):
                Path(root, 'system.slice', 'docker-%s.scope' % theirs, 'kubelet.slice', inner).mkdir(parents=True)
            docker = FakeDocker({warden_node: {'Id': warden_node, 'Name': '/warden-k3s-gvisor', 'Config': {'Labels': {'project': 'warden'}}},
                                 theirs: {'Id': theirs, 'Name': '/materialflow-control-plane', 'Config': {'Labels': {}}}})
            docker.running = lambda labels: [warden_node] if labels == {'project': 'warden'} else [warden_node, theirs]
            r = collector.Resolver(docker=docker, kube=FakeKube([]), cgroup_root=root)
            d = r.resolve(infra[:12])
            self.assertEqual((d.warden, d.resolver, d.klass), (True, 'cgroup', 'node'))
            self.assertIsNone(r.resolve(unlisted[:12]), 'a Warden pod not listed yet: retried, not another container\'s')

    def test_found_nowhere_stays_unresolved_and_is_dropped_after_the_deadline(self):
        node = 'e' * 64
        with tempfile.TemporaryDirectory() as root:
            inspect = self.kind_node(root, node, '6' * 64, {'name': 'materialflow-control-plane'})
            docker = FakeDocker({node: inspect})
            docker.running = lambda labels: [] if labels == {'project': 'warden'} else [node]
            r = collector.Resolver(docker=docker, kube=FakeKube([]), cgroup_root=root)
            self.assertIsNone(r.resolve('7' * 12))
            with tempfile.TemporaryDirectory() as out:
                sink = collector.Sink(out)
                self.addCleanup(sink.close)
                clock = Clock()
                c = collector.Collector('host', sink, r, 20, clock)
                c.feed(raw(event('7' * 12)))
                self.assertEqual(c.snapshot()['pending'], 1)
                clock.t = 19.9
                c.tick()
                self.assertEqual((c.snapshot()['pending'], c.snapshot()['dropped_unresolved']), (1, 0))
                clock.t = 20
                c.tick()
                counts = c.snapshot()
                self.assertEqual((counts['pending'], counts['dropped_unresolved'], counts['dropped_other_container']), (0, 1, 0))

    def test_pod_sandboxes_seen_by_the_pod_watch_resolve_after_they_are_gone(self):
        # The pod watch records each pod's sandbox cgroup while it exists; an
        # alert processed after the sandbox and its cgroup went is still placed.
        r = collector.Resolver(docker=FakeDocker({}), kube=FakeKube([]))
        run, control = pod('warden-lab', 'run-a', 'a' * 64, {'warden.dev/run': 'rA'}), pod('default', 'control', 'b' * 64, {})
        r.remember_pod_cgroups(run, {'6' * 64}, 'warden-k3s-gvisor')
        r.remember_pod_cgroups(control, {'7' * 64}, 'warden-k3s-gvisor')
        d = r.resolve('6' * 12)
        self.assertEqual((d.warden, d.resolver, d.run_id, d.klass, d.detail['inside']), (True, 'cgroup', 'rA', 'sandbox', 'warden-k3s-gvisor'))
        d = r.resolve('7' * 12)
        self.assertEqual((d.warden, d.resolver), (False, 'cgroup-pod'))

    def test_a_nested_cgroup_seen_once_is_remembered(self):
        node = 'd' * 64
        sandbox = '6c918fd05c04' + '0' * 52
        with tempfile.TemporaryDirectory() as root:
            where = Path(root, 'system.slice', 'docker-%s.scope' % node, 'kubepods', 'pod' + uid_of('late'), sandbox)
            where.mkdir(parents=True)
            docker = FakeDocker({node: {'Id': node, 'Name': '/warden-k3s-gvisor', 'Config': {'Labels': {'project': 'warden'}}}})
            docker.running = lambda labels: [node]
            kube = FakeKube([])
            clock = Clock()
            r = collector.Resolver(docker=docker, kube=kube, cgroup_root=root, clock=clock)
            self.assertIsNone(r.resolve(sandbox[:12]), 'the pod is not listed yet')
            where.rmdir()  # the sandbox is gone before the pod list shows it
            kube.items = [pod('warden-lab', 'late', 'a' * 64, {'warden.dev/run': 'rL'})]
            clock.t = 5
            d = r.resolve(sandbox[:12])
            self.assertEqual((d.warden, d.run_id), (True, 'rL'))

    def test_sandbox_ids_of_a_pod(self):
        node = 'd' * 64
        with tempfile.TemporaryDirectory() as root:
            for form in ('pod' + uid_of('p'), 'kubepods-pod%s.slice' % uid_of('p').replace('-', '_')):
                (Path(root, 'system.slice', 'docker-%s.scope' % node, 'kubepods', form, 'a' * 64)).mkdir(parents=True)
            Path(root, 'system.slice', 'docker-%s.scope' % node, 'kubepods', 'pod' + uid_of('p'), 'b' * 64).mkdir()
            self.assertEqual(collector.sandbox_ids(root, [node], uid_of('p')), {'a' * 64, 'b' * 64})
            self.assertEqual(collector.sandbox_ids(root, [node], uid_of('q')), set())

    def test_ambiguous_short_id_is_not_resolved(self):
        twin = 'a' * 12 + 'e' * 52
        kube = FakeKube([pod('warden-lab', 'one', WARDEN, {'warden.dev/run': 'r'}),
                         pod('warden-lab', 'two', twin, {'warden.dev/run': 'r'})])
        r = collector.Resolver(docker=FakeDocker({}), kube=kube)
        self.assertIsNone(r.resolve(WARDEN[:12]))
        self.assertEqual(r.resolve(WARDEN).full_id, WARDEN)

    def test_decisions_are_cached_and_pod_lists_rate_limited(self):
        clock = Clock()
        kube = FakeKube([])
        r = collector.Resolver(docker=FakeDocker({}), kube=kube, clock=clock, kube_refresh=1.0)
        self.assertIsNone(r.resolve(LAB_POD[:12]))
        self.assertIsNone(r.resolve(LAB_POD[:12]))
        self.assertEqual(kube.calls, 1)
        kube.items = [pod('warden-lab', 'late', LAB_POD, {'warden.dev/run': 'r'})]
        clock.t = 1.5
        self.assertTrue(r.resolve(LAB_POD[:12]).warden)
        kube.items = []
        clock.t = 9
        self.assertTrue(r.resolve(LAB_POD[:12]).warden)


class RegistryTest(Base):
    def test_docker_start_and_die_events(self):
        start = {'Type': 'container', 'Action': 'start', 'timeNano': 1763085600123456789,
                 'Actor': {'ID': WARDEN, 'Attributes': {'name': 'warden-x', 'project': 'warden', 'warden.dev/run': 'r1', 'other': 'x'}}}
        rec = collector.registry_from_docker_event(start)
        self.assertEqual((rec['event'], rec['container_id'], rec['labels']), ('start', WARDEN, {'project': 'warden', 'warden.dev/run': 'r1'}))
        self.assertTrue(rec['time'].endswith('.123456789Z'), rec['time'])
        die = dict(start, Action='die')
        die['Actor'] = {'ID': WARDEN, 'Attributes': {'exitCode': '0', 'project': 'warden'}}
        self.assertEqual(collector.registry_from_docker_event(die)['exit_code'], '0')
        self.assertIsNone(collector.registry_from_docker_event(dict(start, Action='create')))

    def test_pod_tracker_records_running_terminated_and_gone(self):
        sandbox = '5' * 64
        t = collector.PodTracker(sandboxes=lambda uid: {sandbox, LAB_POD} if uid == uid_of('run-a') else set())
        running = pod('warden-lab', 'run-a', LAB_POD, {'warden.dev/run': 'r2'})
        recs = t.update([running, pod('default', 'c', OTHER, {'warden.dev/run': 'x'})], 'T1')
        self.assertEqual([(r['event'], r['container_id'], r['run_id'], r['sandbox_id'], r['created_at']) for r in recs],
                         [('running', LAB_POD, 'r2', sandbox, '2026-11-14T01:59:58Z')])
        self.assertEqual(t.update([running], 'T2'), [])
        done = pod('warden-lab', 'run-a', LAB_POD, {'warden.dev/run': 'r2'},
                   {'terminated': {'startedAt': '2026-11-14T02:00:00Z', 'finishedAt': '2026-11-14T02:00:03Z', 'exitCode': 0}})
        recs = t.update([done], 'T3')
        self.assertEqual([(r['event'], r['finished_at'], r['sandbox_id']) for r in recs], [('terminated', '2026-11-14T02:00:03Z', sandbox)])
        recs = t.update([], 'T4')
        self.assertEqual([(r['event'], r['observed_at'], r['sandbox_id']) for r in recs], [('gone', 'T4', sandbox)])


class KubeconfigTest(Base):
    def test_fields(self):
        b = base64.b64encode(b'x').decode()
        text = ('apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: %s\n    server: https://172.30.0.10:6443\n'
                'users:\n- name: default\n  user:\n    client-certificate-data: %s\n    client-key-data: %s\n') % (b, b, b)
        fields = collector.kubeconfig_fields(text)
        self.assertEqual(fields['server'], 'https://172.30.0.10:6443')
        with self.assertRaises(ValueError):
            collector.kubeconfig_fields(text.replace('https://172.30.0.10:6443', 'https://evil.example:6443'))
        with self.assertRaises(ValueError):
            collector.kubeconfig_fields(text + '    client-key-data: %s\n' % b)


class FifoTest(Base):
    def test_fifo_survives_writers_that_close_after_each_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'alerts.fifo')
            fd = collector.open_fifo(path, None)
            try:
                self.assertTrue(stat.S_ISFIFO(os.lstat(path).st_mode))
                self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
                for line in (b'one\n', b'two\n'):
                    w = os.open(path, os.O_WRONLY)
                    os.write(w, line)
                    os.close(w)
                got = b''
                while got.count(b'\n') < 2:
                    got += os.read(fd, 100)
                self.assertEqual(got, b'one\ntwo\n')
            finally:
                os.close(fd)

    def test_fifo_for_a_group(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'alerts.fifo')
            os.close(collector.open_fifo(path, os.getgid()))
            info = os.lstat(path)
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_gid), (0o620, os.getgid()))
            with self.assertRaises(OSError):
                os.getxattr(path, 'system.posix_acl_access')

    def test_refuses_a_path_that_is_not_a_fifo(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'alerts.fifo')
            Path(path).write_text('')
            with self.assertRaises(RuntimeError):
                collector.open_fifo(path, None)


class DockerHandler(http.server.BaseHTTPRequestHandler):
    containers = {}

    def do_GET(self):
        if self.path.startswith('/events'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            for action in ('start', 'die'):
                self.wfile.write(json.dumps({'Type': 'container', 'Action': action, 'timeNano': 1763085600000000000,
                                             'Actor': {'ID': WARDEN, 'Attributes': {'project': 'warden', 'name': 'w'}}}).encode() + b'\n')
                self.wfile.flush()
            time.sleep(30)
            return
        ident = self.path.split('/')[2]
        for full, inspect in self.containers.items():
            if full.startswith(ident) or inspect['Name'].lstrip('/') == ident:
                body = json.dumps(inspect).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_response(404)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        request, _ = super().get_request()
        return request, ('local', 0)


class CommandTest(Base):
    """The collector as `detector.py up` starts it, against a fake Docker API."""

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            DockerHandler.containers = {
                WARDEN: {'Id': WARDEN, 'Name': '/warden-smoke', 'Config': {'Labels': {'project': 'warden', 'warden.dev/run': 'r1'}}},
                OTHER: {'Id': OTHER, 'Name': '/theirs', 'Config': {'Labels': {'project': 'other'}}},
                'f' * 64: {'Id': 'f' * 64, 'Name': '/warden-detect-falco-host', 'Config': {'Labels': {}},
                           'State': {'Running': True, 'StartedAt': '2026-11-14T01:00:00Z', 'OOMKilled': False}, 'RestartCount': 0}}
            sock = os.path.join(d, 'docker.sock')
            server = UnixHTTPServer(sock, DockerHandler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            fifo, out = os.path.join(d, 'run', 'alerts.fifo'), os.path.join(d, 'out')
            os.mkdir(os.path.join(d, 'run'), 0o700)
            script = Path(collector.__file__)
            proc = subprocess.Popen([sys.executable, '-I', '-B', str(script), '--instance', 'host', '--fifo', fifo,
                                     '--out', out, '--falco-container', 'warden-detect-falco-host', '--docker-socket', sock,
                                     '--watch-docker', '--heartbeat', '0.2', '--resolve-deadline', '1'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if os.path.exists(fifo):
                        break
                    time.sleep(0.05)
                lines = [raw(event(WARDEN[:12])), raw(event(OTHER[:12], extra={'proc.cmdline': SECRET})),
                         raw(event('host', extra={'proc.cmdline': SECRET})), raw(metrics(7)),
                         raw(event('9' * 12, extra={'proc.cmdline': SECRET}))]
                for line in lines:
                    w = os.open(fifo, os.O_WRONLY)
                    os.write(w, line + b'\n')
                    os.close(w)
                time.sleep(2)
            finally:
                proc.send_signal(signal.SIGTERM)
                stdout, stderr = proc.communicate(timeout=20)
            self.assertEqual(proc.returncode, 0, stderr)
            o = Path(out)
            self.assertEqual(o.joinpath('alerts.jsonl').read_bytes(), lines[0] + b'\n')
            self.assertEqual(o.joinpath('health.jsonl').read_bytes(), lines[3] + b'\n')
            everything = b''.join(p.read_bytes() for p in o.rglob('*') if p.is_file()) + stdout + stderr
            self.assertNotIn(SECRET.encode(), everything)
            beats = [json.loads(x) for x in o.joinpath('heartbeats.jsonl').read_text().splitlines()]
            last = beats[-1]
            self.assertEqual(last['falco']['started_at'], '2026-11-14T01:00:00Z')
            self.assertEqual({k: last['counts'][k] for k in ('received', 'warden_alerts', 'dropped_other_container',
                                                              'dropped_host', 'dropped_unresolved', 'health_events')},
                             {'received': 5, 'warden_alerts': 1, 'dropped_other_container': 1, 'dropped_host': 1,
                              'dropped_unresolved': 1, 'health_events': 1})
            registry = [json.loads(x) for x in o.joinpath('registry.jsonl').read_text().splitlines()]
            self.assertEqual([r['event'] for r in registry], ['start', 'die'])
            self.assertEqual(last['counts']['collector_restarts'], 0)

            # SIGUSR1 writes a heartbeat at once (the seven-day start and stop
            # use it); a second start in the same directory counts a restart.
            proc = subprocess.Popen([sys.executable, '-I', '-B', str(script), '--instance', 'host', '--fifo', fifo,
                                     '--out', out, '--falco-container', 'warden-detect-falco-host', '--docker-socket', sock,
                                     '--heartbeat', '300'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                before = len(o.joinpath('heartbeats.jsonl').read_text().splitlines())
                for _ in range(100):
                    if len(o.joinpath('heartbeats.jsonl').read_text().splitlines()) > before:
                        break
                    time.sleep(0.05)
                started = len(o.joinpath('heartbeats.jsonl').read_text().splitlines())
                proc.send_signal(signal.SIGUSR1)
                for _ in range(100):
                    if len(o.joinpath('heartbeats.jsonl').read_text().splitlines()) > started:
                        break
                    time.sleep(0.05)
                flushed = len(o.joinpath('heartbeats.jsonl').read_text().splitlines())
            finally:
                proc.send_signal(signal.SIGTERM)
                proc.communicate(timeout=20)
            self.assertGreater(flushed, started, 'SIGUSR1 must write a heartbeat at once')
            beats = [json.loads(x) for x in o.joinpath('heartbeats.jsonl').read_text().splitlines()]
            self.assertEqual(beats[-1]['counts']['collector_restarts'], 1)


if __name__ == '__main__':
    unittest.main()
