"""detect/falco/detector.py against a fake host: what it starts, with which
limits and mounts, what it removes, and what the seven-day start would do.
Nothing here reaches Docker, systemd or the kernel.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

try:
    from detect.falco import detector
except ImportError:
    detector = None

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 14, 2, 0, 0, tzinfo=timezone.utc)
# The heartbeat the host collector writes on SIGUSR1 after the first counting snapshot.
FLUSHED = '2026-11-14T02:00:07.500000000Z'
MODULES = 'overlay 1 0 - Live 0x0\nveth 1 0 - Live 0x0\n'
SYSCTL = ('kernel.timer_migration = 1\nkernel.unprivileged_bpf_disabled = 1\nfs.file-nr = 1 0 9\n'
          'net.ipv4.conf.br-0123456789ab.forwarding = 1\nnet.ipv4.conf.all.forwarding = 1\nkernel.random.uuid = x\n')


class Result:
    def __init__(self, stdout='', returncode=0, stderr=''):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class FakeHost:
    def __init__(self, test):
        self.test, self.calls, self.containers, self.images, self.volumes = test, [], {}, set(), {}
        self.units, self.modules, self.sysctl, self.fail_run = set(), MODULES, SYSCTL, set()
        self.fail_unit = None
        self.images = {spec['image'] for spec in detector.INSTANCES.values()}

    def now(self):
        return NOW

    def sleep(self, seconds):
        pass

    def read(self, path):
        assert path == '/proc/modules', path
        return self.modules

    def run(self, argv, check=True, timeout=120, env=None, cwd=None):
        self.calls.append(('run', argv))
        if argv[0] == '/usr/sbin/sysctl':
            return Result(self.sysctl)
        return Result('')

    def systemd_run(self, args):
        self.calls.append(('systemd-run', args))
        unit = args[args.index('--unit') + 1]
        if unit == self.fail_unit:
            raise RuntimeError('systemd-run failed for ' + unit)
        self.units.add(unit + '.timer' if any(a.startswith('--on-active') for a in args) else unit)
        for flag in ('--fifo', '--audit-fifo'):
            if flag in args:
                fifo = Path(args[args.index(flag) + 1])
                if not fifo.exists():
                    os.mkfifo(fifo)
        return Result('')

    def systemctl(self, args, check=True):
        self.calls.append(('systemctl', args))
        if args[0] == 'is-active':
            return Result(returncode=0 if args[-1] in self.units else 3)
        if args[0] == 'stop':
            self.units.discard(args[1])
        if args[0] == 'kill' and args[-1] == detector.INSTANCES['host']['unit']:
            session = detector.load_state()['session']
            beats = detector.DATA / session / 'host' / 'heartbeats.jsonl'
            with open(beats, 'a') as out:
                out.write(json.dumps({'time': FLUSHED, 'falco': {'running': True}, 'counts': {}}) + '\n')
        if args[0] == 'kill' and args[-1] == detector.INSTANCES['k8saudit']['unit']:
            session = detector.load_state()['session']
            beats = detector.DATA / session / 'k8saudit' / 'heartbeats.jsonl'
            with open(beats, 'a') as out:
                out.write(json.dumps({'time': FLUSHED, 'falco': {'running': True}, 'counts': {},
                                      'feed': {'alive': True, 'fifo_open': True}}) + '\n')
        return Result('')

    def docker(self, args, check=True, timeout=120):
        self.calls.append(('docker', args))
        def fail(msg='Error: No such object'):
            if check:
                raise RuntimeError(msg)
            return Result('', 1, msg)
        if args[0] == 'image' and args[1] == 'inspect':
            image = args[-1]
            return Result(image + '\n') if image in self.images else fail()
        if args[0] == 'load':
            archive = Path(args[-1]).name
            for spec in detector.INSTANCES.values():
                if spec['archive'] == archive:
                    self.images.add(spec['image'])
            return Result('Loaded image\n')
        if args[0] == 'image' and args[1] == 'rm':
            self.images.discard(args[-1])
            return Result('')
        if args[0] == 'container' and args[1] == 'inspect':
            c = self.containers.get(args[-1])
            return Result(json.dumps([c])) if c else fail()
        if args[0] == 'run':
            if 'run' in self.fail_run:
                return fail('docker run failed')
            name = args[args.index('--name') + 1]
            labels = dict(a.split('=', 1) for a in (args[i + 1] for i, x in enumerate(args) if x == '--label'))
            self.containers[name] = {'Id': name[-1] * 64, 'Config': {'Labels': labels},
                                     'State': {'Running': True, 'StartedAt': '2026-11-14T02:00:01Z'}}
            if name == detector.INSTANCES['host']['container']:
                session = labels['warden.detect/session']
                health = detector.DATA / session / 'host' / 'health.jsonl'
                health.write_text(json.dumps({'rule': 'Falco internal: metrics snapshot', 'time': '2026-11-14T02:00:06Z',
                                              'output_fields': {'scap.n_evts': 5000, 'scap.n_drops': 0}}) + '\n')
            if name == detector.INSTANCES['k8saudit']['container']:
                session = labels['warden.detect/session']
                health = detector.DATA / session / 'k8saudit' / 'health.jsonl'
                health.write_text(json.dumps({'rule': 'Falco internal: metrics snapshot', 'time': '2026-11-14T02:00:06Z',
                                              'source': 'internal', 'output_fields': {'falco.num_evts': 0}}) + '\n')
            return Result(name[-1] * 64 + '\n')
        if args[0] == 'logs':
            return Result("Opening 'syscall' source with gVisor. Configuration path: x\n"
                          "Opening 'k8s_audit' source with plugin 'k8saudit'\n")
        if args[0] == 'stop':
            self.containers[args[-1]]['State']['Running'] = False
            return Result('')
        if args[0] == 'rm':
            for name in [a for a in args[1:] if not a.startswith('-')]:
                del self.containers[name]
            return Result('')
        if args[0] == 'volume':
            if args[1] == 'inspect':
                v = self.volumes.get(args[-1])
                return Result(json.dumps([{'Labels': v}])) if v is not None else fail()
            if args[1] == 'create':
                self.volumes[args[-1]] = dict(a.split('=', 1) for a in (args[i + 1] for i, x in enumerate(args) if x == '--label'))
                return Result(args[-1])
            if args[1] == 'rm':
                del self.volumes[args[-1]]
                return Result(args[-1])
        if args[0] == 'ps':
            wants = [args[i + 1].split('=', 1)[1] for i, x in enumerate(args) if x == '--filter']
            def match(labels):
                return all(labels.get(w.split('=', 1)[0]) == w.split('=', 1)[1] if '=' in w else w in labels for w in wants)
            return Result('\n'.join(n for n, c in self.containers.items() if match(c['Config']['Labels'])))
        raise AssertionError(args)

    def of(self, kind):
        return [c[1] for c in self.calls if c[0] == kind]


class Base(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(detector, 'detect/falco/detector.py missing')
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        base = Path(self.dir.name)
        # Stand-ins for the restored archives and runsc, so the test needs no .tools.
        (base / 'tools').mkdir()
        for spec in detector.INSTANCES.values():
            (base / 'tools' / spec['archive']).write_bytes(b'')
        (base / 'runsc').write_bytes(b'')
        # Stand-ins for the k8saudit plugins and rules, pinned to their own
        # digests, and the kind audit lab's audit log.
        (base / 'k8saudit').mkdir()
        pins = {}
        for name in detector.K8SAUDIT_FILES:
            (base / 'k8saudit' / name).write_bytes(name.encode())
            pins[name] = detector.file_sha256(base / 'k8saudit' / name)
        (base / 'audit.log').write_bytes(b'')
        for name, value in (('DETECT', base), ('STATE', base / 'state'), ('RUNDIR', base / 'run'), ('DATA', base / 'data'),
                            ('TOOLS', base / 'tools'), ('RUNSC', base / 'runsc'), ('K8SAUDIT_TOOLS', base / 'k8saudit'),
                            ('K8SAUDIT_FILES', pins), ('KIND_AUDIT_LOG', base / 'audit.log')):
            patcher = mock.patch.object(detector, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.host = FakeHost(self)
        self.out = []

    def up(self):
        return detector.up(self.host, self.out.append)


def option(args, flag):
    return [args[i + 1] for i, x in enumerate(args) if x == flag]


class FalcoArgsTest(Base):
    def test_host_instance(self):
        args = detector.falco_args('host', 'S', 1000)
        for flag, value in (('--network', 'none'), ('--cpuset-cpus', '0-7,16-31'), ('--memory', str(1 << 30)),
                            ('--memory-swap', str(1 << 30)), ('--pids-limit', '512'), ('--log-driver', 'json-file'),
                            ('--restart', 'no'), ('--pull', 'never')):
            self.assertEqual(option(args, flag), [value], flag)
        self.assertEqual(option(args, '--log-opt'), ['max-size=10m', 'max-file=3'])
        self.assertIn('--privileged', args)
        self.assertIn('--read-only', args)
        self.assertEqual(args[-2:], [detector.INSTANCES['host']['image'], '/usr/bin/falco'])
        labels = option(args, '--label')
        self.assertIn('owner=warden-lab', labels)
        self.assertIn('warden.detect/role=falco', labels)
        self.assertFalse([x for x in labels if x.startswith('project=')], 'project=warden would stop the runc lab')
        mounts = option(args, '--mount')
        writable = [m for m in mounts if not m.endswith(',readonly')]
        self.assertEqual(writable, ['type=bind,src=%s,dst=/warden-detect-out' % (detector.RUNDIR / 'host')])
        self.assertIn('type=bind,src=/proc,dst=/host/proc,readonly', mounts)
        self.assertIn('type=bind,src=/var/run/docker.sock,dst=/host/var/run/docker.sock,readonly', mounts)
        self.assertFalse([m for m in mounts if 'dst=/host/etc' in m or 'src=/,' in m or 'src=/etc' in m])
        self.assertFalse([a for a in args if a in ('-p', '--publish', '--pid', '-v', '--volume', '--device')
                          or a.startswith(('--publish=', '--pid=', '--volume=', '--device='))])

    def test_gvisor_instance_has_no_privileges(self):
        args = detector.falco_args('gvisor', 'S', 1234)
        self.assertNotIn('--privileged', args)
        self.assertEqual(option(args, '--cap-drop'), ['ALL'])
        self.assertNotIn('--cap-add', args)
        self.assertEqual(option(args, '--security-opt'), ['no-new-privileges'])
        self.assertEqual(option(args, '--group-add'), ['1234'])
        self.assertEqual(option(args, '--network'), ['none'])
        self.assertEqual(option(args, '--cpuset-cpus'), ['0-7,16-31'])
        self.assertEqual(option(args, '--memory'), [str(512 << 20)])
        mounts = option(args, '--mount')
        self.assertIn('type=bind,src=%s,dst=/usr/local/bin/runsc,readonly' % detector.RUNSC, mounts)
        self.assertIn('type=volume,src=warden-detect-gvisor,dst=/warden-detect', mounts)
        self.assertFalse([m for m in mounts if 'docker.sock' in m or '/proc' in m])
        self.assertEqual(args[-2:], [detector.INSTANCES['gvisor']['image'], '/usr/bin/falco'])

    def test_k8saudit_instance_has_no_privileges_and_no_network(self):
        args = detector.falco_args('k8saudit', 'S', 1234)
        self.assertNotIn('--privileged', args)
        self.assertEqual(option(args, '--cap-drop'), ['ALL'])
        self.assertNotIn('--cap-add', args)
        self.assertEqual(option(args, '--security-opt'), ['no-new-privileges'])
        self.assertEqual(option(args, '--group-add'), ['1234'])
        self.assertEqual(option(args, '--network'), ['none'])
        self.assertEqual(option(args, '--cpuset-cpus'), ['0-7,16-31'])
        self.assertEqual(option(args, '--memory'), [str(512 << 20)])
        self.assertIn('--read-only', args)
        self.assertIn('/etc/falco/config.d:rw,nosuid,nodev,noexec,size=64k', option(args, '--tmpfs'),
                      'only Warden\'s two config files: not the image\'s container plugin')
        mounts = option(args, '--mount')
        self.assertIn('type=bind,src=%s,dst=/warden-plugins,readonly' % detector.K8SAUDIT_TOOLS, mounts)
        self.assertIn('type=bind,src=%s,dst=/etc/falco/config.d/91-warden-engine.yaml,readonly'
                      % (detector.CONFIG / 'falco-k8saudit.yaml'), mounts)
        writable = [m for m in mounts if not m.endswith(',readonly')]
        self.assertEqual(writable, ['type=bind,src=%s,dst=/warden-detect-out' % (detector.RUNDIR / 'k8saudit')])
        self.assertFalse([m for m in mounts if 'docker.sock' in m or '/proc' in m or 'kind-warden-lab' in m])
        self.assertEqual(args[-6:], [detector.INSTANCES['k8saudit']['image'], '/usr/bin/falco', '--enable-source', 'k8s_audit',
                                     '-r', '/warden-plugins/k8s_audit_rules.yaml'])
        self.assertEqual(detector.INSTANCES['k8saudit']['image'], detector.INSTANCES['host']['image'])

    def test_k8saudit_collector_unit(self):
        unit = detector.collector_args('k8saudit', 'S', 1000)
        argv = unit[unit.index('--') + 1:]
        self.assertEqual(argv[:7], ['/usr/bin/taskset', '-c', '0-7,16-31', '/usr/bin/python3', '-I', '-B',
                                    str(detector.CONFIG / 'audit_collector.py')])
        self.assertEqual(option(argv, '--audit-log'), [str(detector.KIND_AUDIT_LOG)])
        self.assertEqual(option(argv, '--audit-fifo'), [str(detector.RUNDIR / 'k8saudit' / 'audit.fifo')])
        self.assertEqual(option(argv, '--fifo'), [str(detector.RUNDIR / 'k8saudit' / 'alerts.fifo')])
        self.assertEqual(option(argv, '--fifo-gid'), ['1000'])
        self.assertEqual(option(argv, '--out'), [str(detector.DATA / 'S' / 'k8saudit')])
        self.assertEqual(option(unit, '--unit'), ['warden-detect-collector-k8saudit'])
        self.assertIn('--property=Restart=on-failure', unit[:unit.index('--')])

    def test_collector_units(self):
        host = detector.collector_args('host', 'S', 1000)
        argv = host[host.index('--') + 1:]
        self.assertEqual(argv[:6], ['/usr/bin/taskset', '-c', '0-7,16-31', '/usr/bin/python3', '-I', '-B'])
        self.assertIn('--watch-docker', argv)
        self.assertIn('--watch-k8s', argv, 'the host collector follows the lab pods for sandbox IDs and the pod rule')
        self.assertEqual(option(argv, '--cgroup-root'), ['/sys/fs/cgroup'])
        self.assertNotIn('--fifo-gid', argv)
        props = host[:host.index('--')]
        self.assertIn('--property=Restart=on-failure', props)
        self.assertIn('--property=RestartSec=2s', props)
        gv = detector.collector_args('gvisor', 'S', 1000)
        self.assertIn('--watch-k8s', gv)
        self.assertEqual(option(gv, '--fifo-gid'), ['1000'])
        self.assertEqual(option(gv, '--unit'), ['warden-detect-collector-gvisor'])


class ConfigTest(Base):
    def text(self, name):
        return (ROOT / 'detect/falco' / name).read_text()

    def test_only_the_fifo_receives_alerts(self):
        common = self.text('falco-common.yaml')
        for section in ('stdout_output', 'syslog_output', 'http_output', 'program_output', 'webserver', 'capture'):
            self.assertRegex(common, r'(?m)^%s:\n  enabled: false$' % section)
        self.assertRegex(common, r'(?m)^file_output:\n  enabled: true\n  keep_alive: false\n  filename: /warden-detect-out/alerts.fifo$')
        for line in ('json_output: true', 'log_syslog: false', 'watch_config_files: false', '  rules_counters_enabled: false',
                     '  libbpf_stats_enabled: false', '  output_rule: true', '  enabled: true\n  interval: 60s'):
            self.assertIn(line, common)
        self.assertNotRegex(common, r'(?m)^(rules_files|rules|load_plugins|append_output):', 'stock rules must stay as shipped')
        self.assertNotIn('grpc', common, 'Falco 0.45.2 has no gRPC settings')

    def test_engines(self):
        self.assertIn('kind: modern_ebpf', self.text('falco-host.yaml'))
        gv = self.text('falco-gvisor.yaml')
        self.assertIn('kind: gvisor', gv)
        self.assertIn('config: /etc/warden-detect/gvisor-pod-init.json', gv)
        pod_init = json.loads(self.text('gvisor-pod-init.json'))
        sink = pod_init['trace_session']['sinks'][0]
        self.assertEqual(sink['config']['endpoint'], '/warden-detect/gvisor.sock')

    def test_k8saudit_engine(self):
        text = self.text('falco-k8saudit.yaml')
        for line in ('  kind: nodriver', 'load_plugins: [k8saudit, json]', '    library_path: /warden-plugins/libk8saudit.so',
                     '    library_path: /warden-plugins/libjson.so', '    open_params: /warden-detect-out/audit.fifo',
                     '      useAsync: false', 'plugins_hostinfo: false'):
            self.assertIn(line, text)
        self.assertNotRegex(text, r'(?m)^(rules_files|rules):', 'the rules file is given with -r and is stock')
        self.assertNotIn('extra_output', text, 'the stock output text stays as it is')
        from detect.report import audit_alert_import
        appended = re.findall(r'(?m)^      - (\S+)$', text.split('append_output:')[1])
        self.assertEqual(appended, ['ka.target.namespace', *audit_alert_import.LABEL_FIELDS, 'ka.auditid', 'ka.useragent'])
        self.assertEqual(audit_alert_import.NAMESPACE_FIELD, 'ka.target.namespace')

    def test_audit_policy_keeps_credentials_out_of_the_log(self):
        policy = self.text('k8s-audit-policy.yaml')
        self.assertIn('omitStages:\n  - RequestReceived', policy)
        metadata = policy.split('level: Metadata')[1].split('- level:')[0]
        for resource in ('secrets', 'configmaps', 'serviceaccounts/token'):
            self.assertIn(resource, metadata)
        self.assertIn('authentication.k8s.io', metadata)
        self.assertIn('certificates.k8s.io', metadata)
        self.assertNotIn('RequestResponse', policy, 'no response bodies: a token request\'s response is the token')
        self.assertTrue(policy.rstrip().endswith('- level: Request'), 'the catch-all keeps request bodies for the stock rules')

    def test_pins_match_restore_tools(self):
        text = (ROOT / 'scripts/restore-tools.sh').read_text()
        pinned = dict(re.findall(r'^\s+(falco-[0-9.]+)=(\S+)$', text, re.M))
        for spec in detector.INSTANCES.values():
            self.assertEqual(pinned.get(spec['archive'][:-len('.oci.tar')]), spec['ref'], spec['archive'])
        self.assertIn('K8SAUDIT_VERSION=0.18.0', text)
        self.assertIn('FALCO_JSON_VERSION=0.7.4', text)
        self.assertIn('K8SAUDIT_RULES_COMMIT=43ec9491a5bf25140868a182734a022625eeb9dd', text)
        self.assertEqual(sorted(detector.K8SAUDIT_FILES), ['k8s_audit_rules.yaml', 'libjson.so', 'libk8saudit.so'])


class LifecycleTest(Base):
    def test_up_starts_collectors_before_falco_and_records_the_host(self):
        self.host.images = set()
        state = self.up()
        kinds = [c[0] + (':' + c[1][0] if c[0] == 'docker' else '') for c in self.host.calls]
        first_run = kinds.index('docker:run')
        self.assertLess(max(i for i, k in enumerate(kinds) if k == 'systemd-run'), first_run)
        loads = [c for c in self.host.of('docker') if c[0] == 'load']
        self.assertEqual([Path(c[-1]).name for c in loads], ['falco-0.45.2.oci.tar'])
        self.assertTrue(state['up'])
        self.assertEqual(state['instances'], ['host'])
        self.assertEqual(list(self.host.containers), ['warden-detect-falco-host'])
        self.assertEqual(self.host.units, {'warden-detect-collector-host'})
        self.assertEqual(self.host.volumes, {}, 'no gVisor-engine volume by default')
        before = json.loads((detector.STATE / ('host-before-%s.json' % state['session'])).read_text())
        self.assertEqual(before['modules'], ['overlay', 'veth'])
        self.assertNotIn('net.ipv4.conf.br-0123456789ab.forwarding', before['sysctls'])
        self.assertIn('net.ipv4.conf.all.forwarding', before['sysctls'])
        self.assertNotIn('kernel.random.uuid', before['sysctls'])
        self.assertEqual(oct(os.stat(detector.DATA / state['session'] / 'host').st_mode & 0o777), '0o700')

    def test_the_gvisor_engine_instance_is_opt_in(self):
        state = detector.up(self.host, self.out.append, engines=('host', 'gvisor'))
        self.assertEqual(state['instances'], ['host', 'gvisor'])
        self.assertEqual(sorted(self.host.containers), ['warden-detect-falco-gvisor', 'warden-detect-falco-host'])
        self.assertEqual(self.host.volumes['warden-detect-gvisor'], detector.LABELS)
        self.assertEqual(oct(os.stat(detector.RUNDIR / 'gvisor').st_mode & 0o777), '0o710')
        detector.down(self.host, self.out.append)
        self.assertEqual((self.host.containers, self.host.volumes), ({}, {}))

    def test_the_k8saudit_instance_is_opt_in(self):
        state = detector.up(self.host, self.out.append, engines=('host', 'k8saudit'))
        self.assertEqual(state['instances'], ['host', 'k8saudit'])
        self.assertEqual(sorted(self.host.containers), ['warden-detect-falco-host', 'warden-detect-falco-k8saudit'])
        self.assertEqual(self.host.units, {'warden-detect-collector-host', 'warden-detect-collector-k8saudit'})
        self.assertEqual(oct(os.stat(detector.RUNDIR / 'k8saudit').st_mode & 0o777), '0o710')
        self.assertTrue((detector.RUNDIR / 'k8saudit' / 'audit.fifo').exists())
        self.assertEqual(detector.audit_ready_point(self.host, state['session']), FLUSHED)
        detector.down(self.host, self.out.append)
        self.assertEqual((self.host.containers, self.host.units), ({}, set()))
        self.assertTrue((detector.DATA / state['session'] / 'k8saudit' / 'falco.log').exists())
        detector.purge(self.host, self.out.append)
        self.assertFalse(detector.RUNDIR.exists())

    def test_k8saudit_up_refuses_unpinned_plugins_or_no_audit_lab(self):
        (detector.K8SAUDIT_TOOLS / 'libk8saudit.so').write_bytes(b'something else')
        with self.assertRaisesRegex(RuntimeError, 'not the pinned file'):
            detector.up(self.host, self.out.append, engines=('host', 'k8saudit'))
        (detector.K8SAUDIT_TOOLS / 'libk8saudit.so').write_bytes(b'libk8saudit.so')
        detector.KIND_AUDIT_LOG.unlink()
        with self.assertRaisesRegex(RuntimeError, 'kind audit lab'):
            detector.up(self.host, self.out.append, engines=('host', 'k8saudit'))
        self.assertEqual([c for c in self.host.of('docker') if c[0] == 'run'], [])
        self.assertEqual(self.host.of('systemd-run'), [])

    def test_up_refuses_an_image_that_is_not_the_pinned_one(self):
        self.host.images = set()
        real = self.host.docker
        def docker(args, check=True, timeout=120):
            if args[0] == 'load':
                self.host.calls.append(('docker', args))
                return Result('')
            return real(args, check, timeout)
        self.host.docker = docker
        with self.assertRaisesRegex(RuntimeError, 'not the pinned'):
            self.up()
        self.assertEqual([c for c in self.host.of('docker') if c[0] == 'run'], [])

    def test_up_refuses_when_already_up_or_a_container_exists(self):
        self.up()
        with self.assertRaisesRegex(RuntimeError, 'already up'):
            self.up()
        detector.save_state({'up': False})
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.up()

    def test_failed_up_leaves_nothing_running(self):
        self.host.fail_run.add('run')
        with self.assertRaises(RuntimeError):
            self.up()
        self.assertEqual(self.host.units, set())
        self.assertFalse(detector.load_state()['up'])

    def test_down_removes_only_the_detectors_containers_and_reports_the_host(self):
        state = self.up()
        self.host.modules += 'xt_bpf 1 0 - Live 0x0\n'
        self.host.sysctl = self.host.sysctl.replace('fs.file-nr = 1 0 9', 'fs.file-nr = 5 0 9').replace(
            'kernel.timer_migration = 1', 'kernel.timer_migration = 0')
        report = detector.down(self.host, self.out.append)
        self.assertEqual(self.host.containers, {})
        self.assertEqual(self.host.units, set())
        self.assertEqual(report['modules_added'], ['xt_bpf'])
        self.assertEqual(report['sysctls_changed'], {'kernel.timer_migration': ['1', '0']})
        self.assertEqual(report['volatile_sysctls_changed'], ['fs.file-nr'])
        self.assertNotIn('warden-detect-gvisor', self.host.volumes)
        self.assertTrue((detector.DATA / state['session'] / 'host' / 'falco.log').exists())
        self.assertFalse(detector.load_state()['up'])

    def test_down_leaves_a_same_named_container_that_is_not_the_detectors(self):
        name = detector.INSTANCES['host']['container']
        self.host.containers[name] = {'Id': 'x' * 64, 'Config': {'Labels': {'project': 'someone'}}, 'State': {'Running': True}}
        with self.assertRaisesRegex(RuntimeError, 'not the detector'):
            detector.down(self.host, self.out.append)
        self.assertIn(name, self.host.containers)
        self.assertFalse([c for c in self.host.of('docker') if c[0] in ('stop', 'rm')])

    def test_purge_removes_images_volume_and_fifos(self):
        detector.up(self.host, self.out.append, engines=('host', 'gvisor'))
        detector.purge(self.host, self.out.append)
        self.assertEqual(self.host.images, set())
        self.assertEqual(self.host.volumes, {})
        self.assertFalse(detector.RUNDIR.exists())


def runc_outer(root, session='s1'):
    return {'Id': 'v' * 64, 'Config': {'Labels': {'project': 'warden', 'owner': 'warden-lab', 'session': session}},
            'State': {'Running': True},
            'Mounts': [{'Type': 'bind', 'Source': '%s/.cache/warden-lab/docker-%s' % (root, session),
                        'Destination': '/opt/warden/.cache/warden-lab'}]}


def node(root_id):
    return {'Id': 'k' * 64, 'Config': {'Labels': {'project': 'warden', 'warden.lab/root': root_id}}, 'State': {'Running': True}}


class CleanLabsTest(Base):
    def lab_downs(self):
        return [c for c in self.host.of('run') if c[-1] == 'down' and c[-2].endswith('k3s_gvisor_lab.sh')]

    def test_this_worktrees_labs_are_taken_down(self):
        self.host.containers['vibrant_x'] = runc_outer(detector.ROOT)
        self.host.containers['warden-k3s-gvisor'] = node(detector.ROOT_ID)
        detector.clean_labs(self.host, out=self.out.append)
        self.assertNotIn('vibrant_x', self.host.containers)
        self.assertEqual(len(self.lab_downs()), 1)

    def test_another_worktrees_labs_are_left_alone(self):
        self.host.containers['vibrant_x'] = runc_outer('/home/someone/Desktop/Warden')
        self.host.containers['warden-k3s-gvisor'] = node('0123456789abcdef')
        detector.clean_labs(self.host, out=self.out.append)
        self.assertIn('vibrant_x', self.host.containers)
        self.assertEqual(self.lab_downs(), [])
        self.assertFalse([c for c in self.host.of('docker') if c[0] == 'rm'])
        self.assertTrue(any('not this worktree' in line for line in self.out), self.out)

    def test_root_id_is_what_the_lab_script_labels_its_node_with(self):
        import hashlib
        self.assertEqual(detector.ROOT_ID, hashlib.sha256(str(detector.ROOT.resolve()).encode()).hexdigest()[:16])


class SevenDayTest(Base):
    runc_outer = staticmethod(runc_outer)
    node = staticmethod(node)

    def test_without_the_confirmation_it_is_a_dry_run(self):
        for confirm in (None, '', 'yes', 'seven-days'):
            with self.subTest(confirm=confirm):
                self.out.clear()
                self.assertIsNone(detector.seven_day_start(self.host, confirm=confirm, out=self.out.append))
                self.assertEqual(self.host.of('systemd-run'), [])
                self.assertFalse([c for c in self.host.of('docker') if c[0] in ('run', 'load', 'volume')])
                self.assertFalse([c for c in self.host.of('run') if c[-1].endswith('build-runtime-lab.sh')])
                text = '\n'.join(self.out)
                self.assertIn('dry run', text)
                self.assertIn('--on-unit-active=3600', text)
                self.assertIn('--on-active=%d' % (7 * 86400 + 900), text)
                self.assertIn('benign.py', text)
                self.assertIn('CONFIRM=seven-day', text)

    def test_refuses_while_warden_labs_or_the_detector_run(self):
        self.host.containers['warden-k3s-gvisor'] = {'Config': {'Labels': {'project': 'warden'}}, 'State': {'Running': True}}
        with self.assertRaisesRegex(RuntimeError, 'Warden lab containers'):
            detector.seven_day_start(self.host, confirm='seven-day', out=self.out.append)
        del self.host.containers['warden-k3s-gvisor']
        detector.save_state({'up': True, 'session': 'x'})
        with self.assertRaisesRegex(RuntimeError, 'is up'):
            detector.seven_day_start(self.host, confirm='seven-day', out=self.out.append)

    def test_refuses_while_the_kind_audit_lab_has_a_node(self):
        for name, labels in (('warden-lab-control-plane', {'io.x-k8s.kind.cluster': 'warden-lab'}),
                             ('warden-lab-worker2', {}), ('renamed-node', {'io.x-k8s.kind.cluster': 'warden-lab'})):
            with self.subTest(name=name):
                self.host.containers = {name: {'Config': {'Labels': labels}, 'State': {'Running': False}}}
                with self.assertRaisesRegex(RuntimeError, 'kind audit lab nodes exist'):
                    detector.seven_day_start(self.host, confirm='seven-day', out=self.out.append)
                with self.assertRaisesRegex(RuntimeError, 'kind audit lab nodes exist'):
                    detector.seven_day_start(self.host, confirm=None, out=self.out.append)
        self.host.containers = {'materialflow-control-plane': {'Config': {'Labels': {'io.x-k8s.kind.cluster': 'materialflow'}},
                                                               'State': {'Running': True}}}
        self.assertIsNone(detector.seven_day_start(self.host, confirm=None, out=self.out.append), "another project's kind cluster")
        self.assertEqual(self.host.of('systemd-run'), [])

    def test_start_begins_at_the_first_healthy_point_and_arms_both_timers(self):
        plan = detector.seven_day_start(self.host, confirm='seven-day', out=self.out.append)
        runs = [c for c in self.host.of('run')]
        self.assertTrue(any(c[-1].endswith('build-runtime-lab.sh') for c in runs))
        units = [c[c.index('--unit') + 1] for c in self.host.of('systemd-run')]
        self.assertEqual(units, ['warden-detect-collector-host', 'warden-detect-benign', 'warden-detect-seven-day-stop'])
        self.assertIn(['kill', '--signal=SIGUSR1', 'warden-detect-collector-host'], self.host.of('systemctl'))
        self.assertEqual((plan['window_start'], plan['window_end']), (FLUSHED, '2026-11-21T02:00:07.500000000Z'))
        self.assertEqual(plan['sources'], ['falco-host'])
        benign = self.host.of('systemd-run')[1]
        argv = benign[benign.index('--') + 1:]
        self.assertEqual(argv[:3], ['/usr/bin/taskset', '-c', '0-7,16-31'])
        self.assertEqual(option(argv, '--session'), [plan['session']])

    def test_both_timers_carry_the_cpuset_and_the_plan_records_it(self):
        plan = detector.seven_day_start(self.host, confirm='seven-day', out=self.out.append)
        self.assertEqual(plan['cpuset'], '0-7,16-31')
        for unit in self.host.of('systemd-run')[1:]:
            self.assertIn('--setenv=WARDEN_CPUSET=0-7,16-31', unit[:unit.index('--')])

    def test_warden_cpuset_overrides_the_cpus_and_is_checked(self):
        import subprocess
        import sys
        code = 'import sys; sys.path.insert(0, %r); import detector; print(detector.CPUSET)' % str(Path(detector.__file__).parent)
        env = {'PATH': '/usr/bin:/bin', 'WARDEN_CPUSET': '0-7'}
        got = subprocess.run([sys.executable, '-I', '-B', '-c', code], env=env, capture_output=True, text=True)
        self.assertEqual((got.returncode, got.stdout.strip()), (0, '0-7'))
        env['WARDEN_CPUSET'] = '0-7;rm'
        bad = subprocess.run([sys.executable, '-I', '-B', '-c', code], env=env, capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('WARDEN_CPUSET must be a CPU list', bad.stderr)

    def test_a_failed_second_timer_undoes_the_first_and_the_detector(self):
        self.host.fail_unit = 'warden-detect-seven-day-stop'
        with self.assertRaisesRegex(RuntimeError, 'systemd-run failed'):
            detector.seven_day_start(self.host, confirm='seven-day', out=self.out.append)
        self.assertIn(['stop', 'warden-detect-benign.timer'], self.host.of('systemctl'))
        self.assertEqual(self.host.units, set())
        self.assertEqual(self.host.containers, {})
        self.assertFalse(detector.load_state()['up'])

    def test_stop_writes_the_records_and_takes_the_labs_down_even_when_down_fails(self):
        plan = detector.seven_day_start(self.host, confirm='seven-day', out=self.out.append)
        # A foreign container under the detector's name makes down fail; a
        # benign run's lab containers are still there.
        self.host.containers['warden-detect-falco-host']['Config']['Labels'] = {'project': 'someone'}
        self.host.containers['vibrant_x'] = self.runc_outer(detector.ROOT)
        self.host.containers['warden-k3s-gvisor'] = self.node(detector.ROOT_ID)
        with self.assertRaisesRegex(RuntimeError, 'not the detector'):
            detector.seven_day_stop(self.host, out=self.out.append)
        result = detector.DATA / plan['session'] / 'seven-day'
        self.assertTrue((result / 'coverage.jsonl').exists())
        self.assertTrue((result / 'review-groups.jsonl').exists())
        self.assertTrue((result / 'review-map-template.jsonl').exists())
        self.assertIn(['kill', '--signal=SIGUSR1', 'warden-detect-collector-host'], self.host.of('systemctl'))
        self.assertTrue(any(c[-1] == 'down' and c[-2].endswith('k3s_gvisor_lab.sh') for c in self.host.of('run')))
        self.assertNotIn('vibrant_x', self.host.containers)
        observation = [c for c in self.host.of('run') if 'detect.report.observation' in c]
        self.assertEqual(len(observation), 1)
        self.assertEqual(option(observation[0], '--source'), ['falco-host'])
        self.assertEqual((option(observation[0], '--start'), option(observation[0], '--end')),
                         ([plan['window_start']], [plan['window_end']]))


if __name__ == '__main__':
    unittest.main()
