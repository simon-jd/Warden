#!/usr/bin/env python3
"""Boundary tests: real wrapper decisions, fake only the external Docker CLI."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.find_spec('runtime_lab_docker')
if SPEC:
    import runtime_lab_docker as lab
import azure_guard


@contextlib.contextmanager
def project_root():
    """Run the real wrapper and the real disk/memory guard against an empty
    temporary project, so results do not depend on this checkout's size or on
    charges left in the real .cache/warden-lab."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for directory in (root / '.cache', root / '.cache/warden-lab'):
            directory.mkdir()
            directory.chmod(0o700)
        # A real checkout is never empty; one allocated block keeps the
        # guard's ">" boundary meaningful.
        (root / 'go.mod').write_text('module warden\n')
        def guard(additional, memory):
            with contextlib.redirect_stdout(io.StringIO()):
                azure_guard.preflight(additional, memory, 0)
        with patch.object(lab, 'ROOT', root), patch.object(azure_guard, 'ROOT', root), patch.object(lab, 'preflight', guard):
            yield root

CID = 'c' * 64
IMAGE = 'sha256:' + 'a' * 64
LABELS = {'project': 'warden', 'owner': 'warden-lab', 'session': 'test-session', 'ttl': '2026-10-24T00:00:00Z'}

class FakeDocker:
    def __init__(self, exit_code=0, interrupted=False, unowned=False, error=False):
        self.calls = []
        self.exists = False
        self.exit_code, self.interrupted, self.unowned, self.error = exit_code, interrupted, unowned, error
    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ['container', 'create']:
            self.exists = True
            return CID + '\n'
        if args[:2] == ['container', 'inspect']:
            if self.error:
                raise RuntimeError('daemon disconnected')
            return json.dumps([{'Id': CID, 'Config': {'Labels': {} if self.unowned else LABELS}}])
        if args[:2] == ['container', 'start']:
            if self.interrupted:
                raise KeyboardInterrupt('SIGTERM')
            return ''
        if args[:2] == ['container', 'wait']:
            return str(self.exit_code)
        if args[:2] == ['container', 'logs']:
            return 'fixed conformance output\n'
        if args[:2] == ['container', 'stop']:
            return CID
        if args[:2] == ['container', 'rm']:
            self.exists = False
            return CID
        if args[:2] == ['container', 'ls']:
            return CID if self.exists else ''
        raise AssertionError(args)

class DockerLabTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(SPEC, 'isolated Docker lab wrapper is missing')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.stdout = io.StringIO()
        capture = contextlib.redirect_stdout(self.stdout)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)
        # Execute the actual guard but retain its expected refusal in the test.
        run = subprocess.run
        def captured_run(*args, **kwargs):
            return run(*args, **{**kwargs, 'capture_output': True})
        guard_capture = patch('runtime_lab_docker.subprocess.run', captured_run)
        guard_capture.start()
        self.addCleanup(guard_capture.stop)

    def test_only_session_bind_and_fixed_command_with_private_namespaces_and_limits(self):
        # Catch host namespace/mount exposure or weakened outer limits.
        fake = FakeDocker()
        lab.execute(IMAGE, self.output, LABELS, 'run', fake)
        args = fake.calls[0]
        for option in ['--network=none', '--cgroupns=private', '--ipc=private', '--memory=4000000000', '--memory-swap=4000000000', '--pids-limit=512', '--cpus=2', '--read-only', '--cap-drop=ALL']:
            self.assertIn(option, args)
        self.assertFalse(any(x.startswith(('--pid=', '--privileged', '--device', '--gpus', '--volume', '--cgroup-parent')) for x in args))
        mounts = [args[i+1] for i, x in enumerate(args) if x == '--mount']
        self.assertEqual(mounts, [f'type=bind,src={self.output},dst=/opt/warden/.cache/warden-lab'])
        self.assertEqual(args[-2:], [IMAGE, 'run'])
        for key, value in LABELS.items():
            self.assertIn(f'{key}={value}', args)
        self.assertIn('--log-opt=max-size=10m', args)
        self.assertIn('--log-opt=max-file=2', args)
        self.assertIn('--cap-add=NET_ADMIN', args)  # runc initializes only the private guest lo device
        self.assertNotIn('--cap-add=NET_RAW', args)

    def egress_setup(self, root, **network):
        directory = root / '.cache' / 'egress-proxy'
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        cfg = {'network': 'warden-egress-0a1b2c3d-sbx', 'ip': '10.231.7.3', 'dir': directory, 'proxy': '10.231.7.2',
               'origin': '10.231.9.5', 'prefix': '10.231.7.0/24'}
        inspect = {'Name': cfg['network'], 'Internal': True, 'Labels': {'warden.test': 'task10'},
                   'IPAM': {'Config': [{'Subnet': '10.231.7.0/24'}]}, **network}
        fake = FakeDocker()
        def cli(args, **kwargs):
            if args[:2] == ['network', 'inspect']:
                fake.calls.append(args)
                return json.dumps([inspect])
            return fake(args, **kwargs)
        return cfg, fake, cli

    def test_egress_mode_joins_only_the_owned_internal_lab_network(self):
        # The runc egress lab needs a real interface on the proxy network; it
        # must be the test's own --internal network, never a host or shared one.
        with project_root() as root:
            cfg, fake, cli = self.egress_setup(root)
            lab.execute(IMAGE, self.output, LABELS, 'egress', cli, egress=cfg)
        args = next(c for c in fake.calls if c[:2] == ['container', 'create'])
        self.assertIn('--network=warden-egress-0a1b2c3d-sbx', args)
        self.assertIn('--ip=10.231.7.3', args)
        self.assertNotIn('--network=none', args)
        mounts = [args[i+1] for i, x in enumerate(args) if x == '--mount']
        self.assertEqual(mounts, [f'type=bind,src={self.output},dst=/opt/warden/.cache/warden-lab',
                                  f'type=bind,src={cfg["dir"]},dst=/opt/warden/egress'])
        envs = [args[i+1] for i, x in enumerate(args) if x == '--env']
        for value in ['WARDEN_EGRESS_DIR=/opt/warden/egress', 'WARDEN_EGRESS_PREFIX=10.231.7.0/24',
                      'WARDEN_EGRESS_PROXY=10.231.7.2', 'WARDEN_EGRESS_ORIGIN_BLOCKED=10.231.9.5']:
            self.assertIn(value, envs)
        for option in ['--cgroupns=private', '--memory=4000000000', '--pids-limit=512', '--read-only', '--cap-drop=ALL', '--cap-add=NET_ADMIN']:
            self.assertIn(option, args)
        self.assertNotIn('--cap-add=NET_RAW', args)
        # runc init is non-dumpable once it joins a namespace by path; its
        # parent then needs SYS_PTRACE to open /proc/<pid>/ns/mnt.
        self.assertIn('--cap-add=SYS_PTRACE', args)
        self.assertEqual(args[-2:], [IMAGE, 'egress'])
        # Without a database target the lab still has only the sandbox NIC.
        self.assertFalse(any(c[:2] == ['network', 'connect'] for c in fake.calls))
        run = FakeDocker()
        lab.execute(IMAGE, self.output, LABELS, 'run', run)
        self.assertNotIn('--cap-add=SYS_PTRACE', run.calls[0])

    def test_egress_mode_rejects_unowned_network_or_paths_before_create(self):
        bad = [
            ({'Internal': False}, {}),
            ({'Labels': {}}, {}),
            ({'IPAM': {'Config': [{'Subnet': '10.9.9.0/24'}]}}, {}),
            ({}, {'network': 'bridge'}),
            ({}, {'ip': '10.231.8.3'}),
            ({}, {'proxy': '10.231.7.3'}),
            ({}, {'origin': 'not-an-ip'}),
            ({}, {'dir': Path('/etc')}),
        ]
        for network, override in bad:
            with self.subTest(network=network, override=override), project_root() as root:
                cfg, fake, cli = self.egress_setup(root, **network)
                cfg.update(override)
                with self.assertRaises((ValueError, RuntimeError, OSError)):
                    lab.execute(IMAGE, self.output, LABELS, 'egress', cli, egress=cfg)
                self.assertFalse(any(c[:2] == ['container', 'create'] for c in fake.calls))
        with project_root() as root:
            cfg, fake, cli = self.egress_setup(root)
            alias = root / '.cache' / 'alias'
            alias.symlink_to(cfg['dir'])
            cfg['dir'] = alias
            with self.assertRaises((ValueError, OSError)):
                lab.execute(IMAGE, self.output, LABELS, 'egress', cli, egress=cfg)
        with self.assertRaises(ValueError):
            lab.execute(IMAGE, self.output, LABELS, 'egress', FakeDocker())

    def test_egress_postgres_is_a_second_nic_and_not_the_ipvlan_parent(self):
        with project_root() as root:
            cfg, fake, cli = self.egress_setup(root)
            def bridged(args, **kwargs):
                if args[:2] == ['network', 'connect']:
                    fake.calls.append(args)
                    return ''
                return cli(args, **kwargs)
            pg = {'network': 'warden-pg-' + 'ab' * 16, 'ip': '10.44.0.2'}
            lab.execute(IMAGE, self.output, LABELS, 'egress', bridged, egress=cfg, pg=pg)
        create = next(c for c in fake.calls if c[:2] == ['container', 'create'])
        self.assertIn('--network=' + cfg['network'], create)
        self.assertIn('--ip=10.231.7.3', create)
        self.assertIn('WARDEN_EGRESS_POSTGRES_HOST=10.44.0.2', create)
        self.assertIn('WARDEN_API_PASSWORD', create)
        connect = next(c for c in fake.calls if c[:2] == ['network', 'connect'])
        self.assertEqual(connect, ['network', 'connect', pg['network'], CID])
        started = [c for c in fake.calls if c[:2] == ['container', 'start']]
        self.assertLess(fake.calls.index(connect), fake.calls.index(started[0]))
        with project_root() as root:
            cfg, fake, cli = self.egress_setup(root)
            with self.assertRaises(ValueError):
                lab.execute(IMAGE, self.output, LABELS, 'egress', cli, egress=cfg, pg={'network': 'bridge', 'ip': '10.44.0.2'})
            self.assertFalse(any(c[:2] == ['container', 'create'] for c in fake.calls))

    def test_cpuset_pins_the_outer_container_only_when_asked(self):
        # WARDEN_LAB_CPUSET (as the gVisor lab's) keeps the lab off CPUs
        # another project times benchmarks on; unset, nothing changes.
        for env, want in (({}, []), ({'WARDEN_LAB_CPUSET': '0-7,16-31'}, ['--cpuset-cpus=0-7,16-31'])):
            with self.subTest(env=env), patch.dict(os.environ, env):
                if not env:
                    os.environ.pop('WARDEN_LAB_CPUSET', None)
                fake = FakeDocker()
                lab.execute(IMAGE, self.output, LABELS, 'run', fake)
                self.assertEqual([a for a in fake.calls[0] if a.startswith('--cpuset')], want)
        for bad in ('0-7;true', '0-7,', 'all', '0-7 16'):
            with self.subTest(bad=bad), patch.dict(os.environ, {'WARDEN_LAB_CPUSET': bad}):
                fake = FakeDocker()
                with self.assertRaises(ValueError):
                    lab.execute(IMAGE, self.output, LABELS, 'run', fake)
                self.assertEqual(fake.calls, [])

    def test_smoke_never_adds_capabilities_or_disables_security_profiles(self):
        fake = FakeDocker()
        lab.execute(IMAGE, self.output, LABELS, 'smoke', fake)
        args = fake.calls[0]
        self.assertFalse(any(x.startswith('--cap-add') or 'unconfined' in x for x in args))
        self.assertIn('--user=65534:65534', args)
        self.assertNotIn('--mount', args)

    def test_nonzero_exit_cleans_exact_owned_id(self):
        fake = FakeDocker(exit_code=19)
        with self.assertRaises(RuntimeError):
            lab.execute(IMAGE, self.output, LABELS, 'run', fake)
        self.assertIn(['container', 'rm', '--force', CID], fake.calls)
        self.assertFalse(fake.exists)
        self.assertIn(['container', 'logs', CID], fake.calls)
        self.assertIn('fixed conformance output', self.stdout.getvalue())

    def test_interrupt_cleans_exact_owned_id(self):
        fake = FakeDocker(interrupted=True)
        with self.assertRaises(KeyboardInterrupt):
            lab.execute(IMAGE, self.output, LABELS, 'run', fake)
        self.assertIn(['container', 'stop', '--time=20', CID], fake.calls)
        self.assertLess(fake.calls.index(['container', 'stop', '--time=20', CID]), fake.calls.index(['container', 'rm', '--force', CID]))
        self.assertIn(['container', 'rm', '--force', CID], fake.calls)

    def test_unowned_object_is_never_removed_or_started(self):
        fake = FakeDocker(unowned=True)
        with self.assertRaises(RuntimeError):
            lab.execute(IMAGE, self.output, LABELS, 'run', fake)
        self.assertFalse(any(x[:2] in (['container', 'rm'], ['container', 'start']) for x in fake.calls))

    def test_committed_create_with_lost_response_recovers_exact_owned_id(self):
        fake = FakeDocker()
        def lost_response(args, **kwargs):
            result = fake(args, **kwargs)
            if args[:2] == ['container', 'create']:
                raise RuntimeError('create response lost')
            return result
        with self.assertRaisesRegex(RuntimeError, 'create response lost'):
            lab.execute(IMAGE, self.output, LABELS, 'run', lost_response)
        self.assertIn(['container', 'rm', '--force', CID], fake.calls)

    def test_real_sigterm_reaches_owned_cleanup(self):
        fake = FakeDocker()
        original = signal.signal(signal.SIGTERM, lab.interrupted)
        def term(args, **kwargs):
            if args[:2] == ['container', 'start']:
                os.kill(os.getpid(), signal.SIGTERM)
            return fake(args, **kwargs)
        try:
            with self.assertRaises(KeyboardInterrupt):
                lab.execute(IMAGE, self.output, LABELS, 'run', term)
        finally:
            signal.signal(signal.SIGTERM, original)
        self.assertIn(['container', 'rm', '--force', CID], fake.calls)

    def test_local_cli_ignores_remote_docker_environment(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://unowned:2375', 'DOCKER_CONTEXT': 'unowned'}):
            with patch('runtime_lab_docker.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '[]')) as process:
                lab.docker(['container', 'ls'])
        argv = process.call_args.args[0]
        self.assertEqual(argv[:2], ['/usr/bin/docker', '--host=unix:///var/run/docker.sock'])
        self.assertNotIn('DOCKER_CONTEXT', process.call_args.kwargs['env'])
        self.assertNotIn('DOCKER_HOST', process.call_args.kwargs['env'])

    def test_unknown_inspection_error_is_not_absence_or_cleanup_success(self):
        fake = FakeDocker(error=True)
        with self.assertRaisesRegex(RuntimeError, 'daemon disconnected'):
            lab.execute(IMAGE, self.output, LABELS, 'run', fake)
        self.assertTrue(fake.exists)
        self.assertFalse(any(x[:2] == ['container', 'rm'] for x in fake.calls))

    def test_arbitrary_command_and_mount_syntax_injection_rejected(self):
        for mode, path in [('sh', self.output), ('run', self.output / 'x,dst=/etc')]:
            fake = FakeDocker()
            with self.assertRaises(ValueError):
                lab.execute(IMAGE, path, LABELS, mode, fake)
            self.assertEqual(fake.calls, [])

    def test_artifact_symlink_and_writable_owner_rejected(self):
        path = self.output / 'artifact'
        path.write_text('probe')
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            lab.read_trusted(path, os.getuid())
        path.chmod(0o600)
        alias = self.output / 'alias'
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            lab.read_trusted(alias, os.getuid())
        self.assertEqual(lab.read_trusted(path, os.getuid()), b'probe')

    def test_failed_image_import_cleans_committed_owned_image(self):
        self.assertTrue(hasattr(lab, 'image_session'), 'owned image lifecycle boundary is missing')
        exists = False
        calls = []
        def cli(args, **kwargs):
            nonlocal exists
            calls.append(args)
            if args[:2] == ['image', 'import']:
                exists = True
                raise RuntimeError('import response lost')
            if args[:2] == ['image', 'ls']:
                return IMAGE if exists and '--all' in args else ''
            if args[:2] == ['image', 'inspect']:
                return json.dumps([{'Id': IMAGE, 'Config': {'Labels': LABELS}}])
            if args[:2] == ['image', 'rm']:
                exists = False
                return IMAGE
            raise AssertionError(args)
        with self.assertRaisesRegex(RuntimeError, 'import response lost'):
            lab.image_session(self.output / 'archive.tar', self.output, LABELS, 'smoke', cli)
        self.assertIn(['image', 'rm', IMAGE], calls)
        self.assertFalse(exists)

    def test_malformed_import_response_recovers_id_instead_of_using_it_as_selector(self):
        exists = False
        calls = []
        def cli(args, **kwargs):
            nonlocal exists
            calls.append(args)
            if args[:2] == ['image', 'import']:
                exists = True
                return '--all'
            if args[:2] == ['image', 'ls']:
                return IMAGE if exists and '--all' in args else ''
            if args[:2] == ['image', 'inspect']:
                return json.dumps([{'Id': IMAGE, 'Config': {'Labels': LABELS}}])
            if args[:2] == ['image', 'rm']:
                exists = False
                return IMAGE
            raise AssertionError(args)
        with self.assertRaises(RuntimeError):
            lab.image_session(self.output / 'archive.tar', self.output, LABELS, 'smoke', cli)
        self.assertIn(['image', 'rm', IMAGE], calls)
        self.assertNotIn(['image', 'inspect', '--all'], calls)

    def test_removed_firecracker_scene_does_not_keep_its_five_gigabyte_reservation(self):
        # The 2026-10-24 scene was deleted with its charge file. A docker-*
        # directory that has no charge, and one whose 5 GB charge is released,
        # must not keep that reservation in the next preflight.
        stale = self.output / 'docker-firecracker-89c9296e79ce14c5dd30e0d5e4772f1d'
        stale.mkdir(mode=0o700)
        released = self.output / 'docker-firecracker-released'
        released.mkdir(mode=0o700)
        lab.record_charge(released, released=True, reserve=5000000000)
        self.assertEqual(lab.outstanding_bytes(self.output), 0)
        self.assertTrue((released / 'charge.json').is_file())
        self.assertFalse((stale / 'charge.json').exists())

    def test_failed_import_charges_accumulate_and_block_retries_at_guard(self):
        self.assertTrue(hasattr(lab, 'outstanding_bytes'), 'persistent failed-import charge is missing')
        def cli(args, **kwargs):
            if args[:2] == ['image', 'import']:
                raise RuntimeError('daemon import failed with unknown content allocation')
            if args[:2] == ['image', 'ls']:
                return ''
            raise AssertionError(args)
        # Seven failed imports (21 GB) plus the next 3 GB reservation exceed 24 GB.
        for i, expected in enumerate(range(3000000000, 21000000001, 3000000000)):
            session = self.output / ('docker-' + str(i))
            session.mkdir(mode=0o700)
            with self.assertRaises(RuntimeError):
                lab.image_session(session / 'archive.tar', session, LABELS, 'smoke', cli)
            self.assertEqual(lab.outstanding_bytes(self.output), expected)
        with project_root(), self.assertRaisesRegex(azure_guard.GuardError, 'Warden project disk'):
            lab.preflight(lab.outstanding_bytes(self.output) + 3000000000, 4000000000)

    def test_confirmed_image_cleanup_releases_charge_but_failed_removal_keeps_it(self):
        self.assertTrue(hasattr(lab, 'outstanding_bytes'), 'persistent failed-import charge is missing')
        for fails in (False, True):
            session = self.output / ('docker-' + str(fails))
            session.mkdir(mode=0o700)
            container = FakeDocker()
            exists = False
            def cli(args, **kwargs):
                nonlocal exists
                if args[:2] == ['image', 'import']:
                    exists = True
                    return IMAGE
                if args[:2] == ['image', 'inspect']:
                    return json.dumps([{'Id': IMAGE, 'Config': {'Labels': LABELS}}])
                if args[:2] == ['image', 'rm']:
                    if fails:
                        raise RuntimeError('remove failed')
                    exists = False
                    return IMAGE
                if args[:2] == ['image', 'ls']:
                    return IMAGE if exists and '--all' in args else ''
                return container(args, **kwargs)
            if fails:
                with self.assertRaisesRegex(RuntimeError, 'remove failed'):
                    lab.image_session(session / 'archive.tar', session, LABELS, 'smoke', cli)
            else:
                lab.image_session(session / 'archive.tar', session, LABELS, 'smoke', cli)
            self.assertEqual(lab.outstanding_bytes(self.output), 3000000000 if fails else 0)

    def test_untagged_image_remaining_after_remove_keeps_charge(self):
        for mode in ('smoke', 'api-smoke'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                container = FakeDocker()
                def cli(args, **kwargs):
                    if args[:2] == ['image', 'import']:
                        return IMAGE
                    if args[:2] == ['image', 'inspect']:
                        return json.dumps([{'Id': IMAGE, 'Config': {'Labels': LABELS}}])
                    if args[:2] == ['image', 'rm']:
                        return ''  # Simulate successful response with object still visible.
                    if args[:2] == ['image', 'ls']:
                        return IMAGE if '--all' in args else ''
                    return container(args, **kwargs)
                with self.assertRaises(RuntimeError):
                    lab.image_session(output / 'archive.tar', output, LABELS, mode, cli)
                self.assertFalse(json.loads((output / 'charge.json').read_text())['released'])

    def test_runc_and_api_account_untagged_owned_images_before_packaging(self):
        for mode, reserve in (('smoke', 3000000000), ('api-code', 5000000000)):
            calls = []
            def cli(args, **kwargs):
                calls.append(args)
                if args[0] == 'info':
                    return json.dumps({'Name': os.uname().nodename, 'CgroupVersion': '2', 'SecurityOptions': [], 'ServerVersion': 'test', 'CgroupDriver': 'systemd'})
                if args[:2] == ['container', 'ls']:
                    return ''
                if args[:2] == ['image', 'ls']:
                    return IMAGE if '--all' in args else ''
                if args[:2] == ['image', 'inspect']:
                    return json.dumps([{'Id': IMAGE, 'Size': 685362655}])
                raise AssertionError('unexpected mutation')
            previous = signal.getsignal(signal.SIGTERM)
            try:
                with self.subTest(mode=mode), project_root(), patch.object(lab, 'docker', cli), patch.object(sys, 'argv', ['lab', mode, '--other-service-memory-bytes', '0']), patch('runtime_lab_api.cached_postgres'), patch.object(lab, 'preflight', side_effect=RuntimeError('stop before packaging')) as guard:
                    with self.assertRaisesRegex(RuntimeError, 'stop before packaging'):
                        lab.main()
                    self.assertEqual(guard.call_args.args[0], reserve + 1434725310)
            finally:
                signal.signal(signal.SIGTERM, previous)

    def test_aggregate_memory_guard_stops_main_before_create_or_import(self):
        calls = []
        def cli(args, **kwargs):
            calls.append(args)
            if args[0] == 'info':
                return json.dumps({'Name': os.uname().nodename, 'CgroupVersion': '2', 'SecurityOptions': [], 'ServerVersion': 'test', 'CgroupDriver': 'systemd'})
            if args[:2] in (['container', 'ls'], ['image', 'ls']):
                return ''
            raise AssertionError('mutation before guard: ' + repr(args))
        previous = signal.getsignal(signal.SIGTERM)
        try:
            with project_root(), patch.object(lab, 'docker', cli), patch.object(sys, 'argv', ['lab', 'smoke', '--other-service-memory-bytes', '16000000001']):
                with self.assertRaisesRegex(azure_guard.GuardError, 'aggregate resident service memory'):
                    lab.main()
        finally:
            signal.signal(signal.SIGTERM, previous)
        self.assertTrue(calls)
        self.assertFalse(any('create' in x or 'import' in x for x in calls))

    def test_budget_guard_refusal_precedes_docker_mutation(self):
        # The real budget guard rejects an aggregate over 24 GB.
        with project_root(), self.assertRaisesRegex(azure_guard.GuardError, 'Warden project disk'):
            lab.preflight(25000000000, 4000000000)
        with project_root():
            lab.preflight(13000000000, 4000000000)

if __name__ == '__main__':
    unittest.main(verbosity=2)
