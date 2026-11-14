import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
import signal
from unittest.mock import patch

SPEC = importlib.util.find_spec('k3s_lab')
if SPEC:
    import k3s_lab as lab

LABELS = {'project': 'warden', 'owner': 'warden-lab', 'session': 'a' * 32,
          'ttl': '2099-01-01T00:00:00Z'}
IMAGE = 'sha256:' + 'b' * 64
CID = 'c' * 64


class DockerBoundary:
    def __init__(self, status='0', fail_remove=False):
        self.commands, self.status, self.fail_remove = [], status, fail_remove
        self.present = False

    def __call__(self, args, **kwargs):
        self.commands.append(args)
        if args[:2] == ['container', 'create']:
            self.present = True
            return CID
        if args[:2] == ['container', 'inspect']:
            return json.dumps([{'Id': CID, 'Config': {'Labels': LABELS}}])
        if args[:2] == ['container', 'start']:
            return '{"cleanup":"empty-reaped-deleted"}\n'
        if args[:2] == ['container', 'wait']:
            return self.status
        if args[:2] == ['container', 'rm']:
            if self.fail_remove:
                raise RuntimeError('refused removal')
            self.present = False
        if args[:2] == ['container', 'ls']:
            return CID if self.present else ''
        return ''


class LabTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(SPEC, 'fixed k3s lab boundary is not implemented')
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def test_capless_smoke_does_not_bind_host_paths_or_grant_capabilities(self):
        args = lab.create_args(IMAGE, LABELS, 'smoke')
        for value in ('--network=none', '--cgroupns=private', '--ipc=private',
                      '--read-only', '--cap-drop=ALL', '--user=65534:65534',
                      '--memory=4000000000', '--memory-swap=4000000000',
                      '--pids-limit=512', '--cpus=2'):
            self.assertIn(value, args)
        self.assertFalse(any(a.startswith(('--mount', '--cap-add', '--device', '--privileged')) for a in args))

    def test_live_requires_review_and_fixed_owned_identity_bind(self):
        binding = {'source': str(lab.BASE / ('docker-' + LABELS['session'])), 'device': 66307, 'inode': 12345, 'uid': os.getuid()}
        with self.assertRaises(ValueError):
            lab.create_args(IMAGE, LABELS, 'bootstrap')
        for bad in ({**binding, 'source': '/home'}, {**binding, 'source': '/proc/1/fd/6'},
                    {**binding, 'extra': 1}, {**binding, 'inode': '123'}, {**binding, 'uid': -1}):
            with self.assertRaises(ValueError):
                lab.create_args(IMAGE, LABELS, 'bootstrap', binding=bad)
        for mode in ('bootstrap', 'mount-smoke'):
            args = lab.create_args(IMAGE, LABELS, mode, binding=binding)
            self.assertEqual(sum(a == '--mount' for a in args), 1)
            self.assertIn('type=bind,src=' + binding['source'] + ',dst=/session,readonly,bind-propagation=rprivate', args)
            self.assertIn('WARDEN_LAB_SESSION_IDENTITY=66307:12345:' + str(os.getuid()), args)
            self.assertNotIn('--cap-add=SYS_MODULE', args)
            self.assertFalse(any(a.startswith(('--device', '--privileged', '--pid=host', '--network=host')) for a in args))
            if mode == 'mount-smoke':
                self.assertIn('--user=' + str(os.getuid()) + ':' + str(os.getuid()), args)
                self.assertFalse(any('unconfined' in a or a.startswith('--cap-add') for a in args))

    def test_unrecognized_modes_labels_and_nonexact_image_ids_fail(self):
        for mode in ('run', 'exec', 'kubectl', 'server', '--help'):
            with self.assertRaises(ValueError):
                lab.create_args(IMAGE, LABELS, mode)
        for image in ('latest', 'k3s:v1', 'b' * 64):
            with self.assertRaises(ValueError):
                lab.create_args(image, LABELS, 'smoke')
        with self.assertRaises(ValueError):
            lab.create_args(IMAGE, {**LABELS, 'owner': 'other'}, 'smoke')

    def test_packaged_selection_drops_wrapper_module_applets_and_unsafe_tools(self):
        k = {n: b'fake' for n in ('bin/k3s', 'bin/runc', 'bin/containerd-shim-runc-v2', 'bin/cni', 'bin/ip', 'bin/busybox', 'bin/aux/modprobe')}
        g = {n: b'fake' for n in ('runsc', 'containerd-shim-runsc-v1', 'gvisor-bin/gvisor_sentry')}
        files, aliases = lab.select_inputs(k, g)
        self.assertNotIn('usr/bin/busybox', files)
        self.assertNotIn('usr/bin/modprobe', files)
        self.assertEqual(files['usr/bin/k3s'], b'fake')
        self.assertEqual(aliases['usr/bin/containerd'], 'k3s')
        self.assertEqual(aliases['usr/bin/loopback'], 'cni')
        self.assertEqual(aliases.get('etc/rancher/k3s'), '/run/k3s-client')
        with self.assertRaises(ValueError):
            lab.select_inputs({**k, 'bin/k3s': b''}, g)

    def test_success_removes_only_the_exact_owned_container(self):
        cli = DockerBoundary()
        lab.execute(IMAGE, LABELS, 'smoke', cli=cli)
        self.assertFalse(cli.present)
        self.assertIn(['container', 'rm', CID], cli.commands)

    def test_failed_live_cleanup_preserves_container_and_raises(self):
        cli = DockerBoundary(status='2')
        with self.assertRaises(RuntimeError):
            lab.execute(IMAGE, LABELS, 'bootstrap', cli=cli, binding={'source': str(lab.BASE / ('docker-' + LABELS['session'])), 'device': 1, 'inode': 2, 'uid': os.getuid()})
        self.assertTrue(cli.present)
        self.assertIn(['container', 'stop', '--time=20', CID], cli.commands)
        self.assertFalse(any(c[:2] == ['container', 'rm'] for c in cli.commands))

    def test_removal_failure_is_not_cleanup_success(self):
        cli = DockerBoundary(fail_remove=True)
        with self.assertRaises(RuntimeError):
            lab.execute(IMAGE, LABELS, 'smoke', cli=cli)
        self.assertTrue(cli.present)

    def test_shared_accounting_counts_k3s_charge_before_other_lab_can_run(self):
        from runtime_lab_docker import record_charge, outstanding_bytes
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            session = base / ('docker-' + 'a' * 32)
            session.mkdir(mode=0o700)
            record_charge(session, reserve=6000000000)
            self.assertEqual(outstanding_bytes(base), 6000000000)
            record_charge(session, released=True, reserve=6000000000)
            self.assertEqual(outstanding_bytes(base), 0)

    def test_python_object_file_is_not_a_missing_dynamic_dependency(self):
        result = subprocess.CompletedProcess([], 1, '', '\tnot a dynamic executable\n')
        self.assertEqual(lab.abi_dependencies(result), set())
        for result in (subprocess.CompletedProcess([], 1, '', 'unexpected failure'),
                       subprocess.CompletedProcess([], 0, 'libx => not found', '')):
            with self.assertRaises(ValueError):
                lab.abi_dependencies(result)

    def test_renamed_session_anchor_fails_postflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'session'
            path.mkdir(mode=0o700)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                lab.verify_anchor(path, fd)
                path.rename(path.with_name('old'))
                path.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    lab.verify_anchor(path, fd)
            finally:
                os.close(fd)

    def test_image_session_drift_before_delete_preserves_objects_and_charge(self):
        # Replace the real pathname after start/stop, or between the two removals.
        for drift_at in ('start', 'stop', 'container-rm'):
            for mode in ('smoke', 'bootstrap'):
                with self.subTest(drift_at=drift_at, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / ('docker-' + LABELS['session'])
                    output.mkdir(mode=0o700)
                    old = output.with_name('renamed')
                    cli = DockerBoundary()
                    image_present = True
                    def docker(args, **kwargs):
                        nonlocal image_present
                        if args[:2] == ['image', 'import']:
                            return IMAGE
                        if args[:2] == ['image', 'inspect']:
                            return json.dumps([{'Id': IMAGE, 'Size': 500, 'Config': {'Labels': LABELS}}])
                        if args[:2] == ['image', 'rm']:
                            image_present = False
                            return ''
                        if args[:2] == ['image', 'ls']:
                            return IMAGE if image_present else ''
                        result = cli(args, **kwargs)
                        if args[:2] == ['container', {'container-rm': 'rm'}.get(drift_at, drift_at)]:
                            output.rename(old)
                            output.mkdir(mode=0o700)
                        return result
                    with patch('k3s_lab.BASE', Path(temporary)), patch('k3s_lab.docker', docker), self.assertRaises((RuntimeError, ValueError)):
                        lab.image_session(output, LABELS, mode)
                    self.assertTrue(image_present, 'path drift must block image deletion')
                    self.assertEqual(cli.present, drift_at != 'container-rm')
                    self.assertFalse(json.loads((old / 'charge.json').read_text())['released'])
                    self.assertEqual(list(output.iterdir()), [], 'replacement path must not receive evidence or charge')

    def test_mount_smoke_content_drift_preserves_objects_and_charge(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                output=Path(temporary)/('docker-'+LABELS['session']);output.mkdir(mode=0o700)
                marker=output/'manifest.json';marker.write_bytes(b'original')
                cli=DockerBoundary();present=True
                def docker(args, **kwargs):
                    nonlocal present
                    if args[:2]==['image','import']: return IMAGE
                    if args[:2]==['image','inspect']: return json.dumps([{'Id':IMAGE,'Size':500,'Config':{'Labels':LABELS}}])
                    if args[:2]==['image','rm']: present=False;return ''
                    if args[:2]==['image','ls']: return IMAGE if present else ''
                    if args[:2]==['container','start'] and changed: marker.write_bytes(b'changed')
                    return cli(args,**kwargs)
                with patch('k3s_lab.BASE',Path(temporary)),patch('k3s_lab.docker',docker):
                    if changed:
                        with self.assertRaises(RuntimeError):lab.image_session(output,LABELS,'mount-smoke')
                    else:
                        lab.image_session(output,LABELS,'mount-smoke')
                self.assertEqual(present, changed)
                self.assertEqual(cli.present, changed)
                self.assertEqual(json.loads((output/'charge.json').read_text())['released'], not changed)

    def test_main_tar_finally_preserves_replaced_directory_and_original_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);output=base/('docker-'+LABELS['session']);old=base/'retained-original'
            labels={};present=False
            def package(archive,manifest):
                archive.write_bytes(b'original archive')
                manifest.write_text('{}')
            def docker(args,**kwargs):
                nonlocal present
                if args[:2]==['image','import']:
                    for value in args:
                        if value.startswith('LABEL '):
                            key,val=value[6:].split('=',1);labels[key]=val
                    return IMAGE
                if args[:2]==['image','inspect']:return json.dumps([{'Id':IMAGE,'Size':500,'Config':{'Labels':labels}}])
                if args[:2]==['container','create']:present=True;return CID
                if args[:2]==['container','inspect']:return json.dumps([{'Id':CID,'Config':{'Labels':labels}}])
                if args[:2]==['container','start']:
                    output.rename(old);output.mkdir(mode=0o700)
                    (output/'rootfs.tar').write_bytes(b'replacement archive')
                    return ''
                if args[:2]==['container','wait']:return '0'
                if args[:2]==['container','stop']:return ''
                if args[:2]==['container','ls']:return CID if present else ''
                raise AssertionError(args)
            previous=signal.getsignal(signal.SIGTERM)
            try:
                with patch('k3s_lab.BASE',base),patch('k3s_lab.secrets.token_hex',return_value=LABELS['session']),patch('k3s_lab.package',package),patch('k3s_lab.accounting'),patch('k3s_lab.docker',docker),patch.object(sys,'argv',['lab','smoke','--other-service-memory-bytes','0']):
                    with self.assertRaises(RuntimeError):lab.main()
            finally:
                signal.signal(signal.SIGTERM,previous)
            self.assertTrue(present)
            self.assertEqual((old/'rootfs.tar').read_bytes(),b'original archive')
            self.assertTrue((output/'rootfs.tar').exists(),'main finally deleted a replacement directory file')
            self.assertEqual((output/'rootfs.tar').read_bytes(),b'replacement archive')

    def test_k3s_accounting_includes_untagged_owned_images(self):
        def docker(args, **kwargs):
            if args[0] == 'info':
                return json.dumps({'Name': os.uname().nodename, 'CgroupVersion': '2', 'SecurityOptions': []})
            if args[:2] == ['container', 'ls']:
                return ''
            if args[:2] == ['image', 'ls']:
                return IMAGE if '--all' in args else ''
            if args[:2] == ['image', 'inspect']:
                return json.dumps([{'Id': IMAGE, 'Size': 685362655, 'Config': {'Labels': LABELS}}])
            raise AssertionError(args)
        with tempfile.TemporaryDirectory() as temporary, patch('k3s_lab.BASE', Path(temporary)), patch('k3s_lab.docker', docker), patch('k3s_lab.subprocess.run') as guard:
            lab.accounting(7000000000)
            command = guard.call_args.args[0]
            self.assertEqual(command[command.index('--additional-bytes') + 1], '7434725310')

    def test_k3s_lost_import_response_recovers_untagged_image(self):
        present = False
        def docker(args, **kwargs):
            nonlocal present
            if args[:2] == ['image', 'import']:
                present = True
                raise RuntimeError('lost import response')
            if args[:2] == ['image', 'ls']:
                return IMAGE if present and '--all' in args else ''
            if args[:2] == ['container', 'ls']:
                return ''
            if args[:2] == ['image', 'inspect']:
                return json.dumps([{'Id': IMAGE, 'Size': 500, 'Config': {'Labels': LABELS}}])
            if args[:2] == ['image', 'rm']:
                present = False
                return ''
            raise AssertionError(args)
        with tempfile.TemporaryDirectory() as temporary, patch('k3s_lab.docker', docker):
            with self.assertRaisesRegex(RuntimeError, 'lost import response'):
                lab.image_session(Path(temporary), LABELS, 'smoke')
            self.assertFalse(present)
            self.assertFalse(json.loads((Path(temporary) / 'charge.json').read_text())['released'])

    def test_failed_capless_smoke_releases_charge_only_after_verified_image_removal(self):
        cli = DockerBoundary(status='2')
        image_present = True
        def docker(args, **kwargs):
            nonlocal image_present
            if args[:2] == ['image', 'import']:
                return IMAGE
            if args[:2] == ['image', 'inspect']:
                return json.dumps([{'Id': IMAGE, 'Size': 500, 'Config': {'Labels': LABELS}}])
            if args[:2] == ['image', 'rm']:
                image_present = False
                return ''
            if args[:2] == ['image', 'ls']:
                return IMAGE if image_present else ''
            return cli(args, **kwargs)
        with tempfile.TemporaryDirectory() as temporary, patch('k3s_lab.docker', docker):
            output = Path(temporary)
            with self.assertRaises(RuntimeError):
                lab.image_session(output, LABELS, 'smoke')
            self.assertFalse(cli.present)
            self.assertFalse(image_present)
            self.assertTrue(json.loads((output / 'charge.json').read_text())['released'])


if __name__ == '__main__':
    unittest.main()
