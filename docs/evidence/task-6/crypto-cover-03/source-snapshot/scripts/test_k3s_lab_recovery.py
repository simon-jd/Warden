import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.find_spec('k3s_lab_recovery_init')
if SPEC:
    import k3s_lab_recovery_init as inner
HOST_SPEC = importlib.util.find_spec('k3s_lab_recover')
if HOST_SPEC:
    import k3s_lab_recover as host


RESOURCE = {'uid': 0, 'nofile_soft': 1024, 'nofile_hard': 2048,
            'fd_entries': 7, 'inotify_result': 'opened', 'inotify_errno': 0}

def proof():
    return json.dumps({'resource_diagnostic': RESOURCE}, sort_keys=True) + '\n' + inner.MARKER + '\n'


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(SPEC, 'fixed stopped-scene recovery not implemented')
        self.resource = patch.object(inner, 'resource_diagnostic', return_value=RESOURCE)
        self.probe = self.resource.start(); self.addCleanup(self.resource.stop)

    def scene(self, root):
        outer_identity = patch.object(inner, 'OUTER_IDENTITY', (root.stat().st_dev, root.stat().st_ino, os.getuid()))
        outer_identity.start(); self.addCleanup(outer_identity.stop)
        child = root / inner.CHILD
        child.mkdir(mode=0o700)
        for name, size in inner.FILES.items():
            path = child / name
            path.write_bytes(b'x' * size)
            path.chmod(0o600)
        return child

    def test_wrong_private_shape_never_remounts_or_deletes(self):
        for mutation in ('extra', 'missing', 'symlink', 'hardlink', 'mode', 'directory-mode', 'fifo', 'size', 'inode', 'device', 'owner', 'blocks'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); child = self.scene(root)
                identity = (child.stat().st_dev, child.stat().st_ino, os.getuid())
                if mutation == 'extra': (child / 'root').mkdir()
                target = child / 'startup-private.log'
                if mutation == 'missing': target.unlink()
                if mutation == 'symlink': target.unlink(); target.symlink_to(root / 'outside')
                if mutation == 'hardlink': os.link(target, root / 'outside')
                if mutation == 'mode': target.chmod(0o644)
                if mutation == 'directory-mode': child.chmod(0o755)
                if mutation == 'fifo': target.unlink(); os.mkfifo(target)
                if mutation == 'size': target.write_bytes(b'wrong')
                if mutation in ('inode', 'device', 'owner'):
                    values = list(identity); values[{'device': 0, 'inode': 1, 'owner': 2}[mutation]] += 1; identity = tuple(values)
                original = os.stat
                def observed(*args, **kwargs):
                    value = original(*args, **kwargs)
                    if mutation == 'blocks' and args[0] == 'startup-private.log':
                        from types import SimpleNamespace
                        value = SimpleNamespace(**{name: getattr(value, name) for name in dir(value) if name.startswith('st_')})
                        value.st_blocks = 100000
                    return value
                with patch.object(inner, 'SESSION', root), patch.object(inner, 'CHILD_IDENTITY', identity), patch.object(inner, 'session_handshake') as handshake, patch.object(inner.os, 'stat', side_effect=observed), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises((ValueError, FileNotFoundError)): inner.reconcile()
                    handshake.assert_called_once_with(live=False)
                    self.probe.assert_not_called()
                self.assertTrue(child.exists())

    def test_exact_private_files_removed_without_reading_contents_or_public_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); child = self.scene(root)
            public = root / 'manifest.json'; public.write_bytes(b'public unchanged')
            ident = (child.stat().st_dev, child.stat().st_ino, os.getuid())
            calls = []
            with patch.object(inner, 'SESSION', root), patch.object(inner, 'CHILD_IDENTITY', ident), patch.object(inner, 'session_handshake', side_effect=lambda **kw: calls.append(kw['live'])), patch.object(inner.os, 'read', side_effect=AssertionError('no content reads')), contextlib.redirect_stdout(io.StringIO()) as output:
                inner.reconcile()
            self.assertEqual(calls, [False, True])
            self.assertFalse(child.exists())
            self.assertEqual(public.read_bytes(), b'public unchanged')
            self.assertEqual(output.getvalue(), proof())
            self.probe.assert_called_once_with()

    def test_replacement_during_remount_preserves_both_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); child = self.scene(root)
            ident = (child.stat().st_dev, child.stat().st_ino, os.getuid())
            def handshake(*, live):
                if live:
                    child.rename(root / 'held-original'); child.mkdir(mode=0o700)
            with patch.object(inner, 'SESSION', root), patch.object(inner, 'CHILD_IDENTITY', ident), patch.object(inner, 'session_handshake', side_effect=handshake):
                with self.assertRaises(ValueError): inner.reconcile()
            self.assertEqual(len(list((root / 'held-original').iterdir())), 3)
            self.assertTrue(child.exists())

    def test_supported_resource_errors_are_observed_after_shape_before_remount_and_do_not_block_cleanup(self):
        for code, errno in (('emfile', 24), ('enfile', 23), ('other', 13)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); child = self.scene(root)
                ident = (child.stat().st_dev, child.stat().st_ino, os.getuid())
                calls = []
                record = {**RESOURCE, 'inotify_result': code, 'inotify_errno': errno}
                def observe():
                    self.assertTrue(child.exists())
                    self.assertEqual(calls, [False])
                    calls.append('resource')
                    return record
                with patch.object(inner, 'SESSION', root), patch.object(inner, 'CHILD_IDENTITY', ident), patch.object(inner, 'session_handshake', side_effect=lambda **kw: calls.append(kw['live'])), patch.object(inner, 'resource_diagnostic', side_effect=observe), contextlib.redirect_stdout(io.StringIO()) as output:
                    inner.reconcile()
                self.assertEqual(calls, [False, 'resource', True])
                self.assertFalse(child.exists())
                self.assertEqual(host.recovery_proof(output.getvalue()), record)


class RecoveryHostTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(HOST_SPEC, 'fixed host recovery boundary not implemented')

    def test_profile_uses_retained_image_and_only_two_capabilities(self):
        args = host.create_args({'project': 'warden', 'owner': 'codex-warden', 'session': 'a' * 32, 'ttl': '2099-01-01T00:00:00Z', 'role': 'fixed-reconciliation'}, 'immutable reviewed code')
        self.assertEqual([x for x in args if x.startswith('--cap-add=')], ['--cap-add=SYS_ADMIN', '--cap-add=DAC_OVERRIDE'])
        for item in ('--memory=256000000', '--memory-swap=256000000', '--pids-limit=32', '--cpus=1', '--read-only', '--network=none', '--ipc=private', '--cgroupns=private', '--pull=never'):
            self.assertIn(item, args)
        self.assertEqual(args[-4:], [host.IMAGE, '-B', '-c', 'immutable reviewed code'])
        self.assertEqual(sum(x == '--mount' for x in args), 1)
        self.assertTrue(args[args.index('--mount') + 1].endswith(',readonly,bind-propagation=rprivate'))

    def test_accounting_excludes_only_exact_reserved_child_and_counts_all_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); outer = root / 'outer'; outer.mkdir(mode=0o700)
            child = outer / inner.CHILD; child.mkdir(mode=0o700)
            (root / 'normal').write_bytes(b'x' * 4097)
            identity = (child.stat().st_dev, child.stat().st_ino, os.getuid())
            with patch.object(host, 'ROOT', root), patch.object(host, 'OUTPUT', outer), patch.object(host, 'CHILD_IDENTITY', identity):
                expected = (root / 'normal').stat().st_blocks * 512
                self.assertEqual(host.allocated_project(), expected)
                unreadable = root / 'unrelated'; unreadable.mkdir(mode=0o000)
                try:
                    with self.assertRaises(PermissionError): host.allocated_project()
                finally:
                    unreadable.chmod(0o700); unreadable.rmdir()
                child.rename(outer / 'old'); child.mkdir(mode=0o700)
                with self.assertRaises(ValueError): host.allocated_project()

    def test_budget_preserves_six_gb_plus_images_and_helper_charge(self):
        with patch.object(host, 'allocated_project', return_value=3000000000), patch.object(host, 'outstanding_bytes', return_value=6000000000), patch.object(host, 'image_charges', return_value=1434733588):
            result = host.preflight(100000000, lambda args, **kw: '')
            self.assertEqual(result['accounted_disk_bytes'], 10498733588)
            self.assertEqual(result['helper_reserve_bytes'], 64000000)
            with self.assertRaises(ValueError): host.preflight(16000000000, lambda args, **kw: '')
        with patch.object(host, 'allocated_project', return_value=6000000000), patch.object(host, 'outstanding_bytes', return_value=6000000000), patch.object(host, 'image_charges', return_value=1434733588):
            with self.assertRaises(ValueError): host.preflight(0, lambda args, **kw: '')

    def test_recovery_lifecycle_preserves_journal_on_lost_response_failure_and_drift(self):
        for fault in (None, 'lost-create', 'wrong-command', 'failed-helper', 'extra-proof', 'wrong-proof', 'missing-proof', 'drift', 'unknown-absence', 'image-rm', 'ordinary-guard', 'tar-drift', 'tar-alias', 'tar-fsync'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
                base = Path(temporary); output = base / ('docker-' + host.LABELS['session'])
                output.mkdir(mode=0o700); child = output / inner.CHILD; child.mkdir(mode=0o700)
                (child / 'startup-private.log').write_bytes(b'private')
                (output / 'charge.json').write_text(json.dumps({'version': 1, 'reserved_bytes': 6000000000, 'released': False}))
                (output / 'charge.json').chmod(0o600)
                archive = output / 'rootfs.tar'; archive.write_bytes(b'fixed archive'); archive.chmod(0o600)
                archive_identity = (archive.stat().st_dev, archive.stat().st_ino, os.getuid())
                stack.enter_context(patch.object(host, 'TAR_IDENTITY', archive_identity, create=True))
                stack.enter_context(patch.object(host, 'TAR_SIZE', archive.stat().st_size, create=True))
                objects = {host.ORIGINAL, host.IMAGE}; helper_id = 'd' * 64
                commands = []; helper_labels = {}; helper_cmd = []; helper_status = 'created'
                def cli(args, **kwargs):
                    nonlocal helper_labels, helper_cmd, helper_status
                    commands.append(args[:3])
                    if args[0] == 'info':
                        return json.dumps({'Name': os.uname().nodename, 'CgroupDriver': 'systemd', 'CgroupVersion': '2', 'SecurityOptions': []})
                    if args[:2] == ['container', 'create']:
                        helper_labels = dict(args[i + 1].split('=', 1) for i, value in enumerate(args) if value == '--label')
                        helper_cmd = args[-3:]; objects.add(helper_id)
                        if fault == 'lost-create': raise RuntimeError('lost response')
                        return helper_id
                    if args[1] == 'inspect':
                        identity = args[2]
                        if identity not in objects:
                            message = 'connection refused' if fault == 'unknown-absence' else 'Error: No such ' + args[0] + ': ' + identity
                            raise subprocess.CalledProcessError(1, args, stderr=message)
                        config = {'Labels': host.LABELS}
                        result = {'Id': identity, 'Config': config, 'Size': 685366794}
                        if args[0] == 'container':
                            result.update({'Image': host.IMAGE, 'State': {'Status': 'exited', 'Pid': 0, 'Running': False}, 'RestartCount': 0, 'HostConfig': {'PidMode': ''}})
                        if identity == helper_id:
                            config.update({'Labels': helper_labels, 'Entrypoint': ['/usr/bin/python3'], 'Cmd': ['untrusted'] if fault == 'wrong-command' else helper_cmd})
                            result['State']['Status'] = helper_status
                        return json.dumps([result])
                    if args[1] == 'ls':
                        kind = args[0]
                        candidates = {x for x in objects if (x.startswith('sha256:')) == (kind == 'image')}
                        filters = dict(value[6:].split('=', 1) for value in args if value.startswith('label='))
                        return '\n'.join(x for x in candidates if all((helper_labels if x == helper_id else host.LABELS).get(k) == v for k, v in filters.items()))
                    if args[:2] == ['container', 'start']:
                        helper_status = 'exited'
                        if fault == 'failed-helper': return ''
                        if fault == 'drift':
                            output.rename(base / 'retained'); output.mkdir(mode=0o700)
                        else: shutil.rmtree(child)
                        if fault == 'extra-proof': return proof() + 'PRIVATE\n'
                        if fault == 'wrong-proof': return proof().replace('"uid": 0', '"uid": 1')
                        if fault == 'missing-proof': return inner.MARKER + '\n'
                        return proof()
                    if args[:2] == ['container', 'wait']: return '2' if fault == 'failed-helper' else '0'
                    if args[1] == 'rm':
                        if fault == 'image-rm' and args[0] == 'image': raise RuntimeError('refused')
                        objects.remove(args[2]); return ''
                    raise AssertionError(args[:3])
                stack.enter_context(patch.object(host, 'BASE', base)); stack.enter_context(patch.object(host, 'OUTPUT', output))
                stack.enter_context(patch.object(host, 'OUTER_IDENTITY', (output.stat().st_dev, output.stat().st_ino, os.getuid())))
                stack.enter_context(patch.object(host, 'CHILD_IDENTITY', (child.stat().st_dev, child.stat().st_ino, os.getuid())))
                stack.enter_context(patch.object(host, 'scope_absent'))
                stack.enter_context(patch.object(host, 'preflight', return_value={'accounted_disk_bytes': 10498733588}))
                def ordinary(*args):
                    commands.append(['fresh-ordinary-guard'])
                    if fault == 'ordinary-guard': raise ValueError('unknown budget')
                    if fault == 'tar-drift':
                        archive.rename(output / 'original-archive'); archive.write_bytes(b'replacement')
                    if fault == 'tar-alias': os.link(archive, output / 'alias')
                stack.enter_context(patch.object(host, 'ordinary_preflight', side_effect=ordinary))
                unlink, fsync = os.unlink, os.fsync
                def observed_unlink(path, *args, **kwargs):
                    if path == 'rootfs.tar': commands.append(['tar-unlink'])
                    return unlink(path, *args, **kwargs)
                def observed_fsync(fd):
                    if fault == 'tar-fsync' and ['tar-unlink'] in commands:
                        raise OSError('directory durability unknown')
                    return fsync(fd)
                stack.enter_context(patch.object(host.os, 'unlink', side_effect=observed_unlink))
                stack.enter_context(patch.object(host.os, 'fsync', side_effect=observed_fsync))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                if fault:
                    with self.assertRaises((ValueError, RuntimeError, OSError)): host.recover(0, reviewed=True, cli=cli)
                else: host.recover(0, reviewed=True, cli=cli)
                retained = base / 'retained' if fault == 'drift' else output
                journal = json.loads((retained / 'recovery.json').read_text())
                self.assertEqual(journal['helper_reserve_bytes'], 64000000)
                self.assertEqual(journal['helper_labels'], helper_labels)
                self.assertEqual(journal.get('archive'), {'identity': list(archive_identity), 'size': len(b'fixed archive')})
                charge = json.loads((retained / 'charge.json').read_text())
                self.assertEqual(charge['released'], fault is None)
                self.assertEqual((retained / 'rootfs.tar').exists(), fault not in (None, 'tar-fsync'))
                if fault in ('lost-create', 'wrong-command', 'failed-helper', 'drift'):
                    self.assertEqual(objects, {host.ORIGINAL, host.IMAGE, helper_id})
                    self.assertFalse(any(command[1:2] == ['rm'] for command in commands))
                if fault == 'unknown-absence': self.assertIn(host.ORIGINAL, objects)
                if fault is None:
                    self.assertEqual(objects, set())
                    self.assertEqual([c for c in commands if c[1:2] == ['rm']], [['container', 'rm', helper_id], ['container', 'rm', host.ORIGINAL], ['image', 'rm', host.IMAGE]])
                    self.assertEqual(commands[-2:], [['fresh-ordinary-guard'], ['tar-unlink']])


if __name__ == '__main__':
    unittest.main()
