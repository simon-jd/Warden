#!/usr/bin/env python3
"""Generated private continuation fixtures; never opens the real cache/journal."""
import hashlib
import io
import json
import os
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import identity_cache as old
import identity_cache_continue as continuation

REPO = Path(__file__).absolute().parent.parent


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='warden-continuation-fixture-')))
        self.parent = self.root / '.cache'
        self.lab = self.parent / 'warden-lab'
        self.public = self.root / 'docs/evidence/task-6'
        self.scripts = self.root / 'scripts'
        for path in (self.lab, self.public, self.scripts):
            path.mkdir(mode=0o700, parents=True)
        self.lock = self.lab / 'docker.lock'
        self.lock.write_bytes(b'')
        self.lock.chmod(0o600)
        self.base = self.parent / 'go-build'
        self.base.mkdir(mode=0o775)
        self.base.chmod(0o775)
        for bucket in old.BUCKETS:
            (self.base / bucket).mkdir(mode=0o775)
            (self.base / bucket).chmod(0o775)
        self.action = self.base / '00' / ('0' * 64 + '-a')
        self.data = self.base / '01' / ('01' + '1' * 62 + '-d')
        self.exedir = self.base / '02' / ('02' + '2' * 62 + '-d')
        self.exedir.mkdir(mode=0o755)
        self.exedir.chmod(0o755)
        self.executable = self.exedir / 'fixture-binary'
        self.metadata = self.base / 'README'
        for path, body, mode in ((self.action, b'a' * 175, 0o664), (self.data, b'data', 0o644),
                                 (self.executable, b'bin', 0o755), (self.metadata, b'retain', 0o644)):
            path.write_bytes(body)
            path.chmod(mode)
        self.sibling = self.parent / 'go-mod'
        self.sibling.mkdir(mode=0o700)
        (self.sibling / 'sentinel').write_bytes(b'preserve')
        parent = os.open(self.parent, old.DIR_FLAGS)
        plan = old.TighteningPlan(parent, os.getuid())
        try:
            directories = {node.fd: node for node in plan.directories}
            entries = []
            self.paths = []
            for node in plan.directories + plan.files + plan.preserved:
                parts = [node.name]
                up = node.parent
                while up in directories:
                    parts.append(directories[up].name)
                    up = directories[up].parent
                relative = '/'.join(reversed(parts))
                entries.append({'relative': relative, 'original': list(old.fingerprint(node.info)),
                                'target_mode': 0o700 if node.fd >= 0 or node.executable else 0o600})
                self.paths.append(self.parent / relative)
        finally:
            plan.close()
            os.close(parent)
        self.prefix = 259  # all258 directories + action; data/executable/README remain original.
        self.intent = {'version': 1, 'state': 'prepared-not-completed', 'cache_name': 'go-build', 'entries': entries}
        intent_raw = raw(self.intent)
        self.put(self.parent / old.INTENT_NAME, intent_raw)
        for path, entry in zip(self.paths[:self.prefix], entries[:self.prefix]):
            path.chmod(entry['target_mode'])
        for name in (*continuation.OLD_SOURCES, 'scripts/identity_cache_continue.py', 'scripts/test_identity_cache_continue.py'):
            self.put(self.root / name, (REPO / name).read_bytes())
        history = {}
        for name in continuation.HISTORY:
            value = json.loads((REPO / name).read_bytes())
            if name.endswith('preflight-20261025.json'):
                value['trusted_anchors_metadata']['.cache'] = self.meta(self.parent)
                value['trusted_anchors_metadata']['.cache/warden-lab'] = self.meta(self.lab)
                value['existing_project_lock_metadata'] = self.meta(self.lock)
            body = raw(value)
            self.put(self.root / name, body)
            history[name] = hashlib.sha256(body).hexdigest()
        # Injection exists only here, for exact generated paths and synthetic pins.
        allowed = {self.root, self.parent, self.lab, self.public, self.scripts}
        def trusted(path, uid):
            self.assertEqual(uid, os.getuid())
            self.assertIn(Path(path), allowed)
            return os.open(path, old.DIR_FLAGS)
        for name, value in {'ROOT': self.root, 'HISTORY': history,
                            'OLD_INTENT_SHA': hashlib.sha256(intent_raw).hexdigest(),
                            'OLD_INTENT_BYTES': len(intent_raw),
                            'COUNTS': {'entries': 262, 'directories': 258, 'files': 4, 'prefix': self.prefix},
                            'trusted_directory': trusted}.items():
            self.stack.enter_context(mock.patch.object(continuation, name, value))

    @staticmethod
    def meta(path):
        s = path.stat(follow_symlinks=False)
        return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                s.st_size, s.st_blocks, s.st_mtime_ns, s.st_ctime_ns]

    @staticmethod
    def put(path, body):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)

    def capture(self):
        result = continuation.capture_checkpoint('generated private fixture writer-free window')
        self.assertEqual(result['state'], 'checkpoint-captured-not-approved')
        result['state'] = 'approved'
        self.put(self.public / continuation.APPROVAL_NAME, raw(result))
        return result

    def run_entry(self):
        with redirect_stdout(io.StringIO()):
            continuation.main([])

    def unchanged(self):
        return {str(p.relative_to(self.parent)): self.meta(p) for p in self.paths if p.exists()}

    def reject_entry(self):
        before = self.unchanged()
        with self.assertRaises((ValueError, OSError)):
            self.run_entry()
        self.assertEqual(self.unchanged(), before)
        self.assertFalse((self.parent / continuation.PREPARED).exists())

    def test_success_preserves_metadata_siblings_and_old_intent_and_fsyncs_every_target(self):
        approval = self.capture()
        original = (self.parent / old.INTENT_NAME).read_bytes()
        target_inodes = {p.stat().st_ino for p in self.paths}
        prefix_inodes = {p.stat().st_ino for p in self.paths[:self.prefix]}
        synced, chmodded = set(), set()
        read, sync, chmod, unlink = os.read, os.fsync, os.fchmod, os.unlink
        def no_body(fd, size):
            self.assertNotIn(os.fstat(fd).st_ino, target_inodes)
            return read(fd, size)
        def syncing(fd):
            synced.add(os.fstat(fd).st_ino)
            return sync(fd)
        def changing(fd, mode):
            self.assertTrue((self.parent / continuation.PREPARED).exists())
            chmodded.add(os.fstat(fd).st_ino)
            return chmod(fd, mode)
        def removing(*args, **kwargs):
            self.assertTrue((self.parent / continuation.READY).exists())
            self.assertTrue(target_inodes <= synced)
            return unlink(*args, **kwargs)
        with (mock.patch.object(os, 'read', side_effect=no_body), mock.patch.object(os, 'fsync', side_effect=syncing),
              mock.patch.object(os, 'fchmod', side_effect=changing), mock.patch.object(os, 'unlink', side_effect=removing)):
            self.run_entry()
        self.assertTrue(target_inodes <= synced)
        self.assertEqual(chmodded, target_inodes - prefix_inodes)
        result = json.loads((self.parent / continuation.RESULT).read_bytes())
        self.assertEqual(result['state'], 'completed')
        self.assertEqual(result['checkpoint_sha256'], approval['checkpoint_sha256'])
        self.assertEqual(result['removed_files'], 3)
        self.assertEqual(result['removed_executable_dirs'], 1)
        self.assertEqual((self.parent / old.INTENT_NAME).read_bytes(), original)
        self.assertFalse((self.parent / old.RESULT_NAME).exists())
        self.assertEqual(self.metadata.read_bytes(), b'retain')
        self.assertEqual((self.sibling / 'sentinel').read_bytes(), b'preserve')
        self.assertEqual(len(list(self.base.iterdir())), 257)
        with self.assertRaises((ValueError, OSError)):
            self.run_entry()

    def test_missing_approval_refuses_before_private_journal_read(self):
        with mock.patch.object(continuation, '_read_private', side_effect=AssertionError('private read before approval')):
            self.reject_entry()

    def test_bad_checkpoint_hash_or_binding_has_no_mutation(self):
        approval = self.capture()
        approval['checkpoint_sha256'] = '0' * 64
        self.put(self.public / continuation.APPROVAL_NAME, raw(approval))
        self.reject_entry()

    def test_changed_source_is_rejected(self):
        self.capture()
        with (self.scripts / 'identity_cache_continue.py').open('ab') as f:
            f.write(b'\n# replacement\n')
        self.reject_entry()

    def test_wrong_history_terminal_is_rejected_even_with_matching_history_hash(self):
        path = self.public / 'controller-cache-execute-result-20261025.json'
        value = json.loads(path.read_bytes())
        value['exit_code'] = 0
        body = raw(value)
        self.put(path, body)
        continuation.HISTORY[str(path.relative_to(self.root))] = hashlib.sha256(body).hexdigest()
        with self.assertRaises(ValueError):
            continuation.capture_checkpoint('fixture')
        self.assertFalse((self.parent / continuation.CHECKPOINT).exists())

    def test_old_intent_hash_mismatch_rejected(self):
        self.put(self.parent / old.INTENT_NAME, raw({**self.intent, 'extra': True}))
        with self.assertRaises(ValueError):
            continuation.capture_checkpoint('fixture')
        self.assertFalse((self.parent / continuation.CHECKPOINT).exists())

    def test_nonprefix_and_suffix_ctime_change_refused(self):
        # Advance one suffix mode without changing counts authority.
        self.data.chmod(0o600)
        with self.assertRaises(ValueError):
            continuation.capture_checkpoint('fixture')
        self.data.chmod(0o644)
        with self.assertRaises(ValueError):
            continuation.capture_checkpoint('fixture')
        self.assertFalse((self.parent / continuation.CHECKPOINT).exists())

    def test_live_change_after_checkpoint_is_rejected(self):
        self.capture()
        self.data.write_bytes(b'different-size')
        self.reject_entry()

    def test_missing_and_unknown_and_hardlink_rejected(self):
        self.capture()
        self.data.unlink()
        self.reject_entry()

    def test_replaced_root_does_not_follow_symlink(self):
        self.capture()
        self.base.rename(self.parent / 'retained-original')
        self.base.symlink_to(self.sibling, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.run_entry()
        self.assertFalse((self.parent / continuation.PREPARED).exists())
        self.assertEqual((self.sibling / 'sentinel').read_bytes(), b'preserve')

    def test_existing_stage_journal_blocks_without_chmod(self):
        self.capture()
        for name in (continuation.PREPARED, continuation.READY, continuation.RESULT, old.RESULT_NAME):
            with self.subTest(name=name):
                path = self.parent / name
                path.symlink_to(self.sibling / 'sentinel')
                with mock.patch.object(os, 'fchmod', side_effect=AssertionError('unexpected chmod')):
                    with self.assertRaises((ValueError, OSError)):
                        self.run_entry()
                path.unlink()

    def test_capture_is_exclusive_and_cannot_replace_checkpoint(self):
        self.capture()
        before = (self.parent / continuation.CHECKPOINT).read_bytes()
        with self.assertRaises((ValueError, OSError)):
            continuation.capture_checkpoint('fixture second capture')
        self.assertEqual((self.parent / continuation.CHECKPOINT).read_bytes(), before)

    def test_all_fixed_entry_arguments_refused_before_filesystem(self):
        with mock.patch.object(continuation, 'trusted_directory', side_effect=AssertionError('filesystem')):
            for argv in (['capture'], ['--retry'], ['/tmp/path']):
                with self.assertRaises(ValueError):
                    continuation.main(argv)

    def test_durable_stage_file_and_parent_failures_retain_state(self):
        # Each subtest has an independent generated fixture; the failed state is
        # never reset or reused as a continuation opportunity.
        self.capture()
        real = os.fsync
        def fail_prepared_parent(fd):
            if (self.parent / continuation.PREPARED).exists() and os.fstat(fd).st_ino == self.parent.stat().st_ino:
                raise OSError('fixture prepared parent fsync')
            return real(fd)
        before = self.unchanged()
        with mock.patch.object(os, 'fsync', side_effect=fail_prepared_parent):
            with self.assertRaises(OSError):
                self.run_entry()
        self.assertEqual(before, self.unchanged())
        self.assertTrue((self.parent / continuation.PREPARED).exists())
        self.assertFalse((self.parent / continuation.READY).exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
