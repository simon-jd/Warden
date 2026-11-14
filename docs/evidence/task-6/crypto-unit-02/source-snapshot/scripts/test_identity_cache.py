#!/usr/bin/env python3
"""Private filesystem fixtures only; never invokes the fixed live-cache entrypoint."""
import os
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import identity_cache as cache


class IdentityCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='warden-identity-cache-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / 'go-build'
        self.base.mkdir(mode=0o700)
        for i in range(256):
            (self.base / f'{i:02x}').mkdir(mode=0o700)
        self.outside = self.root / 'outside'
        self.outside.mkdir(mode=0o700)
        self.sentinel = self.outside / 'sentinel'
        self.sentinel.write_bytes(b'preserve')
        self.sentinel.chmod(0o600)
        self.parent = os.open(self.root, cache.DIR_FLAGS)
        self.addCleanup(os.close, self.parent)
        self.action = self.base / '00' / ('0' * 64 + '-a')
        self.action.write_bytes(b'x' * 175)
        self.action.chmod(0o600)
        self.data = self.base / '01' / ('01' + '1' * 62 + '-d')
        self.data.write_bytes(b'cached output')
        self.data.chmod(0o600)

    def plan(self):
        result = cache.CachePlan(self.parent, os.getuid())
        self.addCleanup(result.close)
        return result

    def rejected(self):
        with self.assertRaises((ValueError, OSError)):
            self.plan()
        self.assertTrue(self.action.exists())
        self.assertEqual(self.sentinel.read_bytes(), b'preserve')

    def test_deletes_only_derived_entries_keeps_buckets_and_metadata_without_reads(self):
        for name in ('README', 'trim.txt', 'testexpire.txt'):
            (self.base / name).write_bytes(b'metadata preserved')
            (self.base / name).chmod(0o600)
        executable_dir = self.base / '02' / ('02' + '2' * 62 + '-d')
        executable_dir.mkdir(mode=0o700)
        executable = executable_dir / 'test-binary'
        executable.write_bytes(b'executable cache')
        executable.chmod(0o700)
        with mock.patch.object(os, 'read', side_effect=AssertionError('body read')):
            plan = self.plan()
            receipt = plan.remove()
        self.assertEqual(receipt['removed_files'], 3)
        self.assertEqual(receipt['removed_executable_dirs'], 1)
        self.assertFalse(self.action.exists())
        self.assertFalse(self.data.exists())
        self.assertFalse(executable_dir.exists())
        self.assertEqual(len(list(self.base.iterdir())), 259)
        self.assertEqual((self.base / 'README').read_bytes(), b'metadata preserved')

    def test_unknown_top_entry_fails_before_any_deletion(self):
        (self.base / 'fuzz').mkdir()
        self.rejected()

    def test_unknown_bucket_entry_and_wrong_hash_prefix_fail(self):
        for name in ('source.go', 'ff' + '0' * 62 + '-d'):
            with self.subTest(name=name):
                path = self.base / '00' / name
                path.write_bytes(b'not authorized')
                path.chmod(0o600)
                self.rejected()
                path.unlink()

    def test_missing_bucket_rejected(self):
        (self.base / 'ff').rmdir()
        self.rejected()

    def test_symlink_root_bucket_file_rejected(self):
        for relative in ('', 'ff', '01/' + self.data.name):
            with self.subTest(relative=relative):
                target = self.base / relative
                saved = target.with_name(target.name + '-saved')
                target.rename(saved)
                target.symlink_to(self.outside, target_is_directory=True)
                with self.assertRaises((ValueError, OSError)):
                    self.plan()
                target.unlink()
                saved.rename(target)
                self.assertEqual(self.sentinel.read_bytes(), b'preserve')

    def test_hardlink_file_rejected(self):
        self.data.unlink()
        os.link(self.sentinel, self.data)
        self.rejected()

    def test_fifo_rejected_without_blocking_open(self):
        self.data.unlink()
        os.mkfifo(self.data, 0o600)
        self.rejected()

    def test_group_writable_root_bucket_file_rejected(self):
        for path, mode in ((self.base, 0o775), (self.base / 'ff', 0o770), (self.data, 0o664)):
            with self.subTest(path=path):
                before = path.stat().st_mode & 0o777
                path.chmod(mode)
                self.rejected()
                path.chmod(before)

    def test_wrong_owner_rejected(self):
        with self.assertRaises(ValueError):
            cache.CachePlan(self.parent, os.getuid() + 1)
        self.assertTrue(self.action.exists())

    def test_malformed_action_length_rejected(self):
        self.action.write_bytes(b'incomplete')
        self.rejected()

    def test_executable_directory_must_contain_exactly_one_plain_executable(self):
        self.data.unlink()
        self.data.mkdir(mode=0o700)
        self.rejected()
        (self.data / 'binary').symlink_to(self.sentinel)
        self.rejected()
        (self.data / 'binary').unlink()
        (self.data / 'binary').write_bytes(b'bin')
        (self.data / 'binary').chmod(0o600)
        self.rejected()
        (self.data / 'binary').chmod(0o700)
        (self.data / 'nested').mkdir()
        self.rejected()

    def test_change_after_scan_refuses_before_deletion(self):
        plan = self.plan()
        self.data.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            plan.remove()
        self.assertTrue(self.action.exists())

    def test_unknown_entry_added_after_scan_refuses_before_deletion(self):
        plan = self.plan()
        (self.base / '00' / 'unexpected').write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            plan.remove()
        self.assertTrue(self.action.exists())

    def test_anchor_replacement_refuses_both_renamed_and_replacement_tree(self):
        plan = self.plan()
        renamed = self.root / 'old-cache'
        self.base.rename(renamed)
        self.base.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            plan.remove()
        self.assertTrue((renamed / '00' / self.action.name).exists())
        self.assertEqual(self.sentinel.read_bytes(), b'preserve')

    def test_file_replacement_after_scan_is_not_removed(self):
        plan = self.plan()
        self.data.unlink()
        self.data.symlink_to(self.sentinel)
        with self.assertRaises((ValueError, OSError)):
            plan.remove()
        self.assertTrue(self.action.exists())
        self.assertTrue(self.data.is_symlink())

    def test_lock_busy_and_wrong_lock_layout_fail_without_cache_access(self):
        lock = self.root / 'docker.lock'
        lock.write_bytes(b'')
        lock.chmod(0o600)
        with cache.project_lock(self.parent, os.getuid()):
            with self.assertRaises(BlockingIOError):
                with cache.project_lock(self.parent, os.getuid()):
                    self.fail('second lock acquired')
        lock.chmod(0o666)
        with self.assertRaises(ValueError):
            with cache.project_lock(self.parent, os.getuid()):
                self.fail('unsafe lock acquired')

    def test_cli_rejects_all_path_and_mode_arguments_before_open(self):
        with mock.patch.object(cache, 'trusted_directory', side_effect=AssertionError('filesystem access')):
            with self.assertRaises(ValueError):
                cache.main(['/tmp/arbitrary'])

    def legacy_modes(self):
        self.base.chmod(0o775)
        for name in cache.BUCKETS:
            (self.base / name).chmod(0o775)
        self.action.chmod(0o664)
        self.data.chmod(0o644)

    def tightening_plan(self):
        result = cache.TighteningPlan(self.parent, os.getuid())
        self.addCleanup(result.close)
        return result

    def test_fixed_tightening_persists_intent_then_reduces_permissions_before_unlink(self):
        self.legacy_modes()
        with self.assertRaises(ValueError):
            self.plan()  # Generic entrypoint remains strict.
        with self.assertRaises(ValueError):
            cache.trusted_directory(str(self.base), os.getuid())
        plan = self.tightening_plan()
        intent = self.root / cache.INTENT_NAME
        original_chmod = os.fchmod
        def checked_chmod(fd, mode):
            self.assertTrue(intent.is_file())
            original_chmod(fd, mode)
        with mock.patch.object(os, 'fchmod', side_effect=checked_chmod):
            plan.tighten()
        self.assertEqual(intent.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.action.exists())
        plan.remove()
        self.assertFalse(self.action.exists())

    def test_legacy_plan_cannot_unlink_without_completed_tightening(self):
        self.legacy_modes()
        plan = self.tightening_plan()
        with self.assertRaises(ValueError):
            plan.remove()
        self.assertTrue(self.action.exists())

    def test_unknown_legacy_mode_or_layout_never_chmods_or_writes_intent(self):
        self.legacy_modes()
        for target, mode in ((self.base, 0o777), (self.data, 0o666)):
            with self.subTest(target=target):
                before = target.stat().st_mode & 0o777
                target.chmod(mode)
                with mock.patch.object(os, 'fchmod', side_effect=AssertionError('mutation')):
                    with self.assertRaises(ValueError):
                        self.tightening_plan()
                self.assertFalse((self.root / cache.INTENT_NAME).exists())
                target.chmod(before)
        (self.base / 'unknown').write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            self.tightening_plan()
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o775)
        self.assertFalse((self.root / cache.INTENT_NAME).exists())

    def test_tightening_replacement_after_plan_has_no_mutation(self):
        self.legacy_modes()
        plan = self.tightening_plan()
        self.data.unlink()
        self.data.symlink_to(self.sentinel)
        with mock.patch.object(os, 'fchmod', side_effect=AssertionError('mutation')):
            with self.assertRaises((ValueError, OSError)):
                plan.tighten()
        self.assertFalse((self.root / cache.INTENT_NAME).exists())
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o775)

    def test_partial_tightening_keeps_intent_and_narrowed_modes_and_never_unlinks(self):
        self.legacy_modes()
        plan = self.tightening_plan()
        original = os.fchmod
        count = 0
        def fail_second(fd, mode):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('fixture interruption')
            original(fd, mode)
        with mock.patch.object(os, 'fchmod', side_effect=fail_second):
            with self.assertRaises(OSError):
                plan.tighten()
        self.assertTrue((self.root / cache.INTENT_NAME).exists())
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o700)
        self.assertTrue(self.action.exists())
        with self.assertRaises(ValueError):
            plan.remove()
        with self.assertRaises((ValueError, FileExistsError)):
            plan.tighten()

    def test_existing_intent_or_intent_alias_refuses_without_chmod(self):
        self.legacy_modes()
        intent = self.root / cache.INTENT_NAME
        intent.symlink_to(self.sentinel)
        plan = self.tightening_plan()
        with mock.patch.object(os, 'fchmod', side_effect=AssertionError('mutation')):
            with self.assertRaises(FileExistsError):
                plan.tighten()
        self.assertTrue(self.action.exists())
        self.assertEqual(self.sentinel.read_bytes(), b'preserve')

    def test_changed_layout_after_tightening_prevents_unlink(self):
        self.legacy_modes()
        plan = self.tightening_plan()
        plan.tighten()
        (self.base / 'ff' / 'unknown').write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            plan.remove()
        self.assertTrue(self.action.exists())

    def test_intent_durability_failure_prevents_all_permission_changes(self):
        self.legacy_modes()
        plan = self.tightening_plan()
        with mock.patch.object(os, 'fsync', side_effect=OSError('fixture fsync failure')):
            with mock.patch.object(os, 'fchmod', side_effect=AssertionError('mutation before durability')):
                with self.assertRaises(OSError):
                    plan.tighten()
        self.assertTrue((self.root / cache.INTENT_NAME).exists())
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o775)
        self.assertTrue(self.action.exists())

    @unittest.skipUnless(os.getuid() == 1000 and os.getgid() == 1000, 'fixed entrypoint requires UID/GID1000')
    def test_fixed_main_in_private_fixture_keeps_other_caches_and_records_completion(self):
        self.legacy_modes()
        parent = self.root / '.cache'
        parent.mkdir(mode=0o700)
        self.base.rename(parent / 'go-build')
        lab = parent / 'warden-lab'
        lab.mkdir(mode=0o700)
        (lab / 'docker.lock').write_bytes(b'')
        (lab / 'docker.lock').chmod(0o600)
        for name in ('go-mod', 'firecracker-code'):
            (parent / name).mkdir(mode=0o700)
            (parent / name / 'sentinel').write_bytes(b'preserve')
        def fixture_parent(path, uid):
            # The tool sandbox presents /tmp as UID65534. Its ancestry is not
            # production's trusted project path. Inject only these two exact
            # already-owned fixture parents, retaining the real cache/lock logic.
            self.assertEqual(uid, 1000)
            self.assertIn(Path(path), (parent, lab))
            return os.open(path, cache.DIR_FLAGS)
        with (mock.patch.object(cache, 'ROOT', self.root),
              mock.patch.object(cache, 'trusted_directory', side_effect=fixture_parent),
              redirect_stdout(io.StringIO())):
            cache.main([])
        self.assertTrue((parent / cache.INTENT_NAME).exists())
        self.assertTrue((parent / cache.RESULT_NAME).exists())
        self.assertFalse((parent / 'go-build' / '00' / self.action.name).exists())
        for name in ('go-mod', 'firecracker-code'):
            self.assertEqual((parent / name / 'sentinel').read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main(verbosity=2)
