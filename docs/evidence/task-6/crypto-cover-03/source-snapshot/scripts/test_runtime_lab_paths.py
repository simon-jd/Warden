#!/usr/bin/env python3
"""Run real filesystem guard behavior without root or any container daemon."""
import os
from pathlib import Path
import tempfile
import unittest
from runtime_lab_paths import prepare_session

class LabPathsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'warden-lab'
        self.base.mkdir(mode=0o700)
        self.outside = Path(self.temp.name) / 'outside'
        self.outside.mkdir(mode=0o700)
        self.sentinel = self.outside / 'sentinel'
        self.sentinel.write_text('untouched')
    def reject(self, base=None, owner=None):
        with self.assertRaises((OSError, ValueError)):
            s = prepare_session(str(base or self.base), os.getuid() if owner is None else owner)
            s.close()
        self.assertEqual(self.sentinel.read_text(), 'untouched')
    def test_lab_directory_symlink_is_rejected_before_write(self):
        self.base.rmdir()
        self.base.symlink_to(self.outside, target_is_directory=True)
        self.reject()
        self.assertFalse((self.outside / 'containerd.toml').exists())
    def test_ancestor_symlink_is_rejected(self):
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(Path(self.temp.name), target_is_directory=True)
        self.reject(alias / 'warden-lab')
    def test_preexisting_targets_and_dangling_aliases_are_rejected(self):
        for name in ['containerd.toml', 'containerd.log', 'root', 'state', 'io', 'containerd.sock']:
            with self.subTest(name=name):
                casebase = self.base / name.replace('.', '-')
                casebase.mkdir(mode=0o700)
                target = casebase / name
                target.symlink_to(self.outside / 'absent')
                self.reject(base=casebase)
                self.assertTrue(target.is_symlink())
                target.unlink()
                target.write_text('existing')
                self.reject(base=casebase)
                self.assertEqual(target.read_text(), 'existing')
                target.unlink()
    def test_untrusted_owner_and_writable_ancestor_fail_closed(self):
        self.reject(owner=os.getuid() + 12345)
        self.base.chmod(0o777)
        self.reject()
    def test_session_is_exclusive_and_files_do_not_overwrite_prior_session(self):
        first = prepare_session(str(self.base), os.getuid())
        self.addCleanup(first.close)
        second = prepare_session(str(self.base), os.getuid())
        self.addCleanup(second.close)
        self.assertNotEqual(first.run, second.run)
        self.assertEqual(first.run.stat().st_mode & 0o777, 0o700)
        self.assertEqual((first.run / 'containerd.toml').stat().st_mode & 0o777, 0o600)
        self.assertTrue((first.run / 'root').is_dir())
    def test_artifact_symlinks_and_group_writable_files_are_rejected(self):
        session = prepare_session(str(self.base), os.getuid())
        self.addCleanup(session.close)
        artifact = self.base / 'runc.test'
        artifact.symlink_to(self.sentinel)
        with self.assertRaises((OSError, ValueError)):
            session.artifact('runc.test')
        artifact.unlink()
        artifact.write_text('untrusted mutable executable')
        artifact.chmod(0o777)
        with self.assertRaises(ValueError):
            session.artifact('runc.test')
        self.assertEqual(self.sentinel.read_text(), 'untouched')

    def test_readonly_image_artifacts_are_separate_from_writable_session(self):
        session = prepare_session(str(self.base), os.getuid())
        self.addCleanup(session.close)
        image = Path(self.temp.name) / 'image'
        image.mkdir(mode=0o700)
        (image / 'runc.test').write_bytes(b'immutable image test')
        (image / 'runc.test').chmod(0o600)
        (self.base / 'runc.test').write_bytes(b'wrong writable copy')
        fd = session.artifact('runc.test', str(image))
        try:
            self.assertEqual(os.read(fd, 100), b'immutable image test')
        finally:
            os.close(fd)

    def test_evidence_handoff_uses_pinned_session_and_known_files_only(self):
        session = prepare_session(str(self.base), os.getuid())
        self.addCleanup(session.close)
        self.assertTrue(hasattr(session, 'release_evidence'), 'safe evidence ownership handoff is missing')
        session.cleanup_data()
        renamed = session.run.with_name(session.run.name + '-moved')
        session.run.rename(renamed)
        session.run.symlink_to(self.outside, target_is_directory=True)
        session.release_evidence()
        self.assertEqual(renamed.stat().st_uid, os.getuid())
        self.assertEqual((renamed / 'containerd.log').stat().st_uid, os.getuid())
        self.assertEqual(self.sentinel.read_text(), 'untouched')

    def test_evidence_handoff_refuses_unknown_state_symlinks_and_hardlinks(self):
        for kind in ('directory', 'symlink', 'hardlink'):
            session = prepare_session(str(self.base), os.getuid())
            try:
                self.assertTrue(hasattr(session, 'release_evidence'), 'safe evidence ownership handoff is missing')
                session.cleanup_data()
                if kind == 'directory':
                    (session.run / 'unverified').mkdir()
                else:
                    (session.run / 'containerd.log').unlink()
                    if kind == 'symlink':
                        (session.run / 'containerd.log').symlink_to(self.sentinel)
                    else:
                        os.link(self.sentinel, session.run / 'containerd.log')
                with self.assertRaises((OSError, ValueError)):
                    session.release_evidence()
                self.assertEqual(self.sentinel.read_text(), 'untouched')
            finally:
                session.close()

    def test_cleanup_rejects_replaced_daemon_child_directory(self):
        session = prepare_session(str(self.base), os.getuid())
        self.addCleanup(session.close)
        (session.run / 'root').rmdir()
        (session.run / 'root').symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            session.cleanup_data()
        self.assertEqual(self.sentinel.read_text(), 'untouched')

    def test_cleanup_never_follows_replaced_session_path(self):
        session = prepare_session(str(self.base), os.getuid())
        self.addCleanup(session.close)
        (session.run / 'root').mkdir(exist_ok=True)
        renamed = session.run.with_name(session.run.name + '-moved')
        session.run.rename(renamed)
        session.run.symlink_to(self.outside, target_is_directory=True)
        # Cleanup is fd-anchored; no lookup through the substituted session.
        session.cleanup_data()
        self.assertEqual(self.sentinel.read_text(), 'untouched')
        self.assertFalse((renamed / 'root').exists())
        self.assertTrue(session.run.is_symlink())

if __name__ == '__main__':
    unittest.main(verbosity=2)
