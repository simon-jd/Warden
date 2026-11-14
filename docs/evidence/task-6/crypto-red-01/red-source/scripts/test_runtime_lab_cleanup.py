#!/usr/bin/env python3
"""Fault injection on temp files and our own harmless child; no privileged lab."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from runtime_lab_paths import Session, prepare_session
from runtime_lab_runner import CleanupError, cleanup_owned


class OwnedCleanupTests(unittest.TestCase):
    def test_docker_cleanup_hands_back_only_verified_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / 'warden-lab'
            base.mkdir(mode=0o700)
            session = prepare_session(str(base), os.getuid())
            try:
                with patch('runtime_lab_paths.os.fchown', wraps=os.fchown) as chown:
                    cleanup_owned(None, None, None, False, session, release_evidence=True)
                self.assertEqual(set(os.listdir(session.fd)), {'containerd.toml', 'containerd.log'})
                self.assertEqual(len(chown.call_args_list), 3)
                self.assertTrue(all(call.args[1:] == (os.getuid(), -1) for call in chown.call_args_list))
                self.assertEqual(chown.call_args_list[-1].args[0], session.fd)
            finally:
                session.close()

    def test_retired_gate_markers_are_retained_and_returned_by_fd(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / 'warden-lab'
            base.mkdir(mode=0o700)
            session = prepare_session(str(base), os.getuid())
            try:
                gate = session.run / 'gate'
                gate.mkdir(mode=0o700)
                for name, data in {'node': 'node/authority', 'retirement': 'proof', 'retirement-binding': 'binding', 'admission': '', 'A'*26: 'revoked-uncertain\n'}.items():
                    target = gate / name
                    target.write_text(data)
                    target.chmod(0o600)
                cleanup_owned(None, None, None, False, session, release_evidence=True)
                self.assertEqual((gate / ('A'*26)).read_text(), 'revoked-uncertain\n')
                self.assertEqual((gate / 'retirement').read_text(), 'proof')
                (gate / 'unknown').write_text('must preserve')
                with self.assertRaises(ValueError): session.release_evidence()
                self.assertTrue((gate / 'unknown').exists())
            finally:
                session.close()

    def test_kill_write_failure_still_reaps_daemon_and_preserves_unknown_state(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / 'warden-lab'
            base.mkdir(mode=0o700)
            run = base / 'session-test'
            run.mkdir(mode=0o700)
            session = Session(str(base), os.open(base, os.O_RDONLY | os.O_DIRECTORY), run.name, os.open(run, os.O_RDONLY | os.O_DIRECTORY), os.getuid())
            self.addCleanup(session.close)
            for name in ('root', 'state', 'io'):
                (run / name).mkdir(mode=0o700)
                (run / name / 'preserve').write_text('unverified state')
            cgroup = Path(temp) / 'fake-cgroup'
            cgroup.mkdir()
            # A directory where the control file should be causes a real write
            # OSError. Missing cgroup.events makes subtree emptiness unverified.
            (cgroup / 'cgroup.kill').mkdir()
            cg_fd = os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, cg_fd)
            child = subprocess.Popen([sys.executable, '-B', '-c', 'import sys; print("READY", flush=True); sys.stdin.buffer.read(1)'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                self.assertEqual(child.stdout.readline(), b'READY\n')
                error = None
                try:
                    cleanup_owned(child, cg_fd, None, False, session, release_evidence=True)
                except BaseException as failure:
                    error = failure
                # A reaped child cannot be waited again through the OS API.
                with self.assertRaises(ChildProcessError):
                    os.waitpid(child.pid, os.WNOHANG)
                self.assertIsNotNone(child.poll(), 'cgroup.kill failure skipped owned daemon termination/reap')
                self.assertIsInstance(error, CleanupError, 'cleanup failures were not aggregated')
                self.assertEqual([phase for phase, _ in error.failures], ['kill cgroup', 'verify subtree empty'])
                self.assertIn('IsADirectoryError', str(error))
                self.assertIn('FileNotFoundError', str(error))
                for name in ('root', 'state', 'io'):
                    self.assertEqual((run / name / 'preserve').read_text(), 'unverified state')
                self.assertTrue((cgroup / 'cgroup.kill').is_dir())
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                child.stdin.close()
                child.stdout.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)

class RetirementCleanupTests(unittest.TestCase):
    # Break caught: runner acknowledges cleanup before reaping its own daemon or
    # after storage deletion failed; neither is a final quiescence proof.
    def test_owned_retirement_cleanup_reaps_and_propagates_data_failure(self):
        from runtime_lab_runner import retirement_cleanup
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)/'warden-lab'
            base.mkdir(mode=0o700)
            session=prepare_session(str(base),os.getuid())
            daemon=subprocess.Popen([sys.executable,'-B','-c','pass'])
            try:
                (session.run/'root').rmdir()
                (session.run/'root').write_text('replaced; preserve')
                with patch('runtime_lab_runner.populated',return_value=False):
                    with self.assertRaises(ValueError): retirement_cleanup(daemon,9,session)
                with self.assertRaises(ChildProcessError): os.waitpid(daemon.pid,os.WNOHANG)
                self.assertEqual((session.run/'root').read_text(),'replaced; preserve')
            finally:
                daemon.wait(timeout=5)
                session.close()
    def test_populated_node_does_not_delete_data(self):
        from runtime_lab_runner import retirement_cleanup
        class Owned:
            def wait(self, timeout): return 0
        class Data:
            def cleanup_data(self): raise AssertionError('deleted live node data')
        with patch('runtime_lab_runner.populated', return_value=True):
            with self.assertRaises(RuntimeError): retirement_cleanup(Owned(),9,Data())
