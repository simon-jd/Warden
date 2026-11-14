"""Scoped synthetic boundaries for fourth-scene recovery and readiness diagnostics."""
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

import k3s_lab as lab
import k3s_lab_init as init
import k3s_lab_recover as host
import k3s_lab_recovery_init as inner
from runtime_lab_paths import prepare_session

RESOURCE = {'uid': 0, 'nofile_soft': 1024, 'nofile_hard': 2048,
            'fd_entries': 7, 'inotify_result': 'opened', 'inotify_errno': 0}


def proof(record=RESOURCE):
    return json.dumps({'resource_diagnostic': record}, sort_keys=True) + '\n' + inner.MARKER + '\n'


class ImageDirectoryTest(unittest.TestCase):
    def test_packaged_empty_flexvolume_directory_exists_with_root_owned_parents(self):
        # Exercise the actual tar writer with synthetic input bytes; no runtime,
        # download, ELF execution, image build/import or large material unpack.
        elf = bytearray(64); elf[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', elf, 18, 62)
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            archive = Path(temporary) / 'root.tar'; manifest = Path(temporary) / 'manifest.json'
            stack.enter_context(patch.object(lab, 'verify', side_effect=lambda data, pin: data))
            stack.enter_context(patch.object(lab, 'read_trusted', return_value=b'synthetic input'))
            stack.enter_context(patch.object(lab, 'embedded_k3s', return_value={}))
            stack.enter_context(patch.object(lab, 'regular_files', return_value={}))
            stack.enter_context(patch.object(lab, 'select_inputs', return_value=({'usr/bin/k3s': bytes(elf)}, {})))
            stack.enter_context(patch.object(lab.os, 'walk', return_value=[]))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            lab.package(archive, manifest)
            with tarfile.open(archive) as packed:
                names = packed.getnames()
                directory = 'usr/libexec/kubernetes/kubelet-plugins/volume/exec'
                for path in (Path(directory), *Path(directory).parents):
                    if str(path) == '.': continue
                    self.assertIn(str(path), names)
                    member = packed.getmember(str(path))
                    self.assertTrue(member.isdir())
                    self.assertEqual((member.uid, member.gid, member.mode), (0, 0, 0o755))
                self.assertFalse(any(name.startswith(directory + '/') for name in names))


class FourthRecoveryTest(unittest.TestCase):
    def test_only_fourth_scene_and_exact_tar_are_selected(self):
        self.assertEqual(host.ORIGINAL, '9a22e3c1817441fa2c4f50616e68a333d2a06c98641d430a05a810ea3f7cac50')
        self.assertEqual(host.IMAGE, 'sha256:2504a55c791dba7ca00cadae8b11f937aea70ac9149243eb83e590d343bc44a3')
        self.assertEqual(host.LABELS, {'owner': 'codex-warden', 'project': 'warden', 'session': 'b5370b6ce57638aee676a14c3c272592', 'ttl': '2026-10-24T19:09:18Z'})
        self.assertEqual(inner.OUTER_IDENTITY, (66307, 56143028, 1000))
        self.assertEqual(inner.CHILD_IDENTITY, (66307, 56143043, 0))
        self.assertEqual(inner.CHILD, 'session-7ca9caee772671b1')
        self.assertEqual(inner.FILES, {'containerd.toml': 124, 'containerd.log': 0, 'startup-private.log': 154227})
        self.assertEqual(host.TAR_IDENTITY, (66307, 56143030, 1000))
        self.assertEqual(host.TAR_SIZE, 496619520)

    def test_self_probe_is_single_bounded_and_closes_success_without_reading_targets(self):
        self.assertTrue(callable(getattr(inner, 'resource_diagnostic', None)))
        for errno, expected in ((0, 'opened'), (24, 'emfile'), (23, 'enfile'), (13, 'other')):
            with self.subTest(errno=errno), contextlib.ExitStack() as stack:
                libc = Mock(); libc.inotify_init1.return_value = 71 if not errno else -1
                stack.enter_context(patch.object(inner.ctypes, 'CDLL', return_value=libc))
                stack.enter_context(patch.object(inner.ctypes, 'get_errno', return_value=errno))
                stack.enter_context(patch.object(inner.resource, 'getrlimit', return_value=(1024, 2048)))
                stack.enter_context(patch.object(inner.os, 'getuid', return_value=0))
                listing = stack.enter_context(patch.object(inner.os, 'scandir', return_value=contextlib.nullcontext(iter([object()] * 7))))
                close = stack.enter_context(patch.object(inner.os, 'close'))
                targets = stack.enter_context(patch.object(inner.os, 'readlink', side_effect=AssertionError('no FD targets')))
                self.assertEqual(inner.resource_diagnostic(), {**RESOURCE, 'inotify_result': expected, 'inotify_errno': errno})
                listing.assert_called_once_with('/proc/self/fd')
                libc.inotify_init1.assert_called_once_with(os.O_CLOEXEC | os.O_NONBLOCK)
                if errno: close.assert_not_called()
                else: close.assert_called_once_with(71)
                targets.assert_not_called()

    def test_probe_refuses_large_fd_inventory_before_inotify_and_close_failure_propagates(self):
        self.assertTrue(callable(getattr(inner, 'resource_diagnostic', None)))
        with patch.object(inner.os, 'scandir', return_value=contextlib.nullcontext(iter([object()] * 4097))), patch.object(inner.ctypes, 'CDLL') as libc:
            with self.assertRaises(ValueError): inner.resource_diagnostic()
            libc.assert_not_called()
        libc = Mock(); libc.inotify_init1.return_value = 71
        with patch.object(inner.os, 'scandir', return_value=contextlib.nullcontext(iter([object()] * 7))), patch.object(inner.os, 'getuid', return_value=0), patch.object(inner.resource, 'getrlimit', return_value=(1024, 2048)), patch.object(inner.ctypes, 'CDLL', return_value=libc), patch.object(inner.os, 'close', side_effect=OSError('PRIVATE')) as close:
            with self.assertRaises(OSError): inner.resource_diagnostic()
            close.assert_called_once_with(71)

    def test_host_accepts_only_exact_bounded_diagnostic_and_original_marker(self):
        self.assertTrue(callable(getattr(host, 'recovery_proof', None)))
        self.assertEqual(host.recovery_proof(proof()), RESOURCE)
        for record in ({**RESOURCE, 'inotify_result': 'emfile', 'inotify_errno': 24},
                       {**RESOURCE, 'nofile_soft': -1, 'nofile_hard': -1}):
            self.assertEqual(host.recovery_proof(proof(record)), record)
        invalid = [inner.MARKER, proof() + 'SECRET\n', 'SECRET\n' + proof(), proof().replace(inner.MARKER, '{}'),
                   proof().replace('\n', '\r\n'), proof().rstrip('\n')]
        for key, value in (('uid', 1000), ('fd_entries', 4097), ('fd_entries', True), ('fd_entries', -1),
                           ('nofile_soft', 4096), ('nofile_hard', 1 << 63), ('nofile_soft', 'SECRET'),
                           ('inotify_result', 'SECRET'), ('inotify_errno', 24), ('inotify_errno', 4096)):
            invalid.append(proof({**RESOURCE, key: value}))
        invalid.extend([proof({**RESOURCE, 'extra': 'SECRET'}), proof({key: value for key, value in RESOURCE.items() if key != 'uid'}),
                        proof().replace('"uid": 0', '"uid": 1, "uid": 0'), proof().replace('"uid": 0', '"uid": 0.0')])
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError) as caught:
                host.recovery_proof(value)
            self.assertNotIn('SECRET', str(caught.exception))


class ReadinessDiagnosticTest(unittest.TestCase):
    def test_actual_query_loop_reports_one_fixed_phase_without_private_bodies(self):
        phases = ('api-query', 'api-body', 'node-query', 'node-json', 'node-ready')
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
                outer = Path(temporary); cgroup = outer / 'cgroup'; cgroup.mkdir(); (cgroup / 'memory.swap.max').write_text('0\n')
                original_open, original_stat = os.open, os.stat
                stack.enter_context(patch.object(init.os, 'open', side_effect=lambda path, flags, *a, **kw: original_open(cgroup if path == '/sys/fs/cgroup' else path, flags, *a, **kw)))
                stack.enter_context(patch.object(init.os, 'stat', side_effect=lambda path, *a, **kw: original_stat(outer if str(path) == '/session' else path, *a, **kw)))
                for name in ('session_handshake', 'prepare_client_directory', 'bootstrap', 'write_control', 'reap_adopted', 'finish_node'):
                    stack.enter_context(patch.object(init, name))
                stack.enter_context(patch.object(init, 'kernel_state', return_value=init.KERNEL_DEFAULTS))
                stack.enter_context(patch.object(init, 'prepare_session', side_effect=lambda *a: prepare_session(str(outer), os.getuid())))
                stack.enter_context(patch.object(init.subprocess, 'Popen', return_value=Mock(poll=Mock(return_value=None))))
                stack.enter_context(patch.object(init.time, 'monotonic', side_effect=(100, 100, 341)))
                stack.enter_context(patch.object(init.time, 'sleep'))
                queries = []
                def run(args, **kwargs):
                    if args[0] == '/usr/bin/ip': return subprocess.CompletedProcess(args, 0)
                    queries.append(args)
                    self.assertEqual(args[:1], ['/usr/bin/kubectl'])
                    self.assertEqual(args[2], '--request-timeout=3s')
                    self.assertEqual(kwargs['env'], {'PATH': '/usr/bin', 'HOME': '/run'})
                    self.assertEqual(kwargs['timeout'], 5)
                    api = args[3:] == ['get', '--raw=/readyz']
                    if phase == ('api-query' if api else 'node-query'):
                        return subprocess.CompletedProcess(args, 1, b'PRIVATE-BODY', b'PRIVATE-STDERR')
                    data = b'ok' if api else b'{"status":{"conditions":[]},"private":"PRIVATE-NODE"}'
                    if api and phase == 'api-body': data = b'PRIVATE-BODY'
                    if not api and phase == 'node-json': data = b'PRIVATE-BAD-JSON'
                    return subprocess.CompletedProcess(args, 0, data, b'PRIVATE-STDERR')
                stack.enter_context(patch.object(init.subprocess, 'run', side_effect=run))
                output = io.StringIO(); stack.enter_context(contextlib.redirect_stdout(output)); stack.enter_context(contextlib.redirect_stderr(output))
                with self.assertRaises(TimeoutError): init.run_node()
                rows = [json.loads(line) for line in output.getvalue().splitlines()]
                reports = [row['readiness_diagnostic'] for row in rows if 'readiness_diagnostic' in row]
                self.assertEqual(reports, [{'last_stage': phase, 'attempts': 1, 'failures': {name: int(name == phase) for name in phases}}])
                self.assertNotIn('PRIVATE', output.getvalue())
                self.assertEqual(len(queries), 1 if phase.startswith('api-') else 2)


if __name__ == '__main__': unittest.main()
