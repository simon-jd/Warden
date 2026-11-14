"""Behavioral regressions for the retained bootstrap, with no Docker work."""
import os
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, Mock

import k3s_lab_init as init
import k3s_lab_recover as host
import k3s_lab_recovery_init as inner


class NoSwapTest(unittest.TestCase):
    def test_kubelet_tolerates_visible_host_swap_but_disallows_workload_swap(self):
        config = init.kubelet_config()
        self.assertIs(config['failSwapOn'], False)
        self.assertEqual(config['memorySwap'], {'swapBehavior': 'NoSwap'})
        self.assertTrue(config['protectKernelDefaults'])
        self.assertEqual(config['cgroupRoot'], '/warden-lab')

    def test_private_outer_swap_check_rejects_missing_nonzero_alias_and_oversize(self):
        self.assertTrue(callable(getattr(init, 'verify_outer_noswap', None)))
        for mutation in ('zero', 'nonzero', 'unlimited', 'missing', 'symlink', 'fifo', 'directory', 'oversize'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); target = root / 'memory.swap.max'
                if mutation == 'symlink':
                    (root / 'outside').write_text('0\n'); target.symlink_to(root / 'outside')
                elif mutation == 'fifo': os.mkfifo(target)
                elif mutation == 'directory': target.mkdir()
                elif mutation != 'missing': target.write_text({'zero': '0\n', 'nonzero': '1\n', 'unlimited': 'max\n', 'oversize': '0\n' + ' ' * 64}[mutation])
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    if mutation == 'zero': init.verify_outer_noswap(fd)
                    else:
                        with self.assertRaises((ValueError, OSError)): init.verify_outer_noswap(fd)
                finally: os.close(fd)

    def test_swap_refusal_happens_before_session_creation_or_k3s_exec(self):
        for value in ('1\n', 'max\n'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); (root / 'memory.swap.max').write_text(value)
                original = os.open
                def open_owned(path, flags, *args, **kwargs):
                    return original(root if path == '/sys/fs/cgroup' else path, flags, *args, **kwargs)
                with patch.object(init, 'session_handshake'), patch.object(init, 'prepare_client_directory'), patch.object(init, 'kernel_state'), patch.object(init, 'bootstrap'), patch.object(init.os, 'open', side_effect=open_owned), patch.object(init, 'prepare_session', side_effect=RuntimeError('session reached')) as prepare, patch.object(init.subprocess, 'Popen') as launch:
                    with self.assertRaises(ValueError): init.run_node()
                    prepare.assert_not_called(); launch.assert_not_called()

    def test_swap_drift_during_cleanup_fails_postflight_and_utc_is_fixed(self):
        from runtime_lab_paths import prepare_session
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            outer = Path(temporary); cgroup = outer / 'cgroup'; cgroup.mkdir(); (cgroup / 'memory.swap.max').write_text('0\n')
            original_open, original_stat = os.open, os.stat
            def open_owned(path, flags, *args, **kwargs):
                return original_open(cgroup if path == '/sys/fs/cgroup' else path, flags, *args, **kwargs)
            def stat_owned(path, *args, **kwargs):
                return original_stat(outer if str(path) == '/session' else path, *args, **kwargs)
            stack.enter_context(patch.object(init.os, 'open', side_effect=open_owned))
            stack.enter_context(patch.object(init.os, 'stat', side_effect=stat_owned))
            for name in ('session_handshake', 'prepare_client_directory', 'bootstrap', 'write_control', 'reap_adopted'):
                stack.enter_context(patch.object(init, name))
            stack.enter_context(patch.object(init, 'kernel_state', return_value=init.KERNEL_DEFAULTS))
            stack.enter_context(patch.object(init, 'prepare_session', side_effect=lambda *args: prepare_session(str(outer), os.getuid())))
            stack.enter_context(patch.object(init.subprocess, 'run'))
            launch = stack.enter_context(patch.object(init.subprocess, 'Popen', return_value=Mock(poll=Mock(return_value=1))))
            stack.enter_context(patch.object(init, 'finish_node', side_effect=lambda *args, **kw: (cgroup / 'memory.swap.max').write_text('1\n')))
            output = io.StringIO(); stack.enter_context(contextlib.redirect_stdout(output)); stack.enter_context(contextlib.redirect_stderr(output))
            with self.assertRaises(ValueError) as caught: init.run_node()
            self.assertIsNotNone(launch.call_args, output.getvalue() + str(caught.exception))
            self.assertEqual(launch.call_args.kwargs['env']['TZ'], 'UTC')
            self.assertIn('"stage": "kernel-postflight"', output.getvalue())
            self.assertNotIn('empty-reaped-deleted', output.getvalue())


class FixedSceneArchiveTest(unittest.TestCase):
    def test_recovery_archive_requires_original_held_inode_and_exact_shape(self):
        self.assertTrue(callable(getattr(host, 'verify_archive', None)))
        for mutation in ('none', 'replacement', 'symlink', 'hardlink', 'size', 'mode'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); tar = root / 'rootfs.tar'; tar.write_bytes(b'tar'); tar.chmod(0o600)
                info = tar.stat(); directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY); fd = os.open(tar, os.O_RDONLY)
                if mutation == 'replacement': tar.rename(root / 'original'); tar.write_bytes(b'tar'); tar.chmod(0o600)
                if mutation == 'symlink': tar.rename(root / 'original'); tar.symlink_to(root / 'original')
                if mutation == 'hardlink': os.link(tar, root / 'alias')
                if mutation == 'size': tar.write_bytes(b'changed')
                if mutation == 'mode': tar.chmod(0o644)
                try:
                    with patch.object(host, 'TAR_IDENTITY', (info.st_dev, info.st_ino, os.getuid())), patch.object(host, 'TAR_SIZE', 3):
                        if mutation == 'none': host.verify_archive(directory, fd)
                        else:
                            with self.assertRaises(ValueError): host.verify_archive(directory, fd)
                    self.assertTrue(tar.exists())
                finally: os.close(fd); os.close(directory)


class StartupTemplateTest(unittest.TestCase):
    START = int(datetime(2026, 10, 24, 6, 0, tzinfo=timezone.utc).timestamp())
    CASES = (
        ('empty-api:apps/v1beta1', 1, 'W1024 06:00:01.123456      12 genericapiserver.go:798] Skipping API apps/v1beta1 because it has no resources.'),
        ('empty-metrics-manifest', 3, 'E1024 06:00:01.123456      12 options.go:205] The manifest file is empty, ignoring.'),
        ('missing-machine-id', 1, 'W1024 06:00:01.123456      12 info.go:54] Couldn\'t collect info from any of the files in "/etc/machine-id,/var/lib/dbus/machine-id"'),
        ('reset-endpoints', 1, 'W1024 06:00:01.123456      12 lease.go:265] Resetting endpoints for master service "kubernetes" to [198.18.0.1]'),
    )
    NS_CASES = (
        ('lease-namespace', 'E1024 06:00:01.123456      12 controller.go:201] "Failed to ensure lease exists, will retry" err="namespaces \\"kube-system\\" not found" interval="200ms"'),
        ('service-namespace', 'E1024 06:00:01.123456      12 controller.go:95] Unable to perform initial Kubernetes service initialization: namespaces "default" not found'),
        ('legacy-configmap-namespace', 'time="2026-10-24T06:00:01Z" level=error msg="Error while syncing ConfigMap" configmap=kube-system/kube-apiserver-legacy-service-account-token-tracking error="namespaces \\"kube-system\\" not found" logger=k3s/UnhandledError'),
    )

    def test_four_exact_source_templates_pass_only_with_bounded_verified_startup(self):
        for enum, limit, line in self.CASES:
            with self.subTest(enum=enum):
                entries = init.warning_lines('\n'.join([line] * limit), source='k3s', ready_window=(self.START, self.START + 10))
                self.assertEqual([x['template'] for x in entries], [enum] * limit)
                self.assertTrue(all(len(x['sha256']) == 64 for x in entries))
                self.assertNotIn('198.18', str(entries)); self.assertNotIn('/etc/', str(entries)); self.assertNotIn('06:00:', str(entries))
                with self.assertRaises(ValueError):
                    init.warning_lines('\n'.join([line] * (limit + 1)), source='k3s', ready_window=(self.START, self.START + 10))
                for window in (None, (self.START + 2, self.START + 10), (self.START - 10, self.START + 1)):
                    with self.assertRaises(ValueError): init.warning_lines(line, source='k3s', ready_window=window)
                with self.assertRaises(ValueError): init.warning_lines(line, source='containerd', ready_window=(self.START, self.START + 10))
        self.assertEqual(init.warning_lines('', source='k3s', ready_window=(self.START, self.START + 10)), [])

    def test_new_templates_reject_wrong_caller_severity_paths_addresses_and_secrets(self):
        for enum, limit, line in self.CASES:
            bad = ['SECRET ' + line, line + ' SECRET', line.replace('.go:', '.go:1'), line.replace('06:00:', '06:01:')]
            bad += [('E' if line[0] == 'W' else 'W') + line[1:]]
            if enum.startswith('empty-api:'): bad += [line.replace('apps/v1beta1', 'apps/v1'), line.replace('apps/v1beta1', 'unknown.example/v1beta1')]
            if enum == 'missing-machine-id': bad += [line.replace('/etc/machine-id', '/etc/credentials')]
            if enum == 'reset-endpoints': bad += [line.replace('198.18.0.1', '198.18.0.2'), line.replace('kubernetes', 'secret')]
            for changed in bad:
                with self.subTest(enum=enum, changed=changed), self.assertRaises(ValueError):
                    init.warning_lines(changed, source='k3s', ready_window=(self.START, self.START + 10))

    def test_klog_utc_window_handles_year_boundary_and_rejects_ambiguous_windows(self):
        line = self.CASES[1][2].replace('1024 06:00:01', '0101 00:00:01')
        start = int(datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())
        self.assertEqual(len(init.warning_lines(line, source='k3s', ready_window=(start, start + 5))), 1)
        for window in ((start, start + 370 * 86400), (start + 2, start), (start, True)):
            with self.assertRaises(ValueError): init.warning_lines(line, source='k3s', ready_window=window)

    def test_namespace_races_require_exact_final_namespace_evidence_and_single_occurrence(self):
        for enum, line in self.NS_CASES:
            with self.subTest(enum=enum):
                kwargs = {'source': 'k3s', 'ready_window': (self.START, self.START + 10), 'verified_namespaces': frozenset({'default', 'kube-system'})}
                self.assertEqual(init.warning_lines(line, **kwargs)[0]['template'], enum)
                for names in (frozenset(), frozenset({'default'}), frozenset({'kube-system'})):
                    with self.assertRaises(ValueError): init.warning_lines(line, **{**kwargs, 'verified_namespaces': names})
                for bad in ('SECRET ' + line, line + ' SECRET', line.replace('not found', 'forbidden'), line.replace('kube-system', 'other'), line.replace('default', 'other'), line + '\n' + line,
                            line.replace('06:00:01', '06:00:10'), line.replace('.go:', '.go:1'),
                            ('W' + line[1:]) if line.startswith('E') else line.replace('level=error', 'level=warning')):
                    if bad != line:
                        with self.assertRaises(ValueError): init.warning_lines(bad, **kwargs)
                with self.assertRaises(ValueError): init.warning_lines(line, **{**kwargs, 'source': 'containerd'})
                with self.assertRaises(ValueError): init.warning_lines(line, **{**kwargs, 'ready_window': None})

    def test_namespace_recheck_only_returns_fixed_names_after_exact_active_identity(self):
        self.assertTrue(callable(getattr(init, 'confirm_bootstrap_namespaces', None)))
        for fault in (None, 'missing', 'wrong-name', 'uid', 'deleting', 'terminating'):
            calls = []
            def query(args):
                calls.append(args); name = args[2]
                if fault == 'missing' and name == 'default': raise ValueError('not ready')
                value = {'metadata': {'name': name, 'uid': 'public-uid', 'annotations': {'secret': 'SECRET'}}, 'status': {'phase': 'Active'}}
                if fault == 'wrong-name': value['metadata']['name'] = 'other'
                if fault == 'uid': value['metadata']['uid'] = ''
                if fault == 'deleting': value['metadata']['deletionTimestamp'] = 'present'
                if fault == 'terminating': value['status']['phase'] = 'Terminating'
                return json.dumps(value).encode()
            if fault:
                with self.subTest(fault=fault), self.assertRaises(ValueError): init.confirm_bootstrap_namespaces(query)
            else:
                self.assertEqual(init.confirm_bootstrap_namespaces(query), frozenset({'default', 'kube-system'}))
                self.assertEqual(calls, [['get', 'namespace', name, '-o=json'] for name in ('default', 'kube-system')])

    def test_empty_api_limits_are_per_fixed_version_and_shutdown_errors_stay_rejected(self):
        line = self.CASES[0][2]
        other = line.replace('apps/v1beta1', 'apps/v1beta2')
        kwargs = {'source': 'k3s', 'ready_window': (self.START, self.START + 10)}
        self.assertEqual(len(init.warning_lines(line + '\n' + other, **kwargs)), 2)
        with self.assertRaises(ValueError): init.warning_lines(line + '\n' + other + '\n' + line, **kwargs)
        for message in ('Failed to migrate node-password secrets: context canceled',
                        'Shutdown request received: kubelet exited', 'running with swap on is not supported'):
            with self.assertRaises(ValueError):
                init.warning_lines('time="2026-10-24T06:00:01Z" level=error msg=' + json.dumps(message), **kwargs)


if __name__ == '__main__': unittest.main()
