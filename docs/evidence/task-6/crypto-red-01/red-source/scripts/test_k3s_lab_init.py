import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import tempfile
import tomllib
from datetime import datetime
from unittest.mock import patch

SPEC = importlib.util.find_spec('k3s_lab_init')
if SPEC:
    import k3s_lab_init as init

SYSCTLS = {'vm/overcommit_memory': '1', 'vm/panic_on_oom': '0',
           'kernel/panic': '10', 'kernel/panic_on_oops': '1',
           'kernel/keys/root_maxkeys': '1000000', 'kernel/keys/root_maxbytes': '25000000'}


class InitTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(SPEC, 'fixed node controller is not implemented')

    def test_session_handshake_rejects_wrong_identity_before_any_target_write(self):
        self.assertTrue(callable(getattr(init, 'session_handshake', None)), 'owned readonly bind handshake missing')
        for mutation in ('device', 'inode', 'owner', 'mode', 'writable', 'shared', 'master', 'extra-mount', 'flag', 'host-ns', 'extra', 'signed'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / 'untouched'
                marker.write_bytes(b'never read or modify this target')
                info = root.stat()
                fields = [info.st_dev, info.st_ino, info.st_uid]
                if mutation in ('device', 'inode', 'owner'):
                    fields[('device', 'inode', 'owner').index(mutation)] += 1
                expected = ':'.join(map(str, fields))
                if mutation == 'extra': expected += ':1'
                if mutation == 'signed': expected = '+' + expected
                if mutation == 'mode': root.chmod(0o755)
                flags = 'rw' if mutation == 'writable' else 'ro'
                optional = 'shared:12' if mutation == 'shared' else ('master:12' if mutation == 'master' else '')
                mount = '12 10 259:3 /x /session ' + flags + ',relatime ' + optional + ' - ext4 /dev/x rw\n'
                if mutation == 'extra-mount': mount += mount
                if mutation == 'flag': mount = mount.replace('relatime', 'unknownflag')
                environment = {'WARDEN_LAB_SESSION_IDENTITY': expected, 'WARDEN_LAB_HOST_MOUNT_NS': 'mnt:[1]'}
                with patch.object(init, 'SESSION', root), patch.object(init, 'mountinfo', return_value=mount), patch.dict(os.environ, environment), patch.object(init.os, 'readlink', return_value='mnt:[1]' if mutation == 'host-ns' else 'mnt:[2]'), patch.object(init, 'remount_session') as remount:
                    with self.assertRaises(ValueError): init.run_node()
                    remount.assert_not_called()
                self.assertEqual(set(p.name for p in root.iterdir()), {'untouched'})
                self.assertEqual(marker.read_bytes(), b'never read or modify this target')

    def test_mount_smoke_only_checks_readonly_identity_and_live_remount_is_pinned(self):
        self.assertTrue(callable(getattr(init, 'session_handshake', None)), 'owned readonly bind handshake missing')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);info=root.stat();state={'ro': True};calls=[]
            environment = {'WARDEN_LAB_SESSION_IDENTITY': f'{info.st_dev}:{info.st_ino}:{info.st_uid}', 'WARDEN_LAB_HOST_MOUNT_NS': 'mnt:[1]'}
            def mounts():
                return '12 10 259:3 /x /session ' + ('ro' if state['ro'] else 'rw') + ',nosuid,nodev,relatime - ext4 /dev/x rw\n'
            def remount(fd, flags):
                observed=os.fstat(fd)
                calls.append((observed.st_dev,observed.st_ino,flags))
                state['ro']=False
            with patch.object(init, 'SESSION', root), patch.object(init, 'mountinfo', side_effect=mounts), patch.dict(os.environ,environment), patch.object(init.os,'readlink',return_value='mnt:[2]'), patch.object(init,'remount_session',side_effect=remount):
                init.session_handshake(live=False)
                self.assertEqual(calls, [])
                init.session_handshake(live=True)
                self.assertEqual(calls, [(info.st_dev,info.st_ino,4096|32|2|4|2097152)])
                self.assertEqual(list(root.iterdir()), [])

    def test_handshake_rechecks_retained_flags_after_remount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);info=root.stat()
            environment={'WARDEN_LAB_SESSION_IDENTITY':f'{info.st_dev}:{info.st_ino}:{info.st_uid}','WARDEN_LAB_HOST_MOUNT_NS':'mnt:[1]'}
            records=['12 10 259:3 /x /session ro,nosuid,relatime - ext4 /dev/x rw\n',
                     '12 10 259:3 /x /session rw,relatime - ext4 /dev/x rw\n']
            with patch.object(init,'SESSION',root),patch.object(init,'mountinfo',side_effect=records),patch.dict(os.environ,environment),patch.object(init.os,'readlink',return_value='mnt:[2]'),patch.object(init,'remount_session'):
                with self.assertRaises(ValueError):init.session_handshake(live=True)
                self.assertEqual(list(root.iterdir()), [])

    def test_sysctl_mismatch_or_writable_proc_sys_refuses_start(self):
        init.validate_kernel(SYSCTLS, True)
        for key in SYSCTLS:
            with self.subTest(key=key), self.assertRaises(ValueError):
                init.validate_kernel({**SYSCTLS, key: '99'}, True)
        with self.assertRaises(ValueError):
            init.validate_kernel(SYSCTLS, False)

    def test_fixed_kubelet_config_protects_host_and_limits_owned_subtree(self):
        config = init.kubelet_config()
        self.assertTrue(config['protectKernelDefaults'])
        self.assertEqual(config['cgroupRoot'], '/warden-lab')
        self.assertEqual(config['kubeletCgroups'], '/warden-lab/service')
        self.assertEqual(config['cgroupDriver'], 'cgroupfs')
        self.assertEqual(config['podPidsLimit'], 128)
        self.assertEqual(config['allowedUnsafeSysctls'], [])
        self.assertEqual(config['maxPods'], 8)

    def test_only_public_identity_fields_leave_the_controller(self):
        node = {'metadata': {'name': 'warden-node', 'uid': 'node-uid',
                            'annotations': {'secret': 'TOKEN'}},
                'status': {'conditions': [{'type': 'Ready', 'status': 'True'}],
                           'nodeInfo': {'kubeletVersion': 'v1.36.5+k3s1',
                                        'containerRuntimeVersion': 'containerd://2.3.4-k3s1.36'}}}
        namespaces = [{'metadata': {'name': name, 'uid': name + '-uid', 'annotations': {'secret': 'TOKEN'}}}
                      for name in ('kube-system', 'warden-lab')]
        result = init.public_identity(node, namespaces, 'a' * 64, 'b' * 64)
        self.assertEqual(result['node_uid'], 'node-uid')
        self.assertEqual(result['namespaces']['warden-lab'], 'warden-lab-uid')
        self.assertNotIn('TOKEN', json.dumps(result))
        self.assertNotIn('annotations', json.dumps(result))
        node['status']['conditions'][0]['status'] = 'False'
        with self.assertRaises(ValueError):
            init.public_identity(node, namespaces, 'a' * 64, 'b' * 64)

    def test_wrong_node_version_or_namespace_identity_fails(self):
        node = {'metadata': {'name': 'wrong', 'uid': 'node-uid'}, 'status': {}}
        with self.assertRaises(ValueError):
            init.public_identity(node, [], 'a' * 64, 'b' * 64)

    def test_handler_verification_rejects_flag_or_runtime_drift(self):
        config = {'version': 3, 'plugins': {'io.containerd.nri.v1.nri': {'disable': True}, 'io.containerd.cri.v1.runtime': {
            'containerd': {'runtimes': {'gvisor': {
                'runtime_type': 'io.containerd.runsc.v1',
                'options': {'TypeUrl': 'io.containerd.runsc.v1.options',
                            'ConfigPath': '/opt/warden/input/runsc.toml'}}}}}}}
        init.verify_handler(config)
        config['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['gvisor']['runtime_type'] = 'io.containerd.runc.v2'
        with self.assertRaises(ValueError):
            init.verify_handler(config)

    def test_template_disables_unused_nri_and_verification_refuses_socket_side_effect(self):
        config = tomllib.loads('version = 3\n' + init.TEMPLATE.replace('{{ template "base" . }}', ''))
        self.assertEqual(config['plugins'].get('io.containerd.nri.v1.nri'), {'disable': True})
        init.verify_handler(config)
        config['plugins']['io.containerd.nri.v1.nri']['disable'] = False
        with self.assertRaises(ValueError):
            init.verify_handler(config)

    def test_adopted_children_are_waited_until_reapable_with_a_deadline(self):
        self.assertTrue(callable(getattr(init, 'reap_adopted', None)), 'bounded adopted-child reap missing')
        with patch.object(init.os, 'waitpid', side_effect=[(0, 0), (23, 9), ChildProcessError]), patch.object(init.time, 'sleep') as sleep:
            init.reap_adopted()
            sleep.assert_called_once()
        with patch.object(init.os, 'waitpid', return_value=(0, 0)), patch.object(init.time, 'monotonic', side_effect=[0, 6]), patch.object(init.time, 'sleep'):
            with self.assertRaises(TimeoutError): init.reap_adopted()

    def test_real_subreaper_waits_for_delayed_adopted_grandchild(self):
        # Unprivileged process-local subreaper; no namespace/cgroup/Docker work.
        script = '''import ctypes, subprocess, sys
from k3s_lab_init import reap_adopted
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
command = 'import subprocess, sys; subprocess.Popen([sys.executable, "-c", "import time; time.sleep(.15)"])'
parent = subprocess.Popen([sys.executable, '-c', command])
parent.wait(timeout=5)
reap_adopted()
try:
 import os; os.waitpid(-1, os.WNOHANG)
except ChildProcessError:
 print('all adopted children reaped')
else:
 raise AssertionError('unreaped child')
'''
        result = subprocess.run([sys.executable, '-B', '-c', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'all adopted children reaped')

    def test_diagnostic_stage_emits_only_fixed_code_and_numeric_errno(self):
        import contextlib
        import io
        self.assertTrue(callable(getattr(init, 'diagnostic_stage', None)), 'safe failure stage missing')
        for error in (RuntimeError('SECRET'), OSError(5, 'SECRET')):
            output = io.StringIO()
            with contextlib.redirect_stderr(output), self.assertRaises(type(error)):
                with init.diagnostic_stage('adopted-reap'):
                    raise error
            result = json.loads(output.getvalue())
            self.assertEqual(result['stage'], 'adopted-reap')
            self.assertNotIn('SECRET', output.getvalue())
            self.assertTrue(set(result) <= {'stage', 'code', 'errno'})
        with self.assertRaises(ValueError):
            with init.diagnostic_stage('SECRET'): pass

    def test_fixed_client_directory_is_exclusive_private_and_preexisting_state_refused(self):
        self.assertTrue(callable(getattr(init, 'prepare_client_directory', None)), 'bounded client directory missing')
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'k3s-client'
            with patch.object(init, 'CLIENT_DIRECTORY', target):
                init.prepare_client_directory()
                self.assertEqual(target.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(list(target.iterdir()), [])
                with self.assertRaises(FileExistsError): init.prepare_client_directory()

    def test_host_cannot_call_smoke_or_forward_arbitrary_commands(self):
        for mode in ('smoke', 'mount-smoke', 'sh', 'kubectl'):
            result = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('k3s_lab_init.py')), mode], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_safe_observed_denial_lines_preserve_order_and_duplicates(self):
        module = 'time="2026-10-24T06:00:00Z" level=warning msg="Failed to load kernel module nft-expr-counter with modprobe"'
        sysctl = 'time="2026-10-24T06:00:01+00:00" level=error msg="Failed to set sysctl: open /proc/sys/net/ipv4/conf/all/forwarding: read-only file system"'
        log = '\n'.join([module, module, sysctl, 'time="now" level=info msg="token=DO_NOT_ARCHIVE"'])
        self.assertEqual(init.warning_lines(log), [module, module, sysctl])

    def test_warning_extra_fields_secret_prefixes_and_unknown_text_are_rejected(self):
        allowed = 'time="2026-10-24T06:00:00Z" level=warning msg="Failed to load kernel module overlay with modprobe"'
        for log in ('secret=TOKEN ' + allowed, allowed + ' token=TOKEN',
                    allowed.replace('06:00:00Z', 'TOKEN'),
                    'level=warning msg="unexpected secret=TOKEN"',
                    'W1024 06:00:00 unexpected secret=TOKEN',
                    allowed.replace('overlay', 'unknown-TOKEN')):
            with self.subTest(log=log):
                with self.assertRaises(ValueError) as caught:
                    init.warning_lines(log)
                self.assertNotIn('TOKEN', str(caught.exception))

    def test_source_backed_startup_templates_need_ready_window_and_redact_internal_fields(self):
        stamp = 'time="2026-10-24T06:00:01Z" '
        cases = [
            ('k3s', 'certificate-cache', stamp + 'level=warning msg="dynamiclistener 198.18.0.1:6443: no cached certificate available for preload - deferring certificate load until storage initialization or first client request"'),
            ('k3s', 'core-initializing', stamp + 'level=error msg="Sending HTTP/1.1 503 response to 198.18.0.1:12345: runtime core not ready"'),
            ('containerd', 'v3-migration', stamp + 'level=warning msg="Configuration migrated from version 3, use `containerd config migrate` to avoid migration" t="31.12µs"'),
            ('containerd', 'fsverity-unsupported', stamp + 'level=warning msg="failed check for fsverity support" error="enable fsverity failed: operation not supported" path=/proc/1/fd/6/root/agent/containerd/io.containerd.content.v1.content'),
        ]
        start = int(datetime.fromisoformat('2026-10-24T06:00:00+00:00').timestamp())
        for source, code, line in cases:
            with self.subTest(code=code):
                records = init.warning_lines(line, source=source, root='/proc/1/fd/6/root', ready_window=(start, start + 10))
                self.assertEqual(records[0]['template'], code)
                self.assertEqual(len(records[0]['sha256']), 64)
                self.assertNotIn('198.18', json.dumps(records))
                self.assertNotIn('/proc/', json.dumps(records))
                for bad in ('SECRET ' + line, line + ' SECRET', line.replace('level=', 'SECRET level='), line.replace('06:00:01', '06:00:11'), line.replace('06:00:01', '05:59:59')):
                    with self.assertRaises(ValueError): init.warning_lines(bad, source=source, root='/proc/1/fd/6/root', ready_window=(start, start + 10))
                with self.assertRaises(ValueError): init.warning_lines(line, source=source, root='/proc/1/fd/6/root')
                with self.assertRaises(ValueError): init.warning_lines(line, source='wrong', root='/proc/1/fd/6/root', ready_window=(start, start + 10))
                repeats = 241 if code == 'core-initializing' else 2
                with self.assertRaises(ValueError): init.warning_lines('\n'.join([line] * repeats), source=source, root='/proc/1/fd/6/root', ready_window=(start, start + 10))
        fsline = cases[-1][2]
        for bad in (fsline.replace('operation not supported', 'permission denied'), fsline.replace('/fd/6/', '/fd/7/'), fsline.replace('path=', 'secret=TOKEN path=')):
            with self.assertRaises(ValueError): init.warning_lines(bad, source='containerd', root='/proc/1/fd/6/root', ready_window=(start, start + 10))

    def test_final_readiness_recheck_refuses_persistent_api_or_node_failure(self):
        self.assertTrue(callable(getattr(init, 'confirm_ready', None)), 'final Ready check missing')
        for api, ready in ((b'ok', True), (b'failed', True), (b'ok', False)):
            node = {'status': {'conditions': [{'type': 'Ready', 'status': str(ready)}]}}
            calls = []
            def query(args):
                calls.append(args)
                return api if args == ['get', '--raw=/readyz'] else json.dumps(node).encode()
            with patch.object(init.time, 'sleep') as sleep:
                if api == b'ok' and ready: self.assertEqual(init.confirm_ready(query), node)
                else:
                    with self.assertRaises(ValueError): init.confirm_ready(query)
                sleep.assert_called_once_with(1)

    def test_separate_containerd_warnings_cannot_bypass_clean_main_log(self):
        self.assertTrue(callable(getattr(init, 'startup_denials', None)), 'bounded two-log gate missing')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'private.log').write_text('level=info msg="ready"\n')
            path = root / 'agent/containerd/containerd.log'
            path.parent.mkdir(parents=True)
            path.write_text('time="2026-10-24T06:00:00Z" level=warning msg="unexpected TOKEN"\n')
            with self.assertRaises(ValueError) as caught:
                init.startup_denials(root)
            self.assertNotIn('TOKEN', str(caught.exception))
            path.write_text('level=info msg="ready"\n')
            self.assertEqual(init.startup_denials(root), [])
            path.unlink()
            with self.assertRaises((ValueError, FileNotFoundError)):
                init.startup_denials(root)

    def test_startup_diagnostics_total_bound_and_symlinks_fail_closed(self):
        self.assertTrue(callable(getattr(init, 'startup_denials', None)), 'bounded two-log gate missing')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'private.log').write_bytes(b'x' * 16000001)
            path = root / 'agent/containerd/containerd.log'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'x' * 16000000)
            with self.assertRaises(ValueError):
                init.startup_denials(root)
            path.unlink()
            path.symlink_to(root / 'private.log')
            with self.assertRaises((ValueError, OSError)):
                init.startup_denials(root)


    def test_private_log_reader_rejects_fifo_directory_and_symlink_ancestor(self):
        for kind in ('fifo', 'directory', 'ancestor'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'private.log').write_bytes(b'')
                if kind == 'ancestor':
                    (root / 'elsewhere/containerd').mkdir(parents=True)
                    (root / 'elsewhere/containerd/containerd.log').write_bytes(b'')
                    (root / 'agent').symlink_to(root / 'elsewhere')
                else:
                    path = root / 'agent/containerd/containerd.log'
                    path.parent.mkdir(parents=True)
                    if kind == 'fifo':
                        os.mkfifo(path)
                    else:
                        path.mkdir()
                with self.assertRaises((ValueError, OSError)):
                    init.startup_denials(root)

    def test_rotated_containerd_history_cannot_bypass_startup_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'private.log').write_text('level=info msg="ready"\n')
            path = root / 'agent/containerd/containerd.log'
            path.parent.mkdir(parents=True)
            path.write_text('level=info msg="ready"\n')
            (path.parent / 'containerd-2026-10-24T06-00-00.000.log.gz').write_bytes(b'private old log')
            with self.assertRaises(ValueError):
                init.startup_denials(root)

    def test_log_growth_after_metadata_check_still_obeys_combined_read_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'private.log'
            path.write_bytes(b'')
            original = os.fstat
            def grow(fd):
                info = original(fd)
                if info.st_ino == path.stat().st_ino:
                    path.write_bytes(b'x' * 32000001)
                return info
            with patch('k3s_lab_init.os.fstat', grow), self.assertRaises(ValueError):
                init.startup_denials(root)

    def test_successful_cleanup_exports_actual_denials_and_removes_private_data(self):
        from runtime_lab_paths import prepare_session
        with tempfile.TemporaryDirectory() as temporary:
            session = prepare_session(temporary, os.getuid())
            try:
                root = Path(session.anchored('root'))
                (root / 'private.log').write_text('level=info msg="SECRET"\n')
                path = root / 'agent/containerd/containerd.log'
                path.parent.mkdir(parents=True)
                line = 'time="2026-10-24T06:00:00Z" level=warning msg="Failed to load kernel module overlay with modprobe"'
                path.write_text(line + '\n' + line + '\n')
                denials = init.startup_denials(root)
                self.assertEqual(denials, [{'source': 'containerd', 'line': line}] * 2)
                Path(session.anchored('containerd.log')).write_text(json.dumps(denials))
                init.finish_node(None, None, None, False, session, success=True)
                self.assertEqual(set(os.listdir(session.fd)), {'containerd.log', 'containerd.toml'})
                self.assertNotIn('SECRET', Path(session.anchored('containerd.log')).read_text())
            finally:
                session.close()

    def test_failed_bootstrap_retains_bounded_private_snapshot_and_reaps(self):
        self.assertTrue(callable(getattr(init, 'finish_node', None)), 'failure snapshot cleanup missing')
        from runtime_lab_paths import prepare_session
        for log_state in ('normal', 'missing', 'oversized', 'symlink'):
            with self.subTest(log_state=log_state), tempfile.TemporaryDirectory() as temporary:
                session = prepare_session(temporary, os.getuid())
                child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'], stdin=subprocess.PIPE)
                try:
                    root = Path(session.anchored('root'))
                    (root / 'private.log').write_bytes(b'SECRET_MAIN\n')
                    path = root / 'agent/containerd/containerd.log'
                    path.parent.mkdir(parents=True)
                    if log_state == 'symlink':
                        path.symlink_to(root / 'private.log')
                        with self.assertRaises(OSError):
                            init.finish_node(child, None, None, False, session, success=False)
                    else:
                        if log_state != 'missing':
                            path.write_bytes(b'SECRET_CONTAINERD\n' if log_state == 'normal' else b'x' * 32000001)
                        init.finish_node(child, None, None, False, session, success=False)
                    self.assertIsNotNone(child.poll(), 'diagnostic errors must not skip child reap')
                    self.assertFalse(root.exists(), 'ordinary owned data cleanup still runs')
                    snapshot = Path(session.anchored('startup-private.log'))
                    self.assertLessEqual(snapshot.stat().st_size, 32000000)
                    self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                    if log_state == 'normal':
                        self.assertIn(b'SECRET_MAIN', snapshot.read_bytes())
                        self.assertIn(b'SECRET_CONTAINERD', snapshot.read_bytes())
                    public = Path(session.anchored('containerd.log')).read_bytes()
                    self.assertNotIn(b'SECRET', public)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait()
                    child.stdin.close()
                    session.close()


if __name__ == '__main__':
    unittest.main()
