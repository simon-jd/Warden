import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

try:
    from attacks.atomic import emulate
except ImportError:
    try:
        import emulate
    except ImportError:
        emulate = None


class AtomicTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(emulate, 'Atomic wrapper missing')

    def target(self):
        return {'Id': 'a' * 64, 'Name': '/warden-lab-atomic-case',
                'Image': 'sha256:' + 'b' * 64, 'State': {'Running': True}, 'Mounts': [],
                'Config': {'Labels': {'warden.lab': 'warden-lab'}},
                'HostConfig': {'NetworkMode': 'none', 'Privileged': False,
                               'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                               'PidMode': '', 'IpcMode': 'private', 'Binds': [],
                               'SecurityOpt': ['no-new-privileges:true']}}

    def test_guard_accepts_only_isolated_dedicated_target(self):
        self.assertEqual(emulate.guard_container(self.target()), 'a' * 64)
        for section, key, value in [('HostConfig', 'NetworkMode', 'host'),
                                    ('HostConfig', 'Privileged', True),
                                    ('HostConfig', 'ReadonlyRootfs', False),
                                    ('HostConfig', 'CapDrop', []),
                                    ('HostConfig', 'SecurityOpt', []),
                                    ('HostConfig', 'PidMode', 'host'),
                                    ('HostConfig', 'Binds', ['/tmp:/host'])]:
            target = self.target()
            target[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                emulate.guard_container(target)
        target = self.target()
        target['Mounts'] = [{'Source': '/'}]
        with self.assertRaises(ValueError):
            emulate.guard_container(target)
        target = self.target()
        target['Config']['Labels'] = {}
        with self.assertRaises(ValueError):
            emulate.guard_container(target)

    def test_extracts_reviewed_official_guid_and_rejects_changed_command(self):
        source = '- name: Hostname Discovery\n  auto_generated_guid: 486e88ea-4f56-470f-9b57-3f4d73f39133\n  supported_platforms:\n  - linux\n  - macos\n  executor:\n    command: |\n      hostname\n    name: sh\n'
        self.assertEqual(emulate.atomic_command(source), 'hostname\n')
        with self.assertRaises(ValueError):
            emulate.atomic_command(source.replace('      hostname', '      rm -rf /'))
        with self.assertRaises(ValueError):
            emulate.atomic_command(source.replace('  - linux', '  - windows'))

    def test_execution_record_has_exact_metrics_contract(self):
        row = emulate.execution_record('exec-1', 'run-1', 'T1082', '2026-11-13T00:00:00Z', 0)
        self.assertEqual(set(row), {'execution_id', 'run_id', 'technique_id', 'executed_at', 'outcome'})
        self.assertEqual(row['outcome'], 'succeeded')
        self.assertEqual(emulate.execution_record('e', 'r', 'T1082', 't', 124)['outcome'], 'failed')

    def test_exclusive_outputs_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'result.json'
            emulate.write_new_json(path, {'one': 1})
            with self.assertRaises(FileExistsError):
                emulate.write_new_json(path, {'two': 2})
            self.assertEqual(json.loads(path.read_text()), {'one': 1})

class AtomicIntegrationTests(unittest.TestCase):
    def test_verifies_actual_git_object_and_rejects_wrong_digest(self):
        import hashlib
        import shutil
        import subprocess
        if emulate is None:
            self.fail('Atomic wrapper missing')
        git = shutil.which('git')
        source = '- name: Hostname Discovery\n  auto_generated_guid: ' + emulate.GUID + '\n  supported_platforms:\n  - linux\n  executor:\n    command: |\n      hostname\n    name: sh\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / emulate.SOURCE_PATH
            file.parent.mkdir(parents=True)
            file.write_text(source)
            def run(*args):
                return subprocess.check_output([git, '-C', directory, *args], stderr=subprocess.STDOUT).decode().strip()
            run('init', '-q')
            run('remote', 'add', 'origin', emulate.OFFICIAL_REMOTES[0])
            run('add', '.')
            run('-c', 'user.name=Local test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'synthetic test-only source')
            commit = run('rev-parse', 'HEAD')
            sha = hashlib.sha256(source.encode()).hexdigest()
            self.assertEqual(emulate.verified_source(directory, commit, sha, git), 'hostname\n')
            with self.assertRaises(ValueError):
                emulate.verified_source(directory, commit, '0' * 64, git)
            run('remote', 'set-url', 'origin', 'https://example.invalid/forged')
            with self.assertRaises(ValueError):
                emulate.verified_source(directory, commit, sha, git)

    def test_guard_refuses_added_caps_unconfined_and_host_userns(self):
        for key, value in [('CapAdd', ['SYS_ADMIN']), ('UsernsMode', 'host'),
                           ('SecurityOpt', ['no-new-privileges:true', 'seccomp=unconfined']),
                           ('Tmpfs', {'/proc': 'rw'})]:
            target = AtomicTests().target()
            target['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                emulate.guard_container(target)

class CommandTests(unittest.TestCase):
    def test_timeout_stops_descendant_processes(self):
        import time
        try:
            from attacks.atomic import lab_common
        except ImportError:
            import lab_common
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'unwanted-child'
            code, _ = lab_common.command(['/bin/sh', '-c', '(sleep 0.2; printf unwanted > "$1") & wait', 'test', str(marker)],
                                          env=lab_common.clean_environment(), timeout=0.02)
            self.assertEqual(code, 124)
            time.sleep(0.3)
            self.assertFalse(marker.exists(), 'timed out child must not continue changing lab state')

class AtomicCLITests(unittest.TestCase):
    def test_wrapper_records_real_tool_exit_and_metrics_contract(self):
        # The fake CLI is a subprocess-boundary fixture, not a live Docker or
        # detector test. Git object verification and evidence files are real.
        import contextlib
        import hashlib
        import io
        import shutil
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / 'atomic'
            root.mkdir()
            source = '- name: Hostname Discovery\n  auto_generated_guid: ' + emulate.GUID + '\n  supported_platforms:\n  - linux\n  executor:\n    command: |\n      hostname\n    name: sh\n'
            source_file = root / emulate.SOURCE_PATH
            source_file.parent.mkdir(parents=True)
            source_file.write_text(source)
            git = shutil.which('git')
            def run(*args):
                return subprocess.check_output([git, '-C', str(root), *args], stderr=subprocess.STDOUT).decode().strip()
            run('init', '-q')
            run('remote', 'add', 'origin', emulate.OFFICIAL_REMOTES[0])
            run('add', '.')
            run('-c', 'user.name=Local test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'synthetic test-only source')
            commit = run('rev-parse', 'HEAD')
            docker = base / 'docker-fixture'
            for exit_code in (0, 17):
                target = json.dumps([AtomicTests().target()])
                docker.write_text('#!/bin/sh\ncase "$3" in inspect) printf \'%s\\n\' ' + "'" + target + "'" + ';; exec) printf \'fixture-only output\\n\'; exit ' + str(exit_code) + ';; *) exit 99;; esac\n')
                docker.chmod(0o700)
                out = base / ('out-' + str(exit_code))
                with contextlib.redirect_stdout(io.StringIO()):
                    result = emulate.main(['--docker', str(docker), '--docker-host', 'unix:///tmp/test-fixture.sock',
                                           '--container', 'warden-lab-atomic-case', '--git', git,
                                           '--atomic-root', str(root), '--atomic-commit', commit,
                                           '--yaml-sha256', hashlib.sha256(source.encode()).hexdigest(),
                                           '--out', str(out), '--ack-dedicated-lab'])
                self.assertEqual(result, 0 if exit_code == 0 else 1)
                execution = json.loads((out / 'executions.jsonl').read_text())
                self.assertEqual(execution['outcome'], 'succeeded' if exit_code == 0 else 'failed')
                self.assertEqual(json.loads((out / 'receipt.json').read_text())['returncode'], exit_code)
                self.assertFalse((out / 'alerts.jsonl').exists())


if __name__ == '__main__':
    unittest.main()
