"""Run one reviewed official Linux Atomic inside a dedicated existing container."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from .lab_common import (checked_tool, clean_environment, command, execution_record,
                             prepare_output, utc_now, write_new_json)
except ImportError:
    from lab_common import (checked_tool, clean_environment, command, execution_record,
                            prepare_output, utc_now, write_new_json)

OFFICIAL_REMOTES = ('https://github.com/redcanaryco/atomic-red-team.git',
                    'https://github.com/redcanaryco/atomic-red-team',
                    'git@github.com:redcanaryco/atomic-red-team.git')
# The target carries Warden's labels, so the online detector's collector keeps
# its alerts as a sandbox's (detect/falco/collector.py) and bindings.py finds
# it by its run: project=warden, owner=warden-lab, warden.dev/run=atomic-<hex>.
RUN_LABEL = 'warden.dev/run'
RUN_ID = re.compile('atomic-[a-f0-9]{24}')
INTERPRETERS = {'sh': '/bin/sh', 'bash': '/bin/bash'}
# The only writable place a target may have: a small /tmp that cannot hold
# executables, devices or set-ID files.
TMPFS_FLAGS = frozenset({'rw', 'noexec', 'nosuid', 'nodev'})
TMPFS_MAX_BYTES = 16 * 1024 * 1024
TIMEOUT_S = 60
CREDS_FLAGS = '-exec sh -c \'echo "=== $1 ===" >> /tmp/creds.txt; cat "$1" >> /tmp/creds.txt\' _ {} \\;'

# The reviewed official Linux Atomics, exactly as they are at the reviewed
# commit: the executor and its command, every input argument with its default,
# and every dependency's check and set-up command. The wrapper runs the command
# with the defaults substituted and nothing else; another Atomic, or a changed
# one, needs its own review and entry here. None needs elevation: the target's
# root has no capabilities.
TESTS = {
    '486e88ea-4f56-470f-9b57-3f4d73f39133': {
        'name': 'Hostname Discovery', 'technique': 'T1082', 'slug': 'hostname',
        'path': 'atomics/T1082/T1082.yaml', 'executor': 'sh',
        'command': 'hostname\n', 'arguments': {}, 'dependencies': ()},
    '46959285-906d-40fa-9437-5a439accd878': {
        'name': 'Discover Private SSH Keys', 'technique': 'T1552.004', 'slug': 'ssh-key-discovery',
        'path': 'atomics/T1552.004/T1552.004.yaml', 'executor': 'sh',
        'command': 'find #{search_path} -name "#{filename}" -type f #{optional_flags} 2>/dev/null\nexit 0\n',
        'arguments': {'search_path': '/', 'filename': 'id_rsa', 'optional_flags': CREDS_FLAGS},
        'dependencies': ()},
    '7c247dc7-5128-4643-907b-73a76d9135c3': {
        'name': 'Copy Private SSH Keys with CP', 'technique': 'T1552.004', 'slug': 'ssh-key-copy',
        'path': 'atomics/T1552.004/T1552.004.yaml', 'executor': 'sh',
        'command': ('mkdir #{output_folder}\n'
                    'find #{search_path} -name id_rsa 2>/dev/null -exec cp --parents {} #{output_folder} \\;\n'
                    'exit 0\n'),
        'arguments': {'search_path': '/', 'output_folder': '/tmp/art-staging'}, 'dependencies': ()},
    '37807632-d3da-442e-8c2e-00f44928ff8f': {
        'name': 'Find AWS credentials', 'technique': 'T1552.001', 'slug': 'aws-credentials',
        'path': 'atomics/T1552.001/T1552.001.yaml', 'executor': 'sh',
        'command': "find #{file_path} -path '*/.aws/#{filename}' -type f 2>/dev/null\n",
        'arguments': {'file_path': '/', 'filename': 'credentials'}, 'dependencies': ()},
    '085fe567-ac84-47c7-ac4c-2688ce28265b': {
        'name': 'Examine password complexity policy - Ubuntu', 'technique': 'T1201', 'slug': 'password-policy',
        'path': 'atomics/T1201/T1201.yaml', 'executor': 'bash',
        'command': 'cat /etc/pam.d/common-password\n', 'arguments': {}, 'dependencies': ()},
    '039b4b10-2900-404b-b67f-4b6d49aa6499': {
        'name': 'Overwrite and delete a file with shred', 'technique': 'T1070.004', 'slug': 'shred',
        'path': 'atomics/T1070.004/T1070.004.yaml', 'executor': 'sh',
        'command': 'shred -u #{file_to_shred}\n', 'arguments': {'file_to_shred': '/tmp/victim-shred.txt'},
        'dependencies': (('if [ -f "#{file_to_shred}" ]; then echo "File already exists"; '
                          'else echo "File does NOT exist yet"; exit 1; fi\n',
                          'touch #{file_to_shred}\n'),)},
}


def tmpfs_allowed(tmpfs):
    if not tmpfs:
        return True
    if not isinstance(tmpfs, dict) or set(tmpfs) != {'/tmp'} or not isinstance(tmpfs['/tmp'], str):
        return False
    options = tmpfs['/tmp'].split(',')
    sizes = [o for o in options if o.startswith('size=')]
    if set(options) - set(sizes) != TMPFS_FLAGS or len(options) != len(TMPFS_FLAGS) + 1 or len(sizes) != 1:
        return False
    match = re.fullmatch('size=([1-9][0-9]{0,8})([km]?)', sizes[0])
    if match is None:
        return False
    return int(match[1]) * {'': 1, 'k': 1024, 'm': 1024 * 1024}[match[2]] <= TMPFS_MAX_BYTES


def guard_container(target):
    """(full container ID, run ID) of a running isolated Warden Atomic target."""
    host = target.get('HostConfig', {})
    security = host.get('SecurityOpt') or []
    labels = target.get('Config', {}).get('Labels') or {}
    if (not re.fullmatch('[a-f0-9]{64}', target.get('Id', '')) or
        not re.fullmatch('/warden-lab-atomic-[a-z0-9-]+', target.get('Name', '')) or
        not re.fullmatch('sha256:[a-f0-9]{64}', target.get('Image', '')) or
        labels.get('project') != 'warden' or labels.get('owner') != 'warden-lab' or
        not RUN_ID.fullmatch(labels.get(RUN_LABEL) or '') or
        target.get('State', {}).get('Running') is not True or target.get('Mounts') != [] or
        host.get('Runtime') != 'runc' or
        host.get('NetworkMode') != 'none' or host.get('Privileged') is not False or
        host.get('ReadonlyRootfs') is not True or host.get('Binds') or
        set(host.get('CapDrop') or []) != {'ALL'} or
        host.get('PidMode') not in ('', 'private') or host.get('IpcMode') != 'private' or
        not any(value in security for value in ('no-new-privileges', 'no-new-privileges:true')) or
        host.get('Devices') or host.get('DeviceRequests') or host.get('CapAdd') or
        not tmpfs_allowed(host.get('Tmpfs')) or host.get('UsernsMode') == 'host' or
        any(value in security for value in ('seccomp=unconfined', 'apparmor=unconfined', 'label=disable'))):
        raise ValueError('target must be a running isolated Warden runc Atomic container '
                         '(project=warden, owner=warden-lab, warden.dev/run=atomic-<24 hex>)')
    return target['Id'], labels[RUN_LABEL]


def section(block, key):
    """The lines under one key of a test (`  key:`), up to the next key."""
    match = re.search(r'(?m)^  ' + re.escape(key) + r':\n((?:(?:    |  - )[^\n]*\n|\n)*)', block)
    return None if match is None else match[1]


def literal(text, key, indent):
    """The value of a literal block scalar `key: |` at the given indent."""
    pad = ' ' * indent
    match = re.search(r'(?m)^' + pad + re.escape(key) + r': \|\n((?:' + pad + '  [^\n]*\n)+)', text or '')
    return None if match is None else ''.join(line[indent + 2:] + '\n' for line in match[1].splitlines())


def input_arguments(block):
    text = section(block, 'input_arguments')
    if text is None:
        return {}
    found = {}
    for match in re.finditer(r'(?m)^    ([A-Za-z0-9_]+):\n((?:      [^\n]*\n)*)', text):
        default = re.search(r'(?m)^      default: ([^\n]*)$', match[2])
        found[match[1]] = None if default is None else default[1]
    return found


def dependencies(block):
    text = section(block, 'dependencies')
    if text is None:
        return ()
    items = re.split(r'(?m)^  - ', text)[1:]
    return tuple((literal(item, 'prereq_command', 4), literal(item, 'get_prereq_command', 4)) for item in items)


def substitute(text, values):
    def value(match):
        if match[1] not in values:
            raise ValueError('Atomic command names an unreviewed input argument')
        return values[match[1]]
    return re.sub(r'#\{([A-Za-z0-9_]+)\}', value, text)


def atomic_command(source, guid):
    # This is deliberately not a general YAML runner. Only a reviewed GUID, the
    # Linux platform and the exact reviewed upstream command, arguments and
    # dependencies are accepted.
    test = TESTS.get(guid)
    if test is None:
        raise ValueError('not a reviewed Atomic GUID')
    blocks = re.split(r'(?m)^- name: ', source)
    matches = [block for block in blocks if '\n  auto_generated_guid: ' + guid + '\n' in block]
    if len(matches) != 1:
        raise ValueError('official Atomic GUID must occur exactly once')
    block = matches[0]
    platforms = section(block, 'supported_platforms')
    executor = section(block, 'executor')
    name = re.search(r'(?m)^    name: ([a-z_]+)$', executor or '')
    if (not block.startswith(test['name'] + '\n') or platforms is None or '  - linux\n' not in platforms or
            executor is None or name is None or name[1] != test['executor'] or
            literal(executor, 'command', 4) != test['command'] or
            re.search(r'(?m)^    elevation_required: true$', executor) or
            re.search(r'(?m)^  dependency_executor_name:', block) or
            input_arguments(block) != test['arguments'] or dependencies(block) != test['dependencies']):
        raise ValueError('reviewed Linux Atomic command, arguments, dependencies or executor changed')
    script = substitute(test['command'], test['arguments'])
    prerequisites = [(substitute(check, test['arguments']), substitute(setup, test['arguments']))
                     for check, setup in test['dependencies']]
    return {'script': script, 'prerequisites': prerequisites}


def verified_source(root, commit, expected_sha, git, guid):
    if guid not in TESTS:
        raise ValueError('not a reviewed Atomic GUID')
    if not re.fullmatch('[a-f0-9]{40}', commit) or not re.fullmatch('[a-f0-9]{64}', expected_sha):
        raise ValueError('full Atomic commit and YAML SHA256 are required')
    root = Path(root)
    if not root.is_absolute() or not root.is_dir():
        raise ValueError('absolute official Atomic checkout required')
    # A partial (blobless) checkout must never fetch while being verified.
    env = dict(clean_environment(), GIT_NO_LAZY_FETCH='1')
    code, remote = command([git, '-C', str(root), 'remote', 'get-url', 'origin'], env=env)
    if code or remote.strip() not in OFFICIAL_REMOTES:
        raise ValueError('Atomic origin must be the official redcanaryco repository')
    code, source = command([git, '-C', str(root), 'show', commit + ':' + TESTS[guid]['path']], env=env)
    if code or hashlib.sha256(source.encode()).hexdigest() != expected_sha:
        raise ValueError('pinned official Atomic YAML content does not match expected SHA256')
    return atomic_command(source, guid)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker', required=True, help='absolute Docker CLI path')
    parser.add_argument('--docker-host', required=True, help='explicit local unix:// socket')
    parser.add_argument('--container', required=True)
    parser.add_argument('--git', required=True)
    parser.add_argument('--atomic-root', required=True)
    parser.add_argument('--atomic-commit', required=True)
    parser.add_argument('--atomic-guid', required=True, help='a reviewed GUID: ' + ', '.join(sorted(TESTS)))
    parser.add_argument('--yaml-sha256', required=True, help="SHA256 of the GUID's whole YAML at the commit")
    parser.add_argument('--out', required=True, help='new absolute evidence directory')
    parser.add_argument('--ack-dedicated-lab', action='store_true', required=True)
    args = parser.parse_args(argv)
    try:
        docker, git = checked_tool(args.docker), checked_tool(args.git)
        if not re.fullmatch(r'unix:///[A-Za-z0-9_./-]+', args.docker_host):
            raise ValueError('explicit local Unix Docker socket required; remote targets refused')
        if not re.fullmatch('warden-lab-atomic-[a-z0-9-]+', args.container):
            raise ValueError('dedicated warden-lab-atomic-* container name required')
        test = TESTS.get(args.atomic_guid)
        if test is None:
            raise ValueError('not a reviewed Atomic GUID')
        reviewed = verified_source(args.atomic_root, args.atomic_commit, args.yaml_sha256, git, args.atomic_guid)
        env = clean_environment()
        base = [docker, '--host', args.docker_host]
        code, raw = command(base + ['inspect', '--type=container', args.container], env=env)
        if code:
            raise ValueError('cannot inspect dedicated lab container')
        targets = json.loads(raw)
        if not isinstance(targets, list) or len(targets) != 1:
            raise ValueError('exactly one dedicated target required')
        target_id, run_id = guard_container(targets[0])
        output = prepare_output(args.out)
        execution_id = run_id + '-' + test['slug']
        shell = base + ['exec', '--env', 'WARDEN_RUN_ID=' + run_id, target_id, INTERPRETERS[test['executor']], '-c']
        receipt = {'source': 'official-atomic-red-team', 'atomic_guid': args.atomic_guid, 'atomic_name': test['name'],
                   'technique_id': test['technique'], 'source_path': test['path'], 'executor': test['executor'],
                   'atomic_commit': args.atomic_commit, 'yaml_sha256': args.yaml_sha256, 'script': reviewed['script'],
                   'container_id': target_id, 'image': targets[0]['Image'], 'execution_id': execution_id,
                   'run_id': run_id, 'prerequisites': [],
                   'limitations': ['Execution success is not detector success.',
                                   'No alert is generated or inferred by this wrapper.',
                                   "The Atomic's cleanup command is not run; removing the target is the cleanup."]}
        # Dependencies first, as Atomic's own runner does: check, set up if
        # needed, check again. They are outside the execution's interval.
        for check, setup in reviewed['prerequisites']:
            step = {'check': check, 'setup': setup, 'started_at': utc_now()}
            code, log = command(shell + [check], env=env, timeout=TIMEOUT_S)
            step['check_returncode'], step['check_output'] = code, log
            if code != 0:
                code, log = command(shell + [setup], env=env, timeout=TIMEOUT_S)
                step['setup_returncode'], step['setup_output'] = code, log
                code, log = command(shell + [check], env=env, timeout=TIMEOUT_S)
                step['recheck_returncode'], step['recheck_output'] = code, log
            step['finished_at'] = utc_now()
            receipt['prerequisites'].append(step)
            if code != 0:
                receipt['executed'] = False
                write_new_json(output / 'receipt.json', receipt)
                raise ValueError('Atomic dependency not met; the test was not run')
        started = utc_now()
        code, log = command(shell + [reviewed['script']], env=env, timeout=TIMEOUT_S)
        finished = utc_now()
        write_new_json(output / 'executions.jsonl', execution_record(execution_id, run_id, test['technique'], started, code))
        write_new_json(output / 'bindings.jsonl', {'execution_id': execution_id, 'run_id': run_id,
                       'container_id': target_id, 'start': started, 'end': finished})
        receipt.update({'executed': True, 'started_at': started, 'finished_at': finished, 'returncode': code, 'output': log})
        write_new_json(output / 'receipt.json', receipt)
        print(str(output))
        return 0 if code == 0 else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
