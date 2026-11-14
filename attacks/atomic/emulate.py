"""Run one reviewed official Linux Atomic inside a dedicated existing container."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys

try:
    from .lab_common import (checked_tool, clean_environment, command, execution_record,
                             prepare_output, utc_now, write_new_json)
except ImportError:
    from lab_common import (checked_tool, clean_environment, command, execution_record,
                            prepare_output, utc_now, write_new_json)

GUID = '486e88ea-4f56-470f-9b57-3f4d73f39133'
TECHNIQUE = 'T1082'
SOURCE_PATH = 'atomics/T1082/T1082.yaml'
OFFICIAL_REMOTES = ('https://github.com/redcanaryco/atomic-red-team.git',
                    'https://github.com/redcanaryco/atomic-red-team',
                    'git@github.com:redcanaryco/atomic-red-team.git')


def guard_container(target):
    host = target.get('HostConfig', {})
    security = host.get('SecurityOpt') or []
    if (not re.fullmatch('[a-f0-9]{64}', target.get('Id', '')) or
        not re.fullmatch('/warden-lab-atomic-[a-z0-9-]+', target.get('Name', '')) or
        not re.fullmatch('sha256:[a-f0-9]{64}', target.get('Image', '')) or
        target.get('Config', {}).get('Labels', {}).get('warden.lab') != 'warden-lab' or
        target.get('State', {}).get('Running') is not True or target.get('Mounts') != [] or
        host.get('NetworkMode') != 'none' or host.get('Privileged') is not False or
        host.get('ReadonlyRootfs') is not True or host.get('Binds') or
        set(host.get('CapDrop') or []) != {'ALL'} or
        host.get('PidMode') not in ('', 'private') or host.get('IpcMode') != 'private' or
        not any(value in security for value in ('no-new-privileges', 'no-new-privileges:true')) or
        host.get('Devices') or host.get('DeviceRequests') or host.get('CapAdd') or
        host.get('Tmpfs') or host.get('UsernsMode') == 'host' or
        any(value in security for value in ('seccomp=unconfined', 'apparmor=unconfined', 'label=disable'))):
        raise ValueError('target must be a running isolated warden-lab Atomic container')
    return target['Id']


def atomic_command(source):
    # This is deliberately not a general YAML runner. Only the reviewed GUID,
    # Linux platform and exact harmless upstream command are accepted.
    blocks = re.split(r'(?m)^- name: ', source)
    matches = [block for block in blocks if '\n  auto_generated_guid: ' + GUID + '\n' in block]
    if len(matches) != 1:
        raise ValueError('official Hostname Discovery GUID must occur exactly once')
    block = matches[0]
    platforms = re.search(r'(?m)^  supported_platforms:\n((?:  - [^\n]+\n)+)', block)
    cmd = re.search(r'(?m)^    command: \|\n((?:      [^\n]*\n)+)', block)
    if (platforms is None or '  - linux\n' not in platforms[1] or cmd is None or
            cmd[1] != '      hostname\n' or not re.search(r'(?m)^    name: sh$', block)):
        raise ValueError('reviewed Linux Atomic command or executor changed')
    return 'hostname\n'


def verified_source(root, commit, expected_sha, git):
    if not re.fullmatch('[a-f0-9]{40}', commit) or not re.fullmatch('[a-f0-9]{64}', expected_sha):
        raise ValueError('full Atomic commit and YAML SHA256 are required')
    root = Path(root)
    if not root.is_absolute() or not root.is_dir():
        raise ValueError('absolute official Atomic checkout required')
    env = clean_environment()
    code, remote = command([git, '-C', str(root), 'remote', 'get-url', 'origin'], env=env)
    if code or remote.strip() not in OFFICIAL_REMOTES:
        raise ValueError('Atomic origin must be the official redcanaryco repository')
    code, source = command([git, '-C', str(root), 'show', commit + ':' + SOURCE_PATH], env=env)
    if code or hashlib.sha256(source.encode()).hexdigest() != expected_sha:
        raise ValueError('pinned official Atomic YAML content does not match expected SHA256')
    return atomic_command(source)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker', required=True, help='absolute Docker CLI path')
    parser.add_argument('--docker-host', required=True, help='explicit local unix:// socket')
    parser.add_argument('--container', required=True)
    parser.add_argument('--git', required=True)
    parser.add_argument('--atomic-root', required=True)
    parser.add_argument('--atomic-commit', required=True)
    parser.add_argument('--yaml-sha256', required=True)
    parser.add_argument('--out', required=True, help='new absolute evidence directory')
    parser.add_argument('--ack-dedicated-lab', action='store_true', required=True)
    args = parser.parse_args(argv)
    try:
        docker, git = checked_tool(args.docker), checked_tool(args.git)
        if not re.fullmatch(r'unix:///[A-Za-z0-9_./-]+', args.docker_host):
            raise ValueError('explicit local Unix Docker socket required; remote targets refused')
        if not re.fullmatch('warden-lab-atomic-[a-z0-9-]+', args.container):
            raise ValueError('dedicated warden-lab-atomic-* container name required')
        script = verified_source(args.atomic_root, args.atomic_commit, args.yaml_sha256, git)
        env = clean_environment()
        base = [docker, '--host', args.docker_host]
        code, raw = command(base + ['inspect', '--type=container', args.container], env=env)
        if code:
            raise ValueError('cannot inspect dedicated lab container')
        targets = json.loads(raw)
        if not isinstance(targets, list) or len(targets) != 1:
            raise ValueError('exactly one dedicated target required')
        target_id = guard_container(targets[0])
        output = prepare_output(args.out)
        run_id = 'atomic-' + secrets.token_hex(12)
        execution_id = run_id + '-hostname'
        started = utc_now()
        code, log = command(base + ['exec', '--env', 'WARDEN_RUN_ID=' + run_id,
                                   target_id, '/bin/sh', '-c', script], env=env, timeout=30)
        finished = utc_now()
        write_new_json(output / 'executions.jsonl', execution_record(execution_id, run_id, TECHNIQUE, started, code))
        write_new_json(output / 'bindings.jsonl', {'execution_id': execution_id, 'run_id': run_id,
                       'container_id': target_id, 'start': started, 'end': finished})
        write_new_json(output / 'receipt.json', {'source': 'official-atomic-red-team', 'atomic_guid': GUID,
                       'atomic_commit': args.atomic_commit, 'yaml_sha256': args.yaml_sha256,
                       'container_id': target_id, 'image': targets[0]['Image'], 'started_at': started,
                       'finished_at': finished, 'returncode': code, 'output': log,
                       'execution_id': execution_id, 'run_id': run_id,
                       'limitations': ['Execution success is not detector success.',
                                       'No alert is generated or inferred by this wrapper.']})
        print(str(output))
        return 0 if code == 0 else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
