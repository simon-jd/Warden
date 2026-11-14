#!/usr/bin/env python3
"""Disposable, locally packaged Docker boundary for the fixed Warden probe."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import tarfile
from runtime_lab_paths import exclusive_file, trusted_directory

ROOT = Path(__file__).absolute().parent.parent
RESERVE = 3000000000  # tar + image layers + daemon/snapshots + bounded Docker logs
CAPS = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID', 'SETPCAP', 'SYS_CHROOT', 'MKNOD', 'KILL', 'SYS_ADMIN', 'NET_ADMIN')


def read_trusted(path, uid):
    parent = trusted_directory(str(path.parent), uid)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, uid) or info.st_mode & 0o022:
                raise ValueError('untrusted input: ' + str(path))
            with os.fdopen(os.dup(fd), 'rb') as source:
                return source.read()
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def preflight(additional, memory):
    subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/azure_guard.py'), 'preflight', '--additional-bytes', str(additional), '--service-memory-bytes', str(memory), '--download-bytes', '0'], check=True)


def docker(args, timeout=60, secret_env=None, **kwargs):
    # Pin the local socket; never inherit a remote Docker context or TLS settings.
    result = subprocess.run(['/usr/bin/docker', '--host=unix:///var/run/docker.sock', *args], check=True, text=True, stdout=subprocess.PIPE, timeout=timeout, env={'PATH': '/usr/bin:/bin', **(secret_env or {})}, **kwargs)
    return result.stdout


def owned_inspect(kind, identity, labels, cli):
    pattern = 'sha256:[0-9a-f]{64}' if kind == 'image' else '[0-9a-f]{64}'
    if not re.fullmatch(pattern, identity):
        raise RuntimeError('exact owned object ID required')
    data = json.loads(cli([kind, 'inspect', identity]))
    if len(data) != 1 or data[0]['Id'] != identity or any(data[0]['Config'].get('Labels', {}).get(k) != v for k, v in labels.items()):
        raise RuntimeError('ownership mismatch; preserving ' + identity)
    return data[0]


def scoped_ids(kind, labels, cli):
    # Docker hides some used untagged/intermediate images without --all.
    # Accounting, lost-import recovery and deletion proof need every match.
    args = [kind, 'ls', '--quiet', '--no-trunc', '--all']
    for key, value in labels.items():
        args += ['--filter', f'label={key}={value}']
    return cli(args).split()


@contextmanager
def defer_signals():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def execute(image, output, labels, mode, cli=docker, pg_target=None, cleanup_ok=None):
    if mode not in ('run', 'smoke', 'api', 'api-smoke', 'api-code') or not re.fullmatch('sha256:[0-9a-f]{64}', image) or any(c in str(output) for c in ',\n\r'):
        raise ValueError('fixed mode, image ID and safe session path required')
    if mode in ('api', 'api-code'):
        from runtime_lab_api import private_target
        private_target(pg_target, labels, cli)
    labels = {**labels, 'role': 'outer'} if mode in ('api', 'api-code') else labels
    args = ['container', 'create', '--pull=never', '--network=none', '--ipc=private', '--cgroupns=private', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=4000000000', '--memory-swap=4000000000', '--pids-limit=512', '--cpus=2', '--log-driver=json-file', '--log-opt=max-size=10m', '--log-opt=max-file=2', '--stop-timeout=20', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777', '--tmpfs=/run:rw,nosuid,nodev,size=64m']
    for key, value in labels.items():
        args += ['--label', f'{key}={value}']
    if mode in ('run', 'api'):
        args += ['--cap-add=' + cap for cap in CAPS]
        args += ['--security-opt=apparmor=unconfined', '--security-opt=seccomp=unconfined', '--mount', f'type=bind,src={output},dst=/opt/warden/.cache/warden-lab', '--env', 'WARDEN_LAB_HOST_CGROUP_NS=' + os.readlink('/proc/self/ns/cgroup')]
    else:
        args += ['--user=65534:65534']
    if mode in ('api', 'api-code'):
        args[args.index('--network=none')] = '--network=container:' + pg_target
        args += ['--env', 'WARDEN_API_PASSWORD']
    args += [image, mode]
    cid = None
    try:
        with defer_signals():
            cid = cli(args).strip()
        if not re.fullmatch('[0-9a-f]{64}', cid):
            raise RuntimeError('Docker did not return an exact container ID')
        owned_inspect('container', cid, labels, cli)
        print('owned container:', cid, flush=True)
        cli(['container', 'start', '--attach', cid], timeout=300)
        status = cli(['container', 'wait', cid]).strip()
        if status != '0':
            raise RuntimeError('lab exited with status ' + status)
    finally:
        # A failed create may have committed before its CLI response was lost.
        # Recover only this unpredictable invocation's full ownership labels.
        with defer_signals():
            identities = [cid] if cid and re.fullmatch('[0-9a-f]{64}', cid) else scoped_ids('container', labels, cli)
            for identity in identities:
                owned_inspect('container', identity, labels, cli)
                try:
                    try:
                        cli(['container', 'stop', '--time=20', identity])
                    finally:
                        print(cli(['container', 'logs', identity]), end='', flush=True)
                finally:
                    cli(['container', 'rm', '--force', identity])
                remaining = cli(['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', 'id=' + identity]).split()
                if identity in remaining:
                    raise RuntimeError('container still exists: ' + identity)
                print('outer container removed:', identity, flush=True)
            if cleanup_ok is not None and cid and re.fullmatch('[0-9a-f]{64}', cid):
                cleanup_ok['outer'] = True


def package(archive, manifest):
    """No apt/pulls/build cache. Copy a trusted host ABI closure into scratch."""
    files = {}
    binaries = ['containerd', 'containerd-shim-runc-v2', 'ctr', 'runc']
    python = Path('/usr/bin/python3').resolve(strict=True)
    inputs = [Path('/usr/bin') / name for name in binaries] + [python]
    stdlib = Path('/usr/lib') / ('python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor))
    for directory, dirs, names in os.walk(stdlib, followlinks=False):
        dirs[:] = [d for d in dirs if d not in ('__pycache__', 'test', 'tests', 'idlelib', 'tkinter', 'ensurepip')]
        for name in names:
            p = Path(directory) / name
            inputs.append(p)
    dependencies = set()
    for path in inputs:
        # System symlinks live under root-only ancestors; copy their validated
        # regular target, never preserve a host filesystem link into the image.
        parent = trusted_directory(str(path.parent), 0)
        os.close(parent)
        if path.lstat().st_uid != 0:
            raise ValueError("untrusted system input owner")
        data = read_trusted(path.resolve(strict=True), 0)
        files[str(path).lstrip('/')] = data
        if data[:4] == b'\x7fELF':
            result = subprocess.run(['/usr/bin/ldd', str(path)], text=True, capture_output=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            if result.returncode and (result.stdout + result.stderr).strip() not in ('not a dynamic executable', 'statically linked'):
                result.check_returncode()
            if 'not found' in result.stdout:
                raise ValueError('missing ELF dependency')
            for line in result.stdout.splitlines():
                match = re.search(r'(?:=>\s+)?(/[^\s]+)', line)
                if match:
                    dependencies.add(match.group(1))
    for name in dependencies:
        files[name.lstrip('/')] = read_trusted(Path(name).resolve(strict=True), 0)
    for name in ('runtime_lab_docker_init.py', 'runtime_lab_runner.py', 'runtime_lab_paths.py'):
        files['opt/warden/scripts/' + name] = read_trusted(ROOT / 'scripts' / name, os.getuid())
    for name in ('runc.test', 'api.test', 'runs.test', 'scheduler.test', 'probe.oci.tar', 'image-digest', 'image-name'):
        files['opt/warden/input/' + name] = read_trusted(ROOT / '.cache/warden-lab' / name, os.getuid())
    files['etc/passwd'] = b'root:x:0:0:root:/root:/usr/bin/python3\nnobody:x:65534:65534:nobody:/:/usr/bin/python3\n'
    files['etc/group'] = b'root:x:0:\nnogroup:x:65534:\n'
    files['etc/os-release'] = read_trusted(Path('/usr/lib/os-release'), 0)
    total = sum(map(len, files.values()))
    if total > 500000000:
        raise ValueError('packaged rootfs exceeds reserved 500MB')
    with tarfile.open(archive, 'x') as tar:
        directories = {'proc', 'sys', 'sys/fs', 'sys/fs/cgroup', 'dev', 'tmp', 'run', 'opt/warden/.cache/warden-lab'}
        for name in files:
            directories.update(str(p) for p in Path(name).parents if str(p) != '.')
        for name in sorted(directories):
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(entry)
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o755 if name.startswith(('usr/bin/', 'lib', 'usr/lib/')) or name.endswith('.test') else 0o644
            tar.addfile(entry, io.BytesIO(data))
        entry = tarfile.TarInfo('usr/bin/python3')
        entry.type, entry.linkname = tarfile.SYMTYPE, python.name
        tar.addfile(entry)
    manifest.write_text(json.dumps({'python': str(python), 'bytes': total, 'sha256': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}, indent=2) + '\n')
    return total


def record_charge(output, released=False, reserve=RESERVE):
    """Durable before import; release means verified object removal, not physical GC."""
    parent = trusted_directory(str(output), os.getuid())
    name = 'charge-released.json' if released else 'charge.json'
    try:
        data = json.dumps({'version': 1, 'reserved_bytes': reserve, 'released': released}).encode() + b'\n'
        fd = exclusive_file(parent, name, data)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        if released:
            os.replace(name, 'charge.json', src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    # Also persist the new session directory entry before any external import.
    base = trusted_directory(str(output.parent), os.getuid())
    try:
        os.fsync(base)
    finally:
        os.close(base)


def outstanding_bytes(base):
    total = 0
    for session in base.iterdir():
        if not session.name.startswith('docker-'):
            continue
        try:
            charge = json.loads(read_trusted(session / 'charge.json', os.getuid()))
        except FileNotFoundError:
            continue  # Packaging-only sessions precede any import/charge.
        if (set(charge) != {'version', 'reserved_bytes', 'released'} or charge['version'] != 1
                or charge['reserved_bytes'] not in (RESERVE, 5000000000, 6000000000) or type(charge['released']) is not bool):
            raise ValueError('invalid outstanding Docker allocation charge')
        if not charge['released']:
            total += charge['reserved_bytes']
    return total


def image_session(archive, output, labels, mode, cli=docker):
    image = None
    imported = False
    reserve = 5000000000 if mode in ('api', 'api-code') else RESERVE
    cleanup_ok = {}
    record_charge(output, reserve=reserve)
    try:
        changes = ['ENTRYPOINT ["/usr/bin/python3", "-B", "/opt/warden/scripts/runtime_lab_docker_init.py"]', 'ENV PATH=/usr/bin:/bin', 'ENV PYTHONDONTWRITEBYTECODE=1']
        changes += [f'LABEL {k}={v}' for k, v in labels.items()]
        command = ['image', 'import']
        for change in changes:
            command += ['--change', change]
        command += [str(archive)]
        with defer_signals():
            image = cli(command, timeout=120).strip()
        if not re.fullmatch('sha256:[0-9a-f]{64}', image):
            image = None
            raise RuntimeError('Docker did not return an exact image ID')
        owned_inspect('image', image, labels, cli)
        imported = True
        print('owned image:', image, flush=True)
        (output / 'identity.json').write_text(json.dumps({'image': image, 'labels': labels}, indent=2) + '\n')
        if mode in ('api', 'api-code'):
            from runtime_lab_api import postgres
            with postgres(labels, cli, cleanup_ok) as target:
                execute(image, output, labels, mode, cli, pg_target=target, cleanup_ok=cleanup_ok)
        else:
            execute(image, output, labels, mode, cli)
    finally:
        with defer_signals():
            for identity in ([image] if image else scoped_ids('image', labels, cli)):
                owned_inspect('image', identity, labels, cli)
                cli(['image', 'rm', identity])
                if identity in scoped_ids('image', labels, cli):
                    raise RuntimeError('owned image still exists: ' + identity)
                print('owned image removed:', identity, flush=True)
            if imported and (mode not in ('api', 'api-code') or (cleanup_ok.get('outer') and cleanup_ok.get('postgres'))):
                record_charge(output, released=True, reserve=reserve)


def interrupted(signum, frame):
    raise KeyboardInterrupt('signal ' + str(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['smoke', 'run', 'api-smoke', 'api', 'api-code'])
    parser.add_argument('--other-service-memory-bytes', type=int, required=True, help='all other Warden resident service memory maxima')
    parser.add_argument('--reviewed-live-profile', action='store_true')
    args = parser.parse_args()
    if args.other_service_memory_bytes < 0:
        parser.error('negative service memory')
    if args.mode in ('run', 'api') and not args.reviewed_live_profile:
        parser.error('live profile requires independent review then --reviewed-live-profile')
    signal.signal(signal.SIGTERM, interrupted)
    rootfd = trusted_directory(str(ROOT / '.cache/warden-lab'), os.getuid())
    os.close(rootfd)
    lockfd = os.open(ROOT / '.cache/warden-lab/docker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = json.loads(docker(['info', '--format', '{{json .}}']))
        if info['Name'] != os.uname().nodename or info['CgroupVersion'] != '2' or any('rootless' in x for x in info['SecurityOptions']):
            raise RuntimeError('local rootful Docker cgroup-v2 daemon identity mismatch')
        print('local Docker daemon:', info['Name'], info['ServerVersion'], info['CgroupDriver'], flush=True)
        labels = {'project': 'warden', 'owner': 'codex-warden', 'session': secrets.token_hex(16), 'ttl': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec='seconds').replace('+00:00', 'Z')}
        other = {'project': 'warden'}
        if scoped_ids('container', other, docker):
            raise RuntimeError('existing Warden containers: reconcile aggregate memory/storage before running')
        external = 0
        for identity in set(scoped_ids('image', other, docker)):
            external += 2 * json.loads(docker(['image', 'inspect', identity]))[0]['Size'] + 64000000
        outstanding = outstanding_bytes(ROOT / '.cache/warden-lab')
        print('outstanding Docker allocation charge:', outstanding, flush=True)
        reserve, memory = RESERVE, 4000000000
        if args.mode in ('api', 'api-code'):
            from runtime_lab_api import cached_postgres, API_RESERVE, PG_MEMORY
            cached_postgres(docker)
            reserve, memory = API_RESERVE, memory + PG_MEMORY
        preflight(reserve + external + outstanding, memory + args.other_service_memory_bytes)
        output = ROOT / '.cache/warden-lab' / ('docker-' + labels['session'])
        output.mkdir(mode=0o700)
        archive = output / 'rootfs.tar'
        try:
            package(archive, output / 'manifest.json')
            cli = docker
            if args.mode in ('api', 'api-code'):
                password = secrets.token_hex(32)
                def cli(command, **kwargs):
                    return docker(command, secret_env={'POSTGRES_PASSWORD': password, 'WARDEN_API_PASSWORD': password}, **kwargs)
            image_session(archive, output, labels, args.mode, cli)
        finally:
            archive.unlink(missing_ok=True)
        print('evidence directory:', output)
    finally:
        os.close(lockfd)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print('Docker lab failed:', error, file=sys.stderr)
        sys.exit(2)
