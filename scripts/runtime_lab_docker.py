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


def egress_target(egress, cli):
    """The runc egress lab joins only the egress test's own --internal sandbox
    network (warden-egress-*-sbx, label warden.test=task10) and binds only the
    Envoy config directory under this project's .cache."""
    import ipaddress
    if not egress or not re.fullmatch(r'warden-egress-[0-9a-f]{8}-sbx', egress['network']):
        raise ValueError('egress mode needs the egress lab sandbox network')
    prefix = ipaddress.IPv4Network(egress['prefix'])
    ip, proxy, origin = (ipaddress.IPv4Address(egress[k]) for k in ('ip', 'proxy', 'origin'))
    if ip not in prefix or proxy not in prefix or ip == proxy or origin in prefix:
        raise ValueError('egress addresses do not fit the sandbox network')
    data = json.loads(cli(['network', 'inspect', egress['network']]))
    if (len(data) != 1 or data[0]['Name'] != egress['network'] or data[0]['Internal'] is not True
            or (data[0].get('Labels') or {}).get('warden.test') != 'task10'
            or [c.get('Subnet') for c in data[0]['IPAM']['Config']] != [str(prefix)]):
        raise RuntimeError('egress network is not the owned internal lab network')
    directory = Path(egress['dir'])
    cache = (ROOT / '.cache').resolve(strict=True)
    if directory.is_symlink() or directory.resolve(strict=True) != directory or cache not in directory.parents:
        raise ValueError('egress directory must be a real directory under the project .cache')
    os.close(trusted_directory(str(directory), os.getuid()))
    return {'network': egress['network'], 'ip': str(ip), 'dir': directory, 'prefix': str(prefix), 'proxy': str(proxy), 'origin': str(origin)}


@contextmanager
def defer_signals():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def execute(image, output, labels, mode, cli=docker, pg_target=None, cleanup_ok=None, egress=None, pg=None):
    if mode not in ('run', 'smoke', 'api', 'api-smoke', 'api-code', 'egress', 'matrix') or not re.fullmatch('sha256:[0-9a-f]{64}', image) or any(c in str(output) for c in ',\n\r'):
        raise ValueError('fixed mode, image ID and safe session path required')
    if mode in ('api', 'api-code'):
        from runtime_lab_api import private_target
        private_target(pg_target, labels, cli)
    if mode == 'egress':
        egress = egress_target(egress, cli)
        if any(c in str(egress['dir']) for c in ',\n\r'):
            raise ValueError('safe egress directory path required')
        if pg is not None:
            if not re.fullmatch(r'warden-pg-[0-9a-f]{32}', str(pg.get('network', ''))) or not re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', str(pg.get('ip', ''))):
                raise ValueError('egress postgres bridge identity required')
    # WARDEN_LAB_CPUSET pins the outer container (as the gVisor lab's does), for
    # a host whose other CPUs are reserved; unset, nothing changes.
    cpuset = os.environ.get('WARDEN_LAB_CPUSET', '')
    if cpuset and not re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*', cpuset):
        raise ValueError('WARDEN_LAB_CPUSET must be a CPU list such as 0-7,16-31')
    labels = {**labels, 'role': 'outer'} if mode in ('api', 'api-code') else labels
    args = ['container', 'create', '--pull=never', '--network=none', '--ipc=private', '--cgroupns=private', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=4000000000', '--memory-swap=4000000000', '--pids-limit=512', '--cpus=2', '--log-driver=json-file', '--log-opt=max-size=10m', '--log-opt=max-file=2', '--stop-timeout=20', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777', '--tmpfs=/run:rw,nosuid,nodev,size=64m']
    for key, value in labels.items():
        args += ['--label', f'{key}={value}']
    if cpuset:
        args.append('--cpuset-cpus=' + cpuset)
    if mode in ('run', 'api', 'egress', 'matrix'):
        args += ['--cap-add=' + cap for cap in CAPS]
        args += ['--security-opt=apparmor=unconfined', '--security-opt=seccomp=unconfined', '--mount', f'type=bind,src={output},dst=/opt/warden/.cache/warden-lab', '--env', 'WARDEN_LAB_HOST_CGROUP_NS=' + os.readlink('/proc/self/ns/cgroup')]
    else:
        args += ['--user=65534:65534']
    if mode == 'egress':
        # One interface on the egress lab's --internal sandbox network: the
        # sandboxes' ipvlan parent. The Envoy config directory is shared so
        # the in-lab EgressController drives the real proxy.
        args[args.index('--network=none')] = '--network=' + egress['network']
        # runc init sets itself non-dumpable when it joins a namespace by path
        # (the sandbox netns); runc then needs SYS_PTRACE to open its
        # /proc/<pid>/ns/mnt. A node's runc has it as real root; sandboxes
        # still get no capabilities.
        args += ['--cap-add=SYS_PTRACE', '--ip=' + egress['ip'], '--mount', f'type=bind,src={egress["dir"]},dst=/opt/warden/egress',
                 '--env', 'WARDEN_EGRESS_DIR=/opt/warden/egress', '--env', 'WARDEN_EGRESS_PREFIX=' + egress['prefix'],
                 '--env', 'WARDEN_EGRESS_PROXY=' + egress['proxy'], '--env', 'WARDEN_EGRESS_ORIGIN_BLOCKED=' + egress['origin']]
        if pg is not None:
            # Second NIC only. eth0 stays the sandbox network, which runc uses
            # as the ipvlan parent. The database is reached by its bridge address.
            args += ['--env', 'WARDEN_EGRESS_POSTGRES_HOST=' + pg['ip'], '--env', 'WARDEN_API_PASSWORD']
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
        if mode == 'egress' and pg is not None:
            cli(['network', 'connect', pg['network'], cid])
        cli(['container', 'start', '--attach', cid], timeout=1800 if mode == 'matrix' else (480 if mode == 'egress' else 300))
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


def corpus_files(root):
    """Copy only bounded, no-follow corpus source files into the lab image."""
    directory = root / 'attacks/corpus'
    os.close(trusted_directory(str(directory), os.getuid()))
    files = {}
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink():
            raise ValueError('corpus symlink is forbidden')
        if entry.is_file():
            continue
        if not re.fullmatch('[a-z][a-z0-9-]{0,63}', entry.name):
            raise ValueError('invalid corpus ID')
        os.close(trusted_directory(str(entry), os.getuid()))
        for name in ('run.sh', 'expect.yaml'):
            path = entry / name
            if path.lstat().st_size > 65536:
                raise ValueError('oversized corpus file')
            files['corpus/' + entry.name + '/' + name] = read_trusted(path, os.getuid())
    if not files or len(files) > 128:
        raise ValueError('empty or oversized corpus')
    return files


def package(archive, manifest, matrix=False):
    """No apt/pulls/build cache. Copy a trusted host ABI closure into scratch."""
    files = {}
    binaries = ['containerd', 'containerd-shim-runc-v2', 'ctr', 'runc', 'ip']
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
    if matrix:
        for name in ('corpus.oci.tar', 'corpus-image-digest', 'corpus-image-name'):
            files['opt/warden/input/' + name] = read_trusted(ROOT / '.cache/warden-lab' / name, os.getuid())
        files.update({'opt/warden/input/' + name: raw for name, raw in corpus_files(ROOT).items()})
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


def image_session(archive, output, labels, mode, cli=docker, egress=None):
    image = None
    imported = False
    reserve = 5000000000 if mode in ('api', 'api-code', 'egress') else RESERVE
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
        elif mode == 'egress':
            from runtime_lab_api import postgres_bridge
            with postgres_bridge(labels, cli, cleanup_ok) as target:
                execute(image, output, labels, mode, cli, cleanup_ok=cleanup_ok, egress=egress, pg=target)
        else:
            execute(image, output, labels, mode, cli, egress=egress)
    finally:
        with defer_signals():
            for identity in ([image] if image else scoped_ids('image', labels, cli)):
                owned_inspect('image', identity, labels, cli)
                cli(['image', 'rm', identity])
                if identity in scoped_ids('image', labels, cli):
                    raise RuntimeError('owned image still exists: ' + identity)
                print('owned image removed:', identity, flush=True)
            if imported and (mode not in ('api', 'api-code', 'egress') or (cleanup_ok.get('outer') and cleanup_ok.get('postgres'))):
                record_charge(output, released=True, reserve=reserve)


def interrupted(signum, frame):
    raise KeyboardInterrupt('signal ' + str(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['smoke', 'run', 'api-smoke', 'api', 'api-code', 'egress', 'matrix'])
    parser.add_argument('--other-service-memory-bytes', type=int, required=True, help='all other Warden resident service memory maxima')
    for name in ('network', 'ip', 'dir', 'prefix', 'proxy', 'origin'):
        parser.add_argument('--egress-' + name, help='egress mode only: set by `make test-egress-runc`')
    args = parser.parse_args()
    if args.other_service_memory_bytes < 0:
        parser.error('negative service memory')
    egress = None
    if args.mode == 'egress':
        egress = {name: getattr(args, 'egress_' + name) for name in ('network', 'ip', 'dir', 'prefix', 'proxy', 'origin')}
        if None in egress.values():
            parser.error('egress mode needs every --egress-* option')
        # Validate before any packaging or charge.
        egress = egress_target(egress, docker)
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
        labels = {'project': 'warden', 'owner': 'warden-lab', 'session': secrets.token_hex(16), 'ttl': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec='seconds').replace('+00:00', 'Z')}
        other = {'project': 'warden'}
        if scoped_ids('container', other, docker):
            raise RuntimeError('existing Warden containers: reconcile aggregate memory/storage before running')
        external = 0
        for identity in set(scoped_ids('image', other, docker)):
            external += 2 * json.loads(docker(['image', 'inspect', identity]))[0]['Size'] + 64000000
        outstanding = outstanding_bytes(ROOT / '.cache/warden-lab')
        print('outstanding Docker allocation charge:', outstanding, flush=True)
        reserve, memory = RESERVE, 4000000000
        if args.mode in ('api', 'api-code', 'egress'):
            from runtime_lab_api import cached_postgres, API_RESERVE, PG_MEMORY
            cached_postgres(docker)
            reserve, memory = API_RESERVE, memory + PG_MEMORY
        preflight(reserve + external + outstanding, memory + args.other_service_memory_bytes)
        output = ROOT / '.cache/warden-lab' / ('docker-' + labels['session'])
        output.mkdir(mode=0o700)
        archive = output / 'rootfs.tar'
        try:
            if args.mode == 'matrix':
                package(archive, output / 'manifest.json', matrix=True)
            else:
                package(archive, output / 'manifest.json')
            cli = docker
            if args.mode in ('api', 'api-code', 'egress'):
                password = secrets.token_hex(32)
                def cli(command, **kwargs):
                    return docker(command, secret_env={'POSTGRES_PASSWORD': password, 'WARDEN_API_PASSWORD': password}, **kwargs)
            image_session(archive, output, labels, args.mode, cli, egress=egress)
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
