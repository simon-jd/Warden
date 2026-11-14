#!/usr/bin/env python3
"""Fixed owned k3s bootstrap; capability mode requires prior independent review."""
import argparse
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
import struct
import subprocess
import sys
import tarfile
import urllib.request
from k3s_lab_materials import PINS, embedded_k3s, regular_files, verify
from runtime_lab_docker import (CAPS, ROOT, defer_signals, docker, owned_inspect,
                               scoped_ids, read_trusted, record_charge, outstanding_bytes)
from runtime_lab_paths import trusted_directory, exclusive_file
from runtime_lab_runner import interrupted

RESERVE = 6000000000
IMAGE_LIMIT = 900000000
BASE = ROOT / '.cache/warden-lab'
MATERIALS = ROOT / '.cache/warden-k3s-materials'


def create_args(image, labels, mode, *, reviewed=False, binding=None):
    if (mode not in ('smoke', 'mount-smoke', 'bootstrap') or not re.fullmatch('sha256:[0-9a-f]{64}', image)
            or set(labels) != {'project', 'owner', 'session', 'ttl'}
            or labels['project'] != 'warden' or labels['owner'] != 'codex-warden'
            or not re.fullmatch('[0-9a-f]{32}', labels['session'])
            or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', labels['ttl'])):
        raise ValueError('fixed mode, exact image ID and complete owned labels required')
    args = ['container', 'create', '--pull=never', '--network=none', '--ipc=private',
            '--cgroupns=private', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--memory=4000000000',
            '--memory-swap=4000000000', '--pids-limit=512', '--cpus=2',
            '--log-driver=json-file', '--log-opt=max-size=10m', '--log-opt=max-file=2',
            '--stop-timeout=20', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777',
            '--tmpfs=/run:rw,nosuid,nodev,size=128m,mode=755']
    for key, value in labels.items():
        args += ['--label', f'{key}={value}']
    if mode == 'smoke':
        args += ['--user=65534:65534']
    else:
        if (not reviewed or not isinstance(binding, dict)
                or set(binding) != {'source', 'device', 'inode', 'uid'}
                or binding['source'] != str(BASE / ('docker-' + labels['session']))
                or any(type(binding[k]) is not int or binding[k] < (0 if k == 'uid' else 1)
                       for k in ('device', 'inode', 'uid'))):
            raise ValueError('reviewed profile and fixed owned session identity required')
        args += ['--mount', f"type=bind,src={binding['source']},dst=/session,readonly,bind-propagation=rprivate",
                 '--env', 'WARDEN_LAB_SESSION_IDENTITY=' + ':'.join(str(binding[k]) for k in ('device', 'inode', 'uid')),
                 '--env', 'WARDEN_LAB_HOST_MOUNT_NS=' + os.readlink('/proc/self/ns/mnt')]
        if mode == 'mount-smoke':
            args += [f"--user={binding['uid']}:{binding['uid']}"]
        else:
            args += ['--cap-add=' + cap for cap in CAPS]
            args += ['--security-opt=apparmor=unconfined', '--security-opt=seccomp=unconfined',
                     '--tmpfs=/etc/rancher/node:rw,nosuid,nodev,noexec,size=1m,mode=700',
                     '--tmpfs=/var/log:rw,nosuid,nodev,noexec,size=32m,mode=755',
                     '--env', 'WARDEN_LAB_HOST_CGROUP_NS=' + os.readlink('/proc/self/ns/cgroup')]
    return args + [image, mode]


def select_inputs(k3s, gvisor):
    names = ('k3s', 'runc', 'containerd-shim-runc-v2', 'cni', 'ip')
    if any(not k3s.get('bin/' + name) for name in names):
        raise ValueError('required k3s regular member missing')
    if any(not gvisor.get(name) for name in ('runsc', 'containerd-shim-runsc-v1', 'gvisor-bin/gvisor_sentry')):
        raise ValueError('required gVisor regular member missing')
    if any(name not in ('runsc', 'containerd-shim-runsc-v1') and not re.fullmatch(r'gvisor-bin/[a-z0-9_-]+', name) for name in gvisor):
        raise ValueError('unexpected gVisor payload')
    files = {'usr/bin/' + name: k3s['bin/' + name] for name in names}
    files.update({'usr/bin/' + name: data for name, data in gvisor.items()})
    aliases = {'usr/bin/' + name: 'k3s' for name in ('containerd', 'kubectl', 'ctr', 'crictl')}
    aliases['usr/bin/loopback'] = 'cni'
    aliases['etc/rancher/k3s'] = '/run/k3s-client'
    return files, aliases


def execute(image, labels, mode, *, cli=docker, reviewed=False, binding=None, before_remove=None):
    args = create_args(image, labels, mode, reviewed=reviewed, binding=binding)
    cid = None
    success = False
    try:
        with defer_signals():
            cid = cli(args).strip()
        owned_inspect('container', cid, labels, cli)
        print(json.dumps({'owned_container': cid, 'mode': mode}), flush=True)
        output = cli(['container', 'start', '--attach', cid], timeout=360)
        if cli(['container', 'wait', cid]).strip() != '0':
            raise RuntimeError('fixed node entrypoint failed; private scene retained')
        if mode == 'bootstrap' and '{"cleanup":"empty-reaped-deleted"}' not in output.splitlines():
            raise RuntimeError('inner cleanup proof absent; private scene retained')
        print(output, end='', flush=True)
        success = True
    finally:
        # Lost create responses are recovered only through all random labels.
        with defer_signals():
            ids = [cid] if cid and re.fullmatch('[0-9a-f]{64}', cid) else scoped_ids('container', labels, cli)
            failures = []
            for identity in ids:
                try:
                    owned_inspect('container', identity, labels, cli)
                    cli(['container', 'stop', '--time=20', identity])
                    if mode == 'smoke' and not success:
                        # This profile has no credentials, network or host bind.
                        # Retain its fixed version/ABI diagnostics before removal.
                        print(cli(['container', 'logs', identity]), end='', flush=True)
                    if success or mode == 'smoke':
                        if before_remove is not None:
                            before_remove()
                        cli(['container', 'rm', identity])
                        if identity in scoped_ids('container', labels, cli):
                            raise RuntimeError('owned container remains')
                        print(json.dumps({'removed_container': identity}), flush=True)
                    else:
                        raise RuntimeError('inner cleanup unproven; container/image/charge retained')
                except BaseException as error:
                    failures.append(type(error).__name__)
            if failures:
                raise RuntimeError('owned cleanup failed: ' + ','.join(failures))


def accounting(memory, download=0):
    info = json.loads(docker(['info', '--format', '{{json .}}']))
    if info['Name'] != os.uname().nodename or info['CgroupVersion'] != '2' or any('rootless' in x for x in info['SecurityOptions']):
        raise RuntimeError('local rootful cgroup-v2 daemon identity mismatch')
    if scoped_ids('container', {'project': 'warden'}, docker):
        raise RuntimeError('existing Warden containers require aggregate reconciliation')
    external = 0
    for identity in set(scoped_ids('image', {'project': 'warden'}, docker)):
        data = json.loads(docker(['image', 'inspect', identity]))
        if len(data) != 1 or data[0]['Id'] != identity or data[0]['Config'].get('Labels', {}).get('project') != 'warden':
            raise ValueError('unknown owned image accounting')
        external += 2 * data[0]['Size'] + 64000000
    outstanding = outstanding_bytes(BASE)
    print(json.dumps({'owned_image_charge': external, 'outstanding_charge': outstanding}), flush=True)
    subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/azure_guard.py'), 'preflight',
                    '--additional-bytes', str(RESERVE + external + outstanding),
                    '--service-memory-bytes', str(memory), '--download-bytes', str(download)], check=True)


def materials(memory):
    MATERIALS.mkdir(mode=0o700, exist_ok=True)
    directory = trusted_directory(str(MATERIALS), os.getuid())
    try:
        for name, pin in PINS.items():
            accounting(memory, pin['bytes'])
            path = MATERIALS / name
            try:
                verify(read_trusted(path, os.getuid()), pin)
            except FileNotFoundError:
                with urllib.request.urlopen(pin['url'], timeout=60) as response:
                    data = verify(response.read(pin['bytes'] + 1), pin)
                fd = exclusive_file(directory, name, data)
                os.fsync(fd)
                os.close(fd)
            print(json.dumps({'material': name, **pin}), flush=True)
        os.fsync(directory)
    finally:
        os.close(directory)


def abi_dependencies(result):
    if result.returncode and (result.stdout + result.stderr).strip() not in ('not a dynamic executable', 'statically linked'):
        raise ValueError('Python ABI dependency inspection failed')
    if 'not found' in result.stdout:
        raise ValueError('Python ABI dependency missing')
    return {m.group(1) for line in result.stdout.splitlines()
            if (m := re.search(r'(?:=>\s+)?(/[^\s]+)', line))}


def verify_anchor(path, fd):
    current = trusted_directory(str(path), os.getuid())
    try:
        a, b = os.fstat(fd), os.fstat(current)
        if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) or b.st_uid != os.getuid() or b.st_mode & 0o777 != 0o700:
            raise ValueError('owned session path drifted; preserving charge')
    finally:
        os.close(current)


def postflight(output, fd):
    verify_anchor(output, fd)
    for name in os.listdir(fd):
        if name.startswith('session-'):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if set(os.listdir(child)) != {'containerd.toml', 'containerd.log'} or os.fstat(child).st_uid != os.getuid():
                    raise RuntimeError('ordinary-UID postflight failed')
                for item in ('containerd.toml', 'containerd.log'):
                    f = os.open(item, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=child)
                    os.close(f)
            finally:
                os.close(child)


def public_session_snapshot(fd):
    snapshot = {}
    for name in os.listdir(fd):
        if name not in ('rootfs.tar', 'manifest.json', 'identity.json', 'charge.json'):
            raise ValueError('unexpected mount-smoke session content')
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        with os.fdopen(child, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError('untrusted mount-smoke input')
            snapshot[name] = (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                              hashlib.file_digest(source, 'sha256').hexdigest())
    return snapshot


def package(archive, manifest):
    """Construct a scratch root from fixed regular inputs and trusted Python ABI."""
    from k3s_lab_init import RUNSC
    wrapper = verify(read_trusted(MATERIALS / 'k3s', os.getuid()), PINS['k3s'])
    payload_hashes = sorted(set(x.decode() for x in re.findall(rb'([0-9a-f]{64})\.tar\.zst', wrapper)))
    k3s = embedded_k3s(wrapper)
    gvisor = regular_files(verify(read_trusted(MATERIALS / 'gvisor.tar.bz2', os.getuid()), PINS['gvisor.tar.bz2']))
    files, aliases = select_inputs(k3s, gvisor)
    # Official runtime artifacts must be static amd64 ELFs; do not execute an
    # unreviewed loader or search host libraries on their behalf.
    for name, data in files.items():
        if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
            raise ValueError('selected artifact is not amd64 ELF: ' + name)
        offset = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        if any(struct.unpack_from('<I', data, offset + i * size)[0] == 3 for i in range(count)):
            raise ValueError('unexpected dynamic runtime artifact')
    selected_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    python = Path('/usr/bin/python3').resolve(strict=True)
    inputs = [python]
    stdlib = Path('/usr/lib') / ('python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor))
    for directory, dirs, names in os.walk(stdlib, followlinks=False):
        dirs[:] = [d for d in dirs if d not in ('__pycache__', 'test', 'tests', 'idlelib', 'tkinter', 'ensurepip')]
        inputs.extend(Path(directory) / name for name in names)
    dependencies = set()
    for path in inputs:
        if path.lstat().st_uid != 0:
            raise ValueError('untrusted Python input owner')
        data = read_trusted(path.resolve(strict=True), 0)
        files[str(path).lstrip('/')] = data
        if data[:4] == b'\x7fELF':
            result = subprocess.run(['/usr/bin/ldd', str(path)], text=True, capture_output=True,
                                    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            dependencies.update(abi_dependencies(result))
    for name in dependencies:
        files[name.lstrip('/')] = read_trusted(Path(name).resolve(strict=True), 0)
    aliases['usr/bin/python3'] = python.name
    for name in ('k3s_lab_init.py', 'runtime_lab_docker_init.py', 'runtime_lab_runner.py', 'runtime_lab_paths.py'):
        files['opt/warden/scripts/' + name] = read_trusted(ROOT / 'scripts' / name, os.getuid())
    files['opt/warden/input/runsc.toml'] = RUNSC.encode()
    files['opt/warden/input/cni/10-loopback.conflist'] = json.dumps({
        'cniVersion': '1.0.0', 'name': 'warden-none', 'plugins': [{'type': 'loopback'}]}).encode()
    files['opt/warden/input/bootstrap.json'] = json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': [
        {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'warden-lab'}},
        {'apiVersion': 'node.k8s.io/v1', 'kind': 'RuntimeClass', 'metadata': {'name': 'gvisor'}, 'handler': 'gvisor'}]}).encode()
    files['etc/passwd'] = b'root:x:0:0:root:/run:/usr/bin/python3\nnobody:x:65534:65534:nobody:/tmp:/usr/bin/python3\n'
    files['etc/group'] = b'root:x:0:\nnogroup:x:65534:\n'
    files['etc/os-release'] = read_trusted(Path('/usr/lib/os-release'), 0)
    document = {'materials': PINS, 'k3s_embedded_payload_sha256': payload_hashes,
                'selected': selected_hashes, 'aliases': aliases,
                'files': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())}}
    manifest.write_text(json.dumps(document, sort_keys=True, indent=2) + '\n')
    files['opt/warden/input/manifest.json'] = manifest.read_bytes()
    total = sum(map(len, files.values()))
    if total > IMAGE_LIMIT:
        raise ValueError('scratch image exceeds reserved size')
    with tarfile.open(archive, 'x') as tar:
        dirs = {'proc', 'sys', 'sys/fs', 'sys/fs/cgroup', 'dev', 'tmp', 'run', 'session',
                'etc/rancher/node', 'var/log', 'var/lib', 'var/lib/kubelet',
                # The controller-manager's fixed default FlexVolume prober
                # must find an empty directory without writing the RO root.
                'usr/libexec', 'usr/libexec/kubernetes',
                'usr/libexec/kubernetes/kubelet-plugins',
                'usr/libexec/kubernetes/kubelet-plugins/volume',
                'usr/libexec/kubernetes/kubelet-plugins/volume/exec'}
        for name in files:
            dirs.update(str(p) for p in Path(name).parents if str(p) != '.')
        for name in sorted(dirs):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(item)
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(data), 0o755 if name.startswith(('usr/bin/', 'lib', 'usr/lib/')) else 0o644
            tar.addfile(item, io.BytesIO(data))
        for name, target in sorted(aliases.items()):
            item = tarfile.TarInfo(name)
            item.type, item.linkname = tarfile.SYMTYPE, target
            tar.addfile(item)
    print(json.dumps({'rootfs_bytes': total, 'archive_bytes': archive.stat().st_size,
                      'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}), flush=True)


def image_session(output, labels, mode, reviewed=False):
    image, cleaned = None, False
    fd = trusted_directory(str(output), os.getuid())
    record_charge(output, reserve=RESERVE)
    preserve_scene = False
    snapshot = None
    def check_cleanup():
        nonlocal preserve_scene
        if preserve_scene:
            raise RuntimeError('session validation failed; objects and charge retained')
        try:
            postflight(output, fd)
            if snapshot is not None and public_session_snapshot(fd) != snapshot:
                raise ValueError('readonly mount-smoke content changed; scene retained')
        except BaseException:
            preserve_scene = True
            raise
    try:
        verify_anchor(output, fd)
        changes = ['ENTRYPOINT ["/usr/bin/python3", "-B", "/opt/warden/scripts/k3s_lab_init.py"]',
                   'ENV PATH=/usr/bin', 'ENV PYTHONDONTWRITEBYTECODE=1']
        changes += [f'LABEL {k}={v}' for k, v in labels.items()]
        command = ['image', 'import']
        for change in changes:
            command += ['--change', change]
        command += [str(output / 'rootfs.tar')]
        with defer_signals():
            candidate = docker(command, timeout=120).strip()
        if not re.fullmatch('sha256:[0-9a-f]{64}', candidate):
            raise ValueError('nonexact image import response')
        image = candidate
        metadata = owned_inspect('image', image, labels, docker)
        if metadata['Size'] > IMAGE_LIMIT:
            raise ValueError('imported image exceeds reserved size')
        identity_record = {'image': image, 'image_size_bytes': metadata['Size'], 'labels': labels}
        (output / 'identity.json').write_text(json.dumps(identity_record, sort_keys=True) + '\n')
        print(json.dumps(identity_record, sort_keys=True), flush=True)
        # Docker binds a fixed real path RO. The open FD supplies immutable
        # identity; PID1 checks it before any session access or RW remount.
        verify_anchor(output, fd)
        info = os.fstat(fd)
        binding = {'source': str(output), 'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid}
        if mode == 'mount-smoke':
            snapshot = public_session_snapshot(fd)
        execute(image, labels, mode, cli=docker, reviewed=reviewed,
                binding=binding, before_remove=check_cleanup)
        check_cleanup()
        cleaned = True
    finally:
        try:
            check_cleanup()
            if not scoped_ids('container', labels, docker):
                for identity in ([image] if image else scoped_ids('image', labels, docker)):
                    owned_inspect('image', identity, labels, docker)
                    check_cleanup()
                    docker(['image', 'rm', identity])
                    if identity in scoped_ids('image', labels, docker):
                        raise RuntimeError('owned image remains; charge retained')
                    print(json.dumps({'removed_image': identity}), flush=True)
                if cleaned or (mode == 'smoke' and image is not None):
                    check_cleanup()
                    record_charge(output, released=True, reserve=RESERVE)
            else:
                raise RuntimeError('container remains; image and charge retained')
        finally:
            os.close(fd)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['materials', 'smoke', 'mount-smoke', 'bootstrap'])
    parser.add_argument('--other-service-memory-bytes', type=int, required=True)
    parser.add_argument('--reviewed-live-profile', action='store_true')
    parser.add_argument('--reviewed-mount-profile', action='store_true')
    args = parser.parse_args()
    if args.other_service_memory_bytes < 0:
        parser.error('negative memory declaration')
    if args.mode == 'bootstrap' and not args.reviewed_live_profile:
        parser.error('capability-bearing bootstrap requires independent review')
    if args.mode == 'mount-smoke' and not args.reviewed_mount_profile:
        parser.error('capless mount probe requires independent profile review')
    signal.signal(signal.SIGTERM, interrupted)
    basefd = trusted_directory(str(BASE), os.getuid())
    os.close(basefd)
    lock = os.open(BASE / 'docker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # 4GB Docker hard maximum plus a conservative 3GB packaging/controller
        # peak; do not hide the host-side assembly process in the container cap.
        memory = 7000000000 + args.other_service_memory_bytes
        if args.mode == 'materials':
            materials(memory)
            return
        accounting(memory)
        labels = {'project': 'warden', 'owner': 'codex-warden', 'session': secrets.token_hex(16),
                  'ttl': (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        output = BASE / ('docker-' + labels['session'])
        output.mkdir(mode=0o700)
        package(output / 'rootfs.tar', output / 'manifest.json')
        output_fd = trusted_directory(str(output), os.getuid())
        completed = False
        try:
            archive_info = os.stat('rootfs.tar', dir_fd=output_fd, follow_symlinks=False)
            accounting(memory)  # fresh current project footprint immediately before import
            image_session(output, labels, args.mode, args.reviewed_live_profile or args.reviewed_mount_profile)
            completed = True
        finally:
            try:
                if completed:
                    verify_anchor(output, output_fd)
                    current = os.stat('rootfs.tar', dir_fd=output_fd, follow_symlinks=False)
                    if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                            or (current.st_dev, current.st_ino) != (archive_info.st_dev, archive_info.st_ino)):
                        raise ValueError('archive identity drifted; retained')
                    os.unlink('rootfs.tar', dir_fd=output_fd)
            finally:
                os.close(output_fd)
        print('public evidence directory: ' + str(output), flush=True)
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print('k3s lab failed: ' + type(error).__name__, file=sys.stderr, flush=True)
        sys.exit(2)
