"""Controller-only exact Task4 phase A recovery; never releases its 5GB charge."""
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
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import time

import firecracker_recovery_init as helper
from runtime_lab_paths import trusted_directory, exclusive_file, NOFOLLOW_DIR
from runtime_lab_docker import scoped_ids, owned_inspect

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / '.cache/warden-lab'
SESSION = '89c9296e79ce14c5dd30e0d5e4772f1d'
SCENE = BASE / ('docker-firecracker-' + SESSION)
LIVE = SCENE / 'live'
PREDECESSOR_WORK = SCENE / 'recovery-a'
SECOND_WORK = SCENE / 'recovery-a-py314-v1'
WORK = SCENE / 'recovery-a-py314-static-v1'
PREDECESSOR_SOURCE = '8c8e9edf4a269effb155ae027b703cd9dc770836'
SECOND_SOURCE = 'ba8cfaf6bffd7996f54bd50db9ccf453ff121022'
PREDECESSOR_HELPER = '72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2'
MATERIAL_POLICY = 'python314-public-material-v1'
PYTHON = Path('/usr/bin/python3.14')
STDLIB = Path('/usr/lib/python3.14')
STDLIB_NAME = 'usr/lib/python3.14/'
SYSCONFIG_ALIAS = '_sysconfigdata__x86_64-linux-gnu.py'
SYSCONFIG_TARGET = '_sysconfigdata__linux_x86_64-linux-gnu.py'
LINKS = {SYSCONFIG_ALIAS: SYSCONFIG_TARGET,
         'sitecustomize.py': '/etc/python3.14/sitecustomize.py',
         'config-3.14-x86_64-linux-gnu/libpython3.14.so': '../../x86_64-linux-gnu/libpython3.14.so.1'}
DEVELOPMENT_OBJECT = 'config-3.14-x86_64-linux-gnu/python.o'
OBJECT_HEADER = bytes.fromhex('7f454c4602010100000000000000000001003e00')
OBJECT_HEADER_SHA = 'f43453b3fe51a3fba833a8277427ab17f9bd218590b0c87a13151612e1b7fe3e'
OMITTED = {STDLIB_NAME + name for name in (*LINKS, DEVELOPMENT_OBJECT) if name != SYSCONFIG_ALIAS}
PARENT = (66307, 56377605)
CID = '360a5600d95920d39dc8c482dc60df635ec26e0a9580770e6612358ee817c078'
IMAGE = 'sha256:31f091d0b413b74df4d0b7ea43da1e827b2e2ed2a9c37ec62e583ee505f82938'
OLD_LABELS = {'project': 'warden', 'owner': 'codex-warden', 'task': 'firecracker',
              'session': SESSION, 'ttl': '2026-10-24T23:22:48.630773+00:00'}
POLICY_SHA = 'bd958d0d3ab7193f91cb14013f9ce53ddd88c46ab6cba89337b7e4eeb6e74404'
EXPECTED_RECORDS = {
    'identity': {'image': IMAGE, 'image_bytes': 148194205, 'labels': OLD_LABELS,
                 'mode': 'boot', 'source': helper.SOURCE},
    'binding': {'binding': {'device': 66307, 'inode': 56377608, 'source': str(LIVE), 'uid': 1000},
                'host_mount_ns': 'mnt:[4026531832]'},
    'receipt': {'container': CID, 'host_cgroup': '0::/system.slice/docker-' + CID + '.scope',
                'host_pid': 2432414, 'host_starttime': 67832627, 'image': IMAGE,
                'outer': {'cgroup_ns': 'cgroup:[4026537031]', 'device': 30, 'inode': 2116013,
                          'kind': 'warden-device-receipt-v1', 'mount_id': 9736,
                          'mount_ns': 'mnt:[4026536060]', 'pid': 1,
                          'policy_sha256': POLICY_SHA, 'policy_version': 'warden-tun-deny-v1'},
                'parent_identity': [30, 75, 0], 'target_identity': [30, 2116013, 0]},
    'absence': {'container': CID, 'target_identity': [30, 2116013, 0],
                'parent_identity': [30, 75, 0], 'exact_original_entry_absent': True,
                'meaning': 'exact owned cgroup path removed; not synchronous kernel allocator GC'},
    'charge': {'version': 1, 'reserved_bytes': 5000000000, 'released': False}}
RECORD_NAMES = {'identity': 'identity.json', 'binding': 'session-binding.json',
                'receipt': 'device-receipt.json', 'absence': 'device-cgroup-absence.json',
                'charge': 'charge.json'}
ENVELOPE = 736000000
INPUT_UID = 0
INPUT_GID = 0
FILE_LIMIT = 128000000
ARCHIVE_LIMIT = IMAGE_LIMIT = 160000000
MODULE = ROOT / 'scripts/firecracker_recovery_init.py'
MODES = ('inspect', 'restore-traversal')
encode = helper.encode
Refusal = helper.Refusal


def sha(data): return hashlib.sha256(data).hexdigest()

def admitted(rest, outstanding, images, services):
    if any(type(x) is not int or x < 0 for x in (rest, outstanding, images, services)) or outstanding < helper.CHARGE:
        raise Refusal('recovery_charge_unknown')
    total, memory = rest + outstanding + images + ENVELOPE, services + 1256000000
    if total > 12000000000 or memory > 16000000000:
        raise Refusal('recovery_resource_limit')
    return {'kind': 'exact-scene-recovery-admission-v1', 'rest_allocated_bytes': rest,
            'original_opaque_charge': helper.CHARGE, 'all_outstanding_bytes': outstanding,
            'all_owned_image_charge': images, 'prospective_helper_growth': ENVELOPE,
            'disk_bytes': total, 'resident_bytes': memory, 'ordinary_guard_pass': False}

def project_rest(root, opaque, anchor):
    root, opaque = Path(root), Path(opaque)
    if root.resolve() != root or opaque.parent.resolve() != opaque.parent or not opaque.is_relative_to(root):
        raise Refusal('rest_path_alias')
    def check():
        s = opaque.lstat()
        if not stat.S_ISDIR(s.st_mode) or (s.st_dev, s.st_ino) != anchor: raise Refusal('opaque_identity_changed')
    check()
    total, skipped = 0, 0
    def unreadable(error): raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in tuple(dirs):
            if Path(directory) / name == opaque:
                check(); dirs.remove(name); skipped += 1
        for name in files:
            s = (Path(directory) / name).lstat()
            if not stat.S_ISLNK(s.st_mode): total += s.st_blocks * 512
    check()
    if skipped != 1: raise Refusal('opaque_subtree_not_exactly_once')
    return total

def verify_records(records):
    # Canonical bytes distinguish bool from int; Python dict equality does not.
    if encode(records) != encode(EXPECTED_RECORDS): raise Refusal('original_records_mismatch')

def create_args(mode, image, labels, host_ns):
    validate_labels(labels, mode)
    if not re.fullmatch('sha256:[0-9a-f]{64}', image) or not re.fullmatch(r'mnt:\[[1-9][0-9]*\]', host_ns):
        raise Refusal('helper_identity')
    args = ['container', 'create', '--pull=never', '--user=0:0', '--network=none',
            '--ipc=private', '--cgroupns=private', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--memory=256000000', '--memory-swap=256000000',
            '--cpus=1', '--pids-limit=32', '--stop-timeout=5',
            '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m', '--log-driver=json-file',
            '--log-opt=max-size=64k', '--log-opt=max-file=1',
            '--mount=type=bind,src=' + str(LIVE) + ',dst=/session,readonly,bind-propagation=rprivate',
            '--env=WARDEN_RECOVERY_HOST_MOUNT_NS=' + host_ns]
    if mode == 'restore-traversal':
        args += ['--cap-add=CHOWN', '--cap-add=SYS_ADMIN',
                 '--security-opt=apparmor=unconfined', '--security-opt=seccomp=unconfined']
    for key, value in labels.items(): args += ['--label', key + '=' + value]
    return args + [image, mode]


def validate_labels(labels, mode):
    if (mode not in MODES or type(labels) is not dict
            or set(labels) != {'project', 'owner', 'task', 'session', 'original_session', 'phase', 'ttl'}
            or labels['project'] != 'warden' or labels['owner'] != 'codex-warden'
            or labels['task'] != 'firecracker-recovery' or labels['original_session'] != SESSION
            or labels['phase'] != mode or type(labels['session']) is not str
            or not re.fullmatch('[0-9a-f]{32}', labels['session'])
            or type(labels['ttl']) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?\+00:00', labels['ttl'])):
        raise Refusal('helper_labels')

def inspect_profile(data, mode, image, labels, host_ns):
    create_args(mode, image, labels, host_ns)
    h, c = data['HostConfig'], data['Config']
    expected = {'Memory': 256000000, 'MemorySwap': 256000000, 'NanoCpus': 1000000000,
                'PidsLimit': 32, 'NetworkMode': 'none', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                'PidMode': '', 'UsernsMode': '', 'CgroupParent': '', 'ReadonlyRootfs': True,
                'Privileged': False, 'CapDrop': ['ALL'],
                'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=16m'},
                'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '64k', 'max-file': '1'}},
                'Mounts': [{'Type': 'bind', 'Source': str(LIVE), 'Target': '/session',
                            'ReadOnly': True, 'BindOptions': {'Propagation': 'rprivate'}}]}
    if encode({k: h.get(k) for k in expected}) != encode(expected): raise Refusal('helper_host_config')
    if any(h.get(k) for k in ('Devices', 'DeviceCgroupRules', 'DeviceRequests', 'Binds', 'VolumesFrom')):
        raise Refusal('helper_extra_authority')
    caps = ['CAP_CHOWN', 'CAP_SYS_ADMIN'] if mode == 'restore-traversal' else []
    actual = h.get('CapAdd') or []
    security = ['no-new-privileges'] + (['apparmor=unconfined', 'seccomp=unconfined'] if mode == 'restore-traversal' else [])
    if type(actual) is not list or sorted(actual) != sorted(caps) or sorted(h.get('SecurityOpt', [])) != sorted(security):
        raise Refusal('helper_caps_lsm')
    expected_config = {'User': '0:0', 'Labels': labels,
                       'Entrypoint': ['/usr/bin/python3', '-I', '-S', '-B', '/recovery.py'],
                       'Cmd': [mode], 'Env': ['WARDEN_RECOVERY_HOST_MOUNT_NS=' + host_ns],
                       'OpenStdin': False, 'StdinOnce': False, 'AttachStdin': False, 'Tty': False}
    if data.get('Image') != image or encode({k: c.get(k) for k in expected_config}) != encode(expected_config):
        raise Refusal('helper_config')
    mounts = data.get('Mounts')
    if type(mounts) is not list or len(mounts) != 1: raise Refusal('helper_mounts')
    m = mounts[0]
    expected_mount = {'Type': 'bind', 'Source': str(LIVE), 'Destination': '/session',
                      'RW': False, 'Propagation': 'rprivate', 'Mode': m.get('Mode')}
    if m.get('Mode') not in ('', 'ro') or encode(m) != encode(expected_mount): raise Refusal('helper_mounts')

def build_archive(output, inputs, module, expected=None):
    output, module = Path(output), Path(module)
    if len(inputs) > 4096 or 'usr/bin/python3' not in inputs:
        raise Refusal('runtime_input_count')
    selected = dict(inputs)
    if OMITTED.intersection(selected): raise Refusal('omitted_material_reintroduced')
    material = inputs if isinstance(inputs, RuntimeMaterial) else None
    if material is not None: material.recheck()
    if 'recovery.py' in selected or 'expected-inventory.json' in selected or 'package-manifest.json' in selected:
        raise Refusal('reserved_package_name')
    selected['recovery.py'] = module
    opened, manifest, total = {}, {}, 0
    try:
        # Full preflight before publishing an archive; no partial unsafe package.
        for name, path in sorted(selected.items()):
            if (not re.fullmatch(r'[A-Za-z0-9_./+\-]+', name) or name.startswith('/')
                    or any(p in ('', '.', '..') for p in name.split('/'))):
                raise Refusal('package_name')
            f = (os.dup(material.target_fd) if material is not None and name in
                 (STDLIB_NAME + SYSCONFIG_ALIAS, STDLIB_NAME + SYSCONFIG_TARGET)
                 else os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC))
            os.lseek(f, 0, os.SEEK_SET)
            opened[name] = f
            s = os.fstat(f)
            owner = os.getuid() if name == 'recovery.py' else INPUT_UID
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != owner or s.st_nlink != 1
                    or s.st_mode & 0o6022 or os.listxattr(f) or s.st_size > FILE_LIMIT):
                raise Refusal('unsafe_package_input')
            total += s.st_size
            if total > FILE_LIMIT: raise Refusal('package_file_limit')
            digest = hashlib.sha256()
            consumed = 0
            while chunk := os.read(f, min(65536, s.st_size + 1 - consumed)):
                consumed += len(chunk)
                if consumed > s.st_size: raise Refusal('package_input_grew')
                digest.update(chunk)
            if consumed != s.st_size or helper.metadata(os.fstat(f)) != helper.metadata(s):
                raise Refusal('package_input_changed')
            os.lseek(f, 0, os.SEEK_SET)
            manifest[name] = {'bytes': s.st_size, 'sha256': digest.hexdigest()}
        if expected is not None:
            helper.validate_inventory(expected, manifest['recovery.py']['sha256'])
            total += len(expected)
        if material is not None:
            for name in (SYSCONFIG_ALIAS, SYSCONFIG_TARGET):
                if manifest[STDLIB_NAME + name]['sha256'] != material.target_sha:
                    raise Refusal('sysconfig_copy_changed')
        document = encode({'version': 1, 'original_source': helper.SOURCE,
                           'files': manifest, 'material_policy': material.receipt if material is not None else None,
                           'expected_inventory_sha256': sha(expected) if expected is not None else None})
        if total + len(document) > FILE_LIMIT: raise Refusal('package_file_limit')
        # Exact upper bound for this USTAR layout, including directory headers.
        names = set(selected) | {'package-manifest.json'} | ({'expected-inventory.json'} if expected is not None else set())
        directories = {'proc', 'sys', 'dev', 'tmp', 'session'}
        for name in names:
            directories.update(str(p) for p in Path(name).parents if str(p) != '.')
        estimate = total + len(document) + 1024 * (len(names) + len(directories)) + 10240
        if estimate > ARCHIVE_LIMIT: raise Refusal('archive_limit')
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            with tarfile.open(fileobj=stream, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                for name in sorted(directories):
                    item = tarfile.TarInfo(name); item.type = tarfile.DIRTYPE; item.mode = 0o755
                    archive.addfile(item)
                for name, f in sorted(opened.items()):
                    os.lseek(f, 0, os.SEEK_SET)  # the two held-target copies share an open-file offset
                    before = os.fstat(f)
                    item = tarfile.TarInfo(name); item.size = manifest[name]['bytes']
                    item.mode = 0o555 if name == 'usr/bin/python3' or 'ld-linux' in name else 0o444
                    with os.fdopen(os.dup(f), 'rb') as reader: archive.addfile(item, reader)
                    if helper.metadata(os.fstat(f)) != helper.metadata(before): raise Refusal('package_input_changed')
                for name, raw in [('package-manifest.json', document)] + ([('expected-inventory.json', expected)] if expected is not None else []):
                    item = tarfile.TarInfo(name); item.size = len(raw); item.mode = 0o444
                    archive.addfile(item, io.BytesIO(raw))
            stream.flush(); os.fsync(stream.fileno())
            if stream.tell() > ARCHIVE_LIMIT: raise Refusal('archive_limit')
        output.chmod(0o400)
        if material is not None: material.recheck()
        with output.open('rb') as archive: digest = hashlib.file_digest(archive, 'sha256').hexdigest()
        return {'file_bytes': total + len(document), 'archive_bytes': output.stat().st_size,
                'archive_sha256': digest, 'files': manifest,
                'helper_sha256': manifest['recovery.py']['sha256'],
                'material_policy': material.receipt if material is not None else None,
                'expected_inventory_sha256': sha(expected) if expected is not None else None}
    finally:
        for f in opened.values(): os.close(f)


def bounded_command(args, timeout=30, limit=262144):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, bufsize=0)
    output = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
    out, err = process.stdout.fileno(), process.stderr.fileno()
    pending, deadline = set(output), time.monotonic() + timeout
    try:
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('fixed_command_deadline')
            ready, _, _ = select.select(list(pending), [], [], remaining)
            if not ready: raise TimeoutError('fixed_command_deadline')
            for fd in ready:
                chunk = os.read(fd, 4096)
                if not chunk: pending.remove(fd); continue
                output[fd].extend(chunk)
                if len(output[fd]) > (limit if fd == out else 4096): raise Refusal('fixed_command_output_bound')
        code = process.wait(timeout=max(.001, deadline - time.monotonic()))
        return code, bytes(output[out]), bytes(output[err])
    finally:
        if process.poll() is None:
            process.kill()  # only this original local CLI child; objects remain charged
            process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()


def docker(args, timeout=30):
    code, output, _ = bounded_command(['/usr/bin/docker', '--host=unix:///var/run/docker.sock', *args], timeout)
    if code: raise Refusal('docker_command_failed')
    return output.decode('utf-8', errors='strict')


def dependencies(stdout, stderr, code):
    if len(stdout) + len(stderr) > 65536: raise Refusal('abi_output_bound')
    if code:
        if (stdout + stderr).strip() in (b'not a dynamic executable', b'statically linked'): return set()
        raise Refusal('unknown_python_abi')
    if stdout.strip() == b'statically linked' and not stderr: return set()
    if stderr.strip(): raise Refusal('unknown_python_abi')
    paths = set()
    for line in stdout.decode('ascii').splitlines():
        line = line.strip()
        if not line or re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line): continue
        match = re.fullmatch(r'(?:[A-Za-z0-9_.+\-]+ => )?(/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+\-]+) \(0x[0-9a-f]+\)', line)
        if not match or '..' in Path(match[1]).parts: raise Refusal('unknown_python_abi')
        paths.add(match[1])
    if not paths: raise Refusal('unknown_python_abi')
    return paths


def cleanup_helper(labels, image=None, cid=None):
    validate_labels(labels, labels.get('phase'))
    containers = scoped_ids('container', labels, docker)
    images = list(set(scoped_ids('image', labels, docker)))
    if len(containers) > 1 or len(images) > 1: raise Refusal('helper_objects_ambiguous')
    if cid is not None and containers and containers != [cid]: raise Refusal('helper_container_changed')
    if image is not None and images and images != [image]: raise Refusal('helper_image_changed')
    observed = []
    for identity in containers:
        item = owned_inspect('container', identity, labels, docker)
        if (item['Config'].get('Labels') != labels or item['State']['Running'] is not False
                or item['Image'] not in images or image is not None and item['Image'] != image):
            raise Refusal('helper_not_known_stopped')
        observed.append(identity)
    for identity in images:
        item = owned_inspect('image', identity, labels, docker)
        if item['Config'].get('Labels') != labels or type(item['Size']) is not int or not 0 < item['Size'] <= IMAGE_LIMIT:
            raise Refusal('helper_image_unknown')
    for identity in observed:
        # Recheck immediately before removal; no stop/kill/force fallback.
        if owned_inspect('container', identity, labels, docker)['State']['Running'] is not False:
            raise Refusal('helper_became_running')
        docker(['container', 'rm', identity])
    if scoped_ids('container', labels, docker): raise Refusal('helper_container_remains')
    for identity in images:
        owned_inspect('image', identity, labels, docker)
        docker(['image', 'rm', identity])
    if scoped_ids('image', labels, docker): raise Refusal('helper_image_remains')


def read_private(parent, name, limit=16384):
    if not re.fullmatch('[A-Za-z0-9_.-]+', name): raise Refusal('single_metadata_name')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o7777 != 0o600 or s.st_nlink != 1 or s.st_size > limit:
            raise Refusal('private_metadata_identity')
        with os.fdopen(os.dup(fd), 'rb') as f: raw = f.read(limit + 1)
        if len(raw) > limit or helper.metadata(os.fstat(fd)) != helper.metadata(s): raise Refusal('private_metadata_changed')
        return raw
    finally: os.close(fd)


def check_anchor(path, fd, identity, uid):
    s, current = os.fstat(fd), Path(path).lstat()
    for info in (s, current):
        if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity
                or info.st_uid != uid or info.st_mode & 0o7777 != 0o700):
            raise Refusal('scene_anchor_changed')
    if Path(path).resolve(strict=True) != Path(path): raise Refusal('scene_realpath_changed')


def exact_absence(parent, identity, name):
    s = os.fstat(parent)
    if (s.st_dev, s.st_ino, s.st_uid) != identity or not stat.S_ISDIR(s.st_mode) or s.st_mode & 0o022:
        raise Refusal('cgroup_parent_changed')
    try: os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError: return
    raise Refusal('original_cgroup_entry_present')


class Scene:
    def __init__(self, cleanup=False):
        self.parent = trusted_directory(str(SCENE), 1000)
        self.live = None
        try:
            self.live = os.open('live', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            uid = os.fstat(self.live).st_uid
            if uid not in ((0, 1000) if cleanup else (0,)): raise Refusal('live_owner_unknown')
            self.check(uid)
        except BaseException:
            self.close(); raise

    def close(self):
        if self.live is not None: os.close(self.live)
        os.close(self.parent)

    def check(self, live_uid):
        check_anchor(SCENE, self.parent, PARENT, 1000)
        check_anchor(LIVE, self.live, helper.ANCHOR, live_uid)
        records = {key: helper.strict_json(read_private(self.parent, name)) for key, name in RECORD_NAMES.items()}
        verify_records(records)
        parent = trusted_directory('/sys/fs/cgroup/system.slice', 0)
        try: exact_absence(parent, (30, 75, 0), 'docker-' + CID + '.scope')
        finally: os.close(parent)
        for kind in ('container', 'image'):
            if scoped_ids(kind, OLD_LABELS, docker): raise Refusal('original_objects_present')


@contextmanager
def project_lock():
    parent = trusted_directory(str(BASE), 1000)
    try: fd = os.open('docker.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally: os.close(parent)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 1000 or s.st_mode & 0o7777 != 0o600 or s.st_nlink != 1:
            raise Refusal('project_lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def private_directory(path):
    fd = trusted_directory(str(path), 1000)
    s = os.fstat(fd)
    if s.st_uid != 1000 or s.st_mode & 0o7777 != 0o700:
        os.close(fd); raise Refusal('private_output_directory')
    return fd


def save(path, value, replace=False):
    raw = value if isinstance(value, bytes) else encode(value)
    if len(raw) > 1048576: raise Refusal('metadata_output_bound')
    parent = private_directory(path.parent)
    try:
        if replace: read_private(parent, path.name, 1048576)
        name = path.name + '.next' if replace else path.name
        fd = exclusive_file(parent, name, raw)
        try: os.fsync(fd)
        finally: os.close(fd)
        if replace: os.replace(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally: os.close(parent)


def load(path, limit=16384):
    parent = private_directory(path.parent)
    try: return read_private(parent, path.name, limit)
    finally: os.close(parent)


def current_charges():
    total = 0
    for path in BASE.iterdir():
        if not path.name.startswith('docker-'): continue
        parent = private_directory(path)
        try:
            try: charge = helper.strict_json(read_private(parent, 'charge.json'))
            except FileNotFoundError: continue
        finally: os.close(parent)
        if (type(charge) is not dict or set(charge) != {'version', 'reserved_bytes', 'released'}
                or type(charge['version']) is not int or charge['version'] != 1
                or type(charge['reserved_bytes']) is not int or charge['reserved_bytes'] not in (3000000000, 5000000000, 6000000000)
                or type(charge['released']) is not bool): raise Refusal('charge_schema')
        if not charge['released']: total += charge['reserved_bytes']
    return total


def image_charge():
    total = 0
    for identity in set(scoped_ids('image', {'project': 'warden'}, docker)):
        data = owned_inspect('image', identity, {'project': 'warden'}, docker)
        if type(data['Size']) is not int or data['Size'] < 0: raise Refusal('image_size_unknown')
        total += 2 * data['Size'] + 64000000
    return total


def account(scene, services, own=None):
    scene.check(0)
    for identity in scoped_ids('container', {'project': 'warden'}, docker):
        if own is None: raise Refusal('other_container_present')
        data = owned_inspect('container', identity, own, docker)
        if data['Config'].get('Labels') != own: raise Refusal('other_container_present')
    result = admitted(project_rest(ROOT, LIVE, helper.ANCHOR), current_charges(), image_charge(), services)
    result['free_bytes'] = shutil.disk_usage(ROOT).free
    result['utc'] = datetime.now(timezone.utc).isoformat()
    return result


def source_sha():
    own = ['scripts/firecracker_recovery.py', 'scripts/firecracker_recovery_init.py']
    fixed = ['runtimes/firecracker', 'runtimes/gate', 'scripts/firecracker_lab.py',
             'scripts/firecracker_device_receipt.py', 'scripts/azure_guard.py', 'scripts/k3s_lab.py',
             'scripts/runtime_lab_docker.py', 'scripts/runtime_lab_paths.py']
    for args in (['diff', '--quiet', 'HEAD', '--', *own],
                 ['diff', '--quiet', helper.SOURCE, '--', *fixed],
                 ['ls-files', '--error-unmatch', '--', *own]):
        code, _, _ = bounded_command(['/usr/bin/git', '-C', str(ROOT), *args])
        if code: raise Refusal('reviewed_source_changed')
    code, raw, _ = bounded_command(['/usr/bin/git', '-C', str(ROOT), 'log', '-1', '--format=%H', '--', *own])
    value = raw.decode().strip()
    if code or not re.fullmatch('[0-9a-f]{40}', value): raise Refusal('source_sha_unknown')
    return value


def public_directory(path):
    # Stricter than the shared general-purpose directory helper: no sticky or
    # group-owned exceptions for these fixed public runtime parents.
    current = os.open('/', NOFOLLOW_DIR)
    try:
        for name in Path(path).parts[1:]:
            child = os.open(name, NOFOLLOW_DIR, dir_fd=current)
            os.close(current); current = child
            info = os.fstat(current)
            if info.st_uid != INPUT_UID or info.st_gid != INPUT_GID or info.st_mode & 0o022:
                raise Refusal('public_parent_identity')
        return current
    except BaseException:
        os.close(current); raise


def open_public(path):
    parent = public_directory(path.parent)
    try: fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally: os.close(parent)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != INPUT_UID or s.st_gid != INPUT_GID
                or s.st_nlink != 1 or s.st_mode & 0o6022 or os.listxattr(fd) or s.st_size > FILE_LIMIT):
            raise Refusal('untrusted_public_runtime')
        return fd
    except BaseException:
        os.close(fd); raise


def held_hash(fd):
    before = os.fstat(fd)
    if before.st_size > FILE_LIMIT: raise Refusal('runtime_file_limit')
    os.lseek(fd, 0, os.SEEK_SET)
    digest, consumed = hashlib.sha256(), 0
    while chunk := os.read(fd, min(65536, before.st_size + 1 - consumed)):
        consumed += len(chunk)
        if consumed > before.st_size: raise Refusal('public_material_grew')
        digest.update(chunk)
    if consumed != before.st_size or helper.metadata(os.fstat(fd)) != helper.metadata(before):
        raise Refusal('public_material_changed')
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


class RuntimeMaterial(dict):
    """Held exact aliases/object; omitted link targets are never dereferenced."""
    def __init__(self):
        super().__init__()
        self.links, self.parents = {}, {}
        self.input_metadata = {}
        self.target_fd = self.object_fd = None
        self.target_sha = None
        self.receipt = {'version': MATERIAL_POLICY, 'links': {}, 'object': None, 'host_abi': None}

    def close(self):
        for fd, _ in self.parents.values(): os.close(fd)
        self.parents.clear()
        for name in ('target_fd', 'object_fd'):
            fd = getattr(self, name)
            if fd is not None: os.close(fd); setattr(self, name, None)

    def parent(self, path):
        if path not in self.parents:
            fd = public_directory(path)
            self.parents[path] = (fd, helper.metadata(os.fstat(fd)))
        return self.parents[path][0]

    def link(self, name):
        path = STDLIB / name; parent = self.parent(path.parent)
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISLNK(before.st_mode) or before.st_uid != INPUT_UID or before.st_gid != INPUT_GID
                or before.st_nlink != 1 or before.st_mode & 0o7777 != 0o777):
            raise Refusal('public_alias_identity')
        text = os.readlink(path.name, dir_fd=parent)
        after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if text != LINKS[name] or helper.metadata(before) != helper.metadata(after):
            raise Refusal('public_alias_changed')
        return helper.metadata(before)

    def authenticate(self):
        for name in LINKS:
            self.links[name] = self.link(name)
            self.receipt['links'][STDLIB_NAME + name] = {
                'action': 'regular-copy' if name == SYSCONFIG_ALIAS else 'omit-link',
                'link_text': LINKS[name], 'metadata': self.links[name]}
        self.target_fd = open_public(STDLIB / SYSCONFIG_TARGET)
        self.target_metadata = helper.metadata(os.fstat(self.target_fd))
        self.target_sha = held_hash(self.target_fd)
        self.receipt['links'][STDLIB_NAME + SYSCONFIG_ALIAS].update(
            target=STDLIB_NAME + SYSCONFIG_TARGET, target_metadata=self.target_metadata, sha256=self.target_sha)
        path = STDLIB / DEVELOPMENT_OBJECT
        self.parent(path.parent)
        self.object_fd = open_public(path)
        info = os.fstat(self.object_fd)
        if info.st_size != 11504 or info.st_mode & 0o7777 != 0o644:
            raise Refusal('development_object_identity')
        header = os.read(self.object_fd, 20)
        self.object_metadata = helper.metadata(info)
        if header != OBJECT_HEADER or sha(header) != OBJECT_HEADER_SHA:
            raise Refusal('development_object_header')
        self.receipt['object'] = {'name': STDLIB_NAME + DEVELOPMENT_OBJECT, 'action': 'omit-development-object',
                                  'metadata': self.object_metadata, 'header_hex': header.hex(),
                                  'header_sha256': sha(header)}
        self.recheck()

    def recheck(self):
        for path, (fd, before) in self.parents.items():
            current = public_directory(path)
            try:
                if helper.metadata(os.fstat(fd)) != before or helper.metadata(os.fstat(current)) != before:
                    raise Refusal('public_parent_changed')
            finally: os.close(current)
        for name, before in self.links.items():
            if self.link(name) != before: raise Refusal('public_alias_changed')
        for name, fd, before in ((SYSCONFIG_TARGET, self.target_fd, self.target_metadata),
                                  (DEVELOPMENT_OBJECT, self.object_fd, self.object_metadata)):
            path = STDLIB / name
            current = os.stat(path.name, dir_fd=self.parent(path.parent), follow_symlinks=False)
            if helper.metadata(os.fstat(fd)) != before or helper.metadata(current) != before or os.listxattr(fd):
                raise Refusal('public_material_changed')
        if held_hash(self.target_fd) != self.target_sha: raise Refusal('sysconfig_target_changed')
        os.lseek(self.object_fd, 0, os.SEEK_SET)
        if os.read(self.object_fd, 20) != OBJECT_HEADER: raise Refusal('development_object_header')
        if helper.metadata(os.fstat(self.object_fd)) != self.object_metadata:
            raise Refusal('public_material_changed')
        for name, before in self.input_metadata.items():
            fd = open_public(self[name])
            try:
                if helper.metadata(os.fstat(fd)) != before: raise Refusal('runtime_input_changed')
            finally: os.close(fd)

    def dependency(self, name):
        if name.lstrip('/') in OMITTED: raise Refusal('omitted_material_reintroduced')
        target = Path(name).resolve(strict=True)
        if not any(target.is_relative_to(base) for base in ('/usr/lib', '/usr/lib64', '/lib', '/lib64')):
            raise Refusal('nonpublic_dependency_target')
        # Refuse before opening a closure target conflicting with exact omissions.
        if str(target).lstrip('/') in OMITTED: raise Refusal('omitted_material_reintroduced')
        fd = open_public(target)
        try: before = helper.metadata(os.fstat(fd))
        finally: os.close(fd)
        if name.lstrip('/') in self and self[name.lstrip('/')] != target:
            raise Refusal('dependency_material_conflict')
        self[name.lstrip('/')] = target
        self.input_metadata[name.lstrip('/')] = before
        if len(self) > 4096: raise Refusal('runtime_input_count')


def select_stdlib():
    material = RuntimeMaterial()
    try:
        material.authenticate()
        seen = set()
        def walk(directory, parent):
            before = helper.metadata(os.fstat(parent))
            with os.scandir(parent) as entries:
                for entry in entries:
                    # DirEntry.is_dir() defaults to following links, including
                    # omitted configuration targets. Use only the entry name.
                    info = os.stat(entry.name, dir_fd=parent, follow_symlinks=False)
                    path = directory / entry.name
                    relative = str(path.relative_to(STDLIB))
                    if stat.S_ISDIR(info.st_mode):
                        if entry.name in ('__pycache__', 'test', 'tests', 'idlelib', 'tkinter',
                                          'ensurepip', 'site-packages', 'dist-packages'): continue
                        child = os.open(entry.name, NOFOLLOW_DIR, dir_fd=parent)
                        try:
                            if (helper.metadata(os.fstat(child)) != helper.metadata(info)
                                    or info.st_uid != INPUT_UID or info.st_gid != INPUT_GID or info.st_mode & 0o022):
                                raise Refusal('public_parent_identity')
                            walk(path, child)
                        finally: os.close(child)
                        continue
                    seen.add(relative)
                    if relative in LINKS:
                        if helper.metadata(info) != material.links[relative]: raise Refusal('public_alias_changed')
                        if relative == SYSCONFIG_ALIAS: material[STDLIB_NAME + relative] = STDLIB / SYSCONFIG_TARGET
                        continue
                    if relative == DEVELOPMENT_OBJECT:
                        if helper.metadata(info) != material.object_metadata: raise Refusal('public_material_changed')
                        continue
                    if not stat.S_ISREG(info.st_mode): raise Refusal('stdlib_file_type')
                    material[STDLIB_NAME + relative] = path
                    if len(material) > 4096: raise Refusal('runtime_input_count')
            if helper.metadata(os.fstat(parent)) != before: raise Refusal('stdlib_directory_changed')
        parent = public_directory(STDLIB)
        try: walk(STDLIB, parent)
        finally: os.close(parent)
        if not set((*LINKS, DEVELOPMENT_OBJECT, SYSCONFIG_TARGET)).issubset(seen):
            raise Refusal('required_public_material_missing')
        material.recheck()
        return material
    except BaseException:
        material.close(); raise


# This literal program has no caller-controlled input. The mount symbol is
# resolved, never invoked. Even import/assertion failures emit no exception text.
HOST_ABI_CHECK = """try:
 import hashlib, ctypes, json, os, re, stat, sys
 import sysconfig
 __import__('_sysconfigdata__linux_x86_64-linux-gnu')
 __import__('_sysconfigdata__x86_64-linux-gnu')
 assert sys.version_info[:2] == (3, 14)
 assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
 assert 'sitecustomize' not in sys.modules
 symbol = ctypes.CDLL(None).mount
 assert callable(symbol)
 print(json.dumps({'kind':'public-python314-host-abi-v1','version':list(sys.version_info[:3]),
  'isolated':True,'no_site':True,'dont_write_bytecode':True,'sitecustomize_absent':True,
  'imports':True,'mount_symbol':True}, sort_keys=True, separators=(',',':')))
except BaseException:
 print('{"kind":"public-python314-host-abi-refused"}')
 raise SystemExit(1)
"""


def host_abi():
    code, output, errors = bounded_command([str(PYTHON), '-I', '-S', '-B', '-c', HOST_ABI_CHECK], limit=16384)
    if code or errors or len(output) > 16384: raise Refusal('public_host_abi_refused')
    value = helper.strict_json(output, 16384)
    version = value.get('version') if type(value) is dict else None
    if (type(version) is not list or len(version) != 3 or any(type(n) is not int or n < 0 for n in version)
            or version[:2] != [3, 14]): raise Refusal('public_host_abi_receipt')
    wanted = {'kind': 'public-python314-host-abi-v1', 'version': version, 'isolated': True,
              'no_site': True, 'dont_write_bytecode': True, 'sitecustomize_absent': True,
              'imports': True, 'mount_symbol': True}
    if encode(value) != encode(wanted): raise Refusal('public_host_abi_receipt')
    return wanted


@contextmanager
def runtime_inputs():
    # Only the authenticated fixed public interpreter; no version/layout fallback.
    if Path('/usr/bin/python3').resolve(strict=True) != PYTHON: raise Refusal('nonpublic_python_target')
    tools = {}
    try:
        for path in (PYTHON, Path('/usr/bin/ldd')):
            fd = open_public(path); tools[path] = (fd, helper.metadata(os.fstat(fd)))
            if not os.fstat(fd).st_mode & 0o100: raise Refusal('untrusted_runtime_tool')
        material = select_stdlib()
        try:
            material['usr/bin/python3'] = PYTHON
            total, elfs = 0, []
            for name, path in material.items():
                fd = open_public(path)
                try:
                    before = os.fstat(fd); total += before.st_size
                    if total > FILE_LIMIT: raise Refusal('runtime_file_limit')
                    header = os.read(fd, 20)
                    if helper.metadata(os.fstat(fd)) != helper.metadata(before): raise Refusal('public_material_changed')
                    material.input_metadata[name] = helper.metadata(before)
                finally: os.close(fd)
                if header.startswith(b'\x7fELF'):
                    # Only ordinary executable/shared ELF goes to ldd. The one
                    # exact ET_REL omission was separately authenticated above.
                    if (len(header) != 20 or header[4:7] != b'\x02\x01\x01'
                            or int.from_bytes(header[16:18], 'little') not in (2, 3)
                            or header[18:20] != b'\x3e\x00'):
                        raise Refusal('unknown_runtime_elf')
                    elfs.append(path)
            material.receipt['host_abi'] = host_abi()
            material.recheck()
            for path in elfs:
                code, output, errors = bounded_command(['/usr/bin/ldd', str(path)], limit=65536)
                for dependency in dependencies(output, errors, code): material.dependency(dependency)
            for path, (fd, before) in tools.items():
                current = open_public(path)
                try:
                    if helper.metadata(os.fstat(fd)) != before or helper.metadata(os.fstat(current)) != before:
                        raise Refusal('runtime_tool_changed')
                finally: os.close(current)
            material.recheck()
            yield material
        finally: material.close()
    finally:
        for fd, _ in tools.values(): os.close(fd)


def validate_result(mode, raw, helper_sha, inventory=None):
    if mode == 'inspect': return helper.validate_inventory(raw, helper_sha)
    if mode != 'restore-traversal' or inventory is None: raise Refusal('result_mode')
    wanted = {'kind': 'physical-traversal-restored-v1', 'source': helper.SOURCE,
              'anchor': list(helper.ANCHOR), 'inventory_digest': inventory['digest'],
              'helper_sha256': helper_sha, 'original_owner_retirement': 'cleanup_pending',
              'creation_outcome': 'unknown', 'never_reopen': True,
              'reserved_bytes': helper.CHARGE, 'released': False}
    value = helper.strict_json(raw)
    if encode(value) != raw or raw != encode(wanted): raise Refusal('physical_receipt_mismatch')
    return value


def file_sha(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 65536 or s.st_mode & 0o022:
            raise Refusal('reviewed_module_identity')
        raw = os.read(fd, 65537)
        if helper.metadata(os.fstat(fd)) != helper.metadata(s) or len(raw) != s.st_size:
            raise Refusal('reviewed_module_changed')
        return sha(raw)
    finally: os.close(fd)


def directory_shape(fd, wanted):
    names = set()
    with os.scandir(fd) as entries:
        for item in entries:
            names.add(item.name)
            if len(names) > len(wanted): raise Refusal('predecessor_shape')
    if names != wanted: raise Refusal('predecessor_shape')


def private_snapshot(parent, name):
    before = helper.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if (helper.metadata(info) != before or info.st_uid != 1000 or info.st_gid != 1000
                or info.st_mode != stat.S_IFREG | 0o600 or info.st_nlink != 1 or info.st_size > 16384):
            raise Refusal('private_snapshot_identity')
        with os.fdopen(os.dup(fd), 'rb') as stream: raw = stream.read(16385)
        if (len(raw) != info.st_size or helper.metadata(os.fstat(fd)) != before
                or helper.metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
            raise Refusal('metadata_path_changed')
        return raw, before
    finally: os.close(fd)


def validate_admission(value):
    keys = {'kind', 'rest_allocated_bytes', 'original_opaque_charge', 'all_outstanding_bytes',
            'all_owned_image_charge', 'prospective_helper_growth', 'disk_bytes', 'resident_bytes',
            'ordinary_guard_pass', 'free_bytes', 'utc'}
    if type(value) is not dict or set(value) != keys: raise Refusal('admission_binding')
    if (type(value['resident_bytes']) is not int or value['resident_bytes'] < 1256000000
            or type(value['free_bytes']) is not int or value['free_bytes'] < 0
            or type(value['utc']) is not str
            or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?\+00:00', value['utc'])):
        raise Refusal('admission_binding')
    wanted = admitted(value['rest_allocated_bytes'], value['all_outstanding_bytes'],
                      value['all_owned_image_charge'], value['resident_bytes'] - 1256000000)
    wanted.update(free_bytes=value['free_bytes'], utc=value['utc'])
    if encode(value) != encode(wanted): raise Refusal('admission_binding')
    return value


def predecessor():
    root = private_directory(PREDECESSOR_WORK)
    phase = None
    try:
        root_info = helper.metadata(os.fstat(root))
        if root_info['gid'] != 1000: raise Refusal('predecessor_directory')
        directory_shape(root, {'inspect'})
        phase = os.open('inspect', NOFOLLOW_DIR, dir_fd=root)
        phase_info = helper.metadata(os.fstat(phase))
        if phase_info['uid'] != 1000 or phase_info['gid'] != 1000 or phase_info['mode'] != stat.S_IFDIR | 0o700:
            raise Refusal('predecessor_directory')
        directory_shape(phase, {'state.json', 'admission-material.json'})
        raw, state_info = private_snapshot(phase, 'state.json')
        admission_raw, admission_info = private_snapshot(phase, 'admission-material.json')
        if state_info['gid'] != 1000 or admission_info['gid'] != 1000: raise Refusal('predecessor_record_group')
        state = validate_phase_state(helper.strict_json(raw))
        if (raw != encode(state) or state['source'] != PREDECESSOR_SOURCE or state['mode'] != 'inspect'
                or state['helper_sha256'] != PREDECESSOR_HELPER or state['step'] != 'objects-settled'
                or state['settled'] is not True or state['success'] is not False
                or state['image'] is not None or state['cid'] is not None):
            raise Refusal('predecessor_state')
        admission = validate_admission(helper.strict_json(admission_raw))
        if admission_raw != encode(admission): raise Refusal('predecessor_admission')
        for kind in ('container', 'image'):
            if scoped_ids(kind, state['labels'], docker): raise Refusal('predecessor_objects_present')
        # Reopen only ordinary metadata parents, never live or its entries.
        current = private_directory(PREDECESSOR_WORK)
        try:
            if helper.metadata(os.fstat(current)) != root_info or helper.metadata(os.fstat(root)) != root_info:
                raise Refusal('predecessor_changed')
        finally: os.close(current)
        if (helper.metadata(os.stat('inspect', dir_fd=root, follow_symlinks=False)) != phase_info
                or helper.metadata(os.fstat(phase)) != phase_info
                or private_snapshot(phase, 'state.json') != (raw, state_info)
                or private_snapshot(phase, 'admission-material.json') != (admission_raw, admission_info)):
            raise Refusal('predecessor_changed')
        directory_shape(root, {'inspect'}); directory_shape(phase, {'state.json', 'admission-material.json'})
        return {'source': PREDECESSOR_SOURCE, 'helper_sha256': PREDECESSOR_HELPER,
                'state_sha256': sha(raw), 'admission_sha256': sha(admission_raw), 'labels': state['labels'],
                'root_metadata': root_info, 'phase_metadata': phase_info,
                'state_metadata': state_info, 'admission_metadata': admission_info}
    finally:
        if phase is not None: os.close(phase)
        os.close(root)


def second_operation_document(prior, first, root):
    # This is ba8's closed historical document, not a current-source operation.
    info = os.fstat(root)
    return {'kind': 'physical-recovery-operation-v1', 'operation': 'recovery-a-py314-v1',
            'material_policy': 'python314-public-material-v1', 'source': SECOND_SOURCE,
            'helper_sha256': PREDECESSOR_HELPER,
            'scene': {'parent': list(PARENT), 'live': list(helper.ANCHOR),
                      'original_source': helper.SOURCE, 'records_sha256': sha(encode(EXPECTED_RECORDS))},
            'root_identity': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode & 0o7777],
            'predecessor': prior, 'admission': validate_admission(first),
            'reserved_bytes': 5000000000, 'released': False, 'helper_envelope_bytes': 736000000}


def second_predecessor(prior):
    root = private_directory(SECOND_WORK)
    phase = None
    try:
        root_info = helper.metadata(os.fstat(root))
        if root_info['gid'] != 1000: raise Refusal('second_history_directory')
        directory_shape(root, {'operation.json', 'inspect'})
        phase = os.open('inspect', NOFOLLOW_DIR, dir_fd=root)
        phase_info = helper.metadata(os.fstat(phase))
        if phase_info['uid'] != 1000 or phase_info['gid'] != 1000 or phase_info['mode'] != stat.S_IFDIR | 0o700:
            raise Refusal('second_history_directory')
        directory_shape(phase, {'state.json', 'provenance.json', 'admission-material.json'})
        operation_raw, operation_info = private_snapshot(root, 'operation.json')
        state_raw, state_info = private_snapshot(phase, 'state.json')
        provenance_raw, provenance_info = private_snapshot(phase, 'provenance.json')
        admission_raw, admission_info = private_snapshot(phase, 'admission-material.json')
        state = validate_phase_state(helper.strict_json(state_raw))
        if (state_raw != encode(state) or state['source'] != SECOND_SOURCE or state['mode'] != 'inspect'
                or state['helper_sha256'] != PREDECESSOR_HELPER or state['step'] != 'objects-settled'
                or state['settled'] is not True or state['success'] is not False
                or state['image'] is not None or state['cid'] is not None):
            raise Refusal('second_history_state')
        operation = helper.strict_json(operation_raw)
        if type(operation) is not dict or 'admission' not in operation: raise Refusal('second_history_operation')
        if operation_raw != encode(second_operation_document(prior, operation['admission'], root)):
            raise Refusal('second_history_operation')
        wanted = {'operation_sha256': sha(operation_raw), 'operation_metadata': operation_info,
                  'source': SECOND_SOURCE, 'material_policy': 'python314-public-material-v1',
                  'predecessor_state_sha256': prior['state_sha256'],
                  'reserved_bytes': 5000000000, 'released': False, 'helper_envelope_bytes': 736000000}
        if provenance_raw != encode(wanted): raise Refusal('second_history_provenance')
        # Material admission was taken after initial operation/state creation.
        admission = validate_admission(helper.strict_json(admission_raw))
        if admission_raw != encode(admission): raise Refusal('second_history_admission')
        for kind in ('container', 'image'):
            if scoped_ids(kind, state['labels'], docker): raise Refusal('second_history_objects_present')
        current = private_directory(SECOND_WORK)
        try:
            if helper.metadata(os.fstat(current)) != root_info or helper.metadata(os.fstat(root)) != root_info:
                raise Refusal('second_history_changed')
        finally: os.close(current)
        if (helper.metadata(os.stat('inspect', dir_fd=root, follow_symlinks=False)) != phase_info
                or helper.metadata(os.fstat(phase)) != phase_info
                or private_snapshot(root, 'operation.json') != (operation_raw, operation_info)
                or private_snapshot(phase, 'state.json') != (state_raw, state_info)
                or private_snapshot(phase, 'provenance.json') != (provenance_raw, provenance_info)
                or private_snapshot(phase, 'admission-material.json') != (admission_raw, admission_info)):
            raise Refusal('second_history_changed')
        directory_shape(root, {'operation.json', 'inspect'})
        directory_shape(phase, {'state.json', 'provenance.json', 'admission-material.json'})
        return {'source': SECOND_SOURCE, 'helper_sha256': PREDECESSOR_HELPER, 'labels': state['labels'],
                'root_metadata': root_info, 'phase_metadata': phase_info,
                'operation_sha256': sha(operation_raw), 'operation_metadata': operation_info,
                'state_sha256': sha(state_raw), 'state_metadata': state_info,
                'provenance_sha256': sha(provenance_raw), 'provenance_metadata': provenance_info,
                'admission_sha256': sha(admission_raw), 'admission_metadata': admission_info}
    finally:
        if phase is not None: os.close(phase)
        os.close(root)


def histories():
    first = predecessor()
    second = second_predecessor(first)
    if encode(predecessor()) != encode(first): raise Refusal('first_history_changed')
    return {'first': first, 'second': second}


def operation_document(source, prior, first, root):
    if not re.fullmatch('[0-9a-f]{40}', source) or file_sha(MODULE) != PREDECESSOR_HELPER:
        raise Refusal('operation_source')
    info = os.fstat(root)
    if type(prior) is not dict or set(prior) != {'first', 'second'}: raise Refusal('operation_history')
    document = {'kind': 'physical-recovery-history-operation-v1', 'operation': 'recovery-a-py314-static-v1',
            'material_policy': MATERIAL_POLICY, 'source': source, 'helper_sha256': PREDECESSOR_HELPER,
            'scene': {'parent': list(PARENT), 'live': list(helper.ANCHOR),
                      'original_source': helper.SOURCE, 'records_sha256': sha(encode(EXPECTED_RECORDS))},
            'root_identity': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode & 0o7777],
            'history': prior, 'admission': validate_admission(first),
            'reserved_bytes': helper.CHARGE, 'released': False, 'helper_envelope_bytes': ENVELOPE}
    if len(encode(document)) > 16384: raise Refusal('operation_metadata_size')
    return document


def operation_read(source):
    prior = histories()
    root = private_directory(WORK)
    try:
        raw, info = private_snapshot(root, 'operation.json')
        value = helper.strict_json(raw)
        if type(value) is not dict or 'admission' not in value: raise Refusal('operation_binding')
        wanted = operation_document(source, prior, value['admission'], root)
        if raw != encode(wanted): raise Refusal('operation_binding')
        current = private_directory(WORK)
        try:
            if os.fstat(current).st_ino != os.fstat(root).st_ino or os.fstat(current).st_dev != os.fstat(root).st_dev:
                raise Refusal('operation_replaced')
        finally: os.close(current)
        return {'operation_sha256': sha(raw), 'operation_metadata': info, 'source': source,
                'material_policy': MATERIAL_POLICY, 'history_sha256': sha(encode(prior)),
                'reserved_bytes': helper.CHARGE, 'released': False, 'helper_envelope_bytes': ENVELOPE}
    finally: os.close(root)


def phase_binding(mode, source):
    binding = operation_read(source)
    if load(WORK / mode / 'provenance.json') != encode(binding): raise Refusal('phase_operation_binding')
    return binding


def bound_account(scene, services, source, mode, own=None):
    phase_binding(mode, source)
    return account(scene, services, own)


def new_phase(mode, source=None, prior=None, first=None):
    if mode not in MODES: raise Refusal('fixed_phase')
    if mode == 'inspect':
        parent = private_directory(SCENE)
        try:
            # Root existence is an unconditional refusal, including a partial
            # previous setup. It cannot be reset or adopted by another inspect.
            os.mkdir(WORK.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        finally: os.close(parent)
        root = private_directory(WORK)
        try: document = operation_document(source, prior, first, root)
        finally: os.close(root)
        save(WORK / 'operation.json', document)  # exclusive, never replace
    else:
        operation_read(source)
    parent = private_directory(WORK)
    try:
        os.mkdir(mode, 0o700, dir_fd=parent)
        os.fsync(parent)
    finally: os.close(parent)
    return WORK / mode


def validate_phase_state(value):
    keys = {'version', 'source', 'mode', 'labels', 'image', 'cid', 'step', 'settled', 'success',
            'reserved_bytes', 'released', 'helper_envelope_bytes', 'helper_sha256'}
    if (type(value) is not dict or set(value) != keys
            or type(value['source']) is not str or not re.fullmatch('[0-9a-f]{40}', value['source'])
            or type(value['version']) is not int or value['version'] != 1
            or value['released'] is not False or type(value['reserved_bytes']) is not int
            or value['reserved_bytes'] != helper.CHARGE or type(value['helper_envelope_bytes']) is not int
            or value['helper_envelope_bytes'] != ENVELOPE
            or type(value['settled']) is not bool or type(value['success']) is not bool
            or value['step'] not in ('material-pending', 'import-pending', 'create-pending', 'start-pending',
                                     'result-validated', 'objects-settled', 'complete')
            or type(value['helper_sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', value['helper_sha256'])):
        raise Refusal('phase_state_unknown')
    validate_labels(value['labels'], value['mode'])
    for key, regex in (('image', 'sha256:[0-9a-f]{64}'), ('cid', '[0-9a-f]{64}')):
        if value[key] is not None and (type(value[key]) is not str or not re.fullmatch(regex, value[key])):
            raise Refusal('phase_object_identity')
    # These are the only states written by this coordinator. Presence of a
    # returned ID does not change a pending operation into a terminal result.
    policy = {
        'material-pending': (False, False, {(False, False)}),
        'import-pending': (False, False, {(False, False), (True, False)}),
        'create-pending': (False, False, {(True, False), (True, True)}),
        'start-pending': (False, False, {(True, True)}),
        'result-validated': (False, False, {(True, True)}),
        'objects-settled': (True, False, {(False, False), (True, True)}),
        'complete': (True, True, {(True, True)}),
    }
    settled, success, identities = policy[value['step']]
    if (value['settled'] != settled or value['success'] != success
            or (value['image'] is not None, value['cid'] is not None) not in identities):
        raise Refusal('inconsistent_phase_state')
    return value


def state_read(mode, source):
    value = validate_phase_state(helper.strict_json(load(WORK / mode / 'state.json')))
    if value['source'] != source or value['mode'] != mode or value['helper_sha256'] != file_sha(MODULE):
        raise Refusal('phase_state_binding')
    return value


def check_image(image, labels):
    data = owned_inspect('image', image, labels, docker)
    if (data['Config'].get('Labels') != labels or type(data['Size']) is not int
            or not 0 < data['Size'] <= IMAGE_LIMIT
            or data['Config'].get('Entrypoint') != ['/usr/bin/python3', '-I', '-S', '-B', '/recovery.py']
            or data['Config'].get('Volumes') or data['Config'].get('Env') or data['Config'].get('OnBuild')):
        raise Refusal('sealed_helper_image')


def check_archive(directory, package):
    parent = private_directory(directory)
    try: fd = os.open('image.tar', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally: os.close(parent)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 1000 or s.st_nlink != 1
                or s.st_mode & 0o7777 != 0o400 or s.st_size != package['archive_bytes'] or s.st_size > ARCHIVE_LIMIT):
            raise Refusal('sealed_archive_identity')
        with os.fdopen(os.dup(fd), 'rb') as f: digest = hashlib.file_digest(f, 'sha256').hexdigest()
        if digest != package['archive_sha256'] or helper.metadata(os.fstat(fd)) != helper.metadata(s):
            raise Refusal('sealed_archive_changed')
    finally: os.close(fd)


def helper_absent(cid):
    if cid is None: return
    parent = trusted_directory('/sys/fs/cgroup/system.slice', 0)
    try: exact_absence(parent, (30, 75, 0), 'docker-' + cid + '.scope')
    finally: os.close(parent)


def cleanup_phase(state):
    validate_phase_state(state)
    if state['step'] in ('import-pending', 'create-pending', 'start-pending'):
        # A local CLI exit/timeout or an empty current listing is not daemon
        # completion. Preserve the pending record, staging and full H/Q before
        # any discovery, deletion or state write, even when IDs are known.
        raise Refusal('unresolved_helper_operation')
    if state['settled']:
        if scoped_ids('container', state['labels'], docker) or scoped_ids('image', state['labels'], docker):
            raise Refusal('settled_helper_objects_reappeared')
        helper_absent(state['cid'])
        return
    if state['step'] == 'material-pending':
        # No daemon request was issued at this durable step. Unexpected objects
        # contradict that premise; they cannot be adopted as material cleanup.
        if scoped_ids('container', state['labels'], docker) or scoped_ids('image', state['labels'], docker):
            raise Refusal('pre_daemon_objects_present')
    else:  # result-validated: successful terminal receipt and both exact IDs
        cleanup_helper(state['labels'], state['image'], state['cid'])
        helper_absent(state['cid'])
    parent = private_directory(WORK / state['mode'])
    try:
        try: info = os.stat('image.tar', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: info = None
        if info is not None:
            # Only our fixed staging file, including an interrupted partial tar.
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_nlink != 1
                    or info.st_mode & 0o7777 not in (0o400, 0o600) or info.st_size > ARCHIVE_LIMIT):
                raise Refusal('staging_identity_unknown')
            os.unlink('image.tar', dir_fd=parent); os.fsync(parent)
    finally: os.close(parent)
    state['step'], state['settled'] = 'objects-settled', True
    save(WORK / state['mode'] / 'state.json', state, replace=True)


def restored_metadata(expected):
    # Same closed FD-relative metadata walk; do not read root-owned files.
    held = helper.HeldInventory()
    try:
        held.fds['.'] = os.open(LIVE, helper.DIR_FLAGS)
        for name in helper.DIRS[1:] + helper.JOURNALS + tuple(helper.ASSETS):
            parent, _, leaf = name.rpartition('/')
            held.fds[name] = os.open(leaf, helper.DIR_FLAGS if name in helper.DIRS else helper.PATH_FLAGS,
                                    dir_fd=held.fds[parent or '.'])
        held.entries = {name: helper.metadata(os.fstat(fd)) for name, fd in held.fds.items()}
        for name, actual in held.entries.items():
            wanted = dict(expected[name])
            if name in helper.DIRS: wanted.update(uid=1000, gid=1000, ctime_ns=actual['ctime_ns'])
            if wanted != actual: raise Refusal('retained_scene_metadata_changed')
        held.recheck(held.entries)
    finally: held.close()


def full_postflight(scene, services, inventory):
    import azure_guard
    scene.check(1000)
    restored_metadata(inventory['entries'])
    if scoped_ids('container', {'project': 'warden'}, docker): raise Refusal('owned_container_remains')
    outstanding, images = current_charges(), image_charge()
    if outstanding < helper.CHARGE: raise Refusal('original_charge_missing')
    # Unchanged ordinary guard counts the whole tree plus the still-booked Q.
    with io.StringIO() as output:
        from contextlib import redirect_stdout
        with redirect_stdout(output): azure_guard.preflight(outstanding + images, services + 1000000000, 0)
        guard = helper.strict_json(output.getvalue().encode())
    baseline = {'vm/overcommit_memory': '1', 'vm/panic_on_oom': '0', 'kernel/panic': '10',
                'kernel/panic_on_oops': '1', 'kernel/keys/root_maxkeys': '1000000',
                'kernel/keys/root_maxbytes': '25000000'}
    observed = {name: helper.fixed_read('/proc/sys/' + name, 64).decode('ascii').strip() for name in baseline}
    if observed != baseline: raise Refusal('protected_sysctl_changed')
    scene.check(1000)
    return {'ordinary_full_guard': guard, 'protected_sysctls': observed, 'protected_baseline_match': True,
            'original_owner_retirement': 'cleanup_pending', 'creation_outcome': 'unknown',
            'never_reopen': True, 'reserved_bytes': helper.CHARGE, 'released': False}


def execute_phase(scene, mode, services, source):
    if mode not in MODES: raise Refusal('fixed_phase')
    expected = inventory = None
    module_sha = file_sha(MODULE)
    if mode == 'restore-traversal':
        phase_binding('inspect', source)
        prior = state_read('inspect', source)
        if not prior['settled'] or not prior['success'] or prior['step'] != 'complete':
            raise Refusal('inspect_not_complete')
        if scoped_ids('container', prior['labels'], docker) or scoped_ids('image', prior['labels'], docker):
            raise Refusal('settled_inspect_objects_reappeared')
        helper_absent(prior['cid'])
        expected = load(WORK / 'inspect' / 'result.json')
        inventory = helper.validate_inventory(expected, module_sha)
    old = histories()
    first = account(scene, services)
    directory = new_phase(mode, source, old, first)
    labels = {'project': 'warden', 'owner': 'codex-warden', 'task': 'firecracker-recovery',
              'session': secrets.token_hex(16), 'original_session': SESSION, 'phase': mode,
              'ttl': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
    state = {'version': 1, 'source': source, 'mode': mode, 'labels': labels, 'image': None, 'cid': None,
             'step': 'material-pending', 'settled': False, 'success': False,
             'reserved_bytes': helper.CHARGE, 'released': False, 'helper_envelope_bytes': ENVELOPE,
             'helper_sha256': module_sha}
    save(directory / 'state.json', state)
    save(directory / 'provenance.json', operation_read(source))
    save(directory / 'admission-material.json', bound_account(scene, services, source, mode))
    # Any exception leaves the durable state, Q and H unchanged; no retry or
    # automatic cleanup can race a possibly live unknown helper.
    with runtime_inputs() as inputs:
        package = build_archive(directory / 'image.tar', inputs, MODULE, expected)
    if package['helper_sha256'] != module_sha: raise Refusal('module_changed_during_package')
    save(directory / 'package.json', package)
    save(directory / 'admission-import.json', bound_account(scene, services, source, mode))
    check_archive(directory, package)
    state['step'] = 'import-pending'; save(directory / 'state.json', state, replace=True)
    args = ['image', 'import', '--change', 'ENTRYPOINT ["/usr/bin/python3","-I","-S","-B","/recovery.py"]']
    for key, value in labels.items(): args += ['--change', 'LABEL ' + key + '=' + value]
    image = docker(args + [str(directory / 'image.tar')], timeout=60).strip()
    if not re.fullmatch('sha256:[0-9a-f]{64}', image): raise Refusal('import_outcome_unknown')
    state['image'] = image
    save(directory / 'state.json', state, replace=True)
    check_image(image, labels)
    save(directory / 'admission-create.json', bound_account(scene, services, source, mode))
    host_ns = os.readlink('/proc/self/ns/mnt')
    state['step'] = 'create-pending'; save(directory / 'state.json', state, replace=True)
    cid = docker(create_args(mode, image, labels, host_ns)).strip()
    if not re.fullmatch('[0-9a-f]{64}', cid): raise Refusal('create_outcome_unknown')
    state['cid'] = cid; save(directory / 'state.json', state, replace=True)
    data = owned_inspect('container', cid, labels, docker)
    inspect_profile(data, mode, image, labels, host_ns)
    if data['State']['Running'] is not False: raise Refusal('helper_started_early')
    save(directory / 'admission-start.json', bound_account(scene, services, source, mode, labels))
    scene.check(0)
    state['step'] = 'start-pending'; save(directory / 'state.json', state, replace=True)
    raw = run_helper(cid, directory)
    data = owned_inspect('container', cid, labels, docker)
    inspect_profile(data, mode, image, labels, host_ns)
    if (data['State']['Running'] is not False or type(data['State']['ExitCode']) is not int
            or data['State']['ExitCode'] != 0 or data['State'].get('OOMKilled') is not False):
        raise Refusal('helper_not_successful')
    result = validate_result(mode, raw, module_sha, inventory)
    save(directory / 'result.json', raw)
    scene.check(0 if mode == 'inspect' else 1000)
    if mode == 'restore-traversal': restored_metadata(inventory['entries'])
    state['step'] = 'result-validated'; save(directory / 'state.json', state, replace=True)
    phase_binding(mode, source)
    cleanup_phase(state)
    phase_binding(mode, source)
    post = account(scene, services) if mode == 'inspect' else full_postflight(scene, services, inventory)
    save(directory / 'postflight.json', post)
    state.update(step='complete', success=True); save(directory / 'state.json', state, replace=True)
    return result


def run_helper(cid, directory):
    code, output, errors = bounded_command(['/usr/bin/docker', '--host=unix:///var/run/docker.sock',
                                            'container', 'start', '--attach', cid], 45, helper.LIMIT)
    refusal = None
    if code and errors:
        try:
            value = helper.strict_json(errors, 4096)
            if (type(value) is dict and set(value) == {'kind', 'error_type', 'reason', 'charge_released'}
                    and value['kind'] == 'recovery-refused' and value['charge_released'] is False
                    and type(value['reason']) is str and re.fullmatch('[a-z0-9_]{1,64}', value['reason'])
                    and value['error_type'] in ('Refusal', 'OSError', 'PermissionError', 'FileNotFoundError',
                                                'ValueError', 'KeyError', 'TypeError', 'RuntimeError')):
                refusal = value
        except (ValueError, TypeError): pass
    save(directory / 'helper-outcome.json', {'exit_code': code, 'stdout_bytes': len(output),
                                            'stderr_bytes': len(errors), 'stdout_sha256': sha(output),
                                            'stderr_sha256': sha(errors), 'helper_refusal': refusal,
                                            'reserved_bytes': helper.CHARGE, 'released': False})
    if code or errors: raise Refusal('helper_failed_or_unexpected_stderr')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=MODES + ('cleanup-inspect', 'cleanup-restore-traversal', 'postflight'))
    parser.add_argument('--reviewed-exact-scene', action='store_true', required=True)
    parser.add_argument('--other-service-memory-bytes', type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 1000 or args.other_service_memory_bytes < 0: raise Refusal('ordinary_controller_required')
    os.umask(0o077)
    source = source_sha()
    with project_lock():
        info = helper.strict_json(docker(['info', '--format', '{{json .}}']).encode(), 262144)
        if (info['Name'] != os.uname().nodename or info['CgroupVersion'] != '2'
                or any('rootless' in value for value in info['SecurityOptions'])):
            raise Refusal('local_rootful_cgroup2_required')
        special = args.mode not in MODES
        scene = Scene(cleanup=special)
        try:
            if args.mode.startswith('cleanup-'):
                phase_binding(args.mode[len('cleanup-'):], source)
                state = state_read(args.mode[len('cleanup-'):], source)
                cleanup_phase(state)
                scene.check(os.fstat(scene.live).st_uid)
                result = {'kind': 'helper-objects-settled', 'success': False, 'released': False,
                          'reserved_bytes': helper.CHARGE, 'new_attempt_authorized': False}
            elif args.mode == 'postflight':
                for mode in MODES:
                    phase_binding(mode, source)
                    state = state_read(mode, source)
                    if not state['settled']: raise Refusal('helper_envelope_unsettled')
                    if scoped_ids('container', state['labels'], docker) or scoped_ids('image', state['labels'], docker):
                        raise Refusal('helper_objects_remain')
                    helper_absent(state['cid'])
                inventory = helper.validate_inventory(load(WORK / 'inspect' / 'result.json'), file_sha(MODULE))
                validate_result('restore-traversal', load(WORK / 'restore-traversal' / 'result.json'), file_sha(MODULE), inventory)
                result = full_postflight(scene, args.other_service_memory_bytes, inventory)
                save(WORK / 'ordinary-full-postflight.json', result)
            else:
                result = execute_phase(scene, args.mode, args.other_service_memory_bytes, source)
            # Inventory remains private on disk; never print its raw file metadata.
            print(encode({'kind': 'phase-A-complete', 'mode': args.mode, 'released': False,
                          'reserved_bytes': helper.CHARGE, 'receipt_kind': result.get('kind', 'ordinary-full-postflight')}).decode(), end='')
        finally: scene.close()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(encode({'kind': 'phase-A-refused', 'error_type': type(error).__name__,
                      'reason': error.code if isinstance(error, Refusal) else 'external_error',
                      'released': False, 'reserved_bytes': helper.CHARGE}).decode(), end='', file=sys.stderr)
        sys.exit(1)
