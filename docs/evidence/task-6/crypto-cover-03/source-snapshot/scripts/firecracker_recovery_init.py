"""Fixed Task4 stopped-scene recovery helper; no runtime retirement authority.

No scene file is opened for reading. Only directory FDs and O_PATH regular-file
FDs are retained. The only permitted mutation is fchown on the directory FDs.
"""
import hashlib
import ctypes
import json
import os
import re
import stat
import sys

class Refusal(ValueError):
    """Only fixed public reason enums are eligible for diagnostic output."""
    def __init__(self, code):
        if not re.fullmatch('[a-z0-9_]{1,64}', code): raise ValueError('invalid_refusal_enum')
        self.code = code
        super().__init__(code)


SOURCE = '95fa55dc0ce97d3e1b99a255a84f80e96972c71f'
RUN = '7J2G4KCYZWPQ3B53EV4TR2RXAI'
ANCHOR = (66307, 56377608)
OWNER = GROUP = 0
TARGET = TARGET_GROUP = 1000
CHARGE = 5000000000
LIMIT = 16384
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
PATH_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
DIRS = ('.', 'node', 'node/gate', 'node/uids', 'node/runs',
        'node/assets', 'node/snapshots', 'jails', 'jails/firecracker')
ASSETS = {'node/assets/kernel': 27893008, 'node/assets/agent.ext4': 33554432,
          'node/assets/payload.ext4': 33554432}
JOURNALS = ('node/owner', 'node/gate/node', 'node/gate/admission',
            'node/gate/retirement', 'node/gate/admission-sealed', 'node/gate/' + RUN,
            'node/uids/lock', 'node/uids/state', 'node/uids/' + RUN, 'node/runs/' + RUN)
NAMES = set(DIRS) | set(ASSETS) | set(JOURNALS)
FIELDS = ('dev', 'ino', 'uid', 'gid', 'mode', 'size', 'blocks', 'nlink', 'mtime_ns', 'ctime_ns')


def metadata(info):
    return {name: getattr(info, 'st_' + name) for name in FIELDS}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def strict_json(raw, limit=LIMIT):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise Refusal('json_bound')
    def unique(items):
        value = {}
        for key, item in items:
            if key in value: raise Refusal('duplicate_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def validate_entries(entries):
    if type(entries) is not dict or set(entries) != NAMES:
        raise Refusal('scene_schema')
    identities = set()
    allocated = 0
    for name, item in entries.items():
        if type(item) is not dict or set(item) != set(FIELDS) or any(type(v) is not int or v < 0 for v in item.values()):
            raise Refusal('metadata_schema')
        if (item['uid'], item['gid']) != (OWNER, GROUP) or not item['dev'] or not item['ino']:
            raise Refusal('scene_owner_identity')
        identity = item['dev'], item['ino']
        if identity in identities: raise Refusal('inode_alias')
        identities.add(identity)
        if name in DIRS:
            if item['mode'] != stat.S_IFDIR | 0o700: raise Refusal('directory_mode')
        else:
            mode = 0o444 if name in ASSETS else 0o600
            if item['mode'] != stat.S_IFREG | mode or item['nlink'] != 1:
                raise Refusal('file_type_mode_links')
            if name in ASSETS and item['size'] != ASSETS[name]: raise Refusal('asset_size')
            if name in JOURNALS and item['size'] > 65536: raise Refusal('journal_size')
        if item['dev'] != entries['.']['dev']: raise Refusal('cross_device')
        allocated += item['blocks'] * 512  # directory blocks included conservatively
    if allocated > CHARGE: raise Refusal('opaque_charge_exceeded')
    return allocated


class HeldInventory:
    def __init__(self):
        self.fds, self.entries = {}, {}

    def __enter__(self): return self

    def __exit__(self, *args): self.close()

    def close(self):
        for fd in self.fds.values(): os.close(fd)
        self.fds.clear()

    def recheck(self, expected):
        if self.entries != expected: raise Refusal('inventory_changed')
        for name, fd in self.fds.items():
            if metadata(os.fstat(fd)) != expected[name]: raise Refusal('held_metadata_changed')
            if name != '.':
                parent, _, leaf = name.rpartition('/')
                current = os.stat(leaf, dir_fd=self.fds[parent or '.'], follow_symlinks=False)
                if metadata(current) != expected[name]: raise Refusal('path_replaced')
        seen = 0
        for name in DIRS:
            prefix = '' if name == '.' else name + '/'
            children = {p[len(prefix):] for p in NAMES if p != name and p.startswith(prefix)
                        and '/' not in p[len(prefix):]}
            with os.scandir(self.fds[name]) as iterator:
                actual = []
                for child in iterator:
                    actual.append(child.name); seen += 1
                    if seen > 64: raise Refusal('directory_count')
            if set(actual) != children: raise Refusal('directory_changed')


def collect(fd):
    held = HeldInventory()
    held.fds['.'] = os.dup(fd)
    try:
        for name in DIRS[1:] + JOURNALS + tuple(ASSETS):
            parent, _, leaf = name.rpartition('/')
            held.fds[name] = os.open(leaf, DIR_FLAGS if name in DIRS else PATH_FLAGS,
                                     dir_fd=held.fds[parent or '.'])
        held.entries = {name: metadata(os.fstat(f)) for name, f in held.fds.items()}
        validate_entries(held.entries)
        held.recheck(held.entries)
        return held
    except BaseException:
        held.close()
        raise

def validate_inventory(raw, helper_sha):
    value = strict_json(raw)
    keys = {'version', 'source', 'helper_sha256', 'anchor', 'entries', 'allocated_bytes', 'digest'}
    if (type(value) is not dict or set(value) != keys or type(value['version']) is not int
            or value['version'] != 1 or value['source'] != SOURCE
            or not re.fullmatch('[0-9a-f]{64}', helper_sha)
            or value['helper_sha256'] != helper_sha or value['anchor'] != list(ANCHOR)
            or any(type(n) is not int for n in value['anchor'])):
        raise Refusal('inventory_binding')
    allocated = validate_entries(value['entries'])
    root = value['entries']['.']
    if (root['dev'], root['ino']) != ANCHOR or type(value['allocated_bytes']) is not int or allocated != value['allocated_bytes']:
        raise Refusal('inventory_total_anchor')
    body = {k: v for k, v in value.items() if k != 'digest'}
    if value['digest'] != hashlib.sha256(encode(body)).hexdigest() or encode(value) != raw:
        raise Refusal('inventory_digest_encoding')
    return value

def verify_mount(raw, metadata, host_ns, current_ns, readonly):
    if (len(raw) > 262144 or not re.fullmatch(r'mnt:\[[1-9][0-9]*\]', host_ns)
            or not re.fullmatch(r'mnt:\[[1-9][0-9]*\]', current_ns) or host_ns == current_ns):
        raise Refusal('private_mount_namespace')
    allowed = {'nosuid': 2, 'nodev': 4, 'noexec': 8, 'nosymfollow': 256,
               'noatime': 1024, 'nodiratime': 2048, 'relatime': 1 << 21,
               'strictatime': 1 << 24, 'lazytime': 1 << 25}
    matches = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 5: continue
        if fields[4].startswith('/session/'): raise Refusal('submount')
        if fields[4] != '/session': continue
        if len(fields) != 10 or fields[6] != '-' or fields[2] != '%d:%d' % (os.major(metadata['dev']), os.minor(metadata['dev'])):
            raise Refusal('mount_identity_or_propagation')
        if not fields[0].isdigit() or int(fields[0]) <= 0: raise Refusal('mount_id')
        options = fields[5].split(',')
        if len(options) != len(set(options)) or set(options) - set(allowed) - {'ro', 'rw'}:
            raise Refusal('mount_options')
        if ('ro' in options) != readonly or ('rw' in options) == readonly:
            raise Refusal('mount_readonly')
        matches.append((int(fields[0]), sum(allowed[x] for x in options if x in allowed)))
    if len(matches) != 1: raise Refusal('sole_mount')
    return matches[0]

def restore(held, expected, remount):
    validate_entries(expected)
    held.recheck(expected)
    writable = False
    try:
        remount(True)
        writable = True
        held.recheck(expected)  # remount must not hide/rebind any entry
        for name in sorted(DIRS, key=lambda p: (-p.count('/'), p != '.', p)):
            # Root is deliberately last, including among zero-depth entries.
            if name == '.': continue
            os.fchown(held.fds[name], TARGET, TARGET_GROUP)
            os.fsync(held.fds[name])
        os.fchown(held.fds['.'], TARGET, TARGET_GROUP)
        os.fsync(held.fds['.'])
        for name, fd in held.fds.items():
            actual = metadata(os.fstat(fd))
            wanted = dict(expected[name])
            if name in DIRS:
                wanted.update(uid=TARGET, gid=TARGET_GROUP, ctime_ns=actual['ctime_ns'])
            if actual != wanted: raise Refusal('post_restore_metadata')
    finally:
        if writable: remount(False)


def validate_runtime(mode, pid, uid, status, mounts):
    if mode not in ('inspect', 'restore-traversal') or pid != 1 or uid != 0 or len(status) > LIMIT:
        raise Refusal('fixed_root_pid1')
    values = {}
    for line in status.splitlines():
        key, sep, value = line.partition(':')
        if key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'):
            if not sep or key in values: raise Refusal('process_status')
            values[key] = value.strip()
    caps = 2097153 if mode == 'restore-traversal' else 0
    expected = {'CapInh': '0000000000000000', 'CapPrm': '%016x' % caps,
                'CapEff': '%016x' % caps, 'CapBnd': '%016x' % caps,
                'CapAmb': '0000000000000000', 'NoNewPrivs': '1',
                'Seccomp': '0' if mode == 'restore-traversal' else '2'}
    if values != expected: raise Refusal('process_caps_nnp_seccomp')
    if len(mounts) > 262144: raise Refusal('mountinfo_bound')
    for path in ('/', '/proc/sys'):
        matches = [f for line in mounts.splitlines() if len(f := line.split()) >= 6 and f[4] == path]
        if len(matches) != 1 or 'ro' not in matches[0][5].split(',') or 'rw' in matches[0][5].split(','):
            raise Refusal('root_proc_readonly')


def fixed_read(path, limit, immutable=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if immutable and (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or s.st_mode & 0o222):
            raise Refusal('immutable_input')
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
        if len(raw) > limit: raise Refusal('fixed_read_bound')
        return bytes(raw)
    finally: os.close(fd)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('inspect', 'restore-traversal'):
        raise Refusal('fixed_mode')
    mode = sys.argv[1]
    mounts = fixed_read('/proc/self/mountinfo', 262144).decode('ascii')
    validate_runtime(mode, os.getpid(), os.geteuid(), fixed_read('/proc/self/status', LIMIT).decode('ascii'), mounts)
    host_ns, current_ns = os.environ.get('WARDEN_RECOVERY_HOST_MOUNT_NS', ''), os.readlink('/proc/self/ns/mnt')
    root = os.open('/session', DIR_FLAGS)
    try:
        info = metadata(os.fstat(root))
        if (info['dev'], info['ino']) != ANCHOR or info['uid'] != 0 or info['gid'] != 0 or info['mode'] != stat.S_IFDIR | 0o700:
            raise Refusal('live_anchor')
        mount = verify_mount(mounts, info, host_ns, current_ns, True)
        # Only now may fixed descendant metadata be inspected. No file bodies.
        helper_sha = hashlib.sha256(fixed_read('/recovery.py', 65536, True)).hexdigest()
        with collect(root) as held:
            body = {'version': 1, 'source': SOURCE, 'helper_sha256': helper_sha,
                    'anchor': list(ANCHOR), 'entries': held.entries,
                    'allocated_bytes': validate_entries(held.entries)}
            body['digest'] = hashlib.sha256(encode(body)).hexdigest()
            raw = encode(body)
            validate_inventory(raw, helper_sha)
            if mode == 'restore-traversal':
                expected = validate_inventory(fixed_read('/expected-inventory.json', LIMIT, True), helper_sha)
                if raw != encode(expected): raise Refusal('inspected_inventory_changed')
                libc = ctypes.CDLL(None, use_errno=True)
                libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
                libc.mount.restype = ctypes.c_int
                def remount(writable):
                    before = fixed_read('/proc/self/mountinfo', 262144).decode('ascii')
                    if verify_mount(before, info, host_ns, current_ns, writable) != mount:
                        raise Refusal('mount_changed_before_remount')
                    flags = 4096 | 32 | mount[1] | (0 if writable else 1)  # BIND|REMOUNT
                    if libc.mount(None, b'/session', None, flags, None) != 0:
                        raise OSError(ctypes.get_errno(), 'private_remount_failed')
                    after = fixed_read('/proc/self/mountinfo', 262144).decode('ascii')
                    if verify_mount(after, info, host_ns, current_ns, not writable) != mount:
                        raise Refusal('mount_changed_after_remount')
                restore(held, expected['entries'], remount)
                raw = encode({'kind': 'physical-traversal-restored-v1', 'source': SOURCE,
                              'anchor': list(ANCHOR), 'inventory_digest': expected['digest'],
                              'helper_sha256': helper_sha, 'original_owner_retirement': 'cleanup_pending',
                              'creation_outcome': 'unknown', 'never_reopen': True,
                              'reserved_bytes': CHARGE, 'released': False})
            if len(raw) > LIMIT: raise Refusal('output_bound')
            sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()
    finally: os.close(root)


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        # Never emit arbitrary paths, exception strings, or retained file data.
        sys.stderr.write(encode({'kind': 'recovery-refused', 'error_type': type(error).__name__,
                                 'reason': error.code if isinstance(error, Refusal) else 'external_error',
                                 'charge_released': False}).decode())
        sys.exit(1)
