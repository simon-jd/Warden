"""Read-only exact-intent metadata audit after timeout; no maintenance retry."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/home/postedism/Desktop/Warden')
OUT = ROOT / 'docs/evidence/task-6'
assert os.getuid() == os.geteuid() == os.getgid() == 1000
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / 'scripts'))
import firecracker_recovery as recovery
from runtime_lab_paths import trusted_directory

execution = json.loads((OUT / 'controller-cache-execute-result-20261025.json').read_bytes())
assert execution['timed_out'] and execution['exit_code'] == -15
pre = json.loads((OUT / 'controller-cache-preflight-20261025.json').read_bytes())
for name, expected in pre['source_hashes'].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_blocks, info.st_mtime_ns, info.st_ctime_ns]


def sibling_metadata(path):
    digest = hashlib.sha256()
    count = allocated = 0

    def add(name, info):
        nonlocal count, allocated
        count += 1
        allocated += info.st_blocks * 512
        digest.update(json.dumps([name, metadata(info)], separators=(',', ':')).encode() + b'\n')

    add('.', path.lstat())
    for directory, dirs, files in os.walk(path, followlinks=False, onerror=lambda error: (_ for _ in ()).throw(error)):
        dirs.sort()
        for name in sorted(dirs + files):
            item = Path(directory) / name
            add(str(item.relative_to(path)), item.lstat())
    return {'entries': count, 'allocated_metadata_bytes_including_dirs': allocated,
            'sha256': digest.hexdigest(), 'root_metadata': metadata(path.lstat())}


counts = {'present_files': 0, 'missing_derived_files': 0, 'present_dirs': 0,
          'missing_executable_dirs': 0, 'narrowed_files': 0, 'original_mode_files': 0,
          'narrowed_dirs': 0, 'original_mode_dirs': 0}
with recovery.project_lock():
    parent = trusted_directory(str(ROOT / '.cache'), 1000)
    fds = {'': parent}
    try:
        fd = os.open('identity-cache-permission-intent.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(fd)
            assert stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 1000
            assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 32000000
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(32000001)
            assert len(raw) == info.st_size
        finally:
            os.close(fd)
        intent = json.loads(raw)
        assert intent['version'] == 1 and intent['state'] == 'prepared-not-completed' and intent['cache_name'] == 'go-build'
        entries = {entry['relative']: entry for entry in intent['entries']}
        assert len(entries) == len(intent['entries'])
        current_names = {}
        for name, entry in sorted(entries.items(), key=lambda item: (item[0].count('/'), item[0])):
            parts = name.split('/')
            assert 1 <= len(parts) <= 4 and parts[0] == 'go-build'
            assert all(part and part not in ('.', '..') for part in parts)
            old = entry['original']
            up = '/'.join(parts[:-1])
            assert up in fds
            try:
                current = os.stat(parts[-1], dir_fd=fds[up], follow_symlinks=False)
            except FileNotFoundError:
                if stat.S_ISDIR(old[4]):
                    assert len(parts) == 3
                    counts['missing_executable_dirs'] += 1
                else:
                    assert name not in ('go-build/README', 'go-build/trim.txt', 'go-build/testexpire.txt')
                    counts['missing_derived_files'] += 1
                continue
            assert [current.st_dev, current.st_ino, current.st_uid, current.st_gid] == old[:4]
            assert stat.S_IFMT(current.st_mode) == stat.S_IFMT(old[4])
            mode = stat.S_IMODE(current.st_mode)
            assert mode in (stat.S_IMODE(old[4]), entry['target_mode'])
            current_names.setdefault(up, set()).add(parts[-1])
            narrowed = mode == entry['target_mode']
            if stat.S_ISDIR(current.st_mode):
                counts['present_dirs'] += 1
                counts['narrowed_dirs' if narrowed else 'original_mode_dirs'] += 1
                fds[name] = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[up])
                assert metadata(os.fstat(fds[name])) == metadata(current)
            else:
                assert stat.S_ISREG(current.st_mode) and current.st_nlink == old[5] == 1
                assert (current.st_size, current.st_mtime_ns) == (old[6], old[7])
                counts['present_files'] += 1
                counts['narrowed_files' if narrowed else 'original_mode_files'] += 1
        for name, fd in fds.items():
            if name:
                assert set(os.listdir(fd)) == current_names.get(name, set())
        try:
            os.stat('identity-cache-permission-result.json', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            completion_present = False
        else:
            completion_present = True
    finally:
        for fd in reversed(list(fds.values())):
            os.close(fd)
    siblings = {name: sibling_metadata(ROOT / '.cache' / name) for name in pre['sibling_cache_metadata']}
    assert siblings == pre['sibling_cache_metadata']
    scene = recovery.Scene(cleanup=True)
    try:
        original_raw = recovery.load(recovery.WORK / 'inspect' / 'result.json')
        assert hashlib.sha256(original_raw).hexdigest() == '55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
        inventory = recovery.helper.validate_inventory(original_raw, recovery.file_sha(recovery.MODULE))
        assert not recovery.scoped_ids('image', {'project': 'warden'}, recovery.docker)
        post = recovery.full_postflight(scene, 0, inventory)
        assert recovery.current_charges() == 5000000000
    finally:
        scene.close()

record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'known_original_process_exit': -15, 'timeout_seconds': 180,
          'cache_metadata_counts': counts,
          'private_intent_bytes': len(raw), 'private_intent_sha256': hashlib.sha256(raw).hexdigest(),
          'completion_receipt_present': completion_present,
          'present_cache_file_identity_size_mtime_unchanged': True,
          'unknown_entries_or_aliases_found': False,
          'sibling_cache_metadata_match': True, 'original_scene_and_Q_postflight': post,
          'all_fixed_source_hashes_match': True, 'cache_bodies_read': False,
          'permissions_rolled_back': False, 'maintenance_retried': False,
          'maintenance_complete': False, 'new3GB_admitted': False,
          'PG_material_or_new_cache_actual_authorized': False,
          'Q_released': False, 'task6_complete': False, 'goal_complete': False}
out = OUT / 'controller-cache-timeout-audit-20261025.json'
with out.open('x') as stream:
    stream.write(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, sort_keys=True))
