"""Fixed read-only controller preflight. Never runs the cache maintenance entrypoint."""
from contextlib import redirect_stdout
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/home/postedism/Desktop/Warden')
assert os.getuid() == os.geteuid() == os.getgid() == 1000
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / 'scripts'))
import firecracker_recovery as recovery
from runtime_lab_paths import trusted_directory

SOURCE_HASHES = {
    'scripts/identity_cache.py': 'f608dc714b79dcc4f3c4c2071ba6dd561c88eec10c45fc905820ec447d8a1ede',
    'scripts/test_identity_cache.py': '807fc390ea6b807f895b39acfd9ffc48d143ccd5a3b3dc4f1f3d05cfdeb93bc2',
    'scripts/runtime_lab_paths.py': '0ce3287feab8197839cf2e7e1cf297fd5cad0e740069023b188e4c366b643f84',
    'scripts/firecracker_recovery.py': 'cccb3378b92816dc5242fd79e72df5fc79fcda338b8f20d34c5a9ca655a8453b',
    'scripts/firecracker_recovery_init.py': '72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2',
    'scripts/azure_guard.py': '303980a3eb5bc2c7a53ae2be985ac29c643b73d4df907e094f8cface2489eb48',
}
FORMAT_HASHES = {
    'cache/cache.go': '22da4896758772a443d90dd148719866d20e811bfefd3668597eae083b6f39b2',
    'cache/default.go': '3b4697e22509682f6339813ab7fdd9ed0f5628bdcbed261ee2eff3003b7f5d54',
    'clean/clean.go': '52db63640ae65ee1ba34c67b92eea3e6634f5876b8de2e92c09c5e0a6ae0153b',
}


def digest_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_blocks, info.st_mtime_ns, info.st_ctime_ns]


def sibling_metadata(path):
    """Only metadata, no bodies or followed symlinks; exclude read-induced atime."""
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


for name, expected in SOURCE_HASHES.items():
    assert digest_file(ROOT / name) == expected
toolchain = ROOT / '.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/src/cmd/go/internal'
for name, expected in FORMAT_HASHES.items():
    assert digest_file(toolchain / name) == expected
legacy = (ROOT / 'scripts/go.sh').read_bytes()
assert b'GOCACHE=/workspace/.cache/go-build' in legacy
assert b'--mount "type=bind,src=$root,dst=/workspace"' in legacy
out = ROOT / 'docs/evidence/task-6/controller-cache-preflight-20261025.json'
assert not out.exists()

with recovery.project_lock():
    scene = recovery.Scene(cleanup=True)
    try:
        scene.check(1000)
        raw = recovery.load(recovery.WORK / 'inspect' / 'result.json')
        assert hashlib.sha256(raw).hexdigest() == '55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
        inventory = recovery.helper.validate_inventory(raw, recovery.file_sha(recovery.MODULE))
        assert not recovery.scoped_ids('image', {'project': 'warden'}, recovery.docker)
        original = recovery.full_postflight(scene, 0, inventory)
        assert recovery.current_charges() == 5000000000
        guard = original['ordinary_full_guard']
        maintenance_total = guard['project_allocated_bytes'] + int(guard['additional_bytes']) + 96000000
        assert maintenance_total <= 12000000000
        assert int(guard['service_memory_bytes']) <= 16000000000
        fds = {}
        try:
            for name in ('.cache', '.cache/warden-lab'):
                fds[name] = trusted_directory(str(ROOT / name), 1000)
            cache_parent = fds['.cache']
            for name in ('identity-cache-permission-intent.json', 'identity-cache-permission-result.json'):
                try:
                    os.stat(name, dir_fd=cache_parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError('existing maintenance state must not be reset')
            fds['go-build'] = os.open('go-build', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=cache_parent)
            old = os.fstat(fds['go-build'])
            assert old.st_uid == old.st_gid == 1000 and stat.S_IMODE(old.st_mode) == 0o775
            assert old.st_dev == os.fstat(cache_parent).st_dev
            lock = os.stat('docker.lock', dir_fd=fds['.cache/warden-lab'], follow_symlinks=False)
            assert stat.S_ISREG(lock.st_mode) and lock.st_uid == lock.st_gid == 1000
            assert lock.st_nlink == 1 and stat.S_IMODE(lock.st_mode) == 0o600
            anchors = {name: metadata(os.fstat(fd)) for name, fd in fds.items()}
        finally:
            for fd in fds.values():
                os.close(fd)
        siblings = {name: sibling_metadata(ROOT / '.cache' / name)
                    for name in ('firecracker-code', 'go-mod', 'warden-lab')}
    finally:
        scene.close()

result = {
    'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'ordinary_uid_gid': 1000, 'source_hashes': SOURCE_HASHES,
    'pinned_local_go_format_source_hashes': FORMAT_HASHES,
    'format_source_read_not_executed': True,
    'retired_go_entrypoint_sha256': hashlib.sha256(legacy).hexdigest(),
    'old_cache_classification_basis': 'fixed project-owned GOCACHE in retired go.sh and prior completed project runs; not a per-file publisher attestation',
    'trusted_anchors_metadata': anchors, 'existing_project_lock_metadata': metadata(lock),
    'maintenance_receipts_absent': True, 'original_ordinary_postflight': original,
    'maintenance_headroom_total_bytes': 96000000, 'charged_with_maintenance_headroom': maintenance_total,
    'prospective_new3GB_total_before_cleanup': guard['project_allocated_bytes'] + int(guard['additional_bytes']) + 3000000000,
    'new3GB_not_admitted_by_this_preflight': True,
    'sibling_cache_metadata': siblings,
    'writer_free_window_basis': 'controller exclusive maintenance window; all earlier project Go/Docker command receipts terminal, identity implementer idle after doc-only handoff, reviewer read-only, no legacy entrypoint or service started; flock alone is insufficient',
    'project_process_inventory_or_nonproject_actions_performed': False,
    'old_recovery_operation_reexecuted': False, 'cache_mutated': False,
    'actual_cleanup_requires_separate_review_and_controller_ruling': True,
    'Q_released': False, 'task6_complete': False, 'goal_complete': False,
}
with out.open('x') as stream:
    stream.write(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: value for key, value in result.items() if key not in ('source_hashes', 'sibling_cache_metadata', 'trusted_anchors_metadata', 'original_ordinary_postflight')}, sort_keys=True))
