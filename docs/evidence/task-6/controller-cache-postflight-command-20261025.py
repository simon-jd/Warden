"""Read-only independent controller postcheck; never reruns maintenance or Go."""
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
OUT = ROOT / 'docs/evidence/task-6'
assert os.getuid() == os.geteuid() == os.getgid() == 1000
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / 'scripts'))
import azure_guard
import firecracker_recovery as recovery
import identity_cache
from runtime_lab_paths import trusted_directory

pre = json.loads((OUT / 'controller-cache-preflight-20261025.json').read_bytes())
execution = json.loads((OUT / 'controller-cache-execute-result-20261025.json').read_bytes())
assert execution['command_exit_zero_not_yet_postflight'] is True
assert execution['exit_code'] == 0 and not execution['timed_out'] and execution['recorder_error'] is None
assert execution['source_hashes_before'] == execution['source_hashes_after'] == pre['source_hashes']
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


def receipt(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 1000
        assert info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_size <= 32000000
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(32000001)
        assert len(raw) == info.st_size
        return json.loads(raw), {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(fd)


with recovery.project_lock():
    parent = trusted_directory(str(ROOT / '.cache'), 1000)
    try:
        intent, intent_meta = receipt(parent, identity_cache.INTENT_NAME)
        result, result_meta = receipt(parent, identity_cache.RESULT_NAME)
        assert intent['version'] == result['version'] == 1
        assert intent['cache_name'] == result['cache_name'] == 'go-build'
        assert intent['state'] == 'prepared-not-completed' and result['state'] == 'completed'
        entries = {entry['relative']: entry for entry in intent['entries']}
        assert len(entries) == len(intent['entries'])
        original_files = sum(stat.S_ISREG(entry['original'][4]) and name not in {'go-build/' + x for x in identity_cache.METADATA}
                             for name, entry in entries.items())
        original_executable_dirs = sum(stat.S_ISDIR(entry['original'][4]) for entry in entries.values()) - 257
        assert result['removed_files'] == original_files
        assert result['removed_executable_dirs'] == original_executable_dirs
        assert result['preserved_bucket_count'] == 256
        plan = identity_cache.CachePlan(parent, 1000)
        try:
            plan._recheck_all()
            assert not plan.files and len(plan.directories) == 257
            assert len(plan.preserved) == result['preserved_metadata_count']
            for node in plan.directories:
                name = 'go-build' if node is plan.root else 'go-build/' + node.name
                old = entries[name]['original']
                current = os.fstat(node.fd)
                assert [current.st_dev, current.st_ino, current.st_uid, current.st_gid] == old[:4]
                assert stat.S_IMODE(current.st_mode) == 0o700
            for node in plan.preserved:
                old = entries['go-build/' + node.name]['original']
                current = os.stat(node.name, dir_fd=node.parent, follow_symlinks=False)
                assert [current.st_dev, current.st_ino, current.st_uid, current.st_gid] == old[:4]
                assert [current.st_nlink, current.st_size, current.st_mtime_ns] == [old[5], old[6], old[7]]
                assert stat.S_IMODE(current.st_mode) == 0o600
        finally:
            plan.close()
    finally:
        os.close(parent)
    siblings = {name: sibling_metadata(ROOT / '.cache' / name) for name in pre['sibling_cache_metadata']}
    assert siblings == pre['sibling_cache_metadata']
    scene = recovery.Scene(cleanup=True)
    try:
        raw = recovery.load(recovery.WORK / 'inspect' / 'result.json')
        assert hashlib.sha256(raw).hexdigest() == '55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
        inventory = recovery.helper.validate_inventory(raw, recovery.file_sha(recovery.MODULE))
        assert not recovery.scoped_ids('image', {'project': 'warden'}, recovery.docker)
        original = recovery.full_postflight(scene, 0, inventory)
        assert recovery.current_charges() == 5000000000
        output = io.StringIO()
        with redirect_stdout(output):
            azure_guard.preflight(8000000000, 3768000000, 0)
        prospective = json.loads(output.getvalue())
    finally:
        scene.close()

record = {
    'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'actual_command_result': execution, 'private_intent_metadata': intent_meta,
    'private_completion_metadata': result_meta, 'cache_completion': result,
    'retained_root_and_256_buckets_identity_verified': True,
    'retained_metadata_identity_size_mtime_verified_without_body_reads': True,
    'all_sibling_cache_metadata_match': True, 'sibling_cache_metadata': siblings,
    'source_hashes_match': True, 'original_scene_and_Q_postflight': original,
    'prospective_standard3GB_plus_Q5GB_ordinary_guard': prospective,
    'new3GB_charge_created': False, 'material_PG_or_Go_started': False,
    'old_recovery_operation_reexecuted': False, 'Q_released': False,
    'task6_complete': False, 'goal_complete': False,
}
out = OUT / 'controller-cache-postflight-20261025.json'
with out.open('x') as stream:
    stream.write(json.dumps(record, indent=2) + '\n')
print(json.dumps({key: value for key, value in record.items() if key not in ('actual_command_result', 'sibling_cache_metadata', 'original_scene_and_Q_postflight')}, sort_keys=True))
