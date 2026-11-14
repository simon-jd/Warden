"""Read-only controller original-state/resource checkpoint after crypto unit handoff."""
import datetime
import hashlib
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

with recovery.project_lock():
    parent = trusted_directory(str(ROOT / '.cache'), 1000)
    try:
        fd = os.open('identity-cache-permission-intent.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(fd)
            assert stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 1000
            assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == 4573737
            with os.fdopen(os.dup(fd), 'rb') as source:
                raw_intent = source.read(4573738)
        finally:
            os.close(fd)
        assert hashlib.sha256(raw_intent).hexdigest() == 'cbc9e3aad72189cf1a048ee1a30270ea43dce2925823563c283fecd3dcf65e5e'
        try:
            os.stat('identity-cache-permission-result.json', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError('unexpected old maintenance result')
        old = os.stat('go-build', dir_fd=parent, follow_symlinks=False)
        original = json.loads((ROOT / 'docs/evidence/task-6/controller-cache-preflight-20261025.json').read_bytes())
        assert [old.st_dev, old.st_ino, old.st_uid, old.st_gid] == original['trusted_anchors_metadata']['go-build'][:4]
        assert stat.S_IMODE(old.st_mode) == 0o700
    finally:
        os.close(parent)
    scene = recovery.Scene(cleanup=True)
    try:
        raw = recovery.load(recovery.WORK / 'inspect' / 'result.json')
        assert hashlib.sha256(raw).hexdigest() == '55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
        inventory = recovery.helper.validate_inventory(raw, recovery.file_sha(recovery.MODULE))
        assert not recovery.scoped_ids('image', {'project': 'warden'}, recovery.docker)
        post = recovery.full_postflight(scene, 0, inventory)
        assert recovery.current_charges() == 5000000000
    finally:
        scene.close()
record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'crypto_source': '6d02de4062c0ee1e5d62825df0ea670d54672b5e',
          'crypto_evidence': 'f4dd9dc75fbabce7b6d7d79eba5d8428f483a1ae',
          'ordinary_original_state_postflight': post,
          'owned_images_and_containers': 0, 'original_22_scene_metadata_match': True,
          'old_cache_root_identity_mode_and_intent_hash_unchanged': True,
          'old_cache_completion_receipt_absent': True,
          'old_cache_all_file_metadata_not_rescanned_here': True,
          'cache_maintenance_not_retried': True, 'native_formatter_not_executed': True,
          'no_tests_rerun_by_controller': True,
          'new3GB_not_admitted': True, 'PG_material_or_identity_actual_started': False,
          'old_recovery_operation_reexecuted': False, 'Q_released': False,
          'source_security_review': 'pending independent reviewer',
          'task6_complete': False, 'goal_complete': False}
out = ROOT / 'docs/evidence/task-6/controller-crypto-postflight-20261025.json'
with out.open('x') as stream:
    stream.write(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, sort_keys=True))
