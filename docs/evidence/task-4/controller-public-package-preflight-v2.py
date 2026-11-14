"""One fresh sealed public archive preflight; never creates a scene phase."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = 'd8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7'
assert os.geteuid() == 1000 and len(sys.argv) == 1
os.umask(0o077)
sys.path.insert(0, str(ROOT / 'scripts'))
import firecracker_recovery as r
assert (ROOT / 'scripts/firecracker_recovery.py').read_bytes() == __import__('subprocess').check_output(
    ['git', '-C', str(ROOT), 'show', SOURCE + ':scripts/firecracker_recovery.py'])
assert r.file_sha(r.MODULE) == '72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2'
OUT = ROOT / 'docs/evidence/task-4/public-package-preflight-v2.json'
fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
record = {'source': SOURCE, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'original_Q_released': False, 'scene_phase_created': False,
          'image_container_helper_created': False, 'live_descendants_read': False}


def timeout(signum, frame):
    raise TimeoutError('public_package_deadline')


signal.signal(signal.SIGALRM, timeout)
signal.alarm(45)
try:
    assert r.source_sha() == SOURCE
    with r.project_lock():
        scene = r.Scene()
        try:
            record['admission_before'] = r.account(scene, 0)
            parent = r.trusted_directory(str(r.BASE), 1000)
            try:
                os.mkdir('public-recovery-package-v1', 0o700, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
            directory = r.BASE / 'public-recovery-package-v1'
            with r.runtime_inputs() as inputs:
                package = r.build_archive(directory / 'image.tar', inputs, r.MODULE)
            r.save(directory / 'package.json', package)
            r.check_archive(directory, package)
            record['sealed_archive'] = {key: package[key] for key in (
                'file_bytes', 'archive_bytes', 'archive_sha256', 'helper_sha256', 'expected_inventory_sha256')}
            record['selected_files_including_helper'] = len(package['files'])
            record['host_abi'] = package['material_policy']['host_abi']
            record['admission_after'] = r.account(scene, 0)
            record['live_uid_after'] = os.fstat(scene.live).st_uid
            record['success'] = True
        finally:
            scene.close()
except Exception as error:
    record['success'] = False
    record['error'] = {'type': type(error).__name__,
                       'reason': error.code if isinstance(error, r.Refusal) else 'external_error'}
finally:
    signal.alarm(0)
    record['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with os.fdopen(fd, 'w') as stream:
        json.dump(record, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    OUT.chmod(0o644)
print(json.dumps(record))
