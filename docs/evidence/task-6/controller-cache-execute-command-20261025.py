"""Single-use controller recorder: only launches the independently reviewed fixed command."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path('/home/postedism/Desktop/Warden')
OUT = ROOT / 'docs/evidence/task-6'
assert os.getuid() == os.geteuid() == os.getgid() == 1000
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / 'scripts'))
import firecracker_recovery as recovery
from runtime_lab_paths import trusted_directory

pre = json.loads((OUT / 'controller-cache-preflight-20261025.json').read_bytes())
assert pre['source_hashes']['scripts/identity_cache.py'] == 'f608dc714b79dcc4f3c4c2071ba6dd561c88eec10c45fc905820ec447d8a1ede'
assert (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(pre['at'])).total_seconds() < 900
assert 'Spec compliance：PASS' in (OUT / 'review-cache-substage-round-1.md').read_text()
assert (OUT / 'controller-cache-operation-ruling-20261025.md').exists()
for name, expected in pre['source_hashes'].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected


def save_exclusive(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


with recovery.project_lock():
    scene = recovery.Scene(cleanup=True)
    try:
        raw = recovery.load(recovery.WORK / 'inspect' / 'result.json')
        assert hashlib.sha256(raw).hexdigest() == '55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
        inventory = recovery.helper.validate_inventory(raw, recovery.file_sha(recovery.MODULE))
        assert not recovery.scoped_ids('image', {'project': 'warden'}, recovery.docker)
        fresh = recovery.full_postflight(scene, 0, inventory)
        assert recovery.current_charges() == 5000000000
        assert fresh['ordinary_full_guard']['project_allocated_bytes'] + 5000000000 + 96000000 <= 12000000000
        parent = trusted_directory(str(ROOT / '.cache'), 1000)
        try:
            old = os.stat('go-build', dir_fd=parent, follow_symlinks=False)
            assert [old.st_dev, old.st_ino, old.st_uid, old.st_gid, old.st_mode, old.st_nlink,
                    old.st_size, old.st_blocks, old.st_mtime_ns, old.st_ctime_ns] == pre['trusted_anchors_metadata']['go-build']
            for name in ('identity-cache-permission-intent.json', 'identity-cache-permission-result.json'):
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError('existing maintenance state; no rerun authorized')
        finally:
            os.close(parent)
    finally:
        scene.close()

command = ['python3', '-B', 'scripts/identity_cache.py']
intent_path = OUT / 'controller-cache-execute-intent-20261025.json'
result_path = OUT / 'controller-cache-execute-result-20261025.json'
log_path = OUT / 'controller-cache-execute-20261025.log'
assert not result_path.exists() and not log_path.exists()
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
save_exclusive(intent_path, {'started': started, 'command': command, 'source_hashes': pre['source_hashes'],
                            'fresh_original_postflight': fresh, 'wall_deadline_seconds': 180,
                            'writer_window': pre['writer_free_window_basis'],
                            'state': 'command-intended-not-known-complete', 'Q_released': False})
clock = time.monotonic()
timed_out = False
proc = None
error = None
returncode = None
try:
    with log_path.open('xb') as output:
        proc = subprocess.Popen(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            returncode = proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                returncode = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                returncode = proc.wait(timeout=5)
        output.flush()
        os.fsync(output.fileno())
except BaseException as exc:
    error = type(exc).__name__
    # Never relaunch/rollback. An uncertain child is not converted into success.
after = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in pre['source_hashes']}
record = {'started': started, 'ended': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'duration_seconds': time.monotonic() - clock, 'command': command,
          'pid': None if proc is None else proc.pid, 'exit_code': returncode,
          'timed_out': timed_out, 'recorder_error': error,
          'source_hashes_before': pre['source_hashes'], 'source_hashes_after': after,
          'log_bytes': log_path.stat().st_size if log_path.exists() else None,
          'log_sha256': hashlib.sha256(log_path.read_bytes()).hexdigest() if log_path.exists() else None,
          'command_exit_zero_not_yet_postflight': returncode == 0 and not timed_out and error is None,
          'postflight_pending': True, 'Q_released': False, 'task6_complete': False, 'goal_complete': False}
save_exclusive(result_path, record)
print(json.dumps(record, sort_keys=True))
assert after == pre['source_hashes']
assert record['command_exit_zero_not_yet_postflight'], 'retain all intent/state; no automatic retry'
assert record['log_bytes'] <= 1048576
