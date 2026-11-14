"""Fixed controller recorder for reviewed A modes; never accepts a command/path."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = '8c8e9edf4a269effb155ae027b703cd9dc770836'
HOST_SHA = '018cba8ea96b108abc4af04ac44f0bc1a40dabfdf296216ee30b1b4c41f05672'
HELPER_SHA = '72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2'
REVIEW = ROOT / 'docs/evidence/task-4/review-recovery-safety-amendment.md'
assert len(sys.argv) == 2 and sys.argv[1] in ('inspect', 'restore-traversal', 'postflight')
assert os.geteuid() == 1000
mode = sys.argv[1]
os.umask(0o077)
os.chdir(ROOT)
for name, wanted in (('scripts/firecracker_recovery.py', HOST_SHA), ('scripts/firecracker_recovery_init.py', HELPER_SHA)):
    raw = (ROOT / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == wanted, name
    assert raw == subprocess.check_output(['git', 'show', SOURCE + ':' + name]), name
assert subprocess.check_output(['git', 'log', '-1', '--format=%H', '--', 'scripts/firecracker_recovery.py']).decode().strip() == SOURCE
review_raw = REVIEW.read_bytes()
assert review_raw
out = ROOT / 'docs/evidence/task-4/recovery-live' / SOURCE
out.mkdir(parents=True, exist_ok=True)
command_path = out / 'controller-recovery-a-command.py'
body = Path(__file__).read_bytes()
if command_path.exists():
    assert command_path.read_bytes() == body
else:
    with os.fdopen(os.open(command_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), 'wb') as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())
args = ['python3', '-B', 'scripts/firecracker_recovery.py', mode,
        '--reviewed-exact-scene', '--other-service-memory-bytes', '0']
meta_path = out / (mode + '-meta.json')
assert not meta_path.exists()
log_path = out / (mode + '.log')
log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
began = time.monotonic()
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
with os.fdopen(log_fd, 'wb') as stream:
    process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream,
                               stderr=subprocess.STDOUT,
                               env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    code = process.wait()
    stream.flush(); os.fsync(stream.fileno())
end = datetime.datetime.now(datetime.timezone.utc).isoformat()
assert log_path.stat().st_size <= 65536
raw = log_path.read_bytes()
meta = {'source': SOURCE, 'mode': mode, 'command': args,
        'started_at': start, 'ended_at': end,
        'duration_seconds': round(time.monotonic() - began, 6), 'exit_code': code,
        'original_charge_released': False, 'original_charge_bytes': 5000000000,
        'review_file': str(REVIEW.relative_to(ROOT)), 'review_sha256': hashlib.sha256(review_raw).hexdigest(),
        'controller_command_sha256': hashlib.sha256(body).hexdigest(),
        'log_bytes': len(raw), 'log_sha256': hashlib.sha256(raw).hexdigest(),
        'original_owner_retirement': 'cleanup_pending', 'creation_outcome': 'unknown',
        'never_reopen': True, 'guest_boot_acceptance': False}
with os.fdopen(os.open(meta_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), 'w') as stream:
    stream.write(json.dumps(meta, indent=2) + '\n'); stream.flush(); os.fsync(stream.fileno())
print(json.dumps(meta, sort_keys=True))
raise SystemExit(code)
