"""Record one reviewed, exact, pre-daemon material-only cleanup."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = 'ba8cfaf6bffd7996f54bd50db9ccf453ff121022'
assert os.geteuid() == 1000
os.umask(0o077)
os.chdir(ROOT)
raw = (ROOT / 'scripts/firecracker_recovery.py').read_bytes()
assert hashlib.sha256(raw).hexdigest() == 'd74bbdbad20c3e12cdc141ef0079a71f70f97d84e470f4d56086aa9282514f73'
assert raw == subprocess.check_output(['git', 'show', SOURCE + ':scripts/firecracker_recovery.py'])
out = Path(__file__).parent
log_path = out / 'cleanup-inspect.log'
meta_path = out / 'cleanup-inspect-meta.json'
assert not log_path.exists() and not meta_path.exists()
args = ['python3', '-B', 'scripts/firecracker_recovery.py', 'cleanup-inspect',
        '--reviewed-exact-scene', '--other-service-memory-bytes', '0']
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
began = time.monotonic()
with log_path.open('xb') as stream:
    process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL,
                               stdout=stream, stderr=subprocess.STDOUT,
                               env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    code = process.wait()
    stream.flush(); os.fsync(stream.fileno())
assert log_path.stat().st_size <= 65536
raw = log_path.read_bytes()
meta = {'source': SOURCE, 'command': args, 'started_at': start,
        'ended_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'duration_seconds': round(time.monotonic() - began, 6), 'exit_code': code,
        'log_bytes': len(raw), 'log_sha256': hashlib.sha256(raw).hexdigest(),
        'original_Q_bytes': 5000000000, 'original_Q_released': False,
        'original_owner_retirement': 'cleanup_pending', 'creation_outcome': 'unknown',
        'never_reopen': True, 'new_attempt_authorized': False}
with meta_path.open('x') as stream:
    json.dump(meta, stream, indent=2); stream.write('\n')
    stream.flush(); os.fsync(stream.fileno())
log_path.chmod(0o644); meta_path.chmod(0o644)
print(json.dumps(meta))
raise SystemExit(code)
