import time
ENTRY = time.monotonic()
import os
import signal
signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
remaining = ENTRY + 30 - time.monotonic()
if remaining <= 0:
    os._exit(124)
signal.setitimer(signal.ITIMER_REAL, remaining)
import hashlib
import json
from pathlib import Path
import resource
import stat
from datetime import datetime, timezone
assert os.getuid() == os.geteuid() == os.getgid() == 1000
resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
FIELDS = ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns', 'blocks')
def meta(info):
    return {key: getattr(info, 'st_' + key) for key in FIELDS}
def public_file(name, limit, body=False):
    path = Path(name)
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        initial = os.fstat(fd)
        assert stat.S_ISREG(initial.st_mode) and initial.st_uid == initial.st_gid == 0
        assert not initial.st_mode & 0o022 and initial.st_nlink == 1 and 0 < initial.st_size <= limit
        digest = hashlib.sha256()
        md5 = hashlib.md5()
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            assert count <= limit
            digest.update(chunk)
            md5.update(chunk)
            if body:
                chunks.append(chunk)
        assert count == initial.st_size
        assert meta(initial) == meta(os.fstat(fd)) == meta(path.lstat())
        return {'path': name, 'metadata': meta(initial), 'sha256': digest.hexdigest(),
                'md5_package_correspondence_only': md5.hexdigest()}, b''.join(chunks)
    finally:
        os.close(fd)
start = datetime.now(timezone.utc).isoformat()
records = []
binary, _ = public_file('/usr/bin/docker', 134217728)
records.append(binary)
status, data = public_file('/var/lib/dpkg/status', 8388608, True)
records.append(status)
packages = []
for paragraph in data.decode('utf-8').split('\n\n'):
    fields = dict(line.split(': ', 1) for line in paragraph.splitlines() if ': ' in line and not line[0].isspace())
    if fields.get('Package') not in ('docker-ce-cli', 'docker.io', 'moby-cli'):
        continue
    if fields.get('Status') != 'install ok installed':
        continue
    package = {key: fields[key] for key in ('Package', 'Status', 'Version', 'Architecture', 'Source') if key in fields}
    sums, raw = public_file('/var/lib/dpkg/info/' + fields['Package'] + '.md5sums', 1048576, True)
    records.append(sums)
    matches = [line.split() for line in raw.decode('ascii').splitlines() if line.split()[-1:] == ['usr/bin/docker']]
    assert len(matches) == 1 and len(matches[0]) == 2
    package['binary_matches_local_package_md5'] = matches[0][0] == binary['md5_package_correspondence_only']
    assert package['binary_matches_local_package_md5']
    packages.append(package)
assert len(packages) == 1
result = {'version': 1, 'scope': 'public binary and local package metadata only; no Docker execution, daemon, config, HOME, credential, private cache or runtime observation',
          'started_utc': start, 'ended_utc': datetime.now(timezone.utc).isoformat(),
          'measured_entry_elapsed_seconds': time.monotonic() - ENTRY,
          'timing_limit': '30s from earliest measured Python entry; interpreter startup not externally bounded',
          'provenance_limit': 'local root-owned package correspondence, not independent vendor attestation or installed-source equivalence',
          'files': records, 'packages': packages}
raw = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
assert len(raw) <= 65536 and time.monotonic() < ENTRY + 30
out = Path('docs/evidence/task-6/controller-cli-material-metadata-20261025.json')
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
try:
    offset = 0
    while offset < len(raw):
        wrote = os.write(fd, raw[offset:])
        assert wrote > 0
        offset += wrote
    os.fsync(fd)
finally:
    os.close(fd)
assert time.monotonic() < ENTRY + 30
print(raw.decode(), end='', flush=True)
assert time.monotonic() < ENTRY + 30
signal.setitimer(signal.ITIMER_REAL, 0)
