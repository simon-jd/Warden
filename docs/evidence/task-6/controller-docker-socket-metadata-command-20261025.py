import time
ENTRY = time.monotonic()
import os
import signal
signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
remaining = ENTRY + 30 - time.monotonic()
if remaining <= 0:
    os._exit(124)
signal.setitimer(signal.ITIMER_REAL, remaining)
import json
from pathlib import Path
import resource
import stat
from datetime import datetime, timezone
assert os.getuid() == os.geteuid() == os.getgid() == 1000
resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
def meta(info):
    return {key:getattr(info, 'st_'+key) for key in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')}
fds = []
try:
    root_fd = os.open('/', flags); fds.append(root_fd)
    run_fd = os.open('run', flags, dir_fd=root_fd); fds.append(run_fd)
    var_fd = os.open('var', flags, dir_fd=root_fd); fds.append(var_fd)
    ancestors = {'/':meta(os.fstat(root_fd)), '/run':meta(os.fstat(run_fd)), '/var':meta(os.fstat(var_fd))}
    for name, value in ancestors.items():
        assert stat.S_ISDIR(value['mode']) and value['uid'] == 0 and not value['mode'] & 0o022
        assert value == meta(Path(name).lstat())
    alias = os.stat('run', dir_fd=var_fd, follow_symlinks=False)
    link = os.readlink('run', dir_fd=var_fd)
    assert stat.S_ISLNK(alias.st_mode) and alias.st_uid == 0 and link == '/run'
    assert meta(alias) == meta(os.stat('run', dir_fd=var_fd, follow_symlinks=False))
    socket_info = os.stat('docker.sock', dir_fd=run_fd, follow_symlinks=False)
    assert stat.S_ISSOCK(socket_info.st_mode) and socket_info.st_uid == 0 and socket_info.st_nlink == 1
    assert not socket_info.st_mode & 0o007
    assert meta(socket_info) == meta(Path('/run/docker.sock').lstat())
    result = {'version':1, 'scope':'fixed root-/run-/var/socket/legacy-alias metadata only; no socket open/connect, daemon API, peer PID, config, environment or private cache read',
              'observed_utc':datetime.now(timezone.utc).isoformat(), 'ancestors':ancestors,
              'legacy_alias':{'path':'/var/run','target':link,'metadata':meta(alias)},
              'socket':{'path':'/run/docker.sock','metadata':meta(socket_info),'permission_mode':oct(stat.S_IMODE(socket_info.st_mode))},
              'peer_identity':'NOT OBSERVED; no connection', 'compatibility':'NOT EXERCISED; no API request',
              'measured_entry_elapsed_seconds':time.monotonic()-ENTRY,
              'timing_scope':'30s from earliest measured Python entry; interpreter startup not externally bounded'}
finally:
    for fd in reversed(fds): os.close(fd)
raw = (json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
assert len(raw) <= 16384 and time.monotonic() < ENTRY + 30
out = Path('docs/evidence/task-6/controller-docker-socket-metadata-20261025.json')
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
try:
    offset = 0
    while offset < len(raw):
        wrote = os.write(fd,raw[offset:]); assert wrote > 0; offset += wrote
    os.fsync(fd)
finally:
    os.close(fd)
assert time.monotonic() < ENTRY + 30
print(raw.decode(),end='',flush=True)
assert time.monotonic() < ENTRY + 30
signal.setitimer(signal.ITIMER_REAL,0)
