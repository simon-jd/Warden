#!/usr/bin/python3
# Reviewed launch wrapper: exec replaces this process; it leaves no supervisor.
import resource
resource.setrlimit(resource.RLIMIT_AS, (67108864, 2147483648))
resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
resource.setrlimit(resource.RLIMIT_FSIZE, (67108864, 67108864))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
import fcntl
import os
import sys

ROOT = '/home/postedism/Desktop/Warden'
PREP = ROOT + '/.superpowers/sdd/2-warden-security-plan/task10-dns-score-fix-r1-cover-20261026'
SDK = ROOT + '/.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64'
if len(sys.argv) < 3 or sys.argv[1] not in ('tool', 'test'):
    raise SystemExit('invalid child wrapper invocation')
mode, program = sys.argv[1:3]
if mode == 'tool':
    permitted = {SDK + '/pkg/tool/linux_amd64/' + name for name in ('compile', 'asm', 'link')}
    if program not in permitted:
        raise SystemExit('unexpected Go tool; stop without fallback')
else:
    resolved = os.path.realpath(program)
    prefix = PREP + '/cover-run/work/tmp/'
    if not resolved.startswith(prefix) or not resolved.endswith('/dns_exfil.test'):
        raise SystemExit('unexpected test executable')
# -p=1 serializes build actions. A concurrent wrapper fails before raising its
# limit or running another large child; lock stays held across os.execv.
fd = os.open(PREP + '/cover-run/work/child.lock', os.O_RDWR)
os.set_inheritable(fd, True)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit('unexpected parallel tool/test child; infrastructure stop')
resource.setrlimit(resource.RLIMIT_AS, (2147483648, 2147483648))
os.execv(program, sys.argv[2:])
