#!/usr/bin/python3
# ROOT R1 regression preparation only; fresh exact admission remains mandatory.
import resource
resource.setrlimit(resource.RLIMIT_AS, (268435456, 4294967296))
resource.setrlimit(resource.RLIMIT_CPU, (15, 60))
resource.setrlimit(resource.RLIMIT_FSIZE, (67108864, 67108864))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
import ctypes
import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import time

ROOT = '/home/postedism/Desktop/Warden'
PREP = ROOT + '/.superpowers/sdd/2-warden-security-plan/task10-dns-score-fix-r1-red-20261026'
SDK = ROOT + '/.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64'
RUN = PREP + '/red-run'
WORK = RUN + '/work'
LOG_LIMIT = 65536
DISK_STOP = 671088640  # 640MiB observed stop threshold, NOT a filesystem quota.
START = time.monotonic()
DEADLINE = START + 80  # leaves <=10s for owned-group cleanup and receipt.
child = None
raw = bytearray()
result = 'INFRASTRUCTURE_FAILURE'
reason = None
returncode = None
cleanup_ok = False
peak_allocated = 0
child_group_absent = True
leader_owned = False
leader_reaped = False
exit_observation = None
cleanup_error = None
owned_run = False

def deadline(signum, frame):
    raise TimeoutError('whole caller deadline entered cleanup reserve')

signal.signal(signal.SIGALRM, deadline)
signal.alarm(80)

def write(name, content):
    fd = os.open(RUN + '/' + name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    directory = os.open(RUN, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for part in iter(lambda: f.read(1048576), b''):
            h.update(part)
    return h.hexdigest()

def allocated(path):
    total = os.lstat(path).st_blocks * 512
    for parent, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            p = os.path.join(parent, name)
            st = os.lstat(p)
            if os.path.islink(p):
                raise RuntimeError('unexpected symlink in owned work tree')
            total += st.st_blocks * 512
    return total

def go_limits():
    # Only the owned Go child raises its soft caps; supervisor stays at 256MiB.
    resource.setrlimit(resource.RLIMIT_AS, (4294967296, 4294967296))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))

def observe_leader():
    # WNOWAIT is mandatory: the zombie pins the owned PID/PGID until ALL
    # nonzero signals are finished. No Popen.poll()/wait() is used.
    global leader_owned
    try:
        return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        leader_owned = False
        raise RuntimeError('owned leader no longer waitable; refuse all signals')

def observed_returncode(observation):
    if observation.si_code == os.CLD_EXITED:
        return observation.si_status
    return -observation.si_status

def reap_after_signals(pgid, until):
    # This function cannot signal. The leader must already be reaped explicitly.
    # New session + subreaper means remaining same-group descendants become our
    # children. ECHILD is the owned-group absence evidence; no killpg(0) follows
    # release of the leader and there is no host PID scan.
    while time.monotonic() < until:
        try:
            pid, _ = os.waitpid(-pgid, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid == 0:
            time.sleep(0.02)
    return False


try:
    if sys.argv != [sys.argv[0], '--root-admitted-r1-red']:
        raise RuntimeError('requires separate ROOT R1 RED admission; flag is not authorization')
    if os.geteuid() != 1000 or os.getcwd() != ROOT:
        raise RuntimeError('requires UID1000 and exact repository cwd')
    freeze = json.load(open(PREP + '/freeze.json'))
    for item in freeze['files']:
        p = ROOT + '/' + item['path']
        if os.path.islink(p) or os.stat(p).st_size != item['bytes'] or sha(p) != item['sha256']:
            raise RuntimeError('frozen input changed: ' + item['path'])
    for binary in ('bin/go', 'pkg/tool/linux_amd64/compile', 'pkg/tool/linux_amd64/link', 'pkg/tool/linux_amd64/asm'):
        if not os.path.isfile(SDK + '/' + binary) or not os.access(SDK + '/' + binary, os.X_OK):
            raise RuntimeError('fixed SDK tool unavailable: ' + binary)
    # Fresh target is a one-shot marker. No retries or reuse of prior work/cache.
    os.mkdir(RUN, 0o700)
    owned_run = True
    os.mkdir(WORK, 0o700)
    for part in ('cache', 'tmp', 'mod', 'gopath', 'stage', 'config', 'telemetry'):
        os.mkdir(WORK + '/' + part, 0o700)
    # Confine both telemetry roots and disable their mode BEFORE any Go launch.
    # HOME/CODEX_HOME and any host telemetry mode are untouched.
    os.mkdir(WORK + '/config/go', 0o700)
    os.mkdir(WORK + '/config/go/telemetry', 0o700)
    for telemetry_root in (WORK + '/config/go/telemetry', WORK + '/telemetry'):
        fd = os.open(telemetry_root + '/mode', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as mode:
            mode.write(b'off\n')
            mode.flush()
            os.fsync(mode.fileno())
    os.mkdir(WORK + '/stage/detect', 0o700)
    os.mkdir(WORK + '/stage/detect/dns_exfil', 0o700)
    for name in ('score.go', 'exfil_test.go'):
        shutil.copyfile(ROOT + '/detect/dns_exfil/' + name, WORK + '/stage/detect/dns_exfil/' + name)
    shutil.copyfile(PREP + '/isolated.go.mod', WORK + '/stage/go.mod')
    frozen_hashes = {item['path']: item['sha256'] for item in freeze['files']}
    for name in ('score.go', 'exfil_test.go'):
        if sha(WORK + '/stage/detect/dns_exfil/' + name) != frozen_hashes['detect/dns_exfil/' + name]:
            raise RuntimeError('staged source does not match freeze')
    fd = os.open(WORK + '/child.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    # Adopt only children orphaned by OUR owned Go process; never scan host PIDs.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER, process-local
        raise RuntimeError('cannot establish owned-descendant reaping')
    env = os.environ.copy()  # HOME/CODEX_HOME/umask are neither reset nor printed.
    env.update({'GOROOT': SDK, 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GONOSUMDB': '*', 'GONOPROXY': 'none', 'GOPRIVATE': '', 'GOENV': 'off', 'GOTELEMETRY': 'off', 'XDG_CONFIG_HOME': WORK + '/config', 'TEST_TELEMETRY_DIR': WORK + '/telemetry', 'GOWORK': 'off', 'CGO_ENABLED': '0', 'GOMAXPROCS': '1', 'GOFLAGS': '', 'GOEXPERIMENT': '', 'GOOS': 'linux', 'GOARCH': 'amd64', 'GOCACHE': WORK + '/cache', 'GOTMPDIR': WORK + '/tmp', 'TMPDIR': WORK + '/tmp', 'GOPATH': WORK + '/gopath', 'GOMODCACHE': WORK + '/mod'})
    wrapper = '/usr/bin/python3 -I -S ' + PREP + '/limit_child.py '
    cmd = [SDK + '/bin/go', 'test', '-mod=readonly', '-p=1', '-vet=off', '-count=1', '-parallel=1', '-timeout=20s', '-v', '-toolexec=' + wrapper + 'tool', '-exec=' + wrapper + 'test', '-run=^TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions$', './detect/dns_exfil']
    child = subprocess.Popen(cmd, cwd=WORK + '/stage', env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=go_limits)
    child_group_absent = False
    leader_owned = True
    write('launch.json', (json.dumps({'owned_go_pid_and_pgid': child.pid, 'command': cmd}) + '\n').encode())
    os.set_blocking(child.stdout.fileno(), False)
    poller = selectors.DefaultSelector()
    poller.register(child.stdout, selectors.EVENT_READ)
    eof = False
    next_disk_check = 0
    while not eof or exit_observation is None:
        exit_observation = observe_leader()
        now = time.monotonic()
        if now >= DEADLINE:
            raise TimeoutError('build/test exceeded 80s inclusive preparation')
        if now >= next_disk_check:
            peak_allocated = max(peak_allocated, allocated(WORK))
            if peak_allocated > DISK_STOP:
                raise RuntimeError('owned disk stop threshold exceeded')
            next_disk_check = now + 0.2
        for key, _ in poller.select(0.05):
            data = os.read(key.fd, 8192)
            if not data:
                eof = True
                poller.unregister(child.stdout)
                break
            if len(raw) + len(data) > LOG_LIMIT:
                raw.extend(data[:LOG_LIMIT-len(raw)])
                raise RuntimeError('combined output exceeded 64KiB')
            raw.extend(data)
    returncode = observed_returncode(exit_observation)
    text = raw.decode('utf-8', 'replace')
    expected = 'TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions'
    lines = text.splitlines()
    started = [line[len('=== RUN   '):] for line in lines if line.startswith('=== RUN   ') and '/' not in line[len('=== RUN   '):]]
    failed = [line.split()[2] for line in lines if line.startswith('--- FAIL: ')]
    subfailed = [line.strip().split()[2] for line in lines if line.startswith('    --- FAIL: ')]
    forbidden = ('SKIP', 'panic:', 'fatal error:', '[build failed]', '[no test files]')
    if (returncode == 1 and started == [expected] and failed == [expected]
            and sorted(subfailed) == sorted([expected + '/_dmarc.example.com', expected + '/com'])
            and text.count('R1_QUALIFYING_WINDOW_OK count=31 mean=5') == 2
            and text.count('expected DNS score alert, got nil') == 2
            and not any(marker in text for marker in forbidden)):
        result = 'EXPECTED_BEHAVIORAL_RED'
    else:
        reason = 'missing exact two-subcase R1 behavioral RED evidence; no acceptance'
except Exception as exc:
    reason = type(exc).__name__ + ': ' + str(exc)
finally:
    # Keep finalization bounded too. Absolute t=87 ends process cleanup, t=89
    # hard-exits even during output/fsync; the unchanged outer watchdog is t=90.
    # An incomplete/nonzero caller is never accepted, even if receipt bytes exist.
    signal.alarm(0)
    signal.signal(signal.SIGALRM, lambda signum, frame: os._exit(124))
    remaining = START + 89 - time.monotonic()
    if remaining <= 0:
        os._exit(124)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    cleanup_end = min(START + 87, time.monotonic() + 6)
    if child is not None:
        pgid = child.pid
        try:
            if not leader_owned or leader_reaped:
                raise RuntimeError('no held leader ownership; signals prohibited')
            observe_leader()  # ECHILD changes ownership and aborts before signals.
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            grace_end = min(cleanup_end, time.monotonic() + 1)
            while time.monotonic() < grace_end and observe_leader() is None:
                time.sleep(0.02)
            # Still held and unreaped, including after an ordinary test exit.
            if not leader_owned or leader_reaped:
                raise RuntimeError('held leader ownership lost before KILL')
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # NO SIGNALS, including signal-zero probes, after this point.
            held_exit = observe_leader()
            while held_exit is None and time.monotonic() < cleanup_end:
                time.sleep(0.02)
                held_exit = observe_leader()
            if held_exit is None:
                raise RuntimeError('leader exit not observed before cleanup deadline')
            pid, wait_status = os.waitpid(pgid, os.WNOHANG)
            if pid != pgid:
                raise RuntimeError('known held leader was not reaped')
            leader_reaped = True
            leader_owned = False
            child.returncode = os.waitstatus_to_exitcode(wait_status)
            if returncode is None:
                returncode = child.returncode
            child_group_absent = reap_after_signals(pgid, cleanup_end)
        except Exception as exc:
            cleanup_error = type(exc).__name__ + ': ' + str(exc)
    cleanup_ok = child_group_absent and (child is None or leader_reaped)
    if not cleanup_ok:
        result = 'INFRASTRUCTURE_FAILURE'
        reason = 'owned process cleanup unproved; retain work charged; stop'
    if owned_run:
        # Retain ALL exact new work, on success and failure. No rmtree or final
        # tree walk. Last observed allocation is not a hard bound/final size.
        write('output.txt', bytes(raw))
        receipt = {'result': result, 'reason': reason, 'cleanup_error': cleanup_error, 'go_returncode': returncode, 'elapsed_seconds': time.monotonic()-START, 'combined_output_bytes': len(raw), 'peak_observed_work_allocated_bytes': peak_allocated, 'leader_reaped_after_all_signals': leader_reaped, 'owned_group_absent': child_group_absent, 'absence_basis': 'ECHILD only under exact new-session + local subreaper + frozen no-setpgid/setsid child chain; no generalized host/quiescence authority; unknown adoption/group escape is STOP', 'process_cleanup_ok': cleanup_ok, 'work_removed': False, 'work_retained_charged': True, 'retained_work_path': WORK, 'retained_accounting': 'full reserved work allowance until separately bounded inventory', 'base_head_root_attested': 'e2fbb97f05f4d062e7a310f23a3907b4be127cc6', 'scope': 'DNS scoring only; no full Task10 acceptance', 'output_sha256': hashlib.sha256(raw).hexdigest()}
        write('receipt.json', (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode())
        # write() fsyncs file and directory. Native exit0 AND this completion
        # output are required; partial receipt or exit124 is incomplete/UNKNOWN.
        print(json.dumps(receipt, sort_keys=True), flush=True)
    else:
        print(json.dumps({'result': result, 'reason': reason, 'no_run_directory_created': True}), flush=True)
    sys.exit(0 if result == 'EXPECTED_BEHAVIORAL_RED' and cleanup_ok else 1)
