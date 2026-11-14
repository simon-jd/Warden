"""Fixed controller observations/receipts. Actual use requires separate admission."""
import time
ENTRY = time.monotonic()
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import types

ROOT = Path('/home/postedism/Desktop/Warden')
PUBLIC = 'docs/evidence/task-6'
PREFIX = 'controller-cache-continuation-v1-20261025-'
LIMIT = 65536
LOG_LIMIT = 1048576
SOURCE_NAMES_SHA = '214713166a6c684864818a69c64e449e70eef6c3ff04c08b97a360b60fec1383'
POLICY = {
    'capture': {'wall_seconds': 90, 'cutoffs': [80, 90], 'cpu_seconds': 75,
                'address_bytes': 536870912, 'file_bytes': 33554432},
    'continue': {'wall_seconds': 600, 'cutoffs': [580, 585, 590, 600], 'cpu_seconds': 60,
                 'address_bytes': 268435456, 'file_bytes': 1048576},
    'observe': {'wall_seconds': 180, 'cpu_seconds': 60, 'address_bytes': 268435456,
                'file_bytes': 1048576},
}
COMMAND = {
    'capture': ['python3', '-B', 'scripts/identity_cache_capture.py'],
    'continue': ['python3', '-B', 'scripts/identity_cache_maintenance.py'],
}
CHILD = ['python3', '-B', 'scripts/identity_cache_continue.py']
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
HEX = re.compile('[0-9a-f]{64}')
MODULES = ('runtime_lab_paths', 'runtime_lab_docker', 'azure_guard', 'firecracker_recovery_init',
           'firecracker_recovery', 'identity_cache', 'identity_cache_continue')
OUTPUTS = {f'{s}-{n}.json' for s in ('capture', 'continue')
           for n in ('preprobe', 'launch', 'receipt', 'postflight')}
OUTPUTS |= {'capture-summary.json', 'continue-pending.json'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_key')
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))


def schema(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'fixed_schema')


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum, 'exact_integer')
    return value


def digest(value):
    require(type(value) is str and HEX.fullmatch(value), 'sha256_required')
    return value


def meta(info):
    return [getattr(info, 'st_' + n) for n in
            ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns', 'blocks')]


def directory(path):
    # Bootstrap before importing even the shared trust helper. Same ancestor policy.
    require(path.is_absolute() and str(path) == os.path.normpath(path), 'absolute_path')
    fd = os.open('/', DIR_FLAGS)
    try:
        for name in path.parts[1:]:
            child = os.open(name, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in (0, 1000) and
                    (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                    'untrusted_ancestor')
        return fd
    except BaseException:
        os.close(fd)
        raise


class Record:
    def __init__(self, path, data, info, limit):
        self.path, self.data, self.info, self.limit = path, data, info, limit

    def recheck(self):
        other = read(self.path, self.limit)
        require(other.data == self.data and meta(other.info) == meta(self.info), 'record_changed')

    def proof(self):
        return {'sha256': sha(self.data), 'bytes': len(self.data), 'metadata': meta(self.info)}


def read(path, limit=LIMIT):
    parent = directory(path.parent)
    fd = None
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 1000 and
                info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o600, 0o644, 0o700, 0o755) and
                info.st_dev == os.fstat(parent).st_dev and 0 < info.st_size <= limit, 'trusted_record')
        fd = os.open(path.name, FILE_FLAGS, dir_fd=parent)
        require(meta(os.fstat(fd)) == meta(info), 'record_open_changed')
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        data = b''.join(chunks)
        require(len(data) == info.st_size and len(data) <= limit and meta(os.fstat(fd)) == meta(info) and
                meta(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == meta(info), 'record_read_changed')
        return Record(path, data, info, limit)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise FileExistsError('existing_state_no_retry')


def durable(suffix, value):
    require(suffix in OUTPUTS, 'fixed_public_output')
    path, data = ROOT / PUBLIC / (PREFIX + suffix), raw(value)
    require(0 < len(data) <= LIMIT, 'public_record_bound')
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        created = os.fstat(fd)
        require(stat.S_ISREG(created.st_mode) and created.st_uid == created.st_gid == 1000 and
                created.st_nlink == 1 and stat.S_IMODE(created.st_mode) == 0o600, 'created_record')
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            require(count > 0, 'write_progress')
            offset += count
        os.fsync(fd)
        current = os.fstat(fd)
        require(meta(current)[:6] == meta(created)[:6] and current.st_size == len(data) and
                meta(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == meta(current), 'record_before_parent')
        os.fsync(parent)
        record = read(path)
        require(meta(os.fstat(fd)) == meta(current) == meta(record.info) and record.data == data,
                'durable_readback_changed')
        return record
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


class Deadline:
    def __init__(self, start, seconds):
        self.start, self.end = start, start + seconds
        self.owner = None

    def now(self):
        return time.monotonic()

    def check(self, cutoff=None):
        require(self.now() < (self.end if cutoff is None else min(self.end, cutoff)), 'deadline_exhausted')

    def arm(self, cutoff=None):
        self.check(cutoff)
        signal.setitimer(signal.ITIMER_REAL, (self.end if cutoff is None else min(self.end, cutoff)) - self.now())

    def expired(self, signum, frame):
        # No wait, postflight or late success writes. Popen pending can be unknown.
        if self.owner is not None:
            try:
                self.owner.signal(signal.SIGKILL)
            except BaseException:
                pass
        os._exit(124)

    def install(self):
        signal.signal(signal.SIGALRM, self.expired)
        signal.signal(signal.SIGTERM, self.expired)
        signal.signal(signal.SIGINT, self.expired)
        self.arm()

    def finish(self):
        self.check()
        signal.setitimer(signal.ITIMER_REAL, 0)


def limits(policy):
    os.umask(0o077)
    require(os.getuid() == os.geteuid() == os.getgid() == 1000, 'ordinary_uid_gid')
    for key, kind in (('cpu_seconds', resource.RLIMIT_CPU), ('address_bytes', resource.RLIMIT_AS),
                      ('file_bytes', resource.RLIMIT_FSIZE)):
        value = policy[key]
        resource.setrlimit(kind, (value, value))


def child_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (540, 540))
    resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))


class UnknownChild(RuntimeError):
    pass


class OwnedProcess:
    """One Popen, never a rediscovered PID. Unknown ownership/terminal is sticky."""
    def __init__(self, deadline):
        self.deadline, self.proc, self.spawn_pending = deadline, None, False
        self.deadline.owner = self
        self.eof, self.count, self.overflow = False, 0, False
        self.hash = hashlib.sha256()

    def signal(self, sig):
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, sig)
            except ProcessLookupError:
                pass  # Still require poll/wait; a sent/missed signal is not terminal proof.

    def chunk(self, timeout):
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            return None
        try:
            return os.read(self.proc.stdout.fileno(), 65536)
        except BlockingIOError:
            return None

    def run(self, command, cutoffs, sink, preexec=None):
        run_end, term_end, kill_end = cutoffs
        self.deadline.check(run_end)
        require(self.proc is None and not self.spawn_pending, 'one_owned_launch')
        self.spawn_pending = True
        try:
            self.proc = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, close_fds=True, start_new_session=True,
                                         env=ENV, preexec_fn=preexec)
        except BaseException as exc:
            raise UnknownChild('spawn_outcome_unknown') from exc
        self.spawn_pending = False
        terminated = killed = False
        last_heartbeat = self.deadline.now()
        try:
            os.set_blocking(self.proc.stdout.fileno(), False)
            while True:
                now = self.deadline.now()
                self.deadline.check()
                code = self.proc.poll()
                if code is not None and self.eof:
                    return {'terminal': True, 'exit_code': code, 'timed_out': terminated,
                            'overflow': self.overflow, 'log_bytes': self.count, 'log_sha256': self.hash.hexdigest()}
                if code is None and now >= run_end and not terminated:
                    self.signal(signal.SIGTERM)
                    terminated = True
                if code is None and now >= term_end and not killed:
                    self.signal(signal.SIGKILL)
                    killed = True
                if now >= kill_end:
                    self.signal(signal.SIGKILL)
                    raise UnknownChild('terminal_or_pipe_drain_unknown')
                if now - last_heartbeat >= 30:
                    print(raw({'phase': 'owned-child', 'elapsed_seconds': round(now - self.deadline.start, 3)}).decode(),
                          end='', flush=True)
                    last_heartbeat = now
                chunk = None if self.eof else self.chunk(min(0.25, max(0, kill_end - now)))
                if chunk == b'':
                    self.eof = True
                elif chunk:
                    accepted = chunk[:max(0, LOG_LIMIT - self.count)]
                    if accepted:
                        sink(accepted)
                        self.count += len(accepted)
                        self.hash.update(accepted)
                    if len(accepted) != len(chunk):
                        self.overflow = True
                        run_end = min(run_end, now)
                        term_end = min(term_end, now + 5)
                        kill_end = min(kill_end, now + 10)
                elif self.eof and code is None:
                    time.sleep(min(0.05, max(0, kill_end - now)))
        except BaseException:
            self.signal(signal.SIGKILL)
            raise
        finally:
            # Keep Popen reachable via deadline.owner even on error/unknown.
            if self.proc.poll() is not None:
                self.proc.stdout.close()


class ReadOnlyDocker:
    def __init__(self, deadline, recovery):
        self.deadline, self.recovery = deadline, recovery
        self.ids = {'image': set(), 'container': set()}
        self.owner = None

    def validate(self, args):
        require(type(args) is list and args and args[0] in self.ids, 'fixed_docker_kind')
        kind = args[0]
        if len(args) == 3 and args[1] == 'inspect':
            require(args[2] in self.ids[kind], 'inspect_requires_scoped_id')
            return kind, False
        lists = []
        for labels in ({'project': 'warden'}, self.recovery.OLD_LABELS):
            expected = [kind, 'ls', '--quiet', '--no-trunc', '--all']
            for key, value in labels.items():
                expected += ['--filter', f'label={key}={value}']
            lists.append(expected)
        require(args in lists, 'readonly_project_scoped_cli')
        return kind, True

    def __call__(self, args, timeout=30):
        kind, listing = self.validate(args)
        require(type(timeout) is int and 0 < timeout <= 30, 'fixed_cli_timeout')
        if self.owner is not None:
            require(self.owner.proc is not None and self.owner.proc.poll() is not None and
                    not self.owner.spawn_pending, 'previous_cli_unknown')
        now = self.deadline.now()
        end = min(now + timeout, self.deadline.end - 10)
        require(end - now > 10, 'cli_budget_insufficient')
        self.owner = OwnedProcess(self.deadline)
        chunks = []
        result = self.owner.run(['/usr/bin/docker', '--host=unix:///var/run/docker.sock', *args],
                                [end - 10, end - 5, end], chunks.append)
        require(result['terminal'] and result['exit_code'] == 0 and not result['timed_out'] and
                not result['overflow'], 'readonly_cli_failed')
        output = b''.join(chunks).decode('utf-8')
        if listing:
            ids = output.split()
            pattern = 'sha256:[0-9a-f]{64}' if kind == 'image' else '[0-9a-f]{64}'
            require(len(ids) <= 1000 and all(re.fullmatch(pattern, x) for x in ids), 'scoped_ids_bound')
            self.ids[kind].update(ids)
        return output


@contextlib.contextmanager
def docker_adapter(recovery, deadline):
    previous = recovery.docker
    adapter = ReadOnlyDocker(deadline, recovery)
    recovery.docker = adapter  # Sole permitted narrowing: no lock/trust/state override.
    try:
        yield adapter
    finally:
        recovery.docker = previous


def clock_identity():
    values = []
    for name, pattern in (('/etc/machine-id', '[0-9a-f]{32}'),
                          ('/proc/sys/kernel/random/boot_id', '[0-9a-f-]{36}')):
        fd = os.open(name, FILE_FLAGS)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'clock_identity_owner')
            value = os.read(fd, 65).decode('ascii').strip()
            require(re.fullmatch(pattern, value), 'clock_identity_format')
            values.append(value)
        finally:
            os.close(fd)
    return {'machine_id': values[0], 'boot_id': values[1]}


def sibling_metadata(path):
    digestor = hashlib.sha256()
    count = allocated = 0
    def add(name, info):
        nonlocal count, allocated
        count += 1
        allocated += info.st_blocks * 512
        digestor.update(raw([name, meta(info)]))
    add('.', path.lstat())
    for parent, dirs, files in os.walk(path, followlinks=False,
                                       onerror=lambda exc: (_ for _ in ()).throw(exc)):
        dirs.sort()
        for name in sorted(dirs + files):
            item = Path(parent) / name
            add(str(item.relative_to(path)), item.lstat())
    return {'entries': count, 'allocated_metadata_bytes_including_dirs': allocated,
            'sha256': digestor.hexdigest(), 'root_metadata': meta(path.lstat())}


class Controller:
    def __init__(self, stage, deadline):
        require(stage in COMMAND, 'fixed_stage')
        self.stage, self.deadline = stage, deadline
        self.records, self.sources = [], {}
        self.admission_record = self.public(stage + '-admission.json')
        self.admission = strict(self.admission_record.data)
        value = self.admission
        schema(value, ('version', 'stage', 'source_commit', 'source_hashes', 'review_sha256', 'ruling_sha256',
                       'writer_basis', 'clock_identity', 'policy', 'outer_invoker_sha256'))
        require(type(value['version']) is int and value['version'] == 1 and value['stage'] == stage and
                type(value['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', value['source_commit']), 'admission_identity')
        for field in ('review_sha256', 'ruling_sha256', 'outer_invoker_sha256'):
            digest(value[field])
        require(type(value['writer_basis']) is str and 0 < len(value['writer_basis'].encode()) <= 4096 and
                raw(value['policy']) == raw(POLICY[stage]), 'admission_policy')
        schema(value['clock_identity'], ('machine_id', 'boot_id'))
        require(type(value['source_hashes']) is dict and len(value['source_hashes']) == 149 and
                sha(('\n'.join(sorted(value['source_hashes'])) + '\n').encode()) == SOURCE_NAMES_SHA, 'canonical_source_names')
        for name, expected in value['source_hashes'].items():
            digest(expected)
            source = read(ROOT / name, 2000000)
            require(sha(source.data) == expected, 'source_hash_mismatch')
            self.sources[name] = source
        # Controller's future exact invoker is separately reviewed, not implemented here.
        invoker = read(ROOT / PUBLIC / 'controller-cache-continuation-outer-invoker-20261025.py', LIMIT)
        require(sha(invoker.data) == value['outer_invoker_sha256'], 'outer_invoker_hash')
        self.records.append(invoker)
        self.modules = {}

    def public(self, suffix):
        record = read(ROOT / PUBLIC / (PREFIX + suffix))
        self.records.append(record)
        return record

    def load_modules(self):
        if self.modules:
            return
        # Execute verified source bytes, not possibly stale/unchecked .pyc files.
        for name in MODULES:
            record = self.sources['scripts/' + name + '.py']
            record.recheck()
            module = types.ModuleType(name)
            module.__file__ = str(record.path)
            sys.modules[name] = module
            exec(compile(record.data, str(record.path), 'exec'), module.__dict__)
            self.modules[name] = module

    def recheck(self):
        self.deadline.check()
        for record in (*self.records, *self.sources.values()):
            record.recheck()

    def clock(self):
        identity = clock_identity()
        require(raw(identity) == raw(self.admission['clock_identity']), 'host_boot_mismatch')
        return identity

    def preparation(self):
        pre_record = self.public(self.stage + '-preprobe.json')
        pre = strict(pre_record.data)
        schema(pre, ('version', 'stage', 'state', 'admission_sha256', 'source_commit', 'source_hashes',
                     'clock_identity', 'observed_monotonic_ns', 'utc', 'facts', 'Q_released'))
        require(type(pre['version']) is int and pre['version'] == 1 and pre['state'] == 'preprobe-complete' and
                pre['stage'] == self.stage and pre['Q_released'] is False and
                pre['admission_sha256'] == sha(self.admission_record.data) and
                pre['source_commit'] == self.admission['source_commit'] and
                raw(pre['source_hashes']) == raw(self.admission['source_hashes']), 'preprobe_binding')
        require(raw(pre['clock_identity']) == raw(self.clock()), 'preprobe_boot')
        age = int(self.deadline.now() * 1000000000) - integer(pre['observed_monotonic_ns'])
        require(0 <= age <= 60000000000, 'preprobe_age')
        for suffix in ('launch.json', 'receipt.json', 'postflight.json'):
            absent(ROOT / PUBLIC / (PREFIX + self.stage + '-' + suffix))
        if self.stage == 'capture':
            absent(ROOT / PUBLIC / (PREFIX + 'capture-summary.json'))
        else:
            absent(ROOT / PUBLIC / (PREFIX + 'continue-pending.json'))
            absent(ROOT / PUBLIC / (PREFIX + 'continue.log'))
        self.recheck()
        return pre_record, pre

    def launch(self, pre_record):
        self.recheck()
        self.fresh(pre_record)
        record = durable(self.stage + '-launch.json', {
            'version': 1, 'stage': self.stage, 'state': 'intended-terminal-unknown',
            'command': COMMAND[self.stage], 'admission': self.admission_record.proof(),
            'preprobe': pre_record.proof(), 'source_commit': self.admission['source_commit'],
            'source_hashes': self.admission['source_hashes'], 'writer_basis': self.admission['writer_basis'],
            'clock_identity': self.admission['clock_identity'], 'policy': POLICY[self.stage],
            'entry_monotonic_ns': int(self.deadline.start * 1000000000),
            'original_exit_code': -15, 'original_timeout_seconds': 180, 'Q_released': False})
        self.records.append(record)
        self.recheck()
        self.fresh(pre_record)
        return record

    def fresh(self, pre_record):
        pre_record.recheck()
        pre = strict(pre_record.data)
        require(raw(pre['clock_identity']) == raw(self.clock()), 'preprobe_boot')
        age = int(self.deadline.now() * 1000000000) - integer(pre['observed_monotonic_ns'])
        require(0 <= age <= 60000000000, 'preprobe_age')

    def receipt(self, launch, outcome, summary=None):
        self.recheck()
        value = {'version': 1, 'stage': self.stage, 'launch_sha256': sha(launch.data),
                 'source_commit': self.admission['source_commit'], 'source_hashes': self.admission['source_hashes'],
                 'outcome': outcome, 'summary': summary, 'Q_released': False,
                 'postflight_pending': True, 'ended_monotonic_ns': int(self.deadline.now() * 1000000000)}
        record = durable(self.stage + '-receipt.json', value)
        self.deadline.check()
        return record

    def outer_gate(self):
        # Only public sources/records are read before independent terminal proof.
        launch = self.public(self.stage + '-launch.json')
        receipt = self.public(self.stage + '-receipt.json')
        outer = strict(self.public(self.stage + '-outer-result.json').data)
        value = strict(receipt.data)
        schema(outer, ('version', 'stage', 'producer', 'terminal', 'exit_code', 'child_terminal',
                       'child_exit_code', 'launch_sha256', 'receipt_sha256', 'source_commit',
                       'outer_invoker_sha256', 'command', 'clock_identity',
                       'started_monotonic_ns', 'ended_monotonic_ns'))
        require(type(outer['version']) is int and outer['version'] == 1 and
                outer['stage'] == self.stage and outer['producer'] == 'controller-tool-result' and
                outer['terminal'] is True and type(outer['exit_code']) is int and
                outer['command'] == COMMAND[self.stage] and
                outer['launch_sha256'] == sha(launch.data) and outer['receipt_sha256'] == sha(receipt.data) and
                outer['source_commit'] == self.admission['source_commit'] and
                outer['outer_invoker_sha256'] == self.admission['outer_invoker_sha256'] and
                raw(outer['clock_identity']) == raw(self.admission['clock_identity']), 'outer_terminal_binding')
        elapsed = integer(outer['ended_monotonic_ns']) - integer(outer['started_monotonic_ns'])
        require(0 <= elapsed <= POLICY[self.stage]['wall_seconds'] * 1000000000, 'outer_wall_bound')
        schema(value, ('version', 'stage', 'launch_sha256', 'source_commit', 'source_hashes', 'outcome',
                       'summary', 'Q_released', 'postflight_pending', 'ended_monotonic_ns'))
        require(type(value['version']) is int and value['version'] == 1 and value['stage'] == self.stage and
                value['launch_sha256'] == sha(launch.data) and value['source_commit'] == self.admission['source_commit'] and
                raw(value['source_hashes']) == raw(self.admission['source_hashes']) and value['Q_released'] is False,
                'receipt_binding')
        result = value['outcome']
        expected = ('terminal', 'exit_code', 'timed_out', 'overflow')
        schema(result, expected if self.stage == 'capture' else (*expected, 'log_bytes', 'log_sha256'))
        require(result.get('terminal') is True and type(result.get('exit_code')) is int and
                type(result.get('timed_out')) is bool and type(result.get('overflow')) is bool,
                'operation_terminal_unknown')
        if self.stage == 'continue':
            require(integer(result['log_bytes']) <= LOG_LIMIT, 'log_bound')
            digest(result['log_sha256'])
            require(type(outer['child_exit_code']) is int, 'exact_child_exit')
        require(outer['child_terminal'] is True and outer['child_exit_code'] ==
                (None if self.stage == 'capture' else result['exit_code']), 'outer_child_terminal')
        success = result['exit_code'] == 0 and result.get('timed_out') is False and result.get('overflow') is False
        require(outer['exit_code'] == (0 if success else 1), 'outer_receipt_exit')
        require(integer(value['ended_monotonic_ns']) <= outer['ended_monotonic_ns'], 'outer_precedes_receipt')
        launch_value = strict(launch.data)
        require(outer['started_monotonic_ns'] <= integer(launch_value['entry_monotonic_ns']), 'outer_start_after_entry')
        return success, value


def observations(control):
    recovery = control.modules['firecracker_recovery']
    with docker_adapter(recovery, control.deadline):
        scene = recovery.Scene(cleanup=True)
        try:
            data = recovery.load(recovery.WORK / 'inspect' / 'result.json')
            require(sha(data) == '55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d', 'original_inventory')
            require(recovery.file_sha(recovery.MODULE) == '72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2', 'original_helper')
            inventory = recovery.helper.validate_inventory(data, recovery.file_sha(recovery.MODULE))
            states = {}
            for mode in ('inspect', 'restore-traversal'):
                state = recovery.state_read(mode, '0c7dedbf38499ee991f879e93e43b9f5df9bb7f4')
                require(state['settled'] is True and state['success'] is True and state['step'] == 'complete' and
                        state['released'] is False, 'old_phase_unsettled')
                recovery.helper_absent(state['cid'])
                states[mode] = sha(raw(state))
            original = recovery.full_postflight(scene, 0, inventory)
            charges, images = recovery.current_charges(), recovery.image_charge()
            integer(charges, 5000000000)
            integer(images)
            guard = original['ordinary_full_guard']
            require(str(guard['additional_bytes']) == str(charges + images) and
                    int(guard['service_memory_bytes']) == 1000000000 and
                    int(guard['project_allocated_bytes']) + charges + images + 96000000 <= 12000000000,
                    'maintenance_resource_guard')
            require(original['released'] is False and original['reserved_bytes'] == 5000000000 and
                    original['never_reopen'] is True and original['protected_baseline_match'] is True,
                    'original_scene_Q')
            ids = recovery.scoped_ids('image', {'project': 'warden'}, recovery.docker)
            return {'ordinary': original, 'charges': charges, 'image_charge': images, 'owned_images': sorted(ids),
                    'phase_state_hashes': states, 'siblings': {n: sibling_metadata(ROOT / '.cache' / n)
                     for n in ('firecracker-code', 'go-mod', 'warden-lab')}}
        finally:
            scene.close()


def summary_check(value, product):
    schema(value, ('version', 'state', 'binding', 'writer_basis', 'captured_at', 'checkpoint_sha256', 'checkpoint_bytes'))
    require(type(value['version']) is int and value['version'] == 1 and
            value['state'] == 'checkpoint-captured-not-approved', 'capture_summary_state')
    digest(value['checkpoint_sha256'])
    require(0 < integer(value['checkpoint_bytes']) <= product.CHECKPOINT_LIMIT, 'checkpoint_size')
    product._basis(value['writer_basis'])
    product._timestamp(value['captured_at'])


def private_postflight(control, success, receipt):
    product, old = control.modules['identity_cache_continue'], control.modules['identity_cache']
    fds = {}
    try:
        for key, name in (('root', ''), ('lab', '.cache/warden-lab'), ('cache', '.cache'),
                          ('public', PUBLIC), ('scripts', 'scripts')):
            fds[key] = product.trusted_directory(str(ROOT / name), 1000)
        if not success:
            # Known terminal failure audit only. No relaxed scanner or continuation.
            audit = {}
            for name in (product.CHECKPOINT, product.PREPARED, product.READY, product.RESULT):
                try:
                    audit[name] = meta(os.stat(name, dir_fd=fds['cache'], follow_symlinks=False))
                except FileNotFoundError:
                    audit[name] = None
            try:
                plan = old.CachePlan(fds['cache'], 1000)
                try:
                    plan._recheck_all()
                    scan = 'accepted-read-only'
                finally:
                    plan.close()
            except (ValueError, OSError):
                scan = 'refused-retain-no-retry'
            return {'state': 'incomplete', 'journal_metadata': audit, 'strict_scan': scan}
        original = product._read_original(fds['cache'])
        checkpoint = product._read_private(fds['cache'], product.CHECKPOINT, product.CHECKPOINT_LIMIT)
        checkpoint_value = product._json(checkpoint.data)
        product._schema(checkpoint_value, ('version', 'state', 'binding', 'writer_basis', 'captured_at', 'anchors', 'entries'))
        product._checkpoint_rows(checkpoint_value['entries'])
        binding = product._binding(fds)
        require(type(checkpoint_value['version']) is int and checkpoint_value['version'] == 1 and
                checkpoint_value['state'] == 'captured' and raw(checkpoint_value['binding']) == raw(binding), 'checkpoint_binding')
        authorities = [original, checkpoint]
        if control.stage == 'capture':
            summary_record = control.public('capture-summary.json')
            summary = strict(summary_record.data)
            summary_check(summary, product)
            require(receipt['summary'] == summary_record.proof() and summary['checkpoint_sha256'] == sha(checkpoint.data) and
                    summary['checkpoint_bytes'] == len(checkpoint.data) and
                    all(raw(summary[k]) == raw(checkpoint_value[k]) for k in ('binding', 'writer_basis', 'captured_at')),
                    'capture_summary_checkpoint')
            plan = product._CheckpointPlan(fds['cache'], 1000)
            try:
                require(product._validate_original(plan, original) == checkpoint_value['entries'], 'capture_live_checkpoint')
            finally:
                plan.close()
        else:
            # The real pin is loaded from verified controller source, never from a fixture default.
            maintenance = control.controller_module('identity_cache_maintenance')
            approval_record = product._read(fds['public'], product.APPROVAL_NAME, LIMIT)
            require(sha(approval_record.data) == maintenance.EXPECTED_APPROVAL_SHA256 and
                    len(approval_record.data) == maintenance.EXPECTED_APPROVAL_BYTES, 'approval_pin')
            approval = product._approval(approval_record, binding)
            require(approval['checkpoint_sha256'] == sha(checkpoint.data) and
                    approval['checkpoint_bytes'] == len(checkpoint.data), 'approval_checkpoint')
            authorities.append(approval_record)
            documents = []
            for name, state in ((product.PREPARED, 'prepared-not-completed'), (product.READY, 'ready-not-completed'),
                                 (product.RESULT, 'completed')):
                record = product._read_private(fds['cache'], name, LIMIT)
                value = product._json(record.data)
                keys = ('version', 'operation', 'binding', 'checkpoint_sha256', 'approval_sha256', 'wall_limit_seconds', 'state')
                extra = () if name == product.PREPARED else (('prepared_sha256', 'synced_entries', 'metadata_sha256')
                    if name == product.READY else ('prepared_sha256', 'ready_sha256', 'removed_files',
                    'removed_executable_dirs', 'removed_logical_bytes', 'removed_allocated_bytes',
                    'preserved_bucket_count', 'preserved_metadata_count'))
                schema(value, (*keys, *extra))
                require(type(value) is dict and type(value.get('version')) is int and value['version'] == 1 and
                        value.get('operation') == product.OPERATION and value.get('state') == state and
                        raw(value.get('binding')) == raw(binding) and type(value.get('wall_limit_seconds')) is int and
                        value['wall_limit_seconds'] == 600 and
                        value.get('checkpoint_sha256') == sha(checkpoint.data) and
                        value.get('approval_sha256') == sha(approval_record.data), 'private_completion_binding')
                authorities.append(record)
                documents.append(value)
            prepared, ready, result = documents
            require(ready['prepared_sha256'] == result['prepared_sha256'] == sha(authorities[-3].data) and
                    result['ready_sha256'] == sha(authorities[-2].data) and
                    type(ready['synced_entries']) is int and ready['synced_entries'] == product.COUNTS['entries'], 'private_links')
            digest(ready['metadata_sha256'])
            rows = {r['relative']: r for r in checkpoint_value['entries']}
            plan = old.CachePlan(fds['cache'], 1000)
            try:
                plan._recheck_all()
                require(not plan.files and len(plan.directories) == 257, 'derived_remains')
                for node in plan.directories:
                    name = 'go-build' if node is plan.root else 'go-build/' + node.name
                    before, now = rows[name]['metadata'], product._meta(os.fstat(node.fd))
                    require(now[:4] == before[:4] and stat.S_IMODE(now[4]) == 0o700 and
                            now[5] == (258 if node is plan.root else 2), 'retained_directory')
                for node in plan.preserved:
                    before = rows['go-build/' + node.name]['metadata']
                    now = product._meta(os.stat(node.name, dir_fd=node.parent, follow_symlinks=False))
                    require(now[:4] == before[:4] and stat.S_IMODE(now[4]) == 0o600 and
                            all(now[i] == before[i] for i in (5, 6, 7, 9)), 'retained_metadata')
                removed_files = sum(stat.S_ISREG(r['metadata'][4]) and r['relative'] not in
                                    {'go-build/' + n for n in old.METADATA} for r in rows.values())
                removed_rows = [r for r in rows.values() if stat.S_ISREG(r['metadata'][4]) and
                                r['relative'] not in {'go-build/' + n for n in old.METADATA}]
                require(integer(result['removed_logical_bytes']) == sum(r['metadata'][6] for r in removed_rows) and
                        integer(result['removed_allocated_bytes']) == sum(r['metadata'][9] * 512 for r in removed_rows),
                        'completion_byte_counts')
                require(type(result['removed_files']) is int and result['removed_files'] == removed_files and
                        type(result['removed_executable_dirs']) is int and result['removed_executable_dirs'] ==
                        product.COUNTS['directories'] - 257 and integer(result['preserved_bucket_count']) == 256 and
                        integer(result['preserved_metadata_count']) == len(plan.preserved), 'completion_counts')
            finally:
                plan.close()
        product._verify_authority(fds, binding, checkpoint_value['anchors'], authorities)
        return {'state': 'verified-not-approved' if control.stage == 'capture' else 'completed-postflight',
                'private_record_hashes': {r.name: sha(r.data) for r in authorities}, 'Q_released': False}
    finally:
        for fd in reversed(list(fds.values())):
            os.close(fd)


def _controller_module(self, name):
    require(name == 'identity_cache_maintenance', 'fixed_controller_module')
    record = self.sources['scripts/' + name + '.py']
    record.recheck()
    module = types.ModuleType(name)
    module.__file__ = str(record.path)
    exec(compile(record.data, str(record.path), 'exec'), module.__dict__)
    return module


Controller.controller_module = _controller_module


def run_probe(mode, deadline):
    require(mode in ('capture-preprobe', 'capture-postflight', 'continue-preprobe', 'continue-postflight'), 'fixed_probe')
    stage, phase = mode.split('-')
    control = Controller(stage, deadline)
    success = receipt = None
    if phase == 'postflight':
        success, receipt = control.outer_gate()  # Before clock/private/cache/guard or project imports.
    control.clock()
    control.load_modules()
    recovery = control.modules['firecracker_recovery']
    with recovery.project_lock():
        if phase == 'postflight':
            private = private_postflight(control, success, receipt)
        facts = observations(control)
        control.recheck()
    if phase == 'preprobe':
        value = {'version': 1, 'stage': stage, 'state': 'preprobe-complete',
                 'admission_sha256': sha(control.admission_record.data), 'source_commit': control.admission['source_commit'],
                 'source_hashes': control.admission['source_hashes'], 'clock_identity': control.admission['clock_identity'],
                 'observed_monotonic_ns': int(deadline.now() * 1000000000),
                 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'facts': facts, 'Q_released': False}
    else:
        pre = strict(control.public(stage + '-preprobe.json').data)
        for key in ('siblings', 'charges', 'owned_images', 'phase_state_hashes'):
            require(raw(facts[key]) == raw(pre['facts'][key]), 'preservation_mismatch')
        value = {'version': 1, 'stage': stage, 'state': 'postflight-success' if success else 'incomplete',
                 'facts': facts, 'private_proof': private, 'receipt_sha256': sha(raw(receipt)),
                 'approval_created': False, 'Q_released': False, 'new3GB_admitted': False}
    record = durable(mode + '.json', value)
    deadline.check()
    print(raw({'record': record.proof(), 'state': value['state']}).decode(), end='', flush=True)
    deadline.check()
    return 0 if phase == 'preprobe' or success else 1


def main():
    deadline = Deadline(ENTRY, 180)
    deadline.install()
    limits(POLICY['observe'])
    require(len(sys.argv) == 2, 'one_fixed_probe_mode')
    mode = sys.argv[1]
    require(mode in ('capture-preprobe', 'capture-postflight', 'continue-preprobe', 'continue-postflight'), 'fixed_probe')
    try:
        code = run_probe(mode, deadline)
    except Exception:
        owner = deadline.owner
        if owner is not None:
            owner.signal(signal.SIGKILL)
        if deadline.now() < deadline.end:
            try:
                durable(mode + '.json', {'version': 1, 'state': 'incomplete-or-unknown-retain',
                        'owned_cli_terminal': owner is None or (not owner.spawn_pending and owner.proc is not None and
                                                               owner.proc.poll() is not None), 'Q_released': False})
            except Exception:
                pass  # Existing/partial record is retained, never replaced.
        raise
    deadline.finish()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
