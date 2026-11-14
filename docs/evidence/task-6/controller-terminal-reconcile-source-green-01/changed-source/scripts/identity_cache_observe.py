"""Fixed controller observations/receipts. Actual use requires separate admission."""
if __name__ == '__main__':
    raise SystemExit('use sole identity_cache_control entry')
import time
ENTRY = time.monotonic()
import contextlib
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import struct
import stat
import subprocess
import sys
import types
from urllib.parse import quote

ROOT = Path('/home/postedism/Desktop/Warden')
PUBLIC = 'docs/evidence/task-6'
PREFIX = 'controller-cache-continuation-v1-20261025-'
LIMIT = 65536
LOG_LIMIT = 1048576
METADATA_POLICY = {'wall_seconds': 30, 'cpu_seconds': 5, 'address_bytes': 134217728, 'file_bytes': 1048576}
SOURCE_NAMES_SHA = 'f61b1c1e7613ee67e38bd9f31a6b023f34df39e4d805ef7f6f5bb9907aa7f079'
POLICY = {
    'capture': {'wall_seconds': 90, 'cutoffs': [80, 90], 'cpu_seconds': 75,
                'address_bytes': 536870912, 'file_bytes': 33554432},
    'continue': {'wall_seconds': 600, 'cutoffs': [580, 585, 590, 600], 'cpu_seconds': 60,
                 'address_bytes': 268435456, 'file_bytes': 1048576,
                 'cpu_hard_seconds': 540, 'address_hard_bytes': 536870912},
    'observe': {'wall_seconds': 180, 'cpu_seconds': 60, 'address_bytes': 268435456,
                'file_bytes': 1048576},
}
COMMAND = {
    'capture': ['python3', '-B', 'scripts/identity_cache_control.py', 'capture'],
    'continue': ['python3', '-B', 'scripts/identity_cache_control.py', 'continue'],
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
    require(suffix in OUTPUTS or suffix in {m + tail for m in MODES for tail in ('-deadline.json', '-deadline-accepted.json')} or
            suffix in {m + tail for m in MODES for tail in ('-supervisor.json', '-terminal.json')} or
            suffix in {'capture-outer-result.json', 'continue-outer-result.json'}, 'fixed_public_output')
    path, data = ROOT / PUBLIC / (PREFIX + suffix), raw(value)
    require(0 < len(data) <= (4096 if suffix.endswith(('-deadline.json', '-deadline-accepted.json')) else LIMIT), 'public_record_bound')
    require(not suffix.endswith('-terminal.json') or len(data) <= 16384, 'terminal_marker_bound')
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
        self.guard = None
        self.entry_monotonic_ns = int(start * 1000000000)

    def now(self):
        return time.monotonic()

    def check(self, cutoff=None):
        cutoff = self.end if cutoff is None else min(self.end, cutoff)
        if self.guard is not None:
            self.guard.check(cutoff)
        require(self.now() < (self.end if cutoff is None else min(self.end, cutoff)), 'deadline_exhausted')

    def reached(self, cutoff):
        return self.guard.reached(cutoff) if self.guard is not None else self.now() >= cutoff

    def arm(self, cutoff=None):
        end = self.end if cutoff is None else min(self.end, cutoff)
        self.check(end)
        remaining = self.guard.remaining(end) if self.guard is not None else end - self.now()
        require(remaining > 0, 'deadline_exhausted')
        signal.setitimer(signal.ITIMER_REAL, remaining)

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


def cpu_expired(signum, frame):
    os._exit(124)


def limits(policy):
    require(os.getuid() == os.geteuid() == os.getgid() == 1000, 'ordinary_uid_gid')
    targets = ((resource.RLIMIT_CPU, policy['cpu_seconds'], policy.get('cpu_hard_seconds', policy['cpu_seconds'])),
               (resource.RLIMIT_AS, policy['address_bytes'], policy.get('address_hard_bytes', policy['address_bytes'])),
               (resource.RLIMIT_FSIZE, policy['file_bytes'], policy.get('file_hard_bytes', policy['file_bytes'])))
    # Validate every inherited hard ceiling before changing any limit.
    for kind, soft, hard in targets:
        inherited = resource.getrlimit(kind)[1]
        require(soft <= hard and (inherited == resource.RLIM_INFINITY or hard <= inherited),
                'inherited_hard_ceiling')
    os.umask(0o077)
    signal.signal(signal.SIGXCPU, cpu_expired)
    for kind, soft, hard in targets:
        resource.setrlimit(kind, (soft, hard))


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
        timed_out, terminal_at = False, None
        last_heartbeat = self.deadline.now()
        try:
            os.set_blocking(self.proc.stdout.fileno(), False)
            while True:
                now = self.deadline.now()
                self.deadline.check()
                code = self.proc.poll()
                first_terminal = code is not None and terminal_at is None
                if first_terminal:
                    terminal_at = now
                # A delayed Popen/poll cannot turn an unproven run-phase exit
                # into success. Drain time after a timely known exit is separate.
                if (terminal_at is None or first_terminal) and self.deadline.reached(run_end):
                    timed_out = True
                if self.deadline.reached(kill_end):
                    self.signal(signal.SIGKILL)
                    raise UnknownChild('terminal_or_pipe_drain_unknown')
                if code is not None and self.eof:
                    return {'terminal': True, 'exit_code': code, 'timed_out': timed_out,
                            'overflow': self.overflow, 'log_bytes': self.count, 'log_sha256': self.hash.hexdigest()}
                if code is None and self.deadline.reached(run_end) and not terminated:
                    self.signal(signal.SIGTERM)
                    terminated = True
                if code is None and self.deadline.reached(term_end) and not killed:
                    self.signal(signal.SIGKILL)
                    killed = True
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


# Fixed local material tuple; replacement requires a separately reviewed update.
DOCKER_SOCKET = (29, 4756, 0, 115, stat.S_IFSOCK | 0o660, 1)
HTTP_HEADER_LIMIT = 65536
HTTP_BODY_LIMIT = 1048576


def _docker_anchor(root, parent, expected=None):
    def identity(info):
        return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode
    roots = os.fstat(root), os.fstat(parent)
    paths = os.stat('/', follow_symlinks=False), os.stat('run', dir_fd=root, follow_symlinks=False)
    for held, path in zip(roots, paths):
        require(stat.S_ISDIR(held.st_mode) and held.st_uid == 0 and not held.st_mode & 0o022 and
                identity(held) == identity(path), 'docker_socket_ancestor')
    info = os.stat('docker.sock', dir_fd=parent, follow_symlinks=False)
    require(tuple(meta(info)[:6]) == DOCKER_SOCKET, 'docker_socket_tuple')
    result = (identity(roots[0]), identity(roots[1]), meta(info))
    require(expected is None or result == expected, 'docker_socket_replaced')
    return result


def _docker_headers(header):
    require(len(header) <= HTTP_HEADER_LIMIT and header.endswith(b'\r\n\r\n'), 'http_header_bound')
    lines = header[:-4].split(b'\r\n')
    require(re.fullmatch(rb'HTTP/1\.[01] 200 [ -~]*', lines[0]), 'http_status')
    critical = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        require(separator and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) and
                all(32 <= ch <= 126 for ch in value), 'http_header_syntax')
        name, value = name.lower(), value.strip(b' ')
        require(name not in (b'transfer-encoding', b'trailer', b'upgrade'), 'http_unsupported_framing')
        if name in (b'content-length', b'content-type', b'content-encoding', b'connection'):
            require(name not in critical, 'http_duplicate_critical')
            critical[name] = value
    require(re.fullmatch(rb'application/json(?:; *charset=(?:utf-8|"utf-8"))?',
                         critical.get(b'content-type', b'').lower()), 'http_content_type')
    require(critical.get(b'content-encoding', b'identity').lower() == b'identity' and
            critical.get(b'connection', b'close').lower() == b'close', 'http_encoding_connection')
    length = critical.get(b'content-length')
    if length is not None:
        require(re.fullmatch(rb'[0-9]+', length), 'http_content_length')
        digits = length.lstrip(b'0') or b'0'
        require(len(digits) <= 7, 'http_body_bound')
        length = int(digits)
        require(length <= HTTP_BODY_LIMIT, 'http_body_bound')
    return length


class ReadOnlyDocker:
    """Four fixed GETs; no daemon mutation, CLI fallback, retry or general client."""
    def __init__(self, deadline, recovery):
        self.deadline, self.recovery = deadline, recovery
        self.labels = ({'project': 'warden'}, dict(recovery.OLD_LABELS))
        self.ids = {'image': {}, 'container': {}}
        self.failed, self.sock = False, None

    def _selection(self, args):
        require(type(args) is list and args and args[0] in self.ids, 'fixed_docker_kind')
        kind = args[0]
        if len(args) == 3 and args[1] == 'inspect':
            pattern = 'sha256:[0-9a-f]{64}' if kind == 'image' else '[0-9a-f]{64}'
            require(type(args[2]) is str and re.fullmatch(pattern, args[2]) and
                    any(args[2] in ids for ids in self.ids[kind].values()), 'inspect_requires_scoped_id')
            return kind, False, None
        for labels in self.labels:
            expected = [kind, 'ls', '--quiet', '--no-trunc', '--all']
            for key, value in labels.items():
                expected += ['--filter', f'label={key}={value}']
            if args == expected:
                return kind, True, tuple(sorted(labels.items()))
        raise ValueError('readonly_project_scoped_get')

    def validate(self, args):
        kind, listing, _ = self._selection(args)
        return kind, listing

    def _remaining(self, cutoff):
        self.deadline.check(cutoff)
        require(self.deadline.guard is not None, 'docker_both_clock_guard_required')
        return min(cutoff - self.deadline.now(), self.deadline.guard.remaining(cutoff))

    def _wait(self, cutoff, writing=False):
        remaining = self._remaining(cutoff)
        require(remaining > 0, 'docker_deadline_exhausted')
        ready_r, ready_w, _ = select.select([] if writing else [self.sock],
                                           [self.sock] if writing else [], [], remaining)
        self.deadline.check(cutoff)
        require(bool(ready_w if writing else ready_r), 'docker_io_timeout')

    def _peer(self):
        data = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        require(type(data) is bytes and len(data) == struct.calcsize('3i'), 'docker_peer_shape')
        pid, uid, gid = struct.unpack('3i', data)
        require(pid > 0 and uid == 0 and gid >= 0, 'docker_peer_uid')
        return pid, uid, gid

    def _exchange(self, uri, io_end, close_end):
        root = parent = None
        peer = None
        try:
            self.deadline.check(io_end)
            root = os.open('/', DIR_FLAGS)
            parent = os.open('run', DIR_FLAGS, dir_fd=root)
            anchor = _docker_anchor(root, parent)
            self.deadline.check(io_end)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.setblocking(False)
            self.deadline.check(io_end)
            code = self.sock.connect_ex('/run/docker.sock')
            if code in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
                self._wait(io_end, True)
                code = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            require(code == 0, 'docker_connect_failed')
            self.deadline.check(io_end)
            _docker_anchor(root, parent, anchor)
            peer = self._peer()
            self.deadline.check(io_end)
            request = ('GET ' + uri + ' HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n'
                       'Accept: application/json\r\n\r\n').encode('ascii')
            offset = 0
            while offset < len(request):
                self._wait(io_end, True)
                try:
                    count = self.sock.send(request[offset:])
                except BlockingIOError:
                    continue
                self.deadline.check(io_end)
                require(type(count) is int and 0 < count <= len(request) - offset, 'docker_send_progress')
                offset += count
            data = bytearray()
            boundary = length = None
            while True:
                self._wait(io_end)
                capacity = HTTP_HEADER_LIMIT + HTTP_BODY_LIMIT - len(data)
                try:
                    chunk = self.sock.recv(min(65536, capacity + 1))
                except BlockingIOError:
                    continue
                self.deadline.check(io_end)
                require(type(chunk) is bytes, 'docker_receive_type')
                if not chunk:
                    break  # Only real orderly EOF, not timeout/reset or reaching CL.
                data.extend(chunk)
                require(len(data) <= HTTP_HEADER_LIMIT + HTTP_BODY_LIMIT, 'http_total_bound')
                if boundary is None:
                    found = data.find(b'\r\n\r\n')
                    if found >= 0:
                        boundary = found + 4
                        length = _docker_headers(bytes(data[:boundary]))
                    else:
                        require(len(data) <= HTTP_HEADER_LIMIT, 'http_header_bound')
                if boundary is not None:
                    size = len(data) - boundary
                    require(size <= HTTP_BODY_LIMIT and (length is None or size <= length), 'http_body_bound')
            self.deadline.arm(close_end)
            require(boundary is not None, 'http_incomplete_header')
            body = bytes(data[boundary:])
            require(length is None or len(body) == length, 'http_length_mismatch')
            value = strict(body.decode('utf-8', errors='strict'))
            self.deadline.check(close_end)
            _docker_anchor(root, parent, anchor)
            require(self._peer() == peer, 'docker_peer_changed')
            self.deadline.check(close_end)
            return value
        finally:
            try:
                if self.sock is not None:
                    # Always attempt closing the one held socket, including timeout.
                    # Successful return additionally requires known timely closure.
                    self.sock.close()
                    self.sock = None
                    self.deadline.check(close_end)
            finally:
                try:
                    if parent is not None:
                        os.close(parent)
                finally:
                    if root is not None:
                        os.close(root)

    @staticmethod
    def _labels(value, wanted):
        require(type(value) is dict and all(type(k) is str and type(v) is str for k, v in value.items()) and
                all(value.get(k) == v for k, v in wanted), 'docker_label_scope')

    def __call__(self, args, timeout=30):
        try:
            require(not self.failed and self.sock is None, 'previous_api_failed')
            kind, listing, scope = self._selection(args)
            require(type(timeout) is int and 1 <= timeout <= 30, 'fixed_api_timeout')
            now = self.deadline.now()
            end = min(now + timeout, self.deadline.end - 10)
            require(end - now > 10, 'api_budget_insufficient')
            io_end, close_end = end - 10, end - 5
            self.deadline.arm(io_end)
            if listing:
                filters = json.dumps({'label': [k + '=' + v for k, v in scope]}, separators=(',', ':'), sort_keys=True)
                uri = '/v1.45/' + ('images' if kind == 'image' else 'containers') + '/json?all=1&filters=' + quote(filters, safe='')
            else:
                uri = '/v1.45/' + ('images' if kind == 'image' else 'containers') + '/' + args[2] + '/json'
            value = self._exchange(uri, io_end, close_end)
            self.deadline.check(close_end)
            if listing:
                require(type(value) is list and len(value) <= 1000, 'docker_list_shape')
                pattern = 'sha256:[0-9a-f]{64}' if kind == 'image' else '[0-9a-f]{64}'
                identities = set()
                for item in value:
                    require(type(item) is dict and type(item.get('Id')) is str and
                            re.fullmatch(pattern, item['Id']) and item['Id'] not in identities, 'docker_list_identity')
                    self._labels(item.get('Labels'), scope)
                    identities.add(item['Id'])
                self.deadline.check(close_end)
                self.deadline.arm(end)
                output = ''.join(identity + '\n' for identity in sorted(identities))
            else:
                require(type(value) is dict and value.get('Id') == args[2] and type(value.get('Config')) is dict,
                        'docker_inspect_identity')
                for wanted, identities in self.ids[kind].items():
                    if args[2] in identities:
                        self._labels(value['Config'].get('Labels'), wanted)
                self.deadline.check(close_end)
                self.deadline.arm(end)
                output = raw([value]).decode('utf-8')
            require(len(output.encode('utf-8')) <= HTTP_BODY_LIMIT, 'docker_serialized_bound')
            self.deadline.check(end)
            self.deadline.arm()  # Restore only original observer total, never a fresh allowance.
            self.deadline.check(end)
            if listing:
                self.ids[kind][scope] = identities
            return output
        except BaseException:
            self.failed = True
            self.ids = {'image': {}, 'container': {}}
            raise


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


# Linux ABI candidate; installed-host/tool semantics still require actual admission.
NS = 1000000000
MODES = ('capture-preprobe', 'capture', 'capture-postflight',
         'continue-preprobe', 'continue', 'continue-postflight')
SUPERVISOR_POLICY = {'cpu_seconds': 10, 'cpu_hard_seconds': 540,
                     'address_bytes': 134217728, 'address_hard_bytes': 536870912,
                     'file_bytes': 1048576, 'file_hard_bytes': 33554432}
INVOKER_NAME = 'controller-cache-continuation-outer-invoker-20261025.py'


def mode_policy(mode):
    require(mode in MODES, 'fixed_controller_mode')
    return POLICY[mode if mode in COMMAND else 'observe']


def target_command(mode):
    require(mode in MODES, 'fixed_controller_mode')
    return ['python3', '-B', 'scripts/identity_cache_control.py', mode]


def outer_cutoffs(mode):
    return [80, 85, 90] if mode == 'capture' else [590, 595, 600] if mode == 'continue' else [170, 175, 180]


def target_limits(mode):
    policy = mode_policy(mode)
    # The supervisor retains adequate hard ceilings; only the child soft values change here.
    targets = ((resource.RLIMIT_CPU, policy['cpu_seconds']),
               (resource.RLIMIT_AS, policy['address_bytes']), (resource.RLIMIT_FSIZE, policy['file_bytes']))
    for kind, soft in targets:
        hard = resource.getrlimit(kind)[1]
        require(hard == resource.RLIM_INFINITY or soft <= hard, 'target_inherited_hard_ceiling')
    for kind, soft in targets:
        resource.setrlimit(kind, (soft, resource.getrlimit(kind)[1]))


def own_proc_text(path):
    require(path in ('/proc/self/stat', '/proc/self/timens_offsets'), 'own_proc_only')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'own_proc_regular')
        data = b''
        while len(data) <= 4096:
            chunk = os.read(fd, 4097 - len(data))
            if not chunk:
                break
            data += chunk
        require(0 < len(data) <= 4096, 'own_proc_bound')
        return data.decode('ascii')
    finally:
        os.close(fd)


def parse_birth(text, pid, hz):
    require(type(pid) is int and pid > 0 and type(hz) is int and hz == 100, 'linux_tick_contract')
    head, separator, tail = text.rpartition(') ')
    require(separator and head.startswith(str(pid) + ' ('), 'own_proc_identity')
    fields = tail.split()
    require(len(fields) == 50 and fields[19].isdigit(), 'linux_stat_layout')
    ticks = int(fields[19])
    require(0 < ticks < 10**12, 'birth_ticks_bound')
    # One full tick before truncation/rounding; integer conservative lower bound.
    lower = ticks * NS // hz - (NS + hz - 1) // hz
    require(lower >= 0, 'birth_lower_bound')
    return ticks, lower


class OwnClock:
    def sample(self):
        require(sys.platform == 'linux', 'linux_clock_contract')
        info = time.get_clock_info('monotonic')
        require(info.implementation == 'clock_gettime(CLOCK_MONOTONIC)' and info.monotonic and
                not info.adjustable and 0 < info.resolution <= 0.000001, 'monotonic_clock_contract')
        offsets = own_proc_text('/proc/self/timens_offsets').splitlines()
        require(len(offsets) == 2 and sorted(line.split() for line in offsets) ==
                [['boottime', '0', '0'], ['monotonic', '0', '0']], 'time_namespace_offsets')
        current = os.stat('/proc/self/ns/time')
        children = os.stat('/proc/self/ns/time_for_children')
        namespace = [current.st_dev, current.st_ino]
        require(namespace == [children.st_dev, children.st_ino], 'child_time_namespace')
        pid, hz = os.getpid(), os.sysconf('SC_CLK_TCK')
        ticks, lower = parse_birth(own_proc_text('/proc/self/stat'), pid, hz)
        before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        after = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        sample = {'pid': pid, 'hz': hz, 'birth_ticks': ticks, 'birth_boot_lower_ns': lower,
                  'namespace': namespace, 'monotonic_before_ns': before,
                  'boottime_ns': boot, 'monotonic_after_ns': after}
        validate_sample(sample)
        return sample


def validate_sample(value):
    schema(value, ('pid', 'hz', 'birth_ticks', 'birth_boot_lower_ns', 'namespace',
                   'monotonic_before_ns', 'boottime_ns', 'monotonic_after_ns'))
    for key in ('pid', 'hz', 'birth_ticks', 'birth_boot_lower_ns', 'monotonic_before_ns',
                'boottime_ns', 'monotonic_after_ns'):
        require(0 <= integer(value[key]) < 10**18, 'clock_integer_bound')
    require(value['pid'] > 0 and value['hz'] == 100 and value['birth_ticks'] > 0 and
            value['birth_boot_lower_ns'] == value['birth_ticks'] * NS // 100 - NS // 100,
            'birth_tick_derivation')
    require(type(value['namespace']) is list and len(value['namespace']) == 2 and
            all(type(x) is int and x >= 0 for x in value['namespace']), 'namespace_identity')
    before, boot, after = (value[k] for k in ('monotonic_before_ns', 'boottime_ns', 'monotonic_after_ns'))
    require(0 <= before <= after and after - before <= 100000000 and
            boot >= before and value['birth_boot_lower_ns'] <= boot, 'clock_sample_order')


def timing_from_birth(sample, entry_ns):
    validate_sample(sample)
    integer(entry_ns)
    start = sample['birth_boot_lower_ns'] - (sample['boottime_ns'] - sample['monotonic_before_ns'])
    require(0 <= start <= entry_ns <= sample['monotonic_after_ns'], 'conservative_start_order')
    return {'sample': sample, 'budget_start_monotonic_lower_ns': start,
            'outer_entry_monotonic_ns': entry_ns}


class ClockBudget:
    """Actual monotonic evidence, independent BOOTTIME enforcement at every phase."""
    def __init__(self, timing, seconds, clock=None):
        schema(timing, ('sample', 'budget_start_monotonic_lower_ns', 'outer_entry_monotonic_ns'))
        require(raw(timing) == raw(timing_from_birth(timing['sample'], timing['outer_entry_monotonic_ns'])),
                'timing_derivation')
        self.timing, self.seconds = timing, seconds
        self.clock = OwnClock() if clock is None else clock
        self.last = None
        self.local_identity = None
        self.start_ns = timing['budget_start_monotonic_lower_ns']

    def sample(self):
        current = self.clock.sample()
        validate_sample(current)
        original = self.timing['sample']
        require(current['namespace'] == original['namespace'], 'namespace_changed')
        identity = current['pid'], current['birth_ticks']
        require(self.local_identity is None or self.local_identity == identity, 'own_process_changed')
        self.local_identity = identity
        previous = original if self.last is None else self.last
        require(current['monotonic_before_ns'] >= previous['monotonic_after_ns'] and
                current['boottime_ns'] >= previous['boottime_ns'], 'clock_reversed')
        # Namespace/suspend offset changes reject; overlapping sample uncertainty is
        # still bounded by the independent BOOTTIME cutoff below, never by a fake now().
        lo = original['boottime_ns'] - original['monotonic_after_ns']
        hi = original['boottime_ns'] - original['monotonic_before_ns']
        new_lo = current['boottime_ns'] - current['monotonic_after_ns']
        new_hi = current['boottime_ns'] - current['monotonic_before_ns']
        require(max(lo, new_lo) <= min(hi, new_hi), 'clock_offset_changed')
        self.last = current
        return current

    def remaining_ns(self, cutoff):
        sample = self.sample()
        # Existing operation callbacks express cutoffs in float seconds. Round
        # conservatively down with 1us margin; stored actual clock fields stay ints.
        mono_end = min(self.start_ns + self.seconds * NS, int(cutoff * NS) - 1000)
        boot_end = self.timing['sample']['birth_boot_lower_ns'] + mono_end - self.start_ns
        return min(mono_end - sample['monotonic_after_ns'], boot_end - sample['boottime_ns'])

    def check(self, cutoff):
        require(self.remaining_ns(cutoff) > 0, 'both_clock_deadline_exhausted')

    def reached(self, cutoff):
        return self.remaining_ns(cutoff) <= 0

    def remaining(self, cutoff):
        value = self.remaining_ns(cutoff)
        require(value > 0, 'both_clock_deadline_exhausted')
        return value / NS


def envelope_value(control, mode, timing):
    require(mode in MODES and mode.split('-')[0] == control.stage, 'envelope_mode')
    policy = mode_policy(mode)
    return {'version': 1, 'mode': mode, 'stage': control.stage, 'command': target_command(mode),
            'source_commit': control.admission['source_commit'],
            'source_manifest_sha256': sha(raw(control.admission['source_hashes'])),
            'admission': control.admission_record.proof(), 'invoker': control.invoker_record.proof(),
            'clock_identity': control.admission['clock_identity'], 'timing': timing,
            'wall_seconds': policy['wall_seconds'], 'outer_cutoffs': outer_cutoffs(mode),
            'inner_cutoffs': policy.get('cutoffs', [policy['wall_seconds']]), 'Q_released': False}


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
        require(type(value['source_hashes']) is dict and len(value['source_hashes']) == 150 and
                sha(('\n'.join(sorted(value['source_hashes'])) + '\n').encode()) == SOURCE_NAMES_SHA, 'canonical_source_names')
        for name, expected in value['source_hashes'].items():
            digest(expected)
            source = read(ROOT / name, 2000000)
            require(sha(source.data) == expected, 'source_hash_mismatch')
            self.sources[name] = source
        # Fixed passive invoker bytes are separately reviewed and admission-pinned.
        invoker = read(ROOT / PUBLIC / INVOKER_NAME, LIMIT)
        require(sha(invoker.data) == value['outer_invoker_sha256'], 'outer_invoker_hash')
        self.records.append(invoker)
        self.invoker_record = invoker
        self.envelope_record = None
        self.modules = {}

    def load_invoker(self):
        self.recheck()
        record = self.invoker_record
        record.recheck()
        module = types.ModuleType('warden_fixed_outer_invoker')
        module.__file__ = str(record.path)
        exec(compile(record.data, str(record.path), 'exec'), module.__dict__)
        return module

    def envelope(self, mode):
        record = self.public(mode + '-deadline.json')
        require(len(record.data) <= 4096, 'envelope_bound')
        value = strict(record.data)
        schema(value, ('version', 'mode', 'stage', 'command', 'source_commit', 'source_manifest_sha256',
                       'admission', 'invoker', 'clock_identity', 'timing', 'wall_seconds',
                       'outer_cutoffs', 'inner_cutoffs', 'Q_released'))
        require(raw(value) == raw(envelope_value(self, mode, value['timing'])), 'envelope_binding')
        ClockBudget(value['timing'], value['wall_seconds'])  # Pure schema/derivation; no host read.
        return record, value

    def claim_value(self, mode, envelope, entry_ns):
        return {'version': 1, 'mode': mode, 'stage': self.stage, 'command': target_command(mode),
                'source_commit': self.admission['source_commit'],
                'admission': self.admission_record.proof(), 'invoker': self.invoker_record.proof(),
                'clock_identity': self.admission['clock_identity'], 'envelope': envelope.proof(),
                'target_entry_monotonic_ns': entry_ns}

    def history_deadline(self, mode, envelope_proof, claim_proof):
        envelope, value = self.envelope(mode)
        require(raw(envelope.proof()) == raw(envelope_proof), 'envelope_proof_changed')
        claim = self.public(mode + '-deadline-accepted.json')
        require(len(claim.data) <= 4096 and raw(claim.proof()) == raw(claim_proof), 'claim_proof_changed')
        accepted = strict(claim.data)
        schema(accepted, ('version', 'mode', 'stage', 'command', 'source_commit', 'admission', 'invoker',
                          'clock_identity', 'envelope', 'target_entry_monotonic_ns'))
        entry = integer(accepted['target_entry_monotonic_ns'])
        require(raw(accepted) == raw(self.claim_value(mode, envelope, entry)) and
                value['timing']['outer_entry_monotonic_ns'] <= entry <
                value['timing']['budget_start_monotonic_lower_ns'] + value['wall_seconds'] * NS,
                'claim_binding')
        return value, accepted

    def adopt_envelope(self, mode):
        require(self.envelope_record is None, 'one_target_envelope')
        envelope, value = self.envelope(mode)
        self.clock()
        start = value['timing']['budget_start_monotonic_lower_ns'] / NS
        require(start <= self.deadline.start and start + value['wall_seconds'] <= self.deadline.end and
                value['timing']['outer_entry_monotonic_ns'] <= self.deadline.entry_monotonic_ns,
                'envelope_cannot_extend')
        self.deadline.start, self.deadline.end = start, start + value['wall_seconds']
        self.deadline.guard = ClockBudget(value['timing'], value['wall_seconds'])
        self.deadline.check()
        self.deadline.arm()
        self.recheck()
        if mode == 'continue':
            self.controller_module('identity_cache_maintenance').require_approval_pins()
        self.deadline.check()
        claim = durable(mode + '-deadline-accepted.json',
                        self.claim_value(mode, envelope, self.deadline.entry_monotonic_ns))
        self.envelope_record, self.claim_record, self.envelope_mode = envelope, claim, mode
        self.records.append(claim)
        self.recheck()

    def require_envelope(self, mode):
        require(self.envelope_record is not None and self.envelope_mode == mode, 'target_envelope_required')
        self.history_deadline(mode, self.envelope_record.proof(), self.claim_record.proof())
        self.recheck()

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
        self.deadline.check()

    def controller_module(self, name):
        require(name in ('identity_cache_capture', 'identity_cache_maintenance'), 'fixed_controller_module')
        record = self.sources['scripts/' + name + '.py']
        record.recheck()
        module = types.ModuleType(name)
        module.__file__ = str(record.path)
        exec(compile(record.data, str(record.path), 'exec'), module.__dict__)
        return module

    def clock(self):
        identity = clock_identity()
        require(raw(identity) == raw(self.admission['clock_identity']), 'host_boot_mismatch')
        return identity

    def preparation(self):
        self.require_envelope(self.stage)
        pre_record = self.public(self.stage + '-preprobe.json')
        pre = strict(pre_record.data)
        schema(pre, ('version', 'stage', 'state', 'admission_sha256', 'source_commit', 'source_hashes',
                     'clock_identity', 'observed_monotonic_ns', 'utc', 'facts', 'Q_released',
                     'deadline_envelope', 'deadline_claim'))
        require(type(pre['version']) is int and pre['version'] == 1 and pre['state'] == 'preprobe-complete' and
                pre['stage'] == self.stage and pre['Q_released'] is False and
                pre['admission_sha256'] == sha(self.admission_record.data) and
                pre['source_commit'] == self.admission['source_commit'] and
                raw(pre['source_hashes']) == raw(self.admission['source_hashes']), 'preprobe_binding')
        self.history_deadline(self.stage + '-preprobe', pre['deadline_envelope'], pre['deadline_claim'])
        require(raw(pre['clock_identity']) == raw(self.clock()), 'preprobe_boot')
        age = int(self.deadline.now() * 1000000000) - integer(pre['observed_monotonic_ns'])
        require(0 <= age <= 60000000000, 'preprobe_age')
        self.preprobe_terminal = self.terminal_gate(self.stage + '-preprobe', success_only=True)
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
        self.require_envelope(self.stage)
        self.recheck()
        self.fresh(pre_record)
        terminal = self.terminal_gate(self.stage + '-preprobe', success_only=True)
        record = durable(self.stage + '-launch.json', {
            'version': 1, 'stage': self.stage, 'state': 'intended-terminal-unknown',
            'command': COMMAND[self.stage], 'admission': self.admission_record.proof(),
            'preprobe': pre_record.proof(), 'preprobe_terminal': terminal.proof(),
            'source_commit': self.admission['source_commit'],
            'source_hashes': self.admission['source_hashes'], 'writer_basis': self.admission['writer_basis'],
            'clock_identity': self.admission['clock_identity'], 'policy': POLICY[self.stage],
            'entry_monotonic_ns': self.deadline.entry_monotonic_ns,
            'deadline_envelope': self.envelope_record.proof(), 'deadline_claim': self.claim_record.proof(),
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

    def launch_binding(self, record):
        value = strict(record.data)
        schema(value, ('version', 'stage', 'state', 'command', 'admission', 'preprobe', 'preprobe_terminal',
                       'source_commit', 'source_hashes', 'writer_basis', 'clock_identity', 'policy',
                       'entry_monotonic_ns', 'original_exit_code', 'original_timeout_seconds', 'Q_released',
                       'deadline_envelope', 'deadline_claim'))
        require(type(value['version']) is int and value['version'] == 1 and
                value['stage'] == self.stage and value['state'] == 'intended-terminal-unknown' and
                raw(value['command']) == raw(COMMAND[self.stage]) and value['Q_released'] is False and
                type(value['original_exit_code']) is int and value['original_exit_code'] == -15 and
                type(value['original_timeout_seconds']) is int and value['original_timeout_seconds'] == 180,
                'launch_identity')
        integer(value['entry_monotonic_ns'])
        envelope, claim = self.history_deadline(self.stage, value['deadline_envelope'], value['deadline_claim'])
        require(value['entry_monotonic_ns'] == claim['target_entry_monotonic_ns'], 'launch_target_entry')
        self.operation_envelope = envelope
        for name in ('source_commit', 'source_hashes', 'writer_basis', 'clock_identity', 'policy'):
            require(raw(value[name]) == raw(self.admission[name]), 'launch_authority')
        for name in ('admission', 'preprobe'):
            proof = value[name]
            schema(proof, ('sha256', 'bytes', 'metadata'))
            digest(proof['sha256'])
            integer(proof['bytes'], 1)
            require(type(proof['metadata']) is list and len(proof['metadata']) == 10 and
                    all(type(item) is int for item in proof['metadata']), 'launch_proof_metadata')
        require(raw(self.admission_record.proof()) == raw(value['admission']), 'launch_admission_proof')
        pre_record = self.public(self.stage + '-preprobe.json')
        require(raw(pre_record.proof()) == raw(value['preprobe']), 'launch_preprobe_proof')
        pre = strict(pre_record.data)
        schema(pre, ('version', 'stage', 'state', 'admission_sha256', 'source_commit', 'source_hashes',
                     'clock_identity', 'observed_monotonic_ns', 'utc', 'facts', 'Q_released',
                     'deadline_envelope', 'deadline_claim'))
        require(type(pre['version']) is int and pre['version'] == 1 and pre['stage'] == self.stage and
                pre['state'] == 'preprobe-complete' and pre['Q_released'] is False and
                pre['admission_sha256'] == sha(self.admission_record.data) and
                pre['source_commit'] == self.admission['source_commit'] and
                raw(pre['source_hashes']) == raw(self.admission['source_hashes']) and
                raw(pre['clock_identity']) == raw(self.admission['clock_identity']) and
                type(pre['facts']) is dict and type(pre['utc']) is str, 'launch_preprobe_binding')
        self.history_deadline(self.stage + '-preprobe', pre['deadline_envelope'], pre['deadline_claim'])
        integer(pre['observed_monotonic_ns'])
        terminal = self.terminal_gate(self.stage + '-preprobe', success_only=True)
        require(raw(value['preprobe_terminal']) == raw(terminal.proof()), 'launch_preprobe_terminal')
        require(pre['observed_monotonic_ns'] <= value['entry_monotonic_ns'] +
                POLICY[self.stage]['wall_seconds'] * 1000000000, 'launch_preprobe_time')
        # No new age limit at postflight. Retain exactly the launch-pinned bytes.
        self.launch_preprobe = pre_record, pre
        self.recheck()
        return value

    def receipt_value(self, launch, receipt):
        value = strict(receipt.data)
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
        return value, result

    def terminal_gate(self, mode, success_only=False):
        record, value = self.load_invoker().validate_terminal(self, mode)
        require(not success_only or value['state'] == 'known-success', 'terminal_success_required')
        self.recheck()
        return record

    def outer_gate(self):
        self.terminal_gate(self.stage)
        return self.outer_value()

    def outer_value(self):
        # Only public sources/records are read before independent terminal proof.
        launch = self.public(self.stage + '-launch.json')
        launch_value = self.launch_binding(launch)
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
        require(outer['started_monotonic_ns'] ==
                self.operation_envelope['timing']['budget_start_monotonic_lower_ns'], 'outer_budget_origin')
        elapsed = integer(outer['ended_monotonic_ns']) - integer(outer['started_monotonic_ns'])
        require(0 <= elapsed <= POLICY[self.stage]['wall_seconds'] * 1000000000, 'outer_wall_bound')
        value, result = self.receipt_value(launch, receipt)
        if self.stage == 'continue':
            require(type(outer['child_exit_code']) is int, 'exact_child_exit')
        require(outer['child_terminal'] is True and outer['child_exit_code'] ==
                (None if self.stage == 'capture' else result['exit_code']), 'outer_child_terminal')
        success = result['exit_code'] == 0 and result.get('timed_out') is False and result.get('overflow') is False
        require(outer['exit_code'] == (0 if success else 1), 'outer_receipt_exit')
        require(integer(value['ended_monotonic_ns']) <= outer['ended_monotonic_ns'], 'outer_precedes_receipt')
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


def run_probe(mode, deadline, control=None):
    require(mode in ('capture-preprobe', 'capture-postflight', 'continue-preprobe', 'continue-postflight'), 'fixed_probe')
    stage, phase = mode.split('-')
    control = Controller(stage, deadline) if control is None else control
    control.require_envelope(mode)
    success = receipt = None
    if phase == 'postflight':
        success, receipt = control.outer_gate()  # Before clock/private/cache/guard or project imports.
    control.recheck()
    control.clock()
    control.recheck()
    control.load_modules()
    recovery = control.modules['firecracker_recovery']
    with recovery.project_lock():
        control.recheck()
        if phase == 'postflight':
            private = private_postflight(control, success, receipt)
        facts = observations(control)
        control.recheck()
    if phase == 'preprobe':
        value = {'version': 1, 'stage': stage, 'state': 'preprobe-complete',
                 'admission_sha256': sha(control.admission_record.data), 'source_commit': control.admission['source_commit'],
                 'source_hashes': control.admission['source_hashes'], 'clock_identity': control.admission['clock_identity'],
                 'observed_monotonic_ns': int(deadline.now() * 1000000000),
                 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'facts': facts, 'Q_released': False,
                 'deadline_envelope': control.envelope_record.proof(), 'deadline_claim': control.claim_record.proof()}
    else:
        pre = control.launch_preprobe[1]
        for key in ('siblings', 'charges', 'owned_images', 'phase_state_hashes'):
            require(raw(facts[key]) == raw(pre['facts'][key]), 'preservation_mismatch')
        value = {'version': 1, 'stage': stage, 'state': 'postflight-success' if success else 'incomplete',
                 'facts': facts, 'private_proof': private, 'receipt_sha256': sha(raw(receipt)),
                 'approval_created': False, 'Q_released': False, 'new3GB_admitted': False,
                 'deadline_envelope': control.envelope_record.proof(), 'deadline_claim': control.claim_record.proof()}
    record = durable(mode + '.json', value)
    deadline.check()
    print(raw({'record': record.proof(), 'state': value['state']}).decode(), end='', flush=True)
    deadline.check()
    return 0 if phase == 'preprobe' or success else 1


def probe_entry(mode, deadline, control=None):
    try:
        code = run_probe(mode, deadline, control)
    except Exception:
        owner = deadline.owner
        if owner is not None:
            owner.signal(signal.SIGKILL)
        if deadline.now() < deadline.end:
            try:
                deadline.check()
                durable(mode + '.json', {'version': 1, 'state': 'incomplete-or-unknown-retain',
                        'deadline_envelope': None if control is None else control.envelope_record.proof(),
                        'deadline_claim': None if control is None else control.claim_record.proof(),
                        'owned_cli_terminal': owner is None or (not owner.spawn_pending and owner.proc is not None and
                                                               owner.proc.poll() is not None), 'Q_released': False})
            except Exception:
                pass  # Existing/partial record is retained, never replaced.
        raise
    return code
