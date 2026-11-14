#!/usr/bin/env python3
"""One-shot reconciliation of the reviewed fourth bootstrap's stopped scene."""
import ctypes
import json
import os
from pathlib import Path
import resource
import stat
import sys
import signal

if __name__ == '__main__':
    sys.path.insert(0, '/opt/warden/scripts')
from k3s_lab_init import session_handshake
from runtime_lab_paths import NOFOLLOW_DIR

SESSION = Path('/session')
OUTER_IDENTITY = (66307, 56143028, 1000)
CHILD = 'session-7ca9caee772671b1'
CHILD_IDENTITY = (66307, 56143043, 0)
FILES = {'containerd.toml': 124, 'containerd.log': 0, 'startup-private.log': 154227}
MARKER = '{"reconciliation":"fixed-private-evidence-deleted"}'


def validate_resource_diagnostic(value):
    keys = {'uid', 'nofile_soft', 'nofile_hard', 'fd_entries', 'inotify_result', 'inotify_errno'}
    if (not isinstance(value, dict) or set(value) != keys
            or any(type(value[key]) is not int for key in keys - {'inotify_result'})
            or value['uid'] != 0 or not 0 <= value['fd_entries'] <= 4096
            or any(not -1 <= value[key] < 2**63 for key in ('nofile_soft', 'nofile_hard'))
            or (value['nofile_hard'] != -1 and
                (value['nofile_soft'] == -1 or value['nofile_soft'] > value['nofile_hard']))
            or type(value['inotify_result']) is not str
            or value['inotify_result'] not in ('opened', 'emfile', 'enfile', 'other')
            or not 0 <= value['inotify_errno'] < 4096):
        raise ValueError('invalid fixed resource diagnostic')
    expected = {'opened': 0, 'emfile': 24, 'enfile': 23}
    if (value['inotify_result'] in expected and value['inotify_errno'] != expected[value['inotify_result']]
            or value['inotify_result'] == 'other' and value['inotify_errno'] in (0, 23, 24)):
        raise ValueError('inconsistent fixed resource diagnostic')
    return value


def resource_diagnostic():
    # One current helper observation, never an inventory of another process or
    # proof that the later K3s launch has enough inotify capacity.
    count = 0
    with os.scandir('/proc/self/fd') as entries:
        for _ in entries:  # No stat, target read or FD-name export.
            count += 1
            # Refuse conservatively at the cap: never enumerate a 4097th FD.
            if count >= 4096:
                raise ValueError('bounded self FD inventory exceeded')
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int
    fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        error = ctypes.get_errno() if fd < 0 else 0
        if fd < 0 and not 0 < error < 4096:
            raise ValueError('unknown fixed inotify syscall result')
        value = {'uid': os.getuid(), 'nofile_soft': soft, 'nofile_hard': hard,
                 'fd_entries': count, 'inotify_errno': error,
                 'inotify_result': {0: 'opened', 24: 'emfile', 23: 'enfile'}.get(error, 'other')}
    finally:
        if fd >= 0:
            os.close(fd)
    return validate_resource_diagnostic(value)


def directory(info, expected):
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino, info.st_uid) != expected):
        raise ValueError('fixed recovery directory identity mismatch')


def reconcile():
    session_handshake(live=False)
    outer = os.open(SESSION, NOFOLLOW_DIR)
    child = None
    try:
        directory(os.fstat(outer), OUTER_IDENTITY)
        child = os.open(CHILD, NOFOLLOW_DIR, dir_fd=outer)
        directory(os.fstat(child), CHILD_IDENTITY)

        def anchored():
            directory(os.stat(SESSION, follow_symlinks=False), OUTER_IDENTITY)
            directory(os.stat(CHILD, dir_fd=outer, follow_symlinks=False), CHILD_IDENTITY)

        def inspect_files():
            anchored()
            names = set()
            with os.scandir(child) as entries:
                for entry in entries:
                    names.add(entry.name)
                    if len(names) > len(FILES):
                        raise ValueError('unexpected private recovery state; preserved')
            if names != set(FILES):
                raise ValueError('unexpected private recovery state; preserved')
            result = {}
            allocated = os.fstat(child).st_blocks * 512
            for name, size in FILES.items():
                info = os.stat(name, dir_fd=child, follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != CHILD_IDENTITY[2] or info.st_size != size
                        or info.st_dev != CHILD_IDENTITY[0]):
                    raise ValueError('fixed private evidence shape mismatch')
                allocated += info.st_blocks * 512
                result[name] = (info.st_dev, info.st_ino)
            if allocated > 33000000:
                raise ValueError('private evidence allocation exceeded bound')
            return result

        files = inspect_files()  # RO: shape and allocation before any mutation.
        print(json.dumps({'resource_diagnostic': resource_diagnostic()}, sort_keys=True), flush=True)
        session_handshake(live=True)  # Reviewed old image remounts only this FD bind.
        if inspect_files() != files:
            raise ValueError('private evidence identity changed; preserved')
        for name, identity in files.items():
            anchored()
            info = os.stat(name, dir_fd=child, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != identity:
                raise ValueError('private evidence drifted; preserved')
            os.unlink(name, dir_fd=child)
        os.fsync(child)
        anchored()
        os.rmdir(CHILD, dir_fd=outer)
        os.fsync(outer)
        print(MARKER, flush=True)
    finally:
        if child is not None:
            os.close(child)
        os.close(outer)


if __name__ == '__main__':
    try:
        os.umask(0o077)
        if os.getpid() != 1 or os.getuid() != 0 or sys.argv[1:]:
            raise ValueError('fixed image PID1 recovery required')
        def deadline(signum, frame):
            raise TimeoutError('fixed recovery deadline')
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(20)
        reconcile()
    except BaseException:
        print('{"reconciliation":"failed-preserved"}', file=sys.stderr, flush=True)
        sys.exit(2)
