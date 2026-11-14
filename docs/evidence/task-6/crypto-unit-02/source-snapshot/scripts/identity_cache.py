#!/usr/bin/env python3
"""Fixed retired Go-cache cleanup. Requires a separately approved writer-free window.

No Docker/Go calls, cache body reads, recursion, or arbitrary CLI paths.
The fixed legacy path may only reduce permissions after durable metadata intent.
Only the pinned Go1.26.10 cache.go layout is recognized. Unknown state is retained.
The shared project lock excludes cooperating Warden operations; it cannot exclude
an uncooperative same-UID writer. The controller must establish quiescence first.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys

from runtime_lab_paths import trusted_directory

ROOT = Path(__file__).absolute().parent.parent
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
BUCKETS = frozenset(f'{i:02x}' for i in range(256))
METADATA = frozenset(('README', 'trim.txt', 'testexpire.txt'))
MAX_FILES = 100000
MAX_BYTES = 3000000000
INTENT_NAME = 'identity-cache-permission-intent.json'
RESULT_NAME = 'identity-cache-permission-result.json'


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def names(fd, limit):
    result = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            result.add(entry.name)
            if len(result) > limit:
                raise ValueError('cache layout exceeds fixed entry bound')
    return result


@contextmanager
def project_lock(lab_fd, uid):
    # Existing lock only: do not create a second lock or replace its inode.
    fd = os.open('docker.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 dir_fd=lab_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != uid
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('unsafe existing project lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if fingerprint(os.stat('docker.lock', dir_fd=lab_fd, follow_symlinks=False)) != fingerprint(info):
            raise ValueError('project lock replaced')
        yield
    finally:
        os.close(fd)


@dataclass
class Node:
    parent: int
    name: str
    info: os.stat_result
    fd: int = -1
    children: set | None = None
    executable: bool = False


class CachePlan:
    """FD-only engine; caller supplies the already trusted .cache parent descriptor.

    The only accepted child name is go-build, including in isolated test fixtures.
    Retains all directory FDs, but only one regular-file FD at a time; no body reads.
    """
    def __init__(self, cache_parent, uid):
        self.uid = uid
        self.parent = os.dup(cache_parent)
        self.device = os.fstat(self.parent).st_dev
        self.directories = []
        self.files = []
        self.preserved = []
        self.seen = set()
        self.logical_bytes = 0
        self.allocated_bytes = 0
        self.finished = False
        try:
            root = self._directory(self.parent, 'go-build', 259)
            self.root = root
            if not BUCKETS <= root.children or root.children - BUCKETS - METADATA:
                raise ValueError('unknown cache root layout')
            for name in sorted(root.children & METADATA):
                node = self._file(root.fd, name, executable=False)
                if node.info.st_size > 1048576:
                    raise ValueError('unexpected metadata size')
                self.preserved.append(node)
            for bucket in sorted(BUCKETS):
                directory = self._directory(root.fd, bucket, 4096)
                for name in sorted(directory.children):
                    if not re.fullmatch(bucket + r'[0-9a-f]{62}-[ad]', name):
                        raise ValueError('unknown cache entry name')
                    info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        if not name.endswith('-d'):
                            raise ValueError('action entry cannot be a directory')
                        binary = self._directory(directory.fd, name, 1)
                        binary.executable = True
                        if len(binary.children) != 1:
                            raise ValueError('executable cache must have one file')
                        child = next(iter(binary.children))
                        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', child):
                            raise ValueError('unsupported executable cache basename')
                        self.files.append(self._file(binary.fd, child, executable=True))
                    else:
                        node = self._file(directory.fd, name, executable=False)
                        if name.endswith('-a') and node.info.st_size != 175:
                            raise ValueError('unexpected Go action index size')
                        self.files.append(node)
                    if len(self.files) > MAX_FILES:
                        raise ValueError('too many cache files')
            self._recheck_all()
        except BaseException:
            self.close()
            raise

    def _validate(self, info, directory=False, executable=False):
        allowed = self._modes(directory, executable)
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (not expected_type(info.st_mode) or info.st_uid != self.uid or info.st_gid != self.uid
                or info.st_dev != self.device or stat.S_IMODE(info.st_mode) not in allowed):
            raise ValueError('untrusted cache owner/device/type/mode')
        if (directory and info.st_nlink < 2) or (not directory and info.st_nlink != 1):
            raise ValueError('untrusted cache link count')
        identity = (info.st_dev, info.st_ino)
        if identity in self.seen:
            raise ValueError('cache inode alias')
        self.seen.add(identity)

    def _modes(self, directory, executable):
        return (0o700, 0o755) if directory or executable else (0o600, 0o644)

    def _directory(self, parent, name, limit):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self._validate(before, directory=True)
        fd = os.open(name, DIR_FLAGS, dir_fd=parent)
        node = Node(parent, name, before, fd)
        self.directories.append(node)
        if fingerprint(os.fstat(fd)) != fingerprint(before):
            raise ValueError('cache directory changed during open')
        node.children = names(fd, limit)
        return node

    def _file(self, parent, name, executable):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self._validate(before, executable=executable)
        fd = os.open(name, FILE_FLAGS, dir_fd=parent)
        try:
            if fingerprint(os.fstat(fd)) != fingerprint(before):
                raise ValueError('cache file changed during open')
        finally:
            os.close(fd)
        self.logical_bytes += before.st_size
        self.allocated_bytes += before.st_blocks * 512
        if self.logical_bytes > MAX_BYTES or self.allocated_bytes > MAX_BYTES:
            raise ValueError('cache exceeds fixed metadata byte bound')
        return Node(parent, name, before, executable=executable)

    def _recheck_node(self, node):
        current = os.stat(node.name, dir_fd=node.parent, follow_symlinks=False)
        if fingerprint(current) != fingerprint(node.info):
            raise ValueError('cache entry changed; remaining data preserved')
        if node.fd >= 0 and fingerprint(os.fstat(node.fd)) != fingerprint(node.info):
            raise ValueError('cache directory descriptor changed')

    def _recheck_all(self):
        for node in self.directories:
            self._recheck_node(node)
            if names(node.fd, 4096) != node.children:
                raise ValueError('cache directory entries changed')
            child_dirs = sum(1 for child in self.directories if child.parent == node.fd)
            if node.info.st_nlink != 2 + child_dirs:
                raise ValueError('unexpected cache directory link count')
        for node in self.files + self.preserved:
            self._recheck_node(node)

    def remove(self):
        if self.finished:
            raise ValueError('cache plan is single-use')
        self.finished = True
        # Validate the complete plan before the first irreversible unlink.
        self._recheck_all()
        by_fd = {node.fd: node for node in self.directories}
        removed = 0
        allocated = 0
        logical = 0
        for node in self.files:
            # Held ancestors plus immediate nofollow stat/fstat protect against
            # accidental replacement. Quiescence remains required: unlinkat
            # has no compare-and-unlink primitive for hostile same-UID writers.
            parent = by_fd[node.parent]
            ancestors = [parent]
            while ancestors[-1].parent in by_fd:
                ancestors.append(by_fd[ancestors[-1].parent])
            for ancestor in reversed(ancestors):
                self._recheck_node(ancestor)
            fd = os.open(node.name, FILE_FLAGS, dir_fd=node.parent)
            try:
                self._recheck_node(node)
                if fingerprint(os.fstat(fd)) != fingerprint(node.info):
                    raise ValueError('cache file replaced before unlink')
                os.unlink(node.name, dir_fd=node.parent)
            finally:
                os.close(fd)
            parent.children.remove(node.name)
            parent.info = os.fstat(parent.fd)
            removed += 1
            logical += node.info.st_size
            allocated += node.info.st_blocks * 512
        removed_dirs = 0
        for node in reversed(self.directories):
            if not node.executable:
                continue
            self._recheck_node(self.root)
            parent = by_fd[node.parent]
            self._recheck_node(parent)
            self._recheck_node(node)
            if names(node.fd, 1):
                raise ValueError('executable cache gained an entry')
            os.rmdir(node.name, dir_fd=node.parent)
            parent.children.remove(node.name)
            parent.info = os.fstat(parent.fd)
            removed_dirs += 1
        for node in self.directories:
            if not node.executable:
                self._recheck_node(node)
                if names(node.fd, 259) != node.children:
                    raise ValueError('unexpected post-cleanup cache entry')
                os.fsync(node.fd)
        for node in self.preserved:
            self._recheck_node(node)
        os.fsync(self.parent)
        return {'removed_files': removed, 'removed_executable_dirs': removed_dirs,
                'removed_logical_bytes': logical, 'removed_allocated_bytes': allocated,
                'preserved_bucket_count': 256, 'preserved_metadata_count': len(self.preserved)}

    def close(self):
        for node in reversed(self.directories):
            if node.fd >= 0:
                os.close(node.fd)
                node.fd = -1
        if self.parent >= 0:
            os.close(self.parent)
            self.parent = -1


def durable_metadata(parent, name, value):
    """Write a new fixed metadata receipt; preserve partial/uncertain writes."""
    if name not in (INTENT_NAME, RESULT_NAME):
        raise ValueError('fixed receipt name required')
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(raw) > 32000000:
        raise ValueError('metadata receipt exceeds fixed bound')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise OSError('metadata write made no progress')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)


class TighteningPlan(CachePlan):
    """The only legacy-mode exception, anchored to the literal go-build child.

    Never exposed as a path/mode option and never changes trusted_directory.
    Failure preserves the intent and any narrowed modes for controller review.
    Existing intent (including uncertain/partial intent) forbids blind retry.
    """
    def __init__(self, cache_parent, uid):
        self.tightened = False
        self.tightening_attempted = False
        super().__init__(cache_parent, uid)

    def _modes(self, directory, executable):
        if self.tightened:
            return super()._modes(directory, executable)
        if directory:
            return (0o755, 0o775)
        return (0o755,) if executable else (0o644, 0o664)

    def tighten(self):
        if self.tightening_attempted:
            raise ValueError('tightening is single-use; preserve intent for review')
        self.tightening_attempted = True
        self._recheck_all()
        for name in (INTENT_NAME, RESULT_NAME):
            try:
                os.stat(name, dir_fd=self.parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FileExistsError('existing cache receipt requires controller review')
        by_fd = {node.fd: node for node in self.directories}
        targets = self.directories + self.files + self.preserved
        metadata = []
        for node in targets:
            parts = [node.name]
            parent = node.parent
            while parent in by_fd:
                parts.append(by_fd[parent].name)
                parent = by_fd[parent].parent
            metadata.append({'relative': '/'.join(reversed(parts)),
                             'original': fingerprint(node.info),
                             'target_mode': 0o700 if node.fd >= 0 or node.executable else 0o600})
        durable_metadata(self.parent, INTENT_NAME,
                         {'version': 1, 'state': 'prepared-not-completed',
                          'cache_name': 'go-build', 'entries': metadata})
        # Intent durability precedes every chmod. A second complete check avoids
        # changing any mode if the layout changed while intent was written.
        self._recheck_all()
        for node in targets:
            ancestors = []
            parent = node.parent
            while parent in by_fd:
                ancestors.append(by_fd[parent])
                parent = by_fd[parent].parent
            for ancestor in reversed(ancestors):
                self._recheck_node(ancestor)
            self._recheck_node(node)
            fd = node.fd if node.fd >= 0 else os.open(node.name, FILE_FLAGS, dir_fd=node.parent)
            try:
                if fingerprint(os.fstat(fd)) != fingerprint(node.info):
                    raise ValueError('cache replaced before permission tightening')
                mode = 0o700 if node.fd >= 0 or node.executable else 0o600
                if mode & ~stat.S_IMODE(node.info.st_mode):
                    raise ValueError('permission change would grant access')
                os.fchmod(fd, mode)
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_nlink) != (
                        node.info.st_dev, node.info.st_ino, node.info.st_uid, node.info.st_gid, node.info.st_nlink):
                    raise ValueError('cache identity changed during tightening')
                if stat.S_IMODE(current.st_mode) != mode:
                    raise ValueError('permission tightening not confirmed')
                node.info = current
                self._recheck_node(node)
                os.fsync(fd)
            finally:
                if node.fd < 0:
                    os.close(fd)
        self._recheck_all()
        # Re-open the complete layout through the original strict engine before
        # unlink authority becomes available. Do not rely only on chmod results.
        strict = CachePlan(self.parent, self.uid)
        try:
            strict._recheck_all()
        finally:
            strict.close()
        self.tightened = True

    def remove(self):
        if not self.tightened:
            raise ValueError('complete durable-intent tightening required before unlink')
        result = super().remove()
        durable_metadata(self.parent, RESULT_NAME,
                         {'version': 1, 'state': 'completed', 'cache_name': 'go-build', **result})
        return result


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        raise ValueError('fixed cache entrypoint accepts no arguments')
    if os.getuid() != 1000 or os.geteuid() != 1000 or os.getgid() != 1000:
        raise ValueError('ordinary UID/GID1000 required')
    os.umask(0o077)
    lab = trusted_directory(str(ROOT / '.cache/warden-lab'), 1000)
    try:
        with project_lock(lab, 1000):
            parent = trusted_directory(str(ROOT / '.cache'), 1000)
            try:
                plan = TighteningPlan(parent, 1000)
                try:
                    print(json.dumps({'phase': 'validated', 'files': len(plan.files),
                                      'logical_bytes': plan.logical_bytes,
                                      'allocated_bytes': plan.allocated_bytes}), flush=True)
                    plan.tighten()
                    print(json.dumps(plan.remove(), sort_keys=True), flush=True)
                finally:
                    plan.close()
            finally:
                os.close(parent)
    finally:
        os.close(lab)


if __name__ == '__main__':
    main()
