"""No-follow, fd-anchored filesystem ownership for a privileged lab session."""
import os
from pathlib import Path
import secrets
import re
import shutil
import stat

NOFOLLOW_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
RESERVED = ('containerd.toml', 'containerd.log', 'containerd.sock', 'containerd.sock.ttrpc', 'root', 'state', 'io')


def trusted_directory(path, trusted_uid):
    """Open every existing component without symlink traversal or root writes."""
    if not os.path.isabs(path) or os.path.normpath(path) != path or trusted_uid < 0:
        raise ValueError('absolute normalized path and trusted operator UID required')
    current = os.open('/', NOFOLLOW_DIR)
    try:
        for name in Path(path).parts[1:]:
            child = os.open(name, NOFOLLOW_DIR, dir_fd=current)
            os.close(current)
            current = child
            info = os.fstat(current)
            if info.st_uid not in (0, trusted_uid):
                raise ValueError('untrusted directory owner')
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_mode & 0o022 and not sticky_root:
                raise ValueError('directory writable by untrusted group or other')
        return current
    except BaseException:
        os.close(current)
        raise


def exclusive_file(parent, name, data=b''):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        with os.fdopen(os.dup(fd), 'wb') as output:
            output.write(data)
        return fd
    except BaseException:
        os.close(fd)
        raise


class Session:
    def __init__(self, base, parent_fd, name, fd, trusted_uid):
        self.path, self.run = Path(base), Path(base) / name
        self.parent_fd, self.fd, self.name = parent_fd, fd, name
        self.trusted_uid = trusted_uid
        self.closed = False

    def anchored(self, name):
        if '/' in name or name in ('', '.', '..'):
            raise ValueError('single owned child name required')
        return f'/proc/{os.getpid()}/fd/{self.fd}/{name}'

    def artifact(self, name, base=None):
        if name not in ('runc.test', 'api.test', 'probe.oci.tar', 'image-digest', 'image-name'):
            raise ValueError('unknown build artifact')
        parent = self.parent_fd if base is None else trusted_directory(base, self.trusted_uid)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        finally:
            if base is not None:
                os.close(parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, self.trusted_uid) or info.st_mode & 0o022:
            os.close(fd)
            raise ValueError('untrusted or writable build artifact')
        return fd

    def cleanup_data(self):
        # rmtree's dir_fd implementation refuses symlink traversal, including
        # replacements during recursion. The session descriptor stays pinned if
        # its pathname or any ancestor is renamed while the root runner runs.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise RuntimeError('symlink-resistant rmtree required')
        for name in ('root', 'state', 'io'):
            try:
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('owned daemon directory was replaced; preserving session')
            shutil.rmtree(name, dir_fd=self.fd)
        for name in ('containerd.sock', 'containerd.sock.ttrpc'):
            try:
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISSOCK(info.st_mode):
                raise ValueError('owned socket was replaced; preserving session')
            os.unlink(name, dir_fd=self.fd)

    def release_evidence(self):
        """After empty-tree cleanup, retain authority/markers and return known FDs."""
        entries = set(os.listdir(self.fd))
        if entries not in ({'containerd.toml', 'containerd.log'}, {'containerd.toml', 'containerd.log', 'gate'}):
            raise ValueError('unknown session state; evidence ownership preserved')
        descriptors = []
        gatefd = None
        try:
            targets = [(self.fd, 'containerd.toml'), (self.fd, 'containerd.log')]
            if 'gate' in entries:
                gatefd = os.open('gate', NOFOLLOW_DIR, dir_fd=self.fd)
                info = os.fstat(gatefd)
                if info.st_uid not in (0, self.trusted_uid) or info.st_mode & 0o777 != 0o700:
                    raise ValueError('unsafe durable gate directory')
                names = os.listdir(gatefd)
                if len(names) > 256 or any(name not in ('node', 'admission', 'retirement', 'retirement-binding') and not re.fullmatch('[A-Z2-7]{26}', name) for name in names):
                    raise ValueError('unknown durable gate state; preserved')
                targets.extend((gatefd, name) for name in names)
            for parent, name in targets:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                descriptors.append(fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, self.trusted_uid) or info.st_mode & 0o077:
                    raise ValueError('untrusted evidence file; ownership preserved')
            for fd in descriptors:
                os.fchown(fd, self.trusted_uid, -1)
            if gatefd is not None:
                os.fchown(gatefd, self.trusted_uid, -1)
            os.fchown(self.fd, self.trusted_uid, -1)
        finally:
            for fd in descriptors:
                os.close(fd)
            if gatefd is not None:
                os.close(gatefd)

    def close(self):
        if not self.closed:
            os.close(self.fd)
            os.close(self.parent_fd)
            self.closed = True


def prepare_session(base, trusted_uid):
    """Reject legacy targets first, then exclusively create this run's objects."""
    parent = trusted_directory(base, trusted_uid)
    try:
        for name in RESERVED:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError(f'pre-existing lab target requires explicit recovery: {name}')
        name = 'session-' + secrets.token_hex(8)
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = os.open(name, NOFOLLOW_DIR, dir_fd=parent)
        try:
            for directory in ('root', 'state', 'io'):
                os.mkdir(directory, 0o700, dir_fd=fd)
            config = exclusive_file(fd, 'containerd.toml', b'version = 3\ndisabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime", "io.containerd.grpc.v1.cri"]\n')
            os.close(config)
            log = exclusive_file(fd, 'containerd.log')
            os.close(log)
            return Session(base, parent, name, fd, trusted_uid)
        except BaseException:
            os.close(fd)
            raise
    except BaseException:
        os.close(parent)
        raise
