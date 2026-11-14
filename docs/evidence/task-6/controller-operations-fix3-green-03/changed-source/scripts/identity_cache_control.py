"""Sole fixed recorder entry. Caller authenticity and actual admission remain external gates."""
import time
ENTRY = time.monotonic()
OBSERVER_PATH = '/home/postedism/Desktop/Warden/scripts/identity_cache_observe.py'
EXPECTED_OBSERVER_SHA256 = '6d3d310478bf8c080a4cc0915a3b701803e3a24e51a4b98559178230f4746dc2'

def load_control():
    # Validate the exact sibling source before executing any project module.
    import hashlib
    import os
    from pathlib import Path
    import stat
    import sys
    import types
    path = Path(OBSERVER_PATH)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open('/', flags)
    fd = None
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid not in (0, 1000) or (info.st_mode & 0o022 and not
                    (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                raise ValueError('untrusted_bootstrap_ancestor')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        def metadata(info):
            return [getattr(info, 'st_' + key) for key in
                    ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns', 'blocks')]
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 1000 or before.st_gid != 1000 or
                before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in (0o600, 0o644) or
                not 0 < before.st_size <= 131072):
            raise ValueError('untrusted_observer_source')
        chunks, size = [], 0
        while size <= 131072:
            chunk = os.read(fd, min(65536, 131073 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        data = b''.join(chunks)
        if (len(data) != before.st_size or hashlib.sha256(data).hexdigest() != EXPECTED_OBSERVER_SHA256 or
                metadata(os.fstat(fd)) != metadata(before) or
                metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != metadata(before)):
            raise ValueError('observer_source_changed')
        module = types.ModuleType('identity_cache_observe')
        module.__file__ = str(path)
        sys.modules[module.__name__] = module
        exec(compile(data, str(path), 'exec'), module.__dict__)
        return module
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


MODES = ('capture-preprobe', 'capture', 'capture-postflight',
         'continue-preprobe', 'continue', 'continue-postflight')


def main():
    import os
    import signal
    import sys
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        raise ValueError('one_fixed_controller_mode')
    mode = sys.argv[1]
    seconds = 90 if mode == 'capture' else 600 if mode == 'continue' else 180
    end = ENTRY + seconds
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    remaining = end - time.monotonic()
    if remaining <= 0:
        os._exit(124)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    module = load_control()
    deadline = module.Deadline(ENTRY, seconds)
    deadline.install()
    module.limits(module.POLICY[mode if mode in ('capture', 'continue') else 'observe'])
    if mode in ('capture', 'continue'):
        control = module.Controller(mode, deadline)
        control.api = module
        operation = control.controller_module('identity_cache_capture' if mode == 'capture'
                                              else 'identity_cache_maintenance')
        code = operation.run(control)
    else:
        code = module.probe_entry(mode, deadline)
    deadline.finish()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
