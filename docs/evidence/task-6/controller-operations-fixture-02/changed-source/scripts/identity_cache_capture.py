"""One admitted in-process checkpoint capture, never approval or continuation."""
import time
ENTRY = time.monotonic()
EXPECTED_OBSERVER_SHA256 = 'UNFROZEN'

def load_control():
    # Validate the exact sibling source before executing any project module.
    import hashlib
    import os
    from pathlib import Path
    import stat
    import sys
    import types
    path = Path('/home/postedism/Desktop/Warden/scripts/identity_cache_observe.py')
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


def run(control):
    c = control
    pre_record, _ = c.preparation()
    c.load_modules()
    product = c.modules['identity_cache_continue']
    launch = c.launch(pre_record)
    c.deadline.arm(c.deadline.start + 80)
    result = product.capture_checkpoint(c.admission['writer_basis'])
    c.deadline.check(c.deadline.start + 80)
    c.deadline.arm()  # Remaining original90seconds, not a new90second interval.
    module = load_api(c)
    module.summary_check(result, product)
    summary = module.durable('capture-summary.json', result)
    c.records.append(summary)
    outcome = {'terminal': True, 'exit_code': 0, 'timed_out': False, 'overflow': False}
    receipt = c.receipt(launch, outcome, summary.proof())
    c.deadline.check()
    print(module.raw({'state': 'capture-returned-postflight-pending', 'receipt': receipt.proof()}).decode(),
          end='', flush=True)
    c.deadline.check()
    return 0


def load_api(control):
    # Controller carries its defining module through the already-verified load.
    return control.api


def main():
    import os
    import signal
    import sys
    # Arm before project bootstrap/import. No child exists on this path.
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.setitimer(signal.ITIMER_REAL, max(0.000001, 90 - (time.monotonic() - ENTRY)))
    module = load_control()
    deadline = module.Deadline(ENTRY, 90)
    deadline.install()
    module.limits(module.POLICY['capture'])
    module.require(not sys.argv[1:], 'capture_takes_no_arguments')
    control = module.Controller('capture', deadline)
    control.api = module
    code = run(control)
    deadline.finish()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
