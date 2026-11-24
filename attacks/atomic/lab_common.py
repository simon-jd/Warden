"""Small stdlib helpers; no attack or filesystem operations at import time."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def checked_tool(value):
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('an explicit absolute executable tool path is required')
    return str(path)


def digest(path, *, max_bytes=256 * 1024 * 1024):
    if type(max_bytes) is not int or not 0 < max_bytes <= 512 * 1024 * 1024:
        raise ValueError('digest size bound must be at most 512 MiB')
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError('bounded regular non-symlink file required')
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        total = 0
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            total += len(block)
            if total > max_bytes:
                raise ValueError('bounded regular non-symlink file required')
            hasher.update(block)
    return hasher.hexdigest()


def execution_record(execution_id, run_id, technique_id, executed_at, returncode):
    return {'execution_id': execution_id, 'run_id': run_id, 'technique_id': technique_id,
            'executed_at': executed_at, 'outcome': 'succeeded' if returncode == 0 else 'failed'}


def write_new_json(path, record):
    # Exclusive/no-follow files prevent accidental evidence replacement.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write(json.dumps(record, sort_keys=True, allow_nan=False) + '\n')


def prepare_output(directory):
    path = Path(directory)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError('absolute non-symlink output path required')
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    return path


def command(argv, *, env=None, timeout=60, file_limit_bytes=8 * 1024 * 1024):
    """Run one process group with separate file-write and captured-output limits."""
    import resource
    import selectors
    import signal
    import time

    output_limit = 8 * 1024 * 1024
    if type(file_limit_bytes) is not int or not 0 < file_limit_bytes <= 512 * 1024 * 1024:
        raise ValueError('file write bound must be at most 512 MiB')

    def limits():
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        cap = min(file_limit_bytes, hard) if hard != resource.RLIM_INFINITY else file_limit_bytes
        resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))

    process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               preexec_fn=limits, start_new_session=True)
    output = bytearray()
    outcome = None
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    outcome = 124
                    break
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    break
                available = output_limit - len(output)
                output.extend(data[:available])
                if len(data) > available:
                    outcome = 125
                    break
        if outcome is None:
            try:
                outcome = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                outcome = 124
        if outcome in (124, 125):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        return outcome, output.decode('utf-8', errors='replace')
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        process.stdout.close()


def clean_environment():
    # Do not pass host cloud credentials, default kubeconfig or Docker context.
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8'}
