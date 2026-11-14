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


def digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('bounded regular non-symlink file required')
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
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


def command(argv, *, env=None, timeout=60):
    # Only explicit argument arrays; no host shell. Output goes to a bounded
    # temporary file so a noisy tool cannot exhaust memory or evidence storage.
    import tempfile
    import resource
    import signal

    def limits():
        os.setsid()
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        cap = min(8 * 1024 * 1024, hard) if hard != resource.RLIM_INFINITY else 8 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))

    with tempfile.TemporaryFile() as capture:
        process = subprocess.Popen(argv, env=env, stdout=capture, stderr=subprocess.STDOUT,
                                   preexec_fn=limits)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            code = 124
        capture.seek(0)
        return code, capture.read(8 * 1024 * 1024).decode('utf-8', errors='replace')


def clean_environment():
    # Do not pass host cloud credentials, default kubeconfig or Docker context.
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8'}
