"""One fixed read-only replay of public dependency validation; no scene phase."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = 'd8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7'
HOST_SHA = 'd871f14b4fc8a43da46b57a0ab0c5e42c4849f5c8cd725e582022fdd098cd357'
HELPER_SHA = '72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2'
assert os.geteuid() == 1000 and len(sys.argv) == 1
os.umask(0o077)
sys.path.insert(0, str(ROOT / 'scripts'))
for name, digest in [('firecracker_recovery.py', HOST_SHA), ('firecracker_recovery_init.py', HELPER_SHA)]:
    assert hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == digest
import firecracker_recovery as r

out = ROOT / 'docs/evidence/task-4/public-abi-closure-v2.json'
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
record = {'source': SOURCE, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'scope': 'read-only public inputs, no scene phase/archive/image/container/guest',
          'dependency_calls': 0, 'original_Q_released': False}


def timeout(signum, frame):
    raise TimeoutError('public_diagnostic_deadline')


def trace(frame, event, arg):
    if frame.f_code.co_filename != str(ROOT / 'scripts/firecracker_recovery.py'):
        return None
    name = frame.f_code.co_name
    if name == 'host_abi' and event == 'return' and type(arg) is dict:
        record['validated_host_abi'] = arg
    if name != 'dependencies':
        return trace if name == 'host_abi' else None
    if event == 'call':
        record['dependency_calls'] += 1
    if event == 'exception' and isinstance(arg[1], r.Refusal):
        local = frame.f_locals
        path = str(frame.f_back.f_locals['path'])
        assert path == str(r.PYTHON) or path.startswith(str(r.STDLIB) + '/')
        stdout, stderr = local['stdout'], local['stderr']
        assert len(stdout) <= 65536 and len(stderr) <= 4096
        record['first_dependency_refusal'] = {
            'public_input': path, 'reason': arg[1].code, 'exit_code': local['code'],
            'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
            'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(stderr).hexdigest(),
            'stdout_addresses_redacted': re.sub(r'0x[0-9a-f]+', '<address>', stdout.decode('ascii')),
            'stderr_addresses_redacted': re.sub(r'0x[0-9a-f]+', '<address>', stderr.decode('ascii'))}
    return trace


signal.signal(signal.SIGALRM, timeout)
signal.alarm(45)
try:
    assert (ROOT / 'docs/evidence/task-4/review-recovery-static-parser.md').read_bytes()
    assert r.source_sha() == SOURCE
    with r.project_lock():
        scene = r.Scene()
        try:
            record['admission_before'] = r.account(scene, 0)
            sys.settrace(trace)
            try:
                with r.runtime_inputs() as inputs:
                    record['public_closure_complete'] = True
                    record['selected_files'] = len(inputs)
            except Exception as error:
                record['result'] = {'type': type(error).__name__,
                                    'reason': error.code if isinstance(error, r.Refusal) else 'external_error'}
            finally:
                sys.settrace(None)
            record['admission_after'] = r.account(scene, 0)
            record['live_uid_after'] = os.fstat(scene.live).st_uid
        finally:
            scene.close()
except Exception as error:
    record['diagnostic_error'] = {'type': type(error).__name__,
                                'reason': error.code if isinstance(error, r.Refusal) else 'external_error'}
finally:
    sys.settrace(None)
    signal.alarm(0)
    record['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with os.fdopen(fd, 'w') as stream:
        json.dump(record, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    out.chmod(0o644)
print(json.dumps(record))
