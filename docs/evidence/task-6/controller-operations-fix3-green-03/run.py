#!/usr/bin/env python3
# BEGIN DEADLINE PREFIX
import time
wall_start = time.monotonic()
wall_end = wall_start + 45
import os
import signal
def expired(signum=None, frame=None):
    os._exit(124)
def remaining():
    value = wall_end - time.monotonic()
    if value <= 0:
        expired()
    return value
def finish_timer():
    remaining()
    signal.setitimer(signal.ITIMER_REAL, 0)
signal.signal(signal.SIGALRM, expired)
signal.setitimer(signal.ITIMER_REAL, remaining())
# END DEADLINE PREFIX
import contextlib
import datetime
import hashlib
import json
from pathlib import Path
import resource
import sys
import unittest
ROOT = Path(__file__).absolute().parents[4]
OUT = Path(__file__).absolute().parent
os.umask(0o077)
if sys.argv[1:]:
    raise ValueError('fixed fixture recorder takes no arguments')
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
baseline = json.loads((OUT/'baseline.json').read_text())
names = set(baseline['sources'])
for name in ('scripts/identity_cache_control.py', 'scripts/identity_cache_capture.py', 'scripts/identity_cache_maintenance.py', 'scripts/identity_cache_observe.py', 'scripts/test_identity_cache_control.py'):
    if (ROOT/name).exists():
        names.add(name)
def sources():
    return {n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in sorted(names)}
def save(name, value):
    with (OUT/name).open('x') as f:
        f.write(json.dumps(value, sort_keys=True, indent=2)+'\n')
pre = sources()
save('pre-source.json', pre)
changed = [n for n in pre if baseline['sources'].get(n) != pre[n]]
for n in changed:
    target = OUT/'changed-source'/n
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with target.open('xb') as f:
        f.write((ROOT/n).read_bytes())
start = time.monotonic()
receipt = {'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'command':['python3','-B',str(Path(__file__).relative_to(ROOT))],
           'test_target':'test_identity_cache_control only, unittest in process',
           'dispatch_base':baseline['dispatch_base'], 'source_commit_at_launch':baseline['source_commit_at_launch'],
           'limits':{'wall_seconds':45,'cpu_seconds':30,'address_bytes':536870912,'file_bytes':33554432},
           'changed_source_snapshots':changed,'live_cache_access':False, 'timing_scope':'earliest measured entry; interpreter startup and essential timer bootstrap externally unbounded', 'tested_prefix_sha256':hashlib.sha256((Path(__file__).read_text().split('# END DEADLINE PREFIX\n')[0]+'# END DEADLINE PREFIX\n').encode()).hexdigest()}
code = 1
save('intent.json', receipt)
try:
    sys.path.insert(0, str(ROOT/'scripts'))
    with (OUT/'output.txt').open('x') as output, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        suite = unittest.defaultTestLoader.loadTestsFromName('test_identity_cache_control')
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        code = 0 if result.wasSuccessful() else 1
        receipt.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
finally:
    post = sources()
    save('post-source.json', post)
    receipt.update(duration_seconds=time.monotonic()-start, whole_wall_until_receipt_seconds=time.monotonic()-wall_start,
                   exit_code=code, source_unchanged=pre==post, source_files=len(pre),
                   completion_requires_process_exit_zero=True)
    save('receipt.json', receipt)
print(json.dumps(receipt,sort_keys=True), flush=True)
# Keep the deadline active through all post-source, receipt and fixed output IO.
finish_timer()
raise SystemExit(code if pre==post else 2)
