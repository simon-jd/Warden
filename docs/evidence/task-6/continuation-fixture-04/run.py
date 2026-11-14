#!/usr/bin/env python3
"""Bounded in-process private fixture runner, no child processes or live entrypoint."""
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import sys
import time
import unittest

ROOT = Path(__file__).absolute().parents[4]
OUT = Path(__file__).absolute().parent
os.umask(0o077)
if sys.argv[1:]:
    raise ValueError('fixed fixture recorder takes no arguments')
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
def expired(signum, frame):
    raise TimeoutError('45 second fixture wall limit')
signal.signal(signal.SIGALRM, expired)
signal.alarm(45)
baseline = json.loads((OUT/'baseline.json').read_text())
names = set(baseline['sources'])
for name in ('scripts/identity_cache_continue.py', 'scripts/test_identity_cache_continue.py'):
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
           'test_target':'test_identity_cache_continue only, unittest in process',
           'dispatch_base':baseline['dispatch_base'], 'source_commit_at_launch':baseline['source_commit_at_launch'],
           'limits':{'wall_seconds':45,'cpu_seconds':30,'address_bytes':536870912,'file_bytes':33554432},
           'changed_source_snapshots':changed,'live_cache_access':False}
code = 1
save('intent.json', receipt)
try:
    sys.path.insert(0, str(ROOT/'scripts'))
    with (OUT/'output.txt').open('x') as output, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        suite = unittest.defaultTestLoader.loadTestsFromName('test_identity_cache_continue')
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        code = 0 if result.wasSuccessful() else 1
        receipt.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
finally:
    signal.alarm(0)
    post = sources()
    save('post-source.json', post)
    receipt.update(duration_seconds=time.monotonic()-start, exit_code=code, source_unchanged=pre==post, source_files=len(pre))
    save('receipt.json', receipt)
print(json.dumps(receipt,sort_keys=True))
raise SystemExit(code if pre==post else 2)
