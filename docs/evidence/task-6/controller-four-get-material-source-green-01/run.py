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
controller_names = ('docs/evidence/task-6/controller-cache-continuation-outer-invoker-20261025.py',
                    'docs/evidence/task-6/test_controller_cache_continuation_invoker_20261025.py')
def sources():
    return {n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in sorted(names)}
def controller_sources():
    return {n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in controller_names if (ROOT/n).is_file()}
def save(name, value):
    with (OUT/name).open('x') as f:
        f.write(json.dumps(value, sort_keys=True, indent=2)+'\n')
pre = sources()
pre_controller = controller_sources()
save('pre-controller.json', pre_controller)
save('pre-source.json', pre)
combined = {**pre, **pre_controller}
changed = [n for n in combined if {**baseline['sources'], **baseline['controller_sources']}.get(n) != combined[n]]
for n in changed:
    target = OUT/'changed-source'/n
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with target.open('xb') as f:
        f.write((ROOT/n).read_bytes())
start = time.monotonic()
receipt = {'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'command':['python3','-B',str(Path(__file__).relative_to(ROOT))],
           'test_target':'material focused generated GREEN; new source context and transport/terminal boundaries',
           'dispatch_base':baseline['dispatch_base'], 'source_commit_at_launch':baseline['source_commit_at_launch'],
           'limits':{'wall_seconds':45,'cpu_seconds':30,'address_bytes':536870912,'file_bytes':33554432},
           'changed_source_snapshots':changed,'live_cache_access':False, 'timing_scope':'earliest measured entry; interpreter startup and essential timer bootstrap externally unbounded', 'tested_prefix_sha256':hashlib.sha256((Path(__file__).read_text().split('# END DEADLINE PREFIX\n')[0]+'# END DEADLINE PREFIX\n').encode()).hexdigest()}
code = 1
save('intent.json', receipt)
try:
    sys.path.insert(0, str(ROOT/'scripts'))
    sys.path.insert(0, str(ROOT/'docs/evidence/task-6'))
    with (OUT/'output.txt').open('x') as output, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        suite = unittest.defaultTestLoader.loadTestsFromNames(['test_controller_cache_continuation_invoker_20261025.MaterialEntryTests','test_controller_cache_continuation_invoker_20261025.MaterialTests'])
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        code = 0 if result.wasSuccessful() else 1
        receipt.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
finally:
    post = sources()
    post_controller = controller_sources()
    save('post-controller.json', post_controller)
    save('post-source.json', post)
    receipt.update(duration_seconds=time.monotonic()-start, whole_wall_until_receipt_seconds=time.monotonic()-wall_start,
                   exit_code=code, source_unchanged=pre==post and pre_controller==post_controller, controller_files=len(pre_controller), source_files=len(pre),
                   completion_requires_process_exit_zero=True)
    save('receipt.json', receipt)
print(json.dumps(receipt,sort_keys=True), flush=True)
# Keep the deadline active through all post-source, receipt and fixed output IO.
finish_timer()
raise SystemExit(code if pre==post and pre_controller==post_controller else 2)
