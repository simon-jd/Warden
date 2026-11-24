#!/usr/bin/env python3
"""One hour's benign workload for the seven-day window: the conformance probes on runc, then on gVisor.

    benign.py --session <detector session> [--only runc|gvisor]

Both run the existing conformance suite (runtimes/conformance, seven probes)
through the real Warden drivers, under taskset -c detector.CPUSET (0-7,16-31
unless WARDEN_CPUSET says otherwise), with the lab containers pinned to the
same CPUs (WARDEN_LAB_CPUSET):

* runc: scripts/runtime_lab_docker.py run, the runc lab (Task 2). Its memory
  guard is told about the two Falco containers' limits.
* gVisor: make test-gvisor on a lab started with --without-corpus, so the
  lab has no Task 5 material. The host instance sees its runsc sentry and
  gofer and the k3s node (host-level coverage; the sandboxes' own system
  calls are not covered). The lab is up only for this run.

A run that reaches its timeout gets SIGTERM (its own cleanup runs), then
SIGKILL after a minute, and then its lab is taken down (detector.clean_labs:
the k3s lab's down, or the runc lab's containers by their labels). The same
happens to the run in progress when benign.py itself gets SIGTERM (systemd's
RuntimeMaxSec).

They run one after the other because the runc lab refuses to start next to
another Warden lab container. Each run appends one record to the session's
workloads.jsonl ({workload_id, runtime, start, end, ok, exit_code, command,
log, log_sha256}); ok means exit 0 and the suite's PASS line. recorder.py
counts the ok ones into each hour's workload_count. A run that cannot start
(detector down, another run still going) is recorded as not ok.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detector  # noqa: E402  (this directory, made explicit: the units run python3 -I)

ROOT = detector.ROOT
RUNS = {
    'runc': {'argv': ['/usr/bin/python3', '-B', 'scripts/runtime_lab_docker.py', 'run',
                      '--other-service-memory-bytes', str(detector.FALCO_MEMORY)],
             'pass': '--- PASS: TestConformance', 'timeout': 1200},
    'gvisor': {'argv': ['/usr/bin/make', '--no-print-directory', 'test-gvisor', 'GVISOR_LAB_FLAGS=--without-corpus'],
               'pass': '--- PASS: TestGVisorConformance', 'timeout': 1800},
}


def now():
    t = datetime.now(timezone.utc)
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%06d000Z' % t.microsecond


class Terminated(Exception):
    """benign.py got SIGTERM."""


def run_process(argv, cwd, env, timeout):
    """(exit code, output, timed out). The run is its own process group; at
    the timeout, or on our own SIGTERM, it gets SIGTERM, then SIGKILL."""
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)
    try:
        output, _ = proc.communicate(timeout=timeout)
        return proc.returncode, output, False
    except (subprocess.TimeoutExpired, Terminated) as stopped:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            output, _ = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            output, _ = proc.communicate()
        if isinstance(stopped, Terminated):
            raise Terminated(output)
        return proc.returncode, output, True


def default_cleanup(runtime):
    detector.clean_labs(detector.Host(), runtimes=(runtime,))


def run_one(runtime, session_dir, runner=run_process, cleanup=default_cleanup, clock=now):
    spec = RUNS[runtime]
    argv = ['/usr/bin/taskset', '-c', detector.CPUSET, *spec['argv']]
    start = clock()
    workload_id = 'benign-%s-%s' % (start.replace(':', '').replace('-', '')[:15], runtime)
    logs = session_dir / 'workloads'
    logs.mkdir(mode=0o700, exist_ok=True)
    log = logs / (workload_id + '.log')
    env = {'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', ''), 'LC_ALL': 'C', 'WARDEN_LAB_CPUSET': detector.CPUSET}
    reason, terminated = None, False
    try:
        code, output, timed_out = runner(argv, cwd=detector.ROOT, env=env, timeout=spec['timeout'])
    except Terminated as stop:
        code, output, timed_out, terminated = None, str(stop), True, True
    if timed_out:
        try:
            cleanup(runtime)
            reason = ('stopped by SIGTERM' if terminated else 'timed out') + '; lab cleaned up'
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            reason = ('stopped by SIGTERM' if terminated else 'timed out') + '; lab cleanup failed: %s' % error
    end = clock()
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write('$ %s\n%s%s' % (' '.join(argv), output, '\n%s\n' % reason if reason else ''))
    record = {'workload_id': workload_id, 'runtime': runtime, 'start': start, 'end': end,
              'ok': code == 0 and not timed_out and spec['pass'] in output, 'exit_code': code, 'command': argv,
              'log': str(log.relative_to(session_dir)), 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
    if reason:
        record['reason'] = reason
    return record, terminated


def append(session_dir, record):
    fd = os.open(session_dir / 'workloads.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as out:
        out.write(json.dumps(record, sort_keys=True) + '\n')


def main(argv=None, runner=run_process, cleanup=default_cleanup):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--session', required=True)
    parser.add_argument('--only', choices=tuple(RUNS))
    args = parser.parse_args(argv)
    os.umask(0o022)  # the runc lab refuses inputs a group or others can write
    session_dir = detector.DATA / args.session
    if not session_dir.is_dir():
        print('no detector session %s' % args.session, file=sys.stderr)
        return 2
    lock = os.open(detector.STATE / 'benign.lock', os.O_WRONLY | os.O_CREAT, 0o600)
    state = detector.load_state()
    runtimes = [args.only] if args.only else list(RUNS)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        for runtime in runtimes:
            append(session_dir, {'workload_id': 'benign-%s-skipped' % runtime, 'runtime': runtime, 'start': now(),
                                 'end': now(), 'ok': False, 'exit_code': None, 'reason': 'another benign run holds the lock'})
        return 1
    def terminate(*_):
        raise Terminated('benign.py got SIGTERM')
    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        status = 0
        for runtime in runtimes:
            terminated = False
            if not state.get('up') or state.get('session') != args.session:
                record = {'workload_id': 'benign-%s-no-detector' % runtime, 'runtime': runtime, 'start': now(), 'end': now(),
                          'ok': False, 'exit_code': None, 'reason': 'detector session %s is not up' % args.session}
            else:
                record, terminated = run_one(runtime, session_dir, runner, cleanup)
            append(session_dir, record)
            print(json.dumps({k: record[k] for k in ('workload_id', 'runtime', 'ok', 'exit_code')}, sort_keys=True), flush=True)
            status |= 0 if record['ok'] else 1
            if terminated:
                return 1
        return status
    finally:
        signal.signal(signal.SIGTERM, previous)
        os.close(lock)


if __name__ == '__main__':
    sys.exit(main())
