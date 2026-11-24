#!/usr/bin/env python3
"""Drive the 2026-11-14 Atomic round on runc under the online detector.

    make detect-up
    python3 -I -B docs/evidence/task-13/atomic-20261114/drive.py start   # the first healthy point
    python3 -I -B docs/evidence/task-13/atomic-20261114/drive.py runs    # 6 Atomics x 5, one container each
    python3 -I -B docs/evidence/task-13/atomic-20261114/drive.py end     # the cutoff, then a flushed heartbeat
    make detect-down

Each run gets a fresh container: Docker's runc runtime, ubuntu:24.04 by image
ID, Warden's labels (project=warden, owner=warden-lab) and its own
warden.dev/run, no network, read-only root with a 1 MiB noexec /tmp, no
capabilities. attacks/atomic/run.sh runs the reviewed Atomic inside it. A
watcher reads the host collector's alerts.jsonl from before the wrapper starts
until 10 s after it ends and notes when each of the container's alerts first
appears there (a 10 ms poll, so an upper bound on its arrival). Then the
container is removed. Rounds rotate the order of the six Atomics. After each
round, `make detect-status`.

The detector, wrapper and scoring are the repository's own; this only
sequences them and records what it saw, in run/ and runs/.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'detect/falco'))
import detector  # noqa: E402

CPUSET = '0-7,16-31'
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
IMAGE = 'sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55'  # ubuntu:24.04
ATOMIC_ROOT = ROOT / '.tools/atomic/atomic-red-team'
RECEIPT = ROOT / '.tools/atomic/atomic-red-team.receipt.json'
# The order of round 1; round r starts r-1 places later.
ORDER = ('46959285-906d-40fa-9437-5a439accd878',   # T1552.004 Discover Private SSH Keys
         '7c247dc7-5128-4643-907b-73a76d9135c3',   # T1552.004 Copy Private SSH Keys with CP
         '37807632-d3da-442e-8c2e-00f44928ff8f',   # T1552.001 Find AWS credentials
         '085fe567-ac84-47c7-ac4c-2688ce28265b',   # T1201 Examine password complexity policy - Ubuntu
         '039b4b10-2900-404b-b67f-4b6d49aa6499',   # T1070.004 Overwrite and delete a file with shred
         '486e88ea-4f56-470f-9b57-3f4d73f39133')   # T1082 Hostname Discovery (control)
ROUNDS = 5
WATCH_S = 10
POLL_S = 0.01


def now():
    ns = time.time_ns()
    return datetime.fromtimestamp(ns // 1_000_000_000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + '.%09dZ' % (ns % 1_000_000_000)


def env():
    keep = ('HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS')
    return {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', **{k: os.environ[k] for k in keep if k in os.environ}}


def sh(argv, check=True, timeout=180):
    result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=timeout, env=env())
    if check and result.returncode != 0:
        raise RuntimeError('%s failed (%d): %s' % (' '.join(argv[:6]), result.returncode, (result.stdout + result.stderr)[-2000:]))
    return result


def docker(*args, check=True):
    return sh(DOCKER + list(args), check=check)


def canonical(event):
    """The digest alert_import.py gives the event (its alert ID is falco-<digest>)."""
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                                     allow_nan=False).encode()).hexdigest()


def session():
    state = detector.load_state()
    if not state.get('up'):
        raise SystemExit('the detector is not up')
    return state['session']


class Watch(threading.Thread):
    """When each of one container's alerts first appears in alerts.jsonl."""

    def __init__(self, path, short_id):
        super().__init__(daemon=True)
        self.path, self.short_id = path, short_id
        self.offset = path.stat().st_size if path.exists() else 0
        self.stop_at, self.seen, self.errors = None, {}, []

    def run(self):
        pending = b''
        while self.stop_at is None or time.monotonic() < self.stop_at:
            chunk = b''
            if self.path.exists():
                with open(self.path, 'rb') as stream:
                    stream.seek(self.offset)
                    chunk = stream.read()
            stamp = now()
            if chunk:
                self.offset += len(chunk)
                *lines, pending = (pending + chunk).split(b'\n')
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                    except ValueError as error:
                        self.errors.append(str(error))
                        continue
                    if (event.get('output_fields') or {}).get('container.id') == self.short_id:
                        digest = canonical(event)
                        self.seen.setdefault(digest, {'alert_sha256': digest, 'rule': event.get('rule'),
                                                      'event_time': event.get('time'), 'observed_at': stamp})
            time.sleep(POLL_S)


def one(index, number, guid, sha, commit, alerts):
    token = secrets.token_hex(12)
    run_id, name = 'atomic-' + token, 'warden-lab-atomic-' + token
    out = HERE / 'runs' / ('%02d-%s' % (index, run_id))
    record = {'index': index, 'round': number, 'atomic_guid': guid, 'run_id': run_id, 'container': name, 'out': out.name}
    try:
        record['created_at'] = now()
        record['container_id'] = docker(
            'run', '--detach', '--name', name, '--runtime', 'runc', '--label', 'project=warden',
            '--label', 'owner=warden-lab', '--label', 'warden.dev/run=' + run_id, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--ipc', 'private', '--pids-limit', '64',
            '--memory', '64m', '--memory-swap', '64m', '--cpus', '1', '--cpuset-cpus', CPUSET,
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=1m', '--log-driver', 'json-file', '--log-opt', 'max-size=1m',
            '--entrypoint', '/bin/sleep', IMAGE, '300').stdout.strip()
        time.sleep(1)
        watch = Watch(alerts, record['container_id'][:12])
        watch.start()
        record['wrapper_started_at'] = now()
        wrapper = sh(['/usr/bin/taskset', '-c', CPUSET, '/usr/bin/bash', str(ROOT / 'attacks/atomic/run.sh'),
                      '--ack-dedicated-lab', '--docker', '/usr/bin/docker', '--docker-host', 'unix:///var/run/docker.sock',
                      '--container', name, '--git', '/usr/bin/git', '--atomic-root', str(ATOMIC_ROOT),
                      '--atomic-commit', commit, '--atomic-guid', guid, '--yaml-sha256', sha, '--out', str(out)], check=False)
        record['wrapper_finished_at'] = now()
        record['wrapper_exit'] = wrapper.returncode
        record['wrapper_stderr'] = wrapper.stderr[-2000:]
        watch.stop_at = time.monotonic() + WATCH_S
        watch.join()
        record['arrivals'] = sorted(watch.seen.values(), key=lambda a: a['observed_at'])
        record['watch_errors'] = watch.errors
        record['watch_ended_at'] = now()
    finally:
        if docker('container', 'inspect', name, check=False).returncode == 0:
            docker('rm', '--force', name)
        record['removed_at'] = now()
    time.sleep(1)
    with open(HERE / 'run/runs.jsonl', 'a') as log:
        log.write(json.dumps(record, sort_keys=True) + '\n')
    return record


def runs():
    current = session()
    left = docker('ps', '-a', '--filter', 'name=warden-lab-atomic-', '--format', '{{.Names}}').stdout.split()
    if left:
        raise SystemExit('Atomic targets already exist: %s' % ' '.join(left))
    if (HERE / 'run/runs.jsonl').exists():
        raise SystemExit('run/runs.jsonl exists; this round has run')
    receipt = json.loads(RECEIPT.read_text())
    sha = {f['path']: f['sha256'] for f in receipt['reviewed_files']}
    sys.path.insert(0, str(ROOT / 'attacks/atomic'))
    import emulate  # noqa: E402
    alerts = detector.DATA / current / 'host' / 'alerts.jsonl'
    index = 0
    for number in range(1, ROUNDS + 1):
        shift = number - 1
        for guid in ORDER[shift % len(ORDER):] + ORDER[:shift % len(ORDER)]:
            index += 1
            record = one(index, number, guid, sha[emulate.TESTS[guid]['path']], receipt['commit'], alerts)
            print('%02d round %d %s exit %s alerts %d' % (index, number, emulate.TESTS[guid]['slug'],
                                                         record.get('wrapper_exit'), len(record.get('arrivals') or [])), flush=True)
        status = sh(['/usr/bin/make', '--no-print-directory', 'detect-status'], check=False)
        (HERE / 'run' / ('detect-status-round-%d.log' % number)).write_text(status.stdout + status.stderr)


def start():
    current = session()
    started = detector.first_healthy_point(detector.Host(), current)
    (HERE / 'run/window-start.json').write_text(json.dumps({'session': current, 'start': started}) + '\n')
    print(started)


def end():
    current = session()
    start_record = json.loads((HERE / 'run/window-start.json').read_text())
    ended = now()
    detector.flush(detector.Host(), current)
    (HERE / 'run/window.json').write_text(json.dumps({'session': current, 'start': start_record['start'], 'end': ended}) + '\n')
    print(ended)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('start', 'runs', 'end'))
    args = parser.parse_args(argv)
    {'start': start, 'runs': runs, 'end': end}[args.command]()
    return 0


if __name__ == '__main__':
    sys.exit(main())
