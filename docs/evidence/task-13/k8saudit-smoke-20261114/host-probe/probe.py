#!/usr/bin/env python3
"""Do pods in the kind audit lab give the host instance alerts it cannot place?

    make kind-audit-up
    make detect-up                      # the host instance only
    python3 -I -B docs/evidence/task-13/k8saudit-smoke-20261114/host-probe/probe.py [--out DIR] [--idle S] [--rounds N]
    make detect-down
    make kind-audit-down

--out (default this directory) gets probe.jsonl; --idle is the idle phase's
length (default 25 s); --rounds the pod rounds (default 3; 0 for an idle
window only, which needs no kind audit lab).

Benign only. After the host instance's first healthy point, the probe records
the host collector's counters (a heartbeat flushed with SIGUSR1) at the start
and end of each phase: one idle phase of 25 s (only kind's own pods and the
host's other containers), then three phases in which it creates a busybox pod
in warden-lab with the wrapper's labels, runs `kubectl exec ... cat
/etc/hostname` in it, deletes it, and waits 25 s. An alert the collector
cannot place is dropped as unresolved 20 s after it arrives, so 25 s after
the phase's last command it shows in dropped_unresolved. probe.jsonl gets one
line per phase: its times and the counter growth.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / 'detect/falco'))
import detector  # noqa: E402

KUBECTL = [str(ROOT / '.tools/kubectl/kubectl'), '--kubeconfig', str(ROOT / '.cache/kind-warden-lab/kubeconfig.json'),
           '--context', 'kind-warden-lab']
IMAGE = 'docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4'
SETTLE_S = 25
KEYS = ('received', 'dropped_other_container', 'dropped_other_nested', 'dropped_unresolved', 'dropped_host', 'warden_alerts',
        'pending', 'collector_errors')


def now():
    ns = time.time_ns()
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ns // 1_000_000_000)) + '.%09dZ' % (ns % 1_000_000_000)


def kubectl(*args, stdin=None):
    result = subprocess.run(KUBECTL + list(args), text=True, capture_output=True, input=stdin, timeout=180,
                            env={'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', '')})
    return result.returncode, (result.stdout + result.stderr).strip()


def counts(session):
    detector.flush(detector.Host(), session)
    beat = json.loads((detector.DATA / session / 'host/heartbeats.jsonl').read_text().splitlines()[-1])
    return beat['time'], {k: beat['counts'].get(k, 0) for k in KEYS}


def phase(session, name, action, out, settle=SETTLE_S):
    t0, c0 = counts(session)
    steps = action()
    acted = now()
    time.sleep(settle)
    t1, c1 = counts(session)
    record = {'phase': name, 'start': t0, 'actions_done': acted, 'end': t1, 'steps': steps,
              'growth': {k: c1[k] - c0[k] for k in KEYS if k != 'pending'}, 'pending_at_end': c1['pending']}
    with open(out / 'probe.jsonl', 'a') as log:
        log.write(json.dumps(record, sort_keys=True) + '\n')
    print(json.dumps({'phase': name, 'growth': record['growth'], 'pending_at_end': record['pending_at_end']}, sort_keys=True), flush=True)


def pod_round():
    run_id = 'probe-' + secrets.token_hex(12)
    pod = 'probe-' + run_id[-12:]
    labels = {'project': 'warden', 'owner': 'warden-lab', 'warden.dev/run': run_id, 'warden_lab': 'warden-lab', 'warden_run_id': run_id}
    manifest = json.dumps({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': pod, 'namespace': 'warden-lab', 'labels': labels},
                           'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'terminationGracePeriodSeconds': 0,
                                    'containers': [{'name': 'busybox', 'image': IMAGE, 'imagePullPolicy': 'Never',
                                                    'command': ['sh', '-c', 'sleep 600']}]}})
    steps = []
    for label, args, stdin in (('create pod', ('create', '-f', '-'), manifest),
                               ('wait Ready', ('wait', '-n', 'warden-lab', '--for=condition=Ready', 'pod/' + pod, '--timeout=120s'), None),
                               ('exec cat /etc/hostname', ('exec', '-n', 'warden-lab', pod, '--', 'cat', '/etc/hostname'), None),
                               ('delete pod', ('delete', '-n', 'warden-lab', 'pod', pod, '--wait=true', '--timeout=120s'), None)):
        code, output = kubectl(*args, stdin=stdin)
        steps.append({'step': label, 'returncode': code, 'output': output, 'at': now()})
    return steps


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', default=str(HERE))
    parser.add_argument('--idle', type=float, default=SETTLE_S)
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    state = detector.load_state()
    if not state.get('up'):
        raise SystemExit('the detector is not up')
    session = state['session']
    if (out / 'probe.jsonl').exists():
        raise SystemExit('probe.jsonl exists')
    (out / 'session.txt').write_text(session + '\n')
    detector.first_healthy_point(detector.Host(), session)
    phase(session, 'idle', lambda: [], out, settle=args.idle)
    for number in range(1, args.rounds + 1):
        phase(session, 'pod-%d' % number, pod_round, out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
