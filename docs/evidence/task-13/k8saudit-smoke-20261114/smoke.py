#!/usr/bin/env python3
"""Benign end-to-end smoke of the k8saudit path, 2026-11-14 (no attack technique).

    make kind-audit-up
    make detect-up DETECT_K8SAUDIT=1
    python3 -I -B docs/evidence/task-13/k8saudit-smoke-20261114/smoke.py start    # both first healthy points; the wrapper's guards
    python3 -I -B docs/evidence/task-13/k8saudit-smoke-20261114/smoke.py exec     # the labelled pod, then the execution
    python3 -I -B docs/evidence/task-13/k8saudit-smoke-20261114/smoke.py end      # the cutoff, then flushed heartbeats
    make detect-down
    python3 -I -B docs/evidence/task-13/k8saudit-smoke-20261114/smoke.py collect  # the collectors' files and the session's audit lines
    make kind-audit-down
    python3 -I -B docs/evidence/task-13/k8saudit-smoke-20261114/score.py          # import, metrics, report, health

The execution is laid out as a run of attacks/stratus/emulate.py is, with
nothing of an attack in it: in the lab's namespace warden-lab it creates a
ServiceAccount and a busybox pod with the wrapper's pod labels
(warden.dev/run and warden_run_id = the run ID, project=warden,
owner=warden-lab, warden_lab=warden-lab) and runs `cat /etc/hostname` in
the pod with `kubectl exec`; then it deletes both. It writes what the
wrapper writes and the importer reads: receipt.json (run_id = execution_id,
started_at, finished_at, returncode, cleanup_returncode, namespace,
pod_image) and executions.jsonl. Like the wrapper's, the window runs from
just before the first command to just after the cleanup. start also runs
the wrapper's own kubeconfig, node and namespace checks (guard_kubeconfig,
guard_nodes, guard_namespace, imported from attacks/stratus/emulate.py,
which this script does not change) against the lab; nothing runs a Stratus
command.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'detect/falco'))
import detector  # noqa: E402

RUN = HERE / 'run'
LAB = ROOT / '.cache/kind-warden-lab'
KUBECONFIG = LAB / 'kubeconfig.json'
KUBECTL = [str(ROOT / '.tools/kubectl/kubectl'), '--kubeconfig', str(KUBECONFIG), '--context', 'kind-warden-lab']
IMAGE = 'docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4'
NAMESPACE = 'warden-lab'
WATCH_S = 10


def now():
    ns = time.time_ns()
    return datetime.fromtimestamp(ns // 1_000_000_000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + '.%09dZ' % (ns % 1_000_000_000)


def env():
    keep = ('HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS')
    return {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', **{k: os.environ[k] for k in keep if k in os.environ}}


def sh(argv, check=True, timeout=180, stdin=None):
    result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=timeout, env=env(), input=stdin)
    if check and result.returncode != 0:
        raise RuntimeError('%s failed (%d): %s' % (' '.join(argv[:6]), result.returncode, (result.stdout + result.stderr)[-2000:]))
    return result


def kubectl(*args, check=True, stdin=None, timeout=180):
    return sh(KUBECTL + list(args), check=check, stdin=stdin, timeout=timeout)


def write(name, data):
    RUN.mkdir(exist_ok=True)
    (RUN / name).write_text(json.dumps(data, indent=1, sort_keys=True) + '\n')


def session():
    state = detector.load_state()
    if not state.get('up') or 'k8saudit' not in state.get('instances', []):
        raise SystemExit('the detector is not up with the k8saudit instance (make detect-up DETECT_K8SAUDIT=1)')
    return state['session']


def start():
    current = session()
    host = detector.Host()
    points = {'host': detector.first_healthy_point(host, current), 'k8saudit': detector.audit_ready_point(host, current)}
    begin = max(points.values(), key=detector.recorder.ns)
    write('window-start.json', {'session': current, 'start': begin, 'first_healthy_points': points})
    # The wrapper's own checks against this lab (its code is only imported).
    spec = importlib.util.spec_from_file_location('stratus_emulate', ROOT / 'attacks/stratus/emulate.py')
    emulate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(emulate)
    config = json.loads(KUBECONFIG.read_text())
    emulate.guard_kubeconfig(config)
    nodes = json.loads(kubectl('get', 'nodes', '-o', 'json').stdout)
    emulate.guard_nodes(nodes)
    namespace = json.loads(kubectl('get', 'namespace', NAMESPACE, '-o', 'json').stdout)
    emulate.guard_namespace(namespace)
    mode = oct(KUBECONFIG.stat().st_mode & 0o777)
    server = urlsplit(config['clusters'][0]['cluster']['server'])
    write('wrapper-guards.json', {'guard_kubeconfig': 'passed', 'guard_nodes': 'passed', 'guard_namespace': 'passed',
                                  'kubeconfig_mode': mode, 'namespace_labels': namespace['metadata'].get('labels'),
                                  'current_context': config['current-context'],
                                  'server_host': server.hostname, 'user_fields': sorted(config['users'][0]['user']),
                                  'nodes': [n['metadata']['name'] for n in nodes['items']]})
    node = json.loads(sh(['/usr/bin/docker', 'container', 'inspect', 'warden-lab-control-plane']).stdout)[0]
    write('environment.json', {
        'node_container': {'name': 'warden-lab-control-plane', 'image': node['Config']['Image'], 'image_id': node['Image'],
                           'cpuset_cpus': node['HostConfig']['CpusetCpus'], 'labels': node['Config']['Labels'],
                           'started_at': node['State']['StartedAt']},
        'kubernetes': [{'name': n['metadata']['name'], 'kubelet': n['status']['nodeInfo']['kubeletVersion'],
                        'runtime': n['status']['nodeInfo']['containerRuntimeVersion']} for n in nodes['items']],
        'kind': sh([str(ROOT / '.tools/kind/kind'), 'version']).stdout.strip(),
        'kubectl': json.loads(sh(KUBECTL[:1] + ['version', '--client', '-o', 'json']).stdout)['clientVersion']['gitVersion'],
        'tools_receipts': {name: hashlib.sha256((ROOT / '.tools' / name).read_bytes()).hexdigest()
                           for name in ('falco-k8saudit/receipt.json', 'stratus/receipt.json')}})
    print(begin)


def manifest(kind, name, run_id, **extra):
    # The labels attacks/stratus/emulate.py's pod_configuration gives its pods.
    labels = {'project': 'warden', 'owner': 'warden-lab', 'warden.dev/run': run_id, 'warden_lab': 'warden-lab',
              'warden_run_id': run_id}
    return json.dumps({'apiVersion': 'v1', 'kind': kind, 'metadata': {'name': name, 'namespace': NAMESPACE, 'labels': labels},
                       **extra})


def execute():
    session()
    if (RUN / 'receipt.json').exists():
        raise SystemExit('run/receipt.json exists; the smoke has run')
    run_id = 'smoke-' + secrets.token_hex(12)
    pod, account = 'smoke-' + run_id[-12:], 'smoke-sa-' + run_id[-12:]
    spec = {'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'terminationGracePeriodSeconds': 0,
                     'containers': [{'name': 'busybox', 'image': IMAGE, 'imagePullPolicy': 'Never',
                                     'command': ['sh', '-c', 'sleep 600']}]}}
    steps = []

    def step(label, *args, stdin=None):
        result = kubectl(*args, check=False, stdin=stdin)
        steps.append({'command': label, 'returncode': result.returncode, 'output': (result.stdout + result.stderr).strip(),
                      'finished_at': now()})
        return result.returncode

    started = now()
    codes = [step('kubectl create -f - (Pod %s, labelled)' % pod, 'create', '-f', '-', stdin=manifest('Pod', pod, run_id, **spec)),
             step('kubectl wait --for=condition=Ready pod/%s' % pod, 'wait', '-n', NAMESPACE, '--for=condition=Ready',
                  'pod/' + pod, '--timeout=120s'),
             step('kubectl create -f - (ServiceAccount %s, labelled)' % account, 'create', '-f', '-',
                  stdin=manifest('ServiceAccount', account, run_id)),
             step('kubectl exec -n %s %s -- cat /etc/hostname' % (NAMESPACE, pod), 'exec', '-n', NAMESPACE, pod, '--',
                  'cat', '/etc/hostname')]
    events = json.loads(kubectl('get', 'events', '-n', NAMESPACE, '--field-selector', 'involvedObject.name=' + pod,
                                '-o', 'json').stdout)
    cleanup = [step('kubectl delete pod %s' % pod, 'delete', '-n', NAMESPACE, 'pod', pod, '--wait=true', '--timeout=120s'),
               step('kubectl delete serviceaccount %s' % account, 'delete', '-n', NAMESPACE, 'serviceaccount', account)]
    finished = now()
    code = next((c for c in codes if c), 0)
    receipt = {'source': 'warden-k8saudit-smoke', 'technique': 'benign kubectl exec smoke (no Stratus technique)',
               'run_id': run_id, 'execution_id': run_id, 'started_at': started, 'finished_at': finished,
               'returncode': code, 'cleanup_returncode': next((c for c in cleanup if c), 0), 'namespace': NAMESPACE,
               'pod_image': IMAGE, 'steps': steps,
               'pod_events': [{'reason': e.get('reason'), 'message': e.get('message')} for e in events['items']]}
    write('receipt.json', receipt)
    (RUN / 'executions.jsonl').write_text(json.dumps({'execution_id': run_id, 'run_id': run_id, 'technique_id': 'T1609',
                                                      'executed_at': started, 'outcome': 'succeeded' if code == 0 else 'failed'},
                                                     sort_keys=True) + '\n')
    time.sleep(WATCH_S)
    left = kubectl('get', 'pods,serviceaccounts', '-n', NAMESPACE, '-l', 'warden.dev/run=' + run_id, '-o', 'name').stdout.strip()
    write('left-after-run.json', {'selector': 'warden.dev/run=' + run_id, 'objects': left.split() if left else []})
    print(json.dumps({k: receipt[k] for k in ('run_id', 'returncode', 'cleanup_returncode', 'started_at', 'finished_at')},
                     sort_keys=True))


def end():
    current = session()
    begin = json.loads((RUN / 'window-start.json').read_text())
    cutoff = now()
    host = detector.Host()
    detector.flush(host, current)
    detector.flush(host, current, instance='k8saudit')
    write('window.json', {'session': current, 'start': begin['start'], 'end': cutoff})
    print(cutoff)


def copy(source, target, gzip_over=1 << 20):
    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.iterdir()):
        if not path.is_file():
            continue
        if path.stat().st_size > gzip_over:
            with open(path, 'rb') as src, gzip.GzipFile(target / (path.name + '.gz'), 'wb', compresslevel=9, mtime=0) as out:
                shutil.copyfileobj(src, out)
        else:
            shutil.copyfile(path, target / path.name)


def collect():
    window = json.loads((RUN / 'window.json').read_text())
    state = detector.load_state()
    if state.get('up'):
        raise SystemExit('bring the detector down first (make detect-down)')
    current = window['session']
    copy(detector.DATA / current / 'host', HERE / 'collector-host')
    copy(detector.DATA / current / 'k8saudit', HERE / 'collector-k8saudit')
    host_dir = HERE / 'host'
    host_dir.mkdir(exist_ok=True)
    for name in ('host-before', 'host-after', 'host-compare'):
        shutil.copyfile(detector.STATE / ('%s-%s.json' % (name, current)), host_dir / ('%s.json' % name))
    # The audit log lines of the session: from where the feed started.
    beats = [json.loads(line) for line in (detector.DATA / current / 'k8saudit/heartbeats.jsonl').read_text().splitlines()]
    offset = beats[0]['feed']['start_offset']
    with open(LAB / 'audit/audit.log', 'rb') as log:
        log.seek(offset)
        lines = log.read()
    with gzip.GzipFile(HERE / 'audit-session.jsonl.gz', 'wb', compresslevel=9, mtime=0) as out:
        out.write(lines)
    write('audit-session.json', {'from_offset': offset, 'bytes': len(lines), 'lines': lines.count(b'\n'),
                                 'sha256': hashlib.sha256(lines).hexdigest(), 'source': '.cache/kind-warden-lab/audit/audit.log'})
    print('collected session %s' % current)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('start', 'exec', 'end', 'collect'))
    args = parser.parse_args(argv)
    {'start': start, 'exec': execute, 'end': end, 'collect': collect}[args.command]()
    return 0


if __name__ == '__main__':
    sys.exit(main())
