#!/usr/bin/env python3
"""Drive the 2026-11-14 Stratus round (Kubernetes) on the kind audit lab: attempt 3.

    make kind-audit-up
    make detect-up DETECT_K8SAUDIT=1
    python3 -I -B docs/evidence/task-13/stratus-20261114/drive.py start     # both first healthy points, the lab's inventory
    python3 -I -B docs/evidence/task-13/stratus-20261114/drive.py runs      # 8 techniques x 5, one wrapper run each
    python3 -I -B docs/evidence/task-13/stratus-20261114/drive.py end       # the cutoff, then flushed heartbeats
    make detect-down
    python3 -I -B docs/evidence/task-13/stratus-20261114/drive.py collect   # the collectors' files and the session's audit lines
    make kind-audit-down
    python3 -I -B docs/evidence/task-13/stratus-20261114/score.py

Attempt 1 (attempt-1/) and attempt 2 (attempt-2/) stopped early; each
keeps its own driver. Each run is one invocation of the user's wrapper
(attacks/stratus/run.sh at 2533736, unchanged here) with a new --out
directory under .cache/stratus-20261114-attempt3/runs/ (ignored; it holds
the run's Stratus state and its downloads, and stays out of the evidence).
The wrapper runs in .cache/stratus-20261114-attempt3/: its own kubectl
checks run without HOME,
and kubectl puts its discovery cache in the working directory. The runs are
sequential; rounds rotate the order of the eight techniques, and after each
round `make detect-status`.

Before each run: `make kind-audit-check-empty` must exit 0, the three
objects create-admin-clusterrole is known to leave must be absent (each
looked up by name), and the by-name inventory of the cluster-scoped
objects, the namespaces and kube-system must equal the one taken at start.
After it: the namespace check every 3 s until it exits 0 (at most 180 s),
and the inventory again.

create-admin-clusterrole fails on Kubernetes 1.24 and later (it waits for a
legacy token Secret) and leaves its ClusterRole, ClusterRoleBinding and
kube-system ServiceAccount: it has no Terraform prerequisites, so its
failed detonation leaves it COLD and Stratus's clean-up does not revert it.
The wrapper (since 9adf201) asks `stratus status`, finds COLD and skips its
fallback cleanup (cleanup_mode "skipped already COLD", cleanup_returncode
0). After each of its runs, the driver deletes exactly those three objects
by name and records each command and its result, then checks again. That
is the one known failure, accepted only with that exact signature:
detonation nonzero, cleanup_mode "skipped already COLD" after a status
check that read COLD, no Stratus state left for the technique, nothing left
but those three objects. The round stops, for a person to look, on any
other result of create-admin-clusterrole, on a nonzero detonation of any
other technique, on any nonzero cleanup_returncode, on a failed namespace
check, on anything else left, or if the wrapper refuses (exit 2) or writes
no receipt. `drive.py restore --note TEXT` is for
a stop: it deletes by name what the stopped run left outside warden-lab and
writes run/resumed-<next>.json, which `runs --from <next>` requires.

While a run's Stratus works, a watcher copies Terraform's lock file (Stratus
removes the technique's directory at its clean-up), and after the run the
Terraform binary and the providers in Stratus's plugin cache are hashed;
score.py compares them with .tools/stratus/receipt.json.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'detect/falco'))
import detector  # noqa: E402

CPUSET = '0-7,16-31'
RUN = HERE / 'run'
RUNS = HERE / 'runs'
PRIVATE = ROOT / '.cache/stratus-20261114-attempt3/runs'
WRAPPER_CWD = ROOT / '.cache/stratus-20261114-attempt3'
LAB = ROOT / '.cache/kind-warden-lab'
KUBECONFIG = LAB / 'kubeconfig.json'
KUBECTL_BIN = ROOT / '.tools/kubectl/kubectl'
KUBECTL = [str(KUBECTL_BIN), '--kubeconfig', str(KUBECONFIG), '--context', 'kind-warden-lab',
           '--cache-dir', str(LAB / 'kubectl-cache')]
STRATUS = ROOT / '.tools/stratus/stratus'
TOOLS_RECEIPT = ROOT / '.tools/stratus/receipt.json'
IMAGE = 'docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4'
NAMESPACE = 'warden-lab'
# Round 1's order; round r starts r-1 places later. create-admin-clusterrole
# is first so that its expected failure and whatever it leaves show at once.
ORDER = ('k8s.persistence.create-admin-clusterrole',
         'k8s.privilege-escalation.privileged-pod',
         'k8s.credential-access.steal-serviceaccount-token',
         'k8s.privilege-escalation.hostpath-volume',
         'k8s.privilege-escalation.nodes-proxy',
         'k8s.credential-access.dump-secrets',
         'k8s.persistence.create-token',
         'k8s.persistence.create-client-certificate')
ROUNDS = 5
WRAPPER_TIMEOUT_S = 480     # the wrapper's own bounds: detonate 240 s, cleanup 120 s
EMPTY_WAIT_S = 180
EMPTY_POLL_S = 3
# Compared by name before and after every run: what a technique could leave
# outside warden-lab.
INVENTORY = (('namespaces', None), ('clusterroles', None), ('clusterrolebindings', None),
             ('certificatesigningrequests', None), ('serviceaccounts', 'kube-system'), ('roles', 'kube-system'),
             ('rolebindings', 'kube-system'), ('pods', 'kube-system'), ('secrets', 'kube-system'))
ADMIN = 'k8s.persistence.create-admin-clusterrole'
# What create-admin-clusterrole leaves when it fails (attempt 1, run 1), as the inventory names them.
KNOWN_LEFTOVERS = {'cluster/clusterroles': ('clusterrole.rbac.authorization.k8s.io/stratus-red-team-clusterrole',),
                   'cluster/clusterrolebindings': ('clusterrolebinding.rbac.authorization.k8s.io/stratus-red-team-crb',),
                   'kube-system/serviceaccounts': ('serviceaccount/stratus-red-team-serviceaccount',)}
PROVIDER = re.compile(r'terraform-provider-[a-z0-9]+_v[0-9][0-9A-Za-z.+-]*_x5')


def now():
    ns = time.time_ns()
    return datetime.fromtimestamp(ns // 1_000_000_000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + '.%09dZ' % (ns % 1_000_000_000)


def env():
    keep = ('HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS')
    return {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', **{k: os.environ[k] for k in keep if k in os.environ}}


def sh(argv, check=True, timeout=180, cwd=ROOT):
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=timeout, env=env())
    if check and result.returncode != 0:
        raise RuntimeError('%s failed (%d): %s' % (' '.join(argv[:6]), result.returncode, (result.stdout + result.stderr)[-2000:]))
    return result


def make(target, check=False, timeout=300):
    return sh(['/usr/bin/make', '--no-print-directory', target], check=check, timeout=timeout)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + '\n')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def session():
    state = detector.load_state()
    if not state.get('up') or 'k8saudit' not in state.get('instances', []):
        raise SystemExit('the detector is not up with the k8saudit instance (make detect-up DETECT_K8SAUDIT=1)')
    return state['session']


def inventory():
    """Names only (no object bodies are printed or kept)."""
    found = {}
    for resource, namespace in INVENTORY:
        args = ['get', resource, '-o', 'name'] + (['-n', namespace] if namespace else [])
        found['%s/%s' % (namespace or 'cluster', resource)] = sorted(sh(KUBECTL + args).stdout.split())
    return found


def difference(before, after):
    out = {}
    for key in sorted(set(before) | set(after)):
        added = sorted(set(after.get(key, [])) - set(before.get(key, [])))
        removed = sorted(set(before.get(key, [])) - set(after.get(key, [])))
        if added or removed:
            out[key] = {'added': added, 'removed': removed}
    return out


def check_empty():
    started = now()
    result = make('kind-audit-check-empty')
    lines = [line for line in result.stdout.splitlines() if line.startswith('{')]
    return {'started_at': started, 'finished_at': now(), 'returncode': result.returncode,
            'result': json.loads(lines[-1]) if lines else None,
            'stderr': result.stderr.strip()[-1000:]}


class Providers(threading.Thread):
    """Hash each provider executable under a run's HOME once Terraform's
    lock file for it is there: Stratus deletes the technique's directory at
    its clean-up."""

    def __init__(self, home):
        super().__init__(daemon=True)
        self.home, self.stop, self.seen, self.locks, self.errors = home, False, {}, {}, []

    def scan(self):
        if not self.home.exists():
            return
        for lock in self.home.rglob('.terraform.lock.hcl'):
            key = str(lock.relative_to(self.home.parent))
            if key not in self.locks:
                try:
                    self.locks[key] = {'sha256': sha256(lock), 'text': lock.read_text(), 'seen_at': now()}
                except OSError as error:
                    self.errors.append('%s: %s' % (key, error))
            for path in (lock.parent / '.terraform').rglob('*') if (lock.parent / '.terraform').exists() else ():
                name = str(path.relative_to(self.home.parent))
                if name in self.seen or not PROVIDER.fullmatch(path.name) or path.is_symlink() or not path.is_file():
                    continue
                try:
                    self.seen[name] = {'path': name, 'bytes': path.stat().st_size, 'sha256': sha256(path), 'hashed_at': now()}
                except OSError as error:
                    self.errors.append('%s: %s' % (name, error))

    def run(self):
        while not self.stop:
            try:
                self.scan()
            except OSError as error:
                self.errors.append(str(error))
            time.sleep(0.5)


def terraform_binaries(out):
    found = []
    for path in sorted((out / 'home').rglob('*')):
        if path.is_file() and not path.is_symlink() and (path.name == 'terraform' or PROVIDER.fullmatch(path.name)):
            found.append({'path': str(path.relative_to(out)), 'bytes': path.stat().st_size, 'sha256': sha256(path)})
    return found


def scope(key):
    namespace = key.split('/')[0]
    return [] if namespace == 'cluster' else ['-n', namespace]


def known_absent():
    """Each object create-admin-clusterrole is known to leave, looked up by name."""
    found = []
    for key, names in sorted(KNOWN_LEFTOVERS.items()):
        for name in names:
            args = ['get', name, '--ignore-not-found', '-o', 'name'] + scope(key)
            result = sh(KUBECTL + args, check=False)
            found.append({'name': name, 'scope': key, 'command': 'kubectl ' + ' '.join(args), 'returncode': result.returncode,
                          'present': bool(result.stdout.strip()), 'stderr': result.stderr.strip()[-500:]})
    return {'all_absent': all(f['returncode'] == 0 and not f['present'] for f in found), 'lookups': found}


def split_known(left):
    """(the known create-admin-clusterrole objects, everything else) of an inventory difference."""
    known, other = {}, {}
    for key, change in left.items():
        added = [n for n in change['added'] if n in KNOWN_LEFTOVERS.get(key, ())]
        rest = {'added': [n for n in change['added'] if n not in added], 'removed': change['removed']}
        if added:
            known[key] = added
        if rest['added'] or rest['removed']:
            other[key] = rest
    return known, other


def delete_known(known):
    steps = []
    for key, names in sorted(known.items()):
        for name in names:
            args = ['delete', name, '--wait=true', '--timeout=60s'] + scope(key)
            result = sh(KUBECTL + args, check=False)
            steps.append({'name': name, 'scope': key, 'command': 'kubectl ' + ' '.join(args), 'returncode': result.returncode,
                          'output': (result.stdout + result.stderr).strip()[-1000:], 'finished_at': now()})
    return steps


def stratus_state(out, technique):
    """What Stratus keeps for the technique in the run's HOME (names only)."""
    directory = out / 'home/.stratus-red-team' / technique
    return sorted(str(p.relative_to(out)) for p in directory.rglob('*')) if directory.exists() else None


def one(index, number, technique, stratus_sha256, baseline):
    short = technique.rsplit('.', 1)[1]
    out = PRIVATE / ('%02d-%s' % (index, short))
    record = {'index': index, 'round': number, 'technique': technique, 'out': out.name}
    record['check_empty_before'] = check_empty()
    record['known_absent_before'] = known_absent()
    record['inventory_before_run'] = difference(baseline, inventory())
    if (record['check_empty_before']['returncode'] != 0 or not record['known_absent_before']['all_absent']
            or record['inventory_before_run']):
        record['stopped'] = 'the lab is not as at start before the run'
        return record
    watcher = Providers(out / 'home')
    watcher.start()
    record['wrapper_started_at'] = now()
    record['wrapper_cwd'] = str(WRAPPER_CWD.relative_to(ROOT))
    wrapper = sh(['/usr/bin/taskset', '-c', CPUSET, '/usr/bin/bash', str(ROOT / 'attacks/stratus/run.sh'),
                  '--ack-dedicated-lab', '--technique', technique, '--stratus', str(STRATUS),
                  '--stratus-sha256', stratus_sha256, '--kubectl', str(KUBECTL_BIN), '--kubeconfig', str(KUBECONFIG),
                  '--pod-image', IMAGE, '--out', str(out)], check=False, timeout=WRAPPER_TIMEOUT_S, cwd=WRAPPER_CWD)
    record['wrapper_finished_at'] = now()
    watcher.scan()
    watcher.stop = True
    watcher.join()
    record['wrapper_exit'] = wrapper.returncode
    record['wrapper_stdout'] = wrapper.stdout.strip()[-1000:]
    record['wrapper_stderr'] = wrapper.stderr.strip()[-2000:]
    receipt = json.loads((out / 'receipt.json').read_text()) if (out / 'receipt.json').exists() else None
    if receipt:
        record.update({k: receipt.get(k) for k in ('run_id', 'correlation_id', 'started_at', 'finished_at', 'returncode',
                                                   'cleanup_returncode', 'cleanup_mode', 'cleanup_invoked',
                                                   'cleanup_command_returncode', 'cleanup_status_check')})
        target = RUNS / out.name
        target.mkdir(parents=True, exist_ok=False)
        for name in ('receipt.json', 'executions.jsonl'):
            if (out / name).exists():
                shutil.copyfile(out / name, target / name)
    record['stratus_state_after'] = stratus_state(out, technique)
    # Afterwards: warden-lab empty again, nothing left elsewhere.
    attempts, deadline = [], time.monotonic() + EMPTY_WAIT_S
    while True:
        attempts.append(check_empty())
        if attempts[-1]['returncode'] == 0 or time.monotonic() > deadline:
            break
        time.sleep(EMPTY_POLL_S)
    record['check_empty_after'] = {'attempts': len(attempts), 'first': attempts[0], 'last': attempts[-1]}
    record['left_outside_namespace'] = difference(baseline, inventory())
    known, other = split_known(record['left_outside_namespace']) if technique == ADMIN else ({}, record['left_outside_namespace'])
    record['downloads'] = {'during_run': sorted(watcher.seen.values(), key=lambda r: r['path']),
                           'lock_files': watcher.locks, 'watch_errors': watcher.errors,
                           'after_run': terraform_binaries(out)}
    known_failure = bool(receipt) and technique == ADMIN and receipt['returncode'] != 0 and \
        receipt.get('cleanup_mode') == 'skipped already COLD' and receipt['cleanup_returncode'] == 0 and \
        (receipt.get('cleanup_status_check') or {}).get('state') == 'COLD' and record['stratus_state_after'] is None
    if wrapper.returncode == 2 or receipt is None:
        record['stopped'] = 'the wrapper refused or wrote no receipt (exit %d)' % wrapper.returncode
    elif technique == ADMIN and not known_failure:
        record['stopped'] = 'create-admin-clusterrole did not fail as known (detonation %d, cleanup %d, %s)' % (
            receipt['returncode'], receipt['cleanup_returncode'], receipt.get('cleanup_mode'))
    elif technique != ADMIN and receipt['returncode'] != 0:
        record['stopped'] = 'detonation returned %d' % receipt['returncode']
    elif receipt['cleanup_returncode'] != 0:
        record['stopped'] = 'cleanup returned %d' % receipt['cleanup_returncode']
    elif attempts[-1]['returncode'] != 0:
        record['stopped'] = 'warden-lab not empty %d s after the run' % EMPTY_WAIT_S
    elif other:
        record['stopped'] = 'objects left outside warden-lab'
    if known_failure and not other:
        record['admin_known_failure'] = ('create-admin-clusterrole: detonation %d; stratus status read COLD, so the '
                                         'fallback cleanup was skipped; no Stratus state left for the technique; nothing '
                                         'left but its known objects' % receipt['returncode'])
    if known and not record.get('stopped'):
        steps = delete_known(known)
        after = {'known_absent': known_absent(), 'inventory': difference(baseline, inventory()), 'check_empty': check_empty()}
        record['known_deleted'] = {'left': known, 'steps': steps, 'after': after}
        if (any(s['returncode'] for s in steps) or not after['known_absent']['all_absent'] or after['inventory']
                or after['check_empty']['returncode'] != 0):
            record['stopped'] = 'the known create-admin-clusterrole objects were not removed'
    return record


def runs(first):
    current = session()
    if not (RUN / 'window-start.json').exists():
        raise SystemExit('run start first')
    baseline = json.loads((RUN / 'inventory-before.json').read_text())
    done = [json.loads(line) for line in (RUN / 'runs.jsonl').read_text().splitlines()] if (RUN / 'runs.jsonl').exists() else []
    if first != len(done) + 1:
        raise SystemExit('runs.jsonl holds %d runs; the next run is %d, not %d' % (len(done), len(done) + 1, first))
    if done and done[-1].get('stopped') and not (RUN / ('resumed-%02d.json' % first)).exists():
        raise SystemExit('run %d stopped (%s); record what was done in run/resumed-%02d.json first'
                         % (done[-1]['index'], done[-1]['stopped'], first))
    PRIVATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    stratus_sha256 = json.loads(TOOLS_RECEIPT.read_text())['files_sha256']['stratus']
    plan = []
    for number in range(1, ROUNDS + 1):
        shift = (number - 1) % len(ORDER)
        plan += [(number, technique) for technique in ORDER[shift:] + ORDER[:shift]]
    for index, (number, technique) in enumerate(plan, start=1):
        if index < first:
            continue
        record = one(index, number, technique, stratus_sha256, baseline)
        record['session'] = current
        with open(RUN / 'runs.jsonl', 'a') as log:
            log.write(json.dumps(record, sort_keys=True) + '\n')
        print('%02d round %d %s wrapper %s detonate %s cleanup %s (%s) empty-after %s%s%s' % (
            index, number, technique, record.get('wrapper_exit'), record.get('returncode'), record.get('cleanup_returncode'),
            record.get('cleanup_mode'), (record.get('check_empty_after') or {}).get('last', {}).get('returncode'),
            ' known objects deleted %s' % [s['returncode'] for s in record['known_deleted']['steps']]
            if record.get('known_deleted') else '',
            ' STOPPED: ' + record['stopped'] if record.get('stopped') else ''), flush=True)
        if record.get('stopped'):
            return 1
        if index % len(ORDER) == 0:
            status = make('detect-status')
            (RUN / ('detect-status-round-%d.log' % number)).write_text(status.stdout + status.stderr)
    print('all %d runs done' % len(plan), flush=True)
    return 0


# What restore may delete: the kinds a technique left outside warden-lab, by
# the exact names the inventory recorded.
RESTORABLE = {'cluster/clusterroles', 'cluster/clusterrolebindings', 'cluster/certificatesigningrequests',
              'kube-system/serviceaccounts', 'kube-system/roles', 'kube-system/rolebindings'}


def restore(note):
    """After a stopped run: delete exactly what it left outside warden-lab
    (by the names in its record), then check that the inventory equals the
    one taken at start and that warden-lab is empty. Writes
    run/resumed-<next>.json, which runs --from <next> requires."""
    session()
    records = [json.loads(line) for line in (RUN / 'runs.jsonl').read_text().splitlines()]
    record = records[-1]
    target = RUN / ('resumed-%02d.json' % (record['index'] + 1))
    if not record.get('stopped') or target.exists():
        raise SystemExit('the last run did not stop, or %s exists' % target.name)
    left = record['left_outside_namespace']
    if set(left) - RESTORABLE or any(change['removed'] for change in left.values()):
        raise SystemExit('not something restore deletes: %s' % json.dumps(left, sort_keys=True))
    steps = []
    for key, change in sorted(left.items()):
        namespace = key.split('/')[0]
        for name in change['added']:
            args = ['delete', name, '--wait=true', '--timeout=60s'] + ([] if namespace == 'cluster' else ['-n', namespace])
            result = sh(KUBECTL + args, check=False)
            steps.append({'command': 'kubectl ' + ' '.join(args), 'returncode': result.returncode,
                          'output': (result.stdout + result.stderr).strip()[-1000:], 'finished_at': now()})
    baseline = json.loads((RUN / 'inventory-before.json').read_text())
    after = difference(baseline, inventory())
    empty = check_empty()
    restored = not after and empty['returncode'] == 0 and not any(s['returncode'] for s in steps)
    write(target, {'after_run': record['index'], 'technique': record['technique'], 'stopped': record['stopped'],
                   'note': note, 'steps': steps, 'inventory_difference_after': after, 'check_empty_after': empty,
                   'restored': restored})
    print(json.dumps({'restored': restored, 'steps': [(s['command'], s['returncode']) for s in steps]}))
    if not restored:
        raise SystemExit('the lab is not restored')


def start():
    current = session()
    host = detector.Host()
    points = {'host': detector.first_healthy_point(host, current), 'k8saudit': detector.audit_ready_point(host, current)}
    begin = max(points.values(), key=detector.recorder.ns)
    write(RUN / 'window-start.json', {'session': current, 'start': begin, 'first_healthy_points': points})
    write(RUN / 'inventory-before.json', inventory())
    nodes = json.loads(sh(KUBECTL + ['get', 'nodes', '-o', 'json']).stdout)
    node = json.loads(sh(['/usr/bin/docker', 'container', 'inspect', 'warden-lab-control-plane']).stdout)[0]
    write(RUN / 'environment.json', {
        'node_container': {'name': 'warden-lab-control-plane', 'image': node['Config']['Image'], 'image_id': node['Image'],
                           'cpuset_cpus': node['HostConfig']['CpusetCpus'], 'started_at': node['State']['StartedAt']},
        'kubernetes': [{'name': n['metadata']['name'], 'kubelet': n['status']['nodeInfo']['kubeletVersion'],
                        'runtime': n['status']['nodeInfo']['containerRuntimeVersion']} for n in nodes['items']],
        'kind': sh([str(ROOT / '.tools/kind/kind'), 'version']).stdout.strip(),
        'kubectl': json.loads(sh([str(KUBECTL_BIN), 'version', '--client', '-o', 'json']).stdout)['clientVersion']['gitVersion'],
        'kubeconfig_mode': oct(KUBECONFIG.stat().st_mode & 0o777),
        'stratus_sha256': sha256(STRATUS),
        'wrapper_commit': sh(['/usr/bin/git', 'log', '-1', '--format=%H', '--', 'attacks/stratus']).stdout.strip(),
        'pod_image': IMAGE,
        'wrapper_commit_files_sha256': {p: sha256(ROOT / p) for p in ('attacks/stratus/emulate.py', 'attacks/stratus/run.sh',
                                                                       'attacks/atomic/lab_common.py')},
        'tools_receipts_sha256': {name: sha256(ROOT / '.tools' / name)
                                  for name in ('falco-k8saudit/receipt.json', 'stratus/receipt.json')}})
    print(begin)


def end():
    current = session()
    begin = json.loads((RUN / 'window-start.json').read_text())
    cutoff = now()
    host = detector.Host()
    detector.flush(host, current)
    detector.flush(host, current, instance='k8saudit')
    write(RUN / 'window.json', {'session': current, 'start': begin['start'], 'end': cutoff})
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
    if detector.load_state().get('up'):
        raise SystemExit('bring the detector down first (make detect-down)')
    current = window['session']
    copy(detector.DATA / current / 'host', HERE / 'collector-host')
    copy(detector.DATA / current / 'k8saudit', HERE / 'collector-k8saudit')
    for name in ('host-before', 'host-after', 'host-compare'):
        (HERE / 'host').mkdir(exist_ok=True)
        shutil.copyfile(detector.STATE / ('%s-%s.json' % (name, current)), HERE / 'host' / ('%s.json' % name))
    # The reference hashes the downloads are compared with.
    (HERE / 'tools').mkdir(exist_ok=True)
    for name in ('stratus', 'falco-k8saudit'):
        shutil.copyfile(ROOT / '.tools' / name / 'receipt.json', HERE / 'tools' / ('%s.receipt.json' % name))
    # The audit log lines of the session: from where the feed started.
    beats = [json.loads(line) for line in (detector.DATA / current / 'k8saudit/heartbeats.jsonl').read_text().splitlines()]
    offset = beats[0]['feed']['start_offset']
    with open(LAB / 'audit/audit.log', 'rb') as log:
        log.seek(offset)
        lines = log.read()
    with gzip.GzipFile(HERE / 'audit-session.jsonl.gz', 'wb', compresslevel=9, mtime=0) as out:
        out.write(lines)
    write(RUN / 'audit-session.json', {'from_offset': offset, 'bytes': len(lines), 'lines': lines.count(b'\n'),
                                       'sha256': hashlib.sha256(lines).hexdigest(),
                                       'source': '.cache/kind-warden-lab/audit/audit.log'})
    print('collected session %s' % current)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('start', 'runs', 'restore', 'end', 'collect'))
    parser.add_argument('--from', dest='first', type=int, default=1, help='runs: the index to start at (to resume)')
    parser.add_argument('--note', default='', help='restore: what happened, for the record')
    args = parser.parse_args(argv)
    if args.command == 'runs':
        return runs(args.first)
    if args.command == 'restore':
        restore(args.note)
        return 0
    {'start': start, 'end': end, 'collect': collect}[args.command]()
    return 0


if __name__ == '__main__':
    sys.exit(main())
