#!/usr/bin/env python3
"""Score the 2026-11-14 Stratus round (Kubernetes, kind audit lab) on k8saudit alerts.

    python3 -I -B docs/evidence/task-13/stratus-20261114/attempt-1/score.py   # from the repository root

Inputs, all in this directory: run/ (drive.py's records: window.json,
runs.jsonl, inventory-before.json), runs/*/ (the wrapper's receipt.json and
executions.jsonl per run, as it wrote them), collector-k8saudit/ and
collector-host/ (the two collectors' files as written; large ones gzip'ed),
host/ (the detector's host snapshots), audit-session.jsonl.gz (the audit log
lines of the session), tools/stratus.receipt.json (the reference hashes of
.tools/stratus) and stock-k8saudit-rules.txt (the 48 rules of the pinned
k8s_audit_rules.yaml; written from .tools/falco-k8saudit if missing). The
corpus and Atomic rounds' executions and alerts (../emulation-20261114/,
../atomic-20261114/) join this round's for the coverage page. Outputs go
next to the inputs, and the page to docs/evidence/detection-coverage.md
(only when all 40 runs are there: a round that stopped early is tabulated
but does not join the page).

Every step is the repository's tool: audit_alert_import (with every run's
receipt.json), detection_metrics, detection_report, audit_collector.coverage
(k8saudit) and recorder.intervals (host). The rule map is the widest one the
round allows: every stock k8saudit rule for every run (any attributed alert
counts, warm-up and clean-up included), and no syscall rule. This script
only feeds the tools and tabulates their outputs.
"""
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
CORPUS = HERE.parents[1] / 'emulation-20261114'
ATOMIC = HERE.parents[1] / 'atomic-20261114'
sys.path.insert(0, str(ROOT / 'detect/falco'))
import audit_collector  # noqa: E402
import detector  # noqa: E402
import recorder  # noqa: E402

CPU = ['/usr/bin/taskset', '-c', '0-7,16-31']
PY = ['/usr/bin/python3', '-E', '-s', '-B']
ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT / '.cache/home'), 'LC_ALL': 'C'}
RUN = HERE / 'run'
NO_RULE = ('k8s.credential-access.dump-secrets', 'k8s.persistence.create-token')
EXPECTED_FAILURE = 'k8s.persistence.create-admin-clusterrole'
SECRET = re.compile(rb'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|'
                    rb'client-key-data|"token"\s*:\s*"[^"]')
OUTPUTS = ('expected-rules.jsonl', 'executions.jsonl', 'alerts.jsonl', 'alert-provenance.jsonl', 'alert-import.out',
           'metrics.json', 'metrics-written-rules.json', 'metrics-all-rounds.json', 'report.md', 'alerts-detail.json',
           'unattributed.json', 'runs.json', 'runs.md', 'techniques.json', 'techniques.md', 'downloads.json', 'downloads.md',
           'coverage.jsonl', 'explain.jsonl', 'checks.json')
# The coverage page's Scope section (detection_report.py --note).
SCOPE = (
    'Cohort: three rounds on 2026-11-14 under the same detector build. The Task 5 corpus: 14 probes once on runc and '
    'once on gVisor (28 runs; one reached its goal). The Atomic round: six reviewed official Linux Atomic Red Team '
    'tests, five runs each, on runc only (30 runs), each in its own container (ubuntu:24.04, no network, read-only '
    'root, no capabilities). The Stratus round: the eight Kubernetes techniques of Stratus Red Team v2.38.0 that the '
    "user's wrapper admits, five runs each (40 runs), on the dedicated kind audit lab (Kubernetes 1.34.11).",
    'The Atomic round includes T1082 Hostname Discovery as a control that no stock rule describes; its five '
    'successful runs are in the denominator of the rate. T1552.001 Find AWS credentials exited 1 in every run (find '
    'meets two directories that root cannot enter without capabilities), so it is a failed execution and not in the rate; '
    'counted as executed it would add 5 misses. The two T1552.004 SSH-key searches meet the same two directories and '
    'succeed only because their scripts end in `exit 0`.',
    'Rule maps, both the widest: the corpus and Atomic rounds against the 25 stock syscall rules of the pinned Falco '
    "0.45.2 (any kept alert on the run's container inside its execution counts); the Stratus round against the 48 "
    "stock rules of k8s_audit_rules.yaml (k8saudit plugin 0.18.0) only, any alert attributed to the run (by Stratus's "
    "User-Agent correlation token, the run label or the run's namespace) inside its window counts, Stratus's warm-up and "
    'clean-up included. No narrower map has been reviewed.',
    'Stratus: no stock rule is written for k8s.credential-access.dump-secrets (T1552.007) or k8s.persistence.create-token '
    "(T1098); whatever the widest map counts for them comes from other rules matching the technique's set-up, "
    'clean-up or side requests, not from a rule describing the technique (round README). '
    'k8s.persistence.create-admin-clusterrole (T1098.006) fails on Kubernetes 1.24 and later (it waits for a legacy '
    'token Secret), so its runs are failed executions and their alerts are alerts on failed executions.',
    'Techniques are ATT&CK IDs, so rows merge across rounds and Stratus techniques: T1611 holds the corpus\'s two '
    'container-escape probes and Stratus\'s privileged-pod and hostpath-volume. Per-technique rows by Stratus name are in '
    'the round README.',
    "Coverage: runc at host level; gVisor at host level only (a sandbox's own system calls are not seen); Firecracker "
    'not covered and not run; the kind lab through its API server audit log only (no syscall rule scores a Stratus run).',
    "Time to detect runs from the execution's start to the alerted event's own time (Falco's `time`; for k8saudit the "
    "audit event's stageTimestamp). The Atomic and Stratus READMEs also give start to arrival in the collector's "
    'alerts.jsonl; the corpus round has no arrival times.',
    "Observed until is the Stratus round's cutoff. The corpus round's detector ran 15:27:48 to 15:30:46 UTC and the "
    "Atomic round's until 17:30:10 UTC, so their undetected rows were observed only until then.",
    'Not run: Stratus cloud techniques (AWS, GCP, Azure), the Atomic round on gVisor or Firecracker. Task 12\'s Sigma '
    'rules are not in this scoring path; no seven-day normal window, so no false-positive count.',
)


def jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)


def rows_of(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def pairs(path):
    return [(line.encode(), json.loads(line)) for line in Path(path).read_text().splitlines() if line.strip()]


def run(argv, check=True):
    result = subprocess.run(CPU + argv, cwd=ROOT, text=True, capture_output=True, env=ENV)
    if check and result.returncode != 0:
        raise SystemExit('%s failed (%d): %s' % (' '.join(argv[:8]), result.returncode, (result.stdout + result.stderr)[-3000:]))
    return result


def ns(value):
    return recorder.ns(value)


def seconds(delta):
    return None if delta is None else round(delta / 1e9, 3)


def rank(values, percent):
    """Nearest rank, as detect/report/detection_metrics.py computes p50/p95."""
    values = sorted(values)
    return values[(percent * len(values) + 99) // 100 - 1] if values else None


def spread(values):
    return {'n': len(values), 'min': seconds(min(values)) if values else None, 'p50': seconds(rank(values, 50)),
            'p95': seconds(rank(values, 95)), 'max': seconds(max(values)) if values else None}


def stock_k8saudit_rules():
    path = HERE / 'stock-k8saudit-rules.txt'
    if not path.exists():
        rules_file = ROOT / '.tools/falco-k8saudit/k8s_audit_rules.yaml'
        if detector.file_sha256(rules_file) != detector.K8SAUDIT_FILES['k8s_audit_rules.yaml']:
            raise SystemExit('the rules file is not the pinned one')
        names = re.findall(r'^- rule: (.+)$', rules_file.read_text(), re.M)
        path.write_text(''.join(name.strip() + '\n' for name in names))
    return [line for line in path.read_text().splitlines() if line.strip()]


def actor(user_agent):
    """Who sent the request, from its User-Agent: Terraform (Stratus's warm-up
    and clean-up), Stratus's own client (detonation and revert), or another."""
    if not user_agent:
        return 'none'
    if 'Terraform/' in user_agent:
        return 'terraform'
    if 'stratus-red-team_' in user_agent:
        return 'stratus'
    return user_agent.split('/')[0].split(' ')[0]


def plain(directory, name, scratch):
    path = HERE / directory / name
    if path.exists():
        return path
    target = scratch / (directory + '-' + name)
    if Path(str(path) + '.gz').exists():
        with gzip.open(str(path) + '.gz', 'rb') as source:
            target.write_bytes(source.read())
    else:
        target.write_text('')
    return target


def metrics(scratch, executions, alerts, cutoff, name):
    (scratch / (name + '-ex.jsonl')).write_text(jsonl(executions))
    ids = {e['execution_id'] for e in executions}
    (scratch / (name + '-al.jsonl')).write_text(jsonl(a for a in alerts if a['execution_id'] in ids))
    return run(PY + ['-m', 'detect.report.detection_metrics', '--executions', str(scratch / (name + '-ex.jsonl')),
                     '--alerts', str(scratch / (name + '-al.jsonl')), '--observed-until', cutoff]).stdout


def lock_hashes(text):
    """provider -> (version, [hashes]) from a .terraform.lock.hcl."""
    found = {}
    for match in re.finditer(r'provider "([^"]+)" \{(.*?)\n\}', text, re.S):
        body = match[2]
        version = re.search(r'version\s*=\s*"([^"]+)"', body)
        found[match[1]] = {'version': version[1] if version else None, 'hashes': re.findall(r'"((?:h1|zh):[^"]+)"', body)}
    return found


def downloads(records, reference):
    files = reference['files_sha256']
    rows, ok = [], True
    for r in records:
        dl = r.get('downloads') or {}
        terraform = [f for f in dl.get('after_run', []) if f['path'].endswith('/terraform')]
        providers = {}
        for f in dl.get('during_run', []) + [f for f in dl.get('after_run', []) if not f['path'].endswith('/terraform')]:
            providers.setdefault(f['path'], f)
        checked = []
        for f in terraform:
            checked.append({'what': 'terraform 1.3.10', 'path': f['path'], 'sha256': f['sha256'],
                            'reference': files['terraform/terraform'], 'match': f['sha256'] == files['terraform/terraform']})
        for path, f in sorted(providers.items()):
            m = re.search(r'(registry\.terraform\.io/hashicorp/kubernetes/([0-9.]+)/linux_amd64/terraform-provider-kubernetes_v[0-9.]+_x5)$', path)
            key = 'providers/' + m[1] if m else None
            checked.append({'what': 'hashicorp/kubernetes %s' % (m[2] if m else '?'), 'path': path, 'sha256': f['sha256'],
                            'reference': files.get(key), 'match': bool(key) and f['sha256'] == files.get(key)})
        for path, lock in sorted((dl.get('lock_files') or {}).items()):
            for provider, entry in lock_hashes(lock['text']).items():
                zip_ref = reference['providers_zip_sha256'].get(entry['version'])
                checked.append({'what': 'lock file %s %s: zh of the linux_amd64 zip' % (provider, entry['version']),
                                'path': path, 'sha256': zip_ref, 'reference': zip_ref,
                                'match': bool(zip_ref) and ('zh:' + zip_ref) in entry['hashes']})
        if not terraform or not all(c['match'] for c in checked):
            ok = False
        rows.append({'index': r['index'], 'technique': r['technique'], 'out': r['out'], 'checked': checked,
                     'terraform_found': len(terraform), 'providers_found': len(providers),
                     'lock_files': len(dl.get('lock_files') or {}), 'watch_errors': dl.get('watch_errors')})
    return rows, ok


def main():
    for name in OUTPUTS:
        if (HERE / name).exists():
            (HERE / name).unlink()
    (ROOT / '.cache/test-tmp').mkdir(parents=True, exist_ok=True)
    window = json.loads((RUN / 'window.json').read_text())
    records = rows_of(RUN / 'runs.jsonl')
    rules = stock_k8saudit_rules()
    if len(rules) != 48 or len(set(rules)) != 48:
        raise SystemExit('stock-k8saudit-rules.txt must name the 48 stock rules')
    runs = []
    for record in records:
        out = HERE / 'runs' / record['out']
        receipt = json.loads((out / 'receipt.json').read_text())
        execution = rows_of(out / 'executions.jsonl')[0]
        runs.append((record, receipt, execution))
    executions = [e for _, _, e in runs]
    # A round that stopped early is tabulated, but it does not join the
    # coverage page.
    complete = len(runs) == 40
    (HERE / 'executions.jsonl').write_text(jsonl(executions))
    (HERE / 'expected-rules.jsonl').write_text(jsonl({'execution_id': e['execution_id'], 'rule_id': r}
                                                     for e in executions for r in rules))
    with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as tmp:
        scratch = Path(tmp)
        kept = plain('collector-k8saudit', 'alerts.jsonl', scratch)
        receipts = [arg for record, _, _ in runs for arg in ('--receipt', str(HERE / 'runs' / record['out'] / 'receipt.json'))]
        imported = run(PY + ['-m', 'detect.report.audit_alert_import', '--falco', str(kept)] + receipts
                       + ['--expected-rules', str(HERE / 'expected-rules.jsonl'), '--out', str(HERE / 'alerts.jsonl'),
                          '--provenance', str(HERE / 'alert-provenance.jsonl')])
        (HERE / 'alert-import.out').write_text(imported.stdout + imported.stderr)
        alerts = rows_of(HERE / 'alerts.jsonl')

        # Metrics: this round; without the two techniques no rule is written
        # for; all three rounds (the page).
        no_rule_ids = {e['execution_id'] for r, _, e in runs if r['technique'] in NO_RULE}
        reports = {}
        cohorts = [('metrics.json', executions, []),
                   ('metrics-written-rules.json', [e for e in executions if e['execution_id'] not in no_rule_ids], [])]
        if complete:
            cohorts.append(('metrics-all-rounds.json',
                            rows_of(CORPUS / 'executions.jsonl') + rows_of(ATOMIC / 'executions.jsonl') + executions,
                            rows_of(CORPUS / 'alerts.jsonl') + rows_of(ATOMIC / 'alerts.jsonl')))
        for name, rows, extra in cohorts:
            text = metrics(scratch, rows, extra + alerts, window['end'], name.split('.')[0])
            (HERE / name).write_text(text)
            reports[name] = json.loads(text)
        notes = ('The Stratus round alone: eight Kubernetes techniques of Stratus Red Team v2.38.0, five runs each, on the kind '
                 'audit lab; k8saudit alerts only, against all 48 stock k8s_audit_rules.yaml rules (the widest map).',
                 'No stock rule is written for dump-secrets (T1552.007) or create-token (T1098); create-admin-clusterrole '
                 '(T1098.006) fails on Kubernetes 1.24 and later. T1611 is privileged-pod and hostpath-volume together.')
        run(PY + ['-m', 'detect.report.detection_report', '--metrics', str(HERE / 'metrics.json'), '--out', str(HERE / 'report.md')]
            + [arg for note in notes for arg in ('--note', note)])
        if complete:
            run(PY + ['-m', 'detect.report.detection_report', '--metrics', str(HERE / 'metrics-all-rounds.json'),
                      '--out', str(ROOT / 'docs/evidence/detection-coverage.md')] + [arg for note in SCOPE for arg in ('--note', note)])

        # Each imported alert: its audit event, when it was fed, when it
        # reached alerts.jsonl.
        with gzip.open(HERE / 'audit-session.jsonl.gz', 'rb') as source:
            audit = {}
            for line in source:
                if line.strip():
                    event = json.loads(line)
                    audit[(event['auditID'], ns(event['stageTimestamp']))] = event
        feed = rows_of(plain('collector-k8saudit', 'feed.jsonl', scratch))
        fed = {(f['audit_id'], ns(f['stage_timestamp'])): f for f in feed}
        arrivals = {a['raw_event_sha256']: a for a in rows_of(plain('collector-k8saudit', 'arrivals.jsonl', scratch))}
        start_of = {e['execution_id']: ns(rc['started_at']) for _, rc, e in runs}
        execution_of = {e['run_id']: e['execution_id'] for e in executions}
        detail = []
        for prov in rows_of(HERE / 'alert-provenance.jsonl'):
            event = prov['raw_event']
            stage = ns(event['time'])
            line = audit.get((prov['audit_id'], stage))
            feed_row = fed.get((prov['audit_id'], stage))
            arrival = arrivals.get(prov['raw_event_sha256'])
            execution_id = execution_of[prov['run_id']]
            start = start_of[execution_id]
            fields = event.get('output_fields') or {}
            received = ns(line['requestReceivedTimestamp']) if line else None
            detail.append({
                'alert_id': prov['alert_id'], 'execution_id': execution_id, 'rule': event['rule'],
                'matched_by': prov['matched_by'], 'namespace': prov['namespace'], 'audit_id': prov['audit_id'],
                'verb': line and line.get('verb'), 'stage': line and line.get('stage'),
                'resource': line and '/'.join(x for x in ((line.get('objectRef') or {}).get('resource'),
                                                         (line.get('objectRef') or {}).get('subresource')) if x),
                'target_name': fields.get('ka.target.name'), 'user': (line or {}).get('user', {}).get('username'),
                'actor': actor(fields.get('ka.useragent')), 'user_agent': fields.get('ka.useragent'),
                'request_received_at': line and line['requestReceivedTimestamp'], 'event_time': event['time'],
                'fed_at': feed_row and feed_row['fed_at'], 'written_at': arrival and arrival['written_at'],
                'start_to_request_received_ns': received - start if received else None,
                'start_to_event_ns': stage - start,
                'start_to_fed_ns': ns(feed_row['fed_at']) - start if feed_row else None,
                'start_to_alerts_file_ns': ns(arrival['written_at']) - start if arrival else None})
        detail.sort(key=lambda d: d['event_time'])
        (HERE / 'alerts-detail.json').write_text(json.dumps(detail, indent=1, sort_keys=True) + '\n')

        # The session's other alerts: what the import did not attribute.
        imported_ids = {d['alert_id'] for d in detail}
        windows = [(ns(rc['started_at']), ns(rc['finished_at']), r['index']) for r, rc, _ in runs]
        unattributed = {}
        for raw in rows_of(kept):
            digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                                               allow_nan=False).encode()).hexdigest()
            if 'falco-' + digest in imported_ids:
                continue
            t = ns(raw['time'])
            inside = next((i for s, e, i in windows if s <= t <= e), None)
            fields = raw.get('output_fields') or {}
            key = '%s | %s | %s | %s' % (raw['rule'], 'inside run %d' % inside if inside else 'outside every run window',
                                         fields.get('ka.target.namespace') or '-', actor(fields.get('ka.useragent')))
            unattributed[key] = unattributed.get(key, 0) + 1
        (HERE / 'unattributed.json').write_text(json.dumps(unattributed, indent=1, sort_keys=True) + '\n')

        # Per run.
        metric_rows = {row['execution_id']: row for row in reports['metrics.json']['executions']}
        by_execution = {}
        for d in detail:
            by_execution.setdefault(d['execution_id'], []).append(d)
        table = []
        for record, receipt, execution in runs:
            eid = execution['execution_id']
            found = by_execution.get(eid, [])
            first = found[0] if found else None
            row = metric_rows[eid]
            table.append({
                'index': record['index'], 'round': record['round'], 'technique': record['technique'],
                'technique_id': execution['technique_id'], 'run_id': receipt['run_id'], 'correlation_id': receipt.get('correlation_id'),
                'started_at': receipt['started_at'], 'finished_at': receipt['finished_at'],
                'duration_s': seconds(ns(receipt['finished_at']) - ns(receipt['started_at'])),
                'wrapper_exit': record['wrapper_exit'], 'returncode': receipt['returncode'],
                'cleanup_returncode': receipt['cleanup_returncode'], 'outcome': execution['outcome'], 'status': row['status'],
                'check_empty_before': record['check_empty_before']['returncode'],
                'check_empty_after': record['check_empty_after']['last']['returncode'],
                'check_empty_after_attempts': record['check_empty_after']['attempts'],
                'left_outside_namespace': record['left_outside_namespace'],
                'alerts': [{k: d[k] for k in ('rule', 'matched_by', 'actor', 'verb', 'resource', 'event_time')} for d in found],
                'first_alert': first and {k: first[k] for k in ('rule', 'matched_by', 'actor', 'verb', 'resource')},
                'start_to_request_received_s': seconds(first and first['start_to_request_received_ns']),
                'start_to_event_s': seconds(first and first['start_to_event_ns']),
                'start_to_fed_s': seconds(first and first['start_to_fed_ns']),
                'start_to_alerts_file_s': seconds(min(d['start_to_alerts_file_ns'] for d in found)) if found and all(
                    d['start_to_alerts_file_ns'] is not None for d in found) else None,
                'metrics_latency_s': seconds(row.get('latency_ns'))})
        (HERE / 'runs.json').write_text(json.dumps(table, indent=1, sort_keys=True) + '\n')

        def cell(value):
            return '–' if value is None else '%.3f' % value
        lines = ['| # | Round | Technique | Wrapper | Detonate | Cleanup | Outcome | Status | Run (s) | Rules on the run | First alert (s): event / alerts file |',
                 '|---|---|---|---|---|---|---|---|---|---|---|']
        for r in table:
            fired = {}
            for a in r['alerts']:
                fired[a['rule']] = fired.get(a['rule'], 0) + 1
            lines.append('| %d | %d | %s | %s | %s | %s | %s | %s | %.1f | %s | %s / %s |' % (
                r['index'], r['round'], r['technique'].split('.', 2)[2], r['wrapper_exit'], r['returncode'],
                r['cleanup_returncode'], r['outcome'], r['status'], r['duration_s'],
                ', '.join('%s (%d)' % kv for kv in sorted(fired.items())) or 'none',
                cell(r['start_to_event_s']), cell(r['start_to_alerts_file_s'])))
        (HERE / 'runs.md').write_text('\n'.join(lines) + '\n')

        # Per technique.
        techniques, pooled = [], {k: [] for k in ('request_received', 'event', 'fed', 'alerts_file')}
        for technique in sorted({r['technique'] for r in table}):
            mine = [r for r in table if r['technique'] == technique]
            ok = [r for r in mine if r['outcome'] == 'succeeded']
            hit = [r for r in ok if r['status'] == 'detected']
            values = {k: [round(r['start_to_%s_s' % k] * 1e9) for r in hit if r['start_to_%s_s' % k] is not None]
                      for k in pooled}
            for k in pooled:
                pooled[k] += values[k]
            fired_ok, fired_failed, actors = {}, {}, {}
            for r in mine:
                for a in r['alerts']:
                    target = fired_ok if r['outcome'] == 'succeeded' else fired_failed
                    target[a['rule']] = target.get(a['rule'], 0) + 1
                    label = '%s by %s' % (a['rule'], a['actor'])
                    actors[label] = actors.get(label, 0) + 1
            techniques.append({
                'technique': technique, 'technique_id': mine[0]['technique_id'], 'n': len(mine), 'succeeded': len(ok),
                'detected': len(hit), 'failed': len(mine) - len(ok),
                'alerts_on_succeeded_runs': fired_ok, 'alerts_on_failed_runs': fired_failed, 'alerts_by_actor': actors,
                'first_alert_rules': sorted({r['first_alert']['rule'] for r in hit}),
                'no_rule_written': technique in NO_RULE,
                **{'start_to_' + k: spread(v) for k, v in values.items()}})
        rate = reports['metrics.json']['execution_detection']
        summary_pooled = {'execution_detection': rate, 'latency_ns': reports['metrics.json']['latency_ns'],
                          'written_rules_execution_detection': reports['metrics-written-rules.json']['execution_detection'],
                          'written_rules_latency_ns': reports['metrics-written-rules.json']['latency_ns'],
                          **{'start_to_' + k: spread(v) for k, v in pooled.items()}}
        (HERE / 'techniques.json').write_text(json.dumps({'techniques': techniques, 'pooled_detected_runs': summary_pooled},
                                                         indent=1, sort_keys=True) + '\n')

        def trio(s):
            return '%s / %s / %s' % tuple('–' if s[k] is None else '%.3f' % s[k] for k in ('min', 'p50', 'max'))
        lines = ['| Technique (ATT&CK) | n | Succeeded | Detected | Rules fired on succeeded runs (alerts) | Alerts on failed runs | '
                 'Start → audit event = Falco time, s (min / p50 / max) | Start → alerts file, s (min / p50 / max) |',
                 '|---|---|---|---|---|---|---|---|']
        for t in techniques:
            lines.append('| %s (%s)%s | %d | %d | %d | %s | %s | %s | %s |' % (
                t['technique'].split('.', 2)[2], t['technique_id'], ' ¹' if t['no_rule_written'] else '', t['n'],
                t['succeeded'], t['detected'],
                ', '.join('%s (%d)' % kv for kv in sorted(t['alerts_on_succeeded_runs'].items())) or 'none',
                ', '.join('%s (%d)' % kv for kv in sorted(t['alerts_on_failed_runs'].items())) or 'none',
                trio(t['start_to_event']), trio(t['start_to_alerts_file'])))
        (HERE / 'techniques.md').write_text('\n'.join(lines) + '\n')

        # The downloads against .tools/stratus's reference hashes.
        reference = json.loads((HERE / 'tools/stratus.receipt.json').read_text())
        dl_rows, dl_ok = downloads(records, reference)
        (HERE / 'downloads.json').write_text(json.dumps(dl_rows, indent=1, sort_keys=True) + '\n')
        lines = ['| # | Technique | Checked | Matches | Not matching |', '|---|---|---|---|---|']
        for d in dl_rows:
            bad = [c['what'] for c in d['checked'] if not c['match']]
            lines.append('| %d | %s | %s | %d of %d | %s |' % (
                d['index'], d['technique'].split('.', 2)[2], ', '.join(sorted({c['what'].split(':')[0] for c in d['checked']})),
                sum(c['match'] for c in d['checked']), len(d['checked']), ', '.join(bad) or 'none'))
        (HERE / 'downloads.md').write_text('\n'.join(lines) + '\n')

        # Both instances' health over the window.
        explain_host, explain_audit = [], []
        host = recorder.intervals(pairs(plain('collector-host', 'heartbeats.jsonl', scratch)),
                                  pairs(plain('collector-host', 'health.jsonl', scratch)), [],
                                  source_id='falco-host', runtimes=('runc', 'gvisor'), start=window['start'], end=window['end'],
                                  period=3600, max_gap=90, snapshot_gap=150, explain=explain_host)
        audit_cov = audit_collector.coverage(pairs(plain('collector-k8saudit', 'heartbeats.jsonl', scratch)),
                                             pairs(plain('collector-k8saudit', 'health.jsonl', scratch)), feed,
                                             start=window['start'], end=window['end'], explain=explain_audit)
        (HERE / 'coverage.jsonl').write_text(jsonl(host + audit_cov))
        (HERE / 'explain.jsonl').write_text(jsonl(dict(r, source_id=s) for s, rs in (('falco-host', explain_host),
                                                                                     ('falco-k8saudit', explain_audit)) for r in rs))
        audit_beats = rows_of(plain('collector-k8saudit', 'heartbeats.jsonl', scratch))
        host_beats = rows_of(plain('collector-host', 'heartbeats.jsonl', scratch))
        host_kept = len(rows_of(plain('collector-host', 'alerts.jsonl', scratch)))

    compare = json.loads((HERE / 'host/host-compare.json').read_text())
    leaked = []
    for path in sorted(HERE.rglob('*')):
        if path.is_file() and path.name not in ('score.py', 'drive.py', 'README.md'):  # these name the patterns
            data = gzip.open(path).read() if path.suffix == '.gz' else path.read_bytes()
            if SECRET.search(data):
                leaked.append(str(path.relative_to(HERE)))
    end_ns = ns(window['end'])
    at_end = next(b for b in host_beats if ns(b['time']) >= end_ns)
    checks = {
        'round_complete': complete,
        'forty_runs_five_per_technique': len(table) == 40 and all(t['n'] == 5 for t in techniques) and len(techniques) == 8,
        'check_empty_before_every_run': all(r['check_empty_before'] == 0 for r in table),
        'empty_again_after_every_run': all(r['check_empty_after'] == 0 for r in table),
        'nothing_left_outside_namespace': not any(r['left_outside_namespace'] for r in table),
        'every_cleanup_returned_0': all(r['cleanup_returncode'] == 0 for r in table),
        'every_receipt_has_correlation_id': all(r['correlation_id'] for r in table),
        'runs_inside_window': all(ns(window['start']) <= ns(r['started_at']) and ns(r['finished_at']) <= end_ns for r in table),
        'every_alert_joined_to_audit_feed_and_arrival': all(d['request_received_at'] and d['fed_at'] and d['written_at']
                                                           for d in detail),
        'downloads_match_reference': dl_ok,
        'host_coverage_healthy': bool(host) and all(r['healthy'] for r in host),
        'k8saudit_coverage_healthy': bool(audit_cov) and all(r['healthy'] for r in audit_cov),
        'dropped_events': sum(r['dropped_events'] for r in host + audit_cov),
        'host_alerts_kept': host_kept,
        'host_pending_at_cutoff': at_end['counts'].get('pending', 0),
        'host_unresolved_after_cutoff': host_beats[-1]['counts']['dropped_unresolved'] - at_end['counts']['dropped_unresolved'],
        'no_module_or_sysctl_change': not compare['modules_added'] and not compare['modules_removed'] and not compare['sysctls_changed'],
        'no_token_or_private_key_in_evidence': not leaked,
    }
    summary = {'window': window, 'checks': checks, 'leaked': leaked,
               'k8saudit_counts': audit_beats[-1]['counts'], 'host_counts': host_beats[-1]['counts'],
               'alerts_imported': len(detail), 'k8saudit_alerts_kept': sum(1 for _ in rows_of(kept)) if kept.exists() else None,
               'pooled_detected_runs': summary_pooled,
               'metrics': {name: {'execution_detection': m['execution_detection'], 'technique_detection': m['technique_detection'],
                                  'latency_ns': m['latency_ns'], 'execution_count': m['execution_count'],
                                  'alerts_on_failed_or_skipped_executions': m['alerts_on_failed_or_skipped_executions']}
                           for name, m in reports.items()},
               'audit_session_sha256': hashlib.sha256(gzip.open(HERE / 'audit-session.jsonl.gz').read()).hexdigest()}
    (HERE / 'checks.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
