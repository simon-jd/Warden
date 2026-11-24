#!/usr/bin/env python3
"""Score the 2026-11-14 k8saudit smoke through the new path.

    python3 -I -B docs/evidence/task-13/k8saudit-smoke-20261114/score.py   # from the repository root

Inputs, all in this directory: run/ (smoke.py's records: window.json,
receipt.json, executions.jsonl, wrapper-guards.json), collector-k8saudit/
and collector-host/ (the two collectors' files as written), host/ (the
detector's host snapshots), audit-session.jsonl.gz (the audit log lines of
the session) and stock-k8saudit-rules.txt (the rules of the pinned
k8s_audit_rules.yaml; written from .tools/falco-k8saudit if missing). The
syscall rules are the Atomic round's stock-rules.txt. Outputs go next to the
inputs; the coverage page (docs/evidence/detection-coverage.md) is not
touched: this smoke is no attack round.

Every step is the repository's tool: audit_alert_import (with the run's
receipt.json, as for a wrapper run), detection_metrics, detection_report,
recorder.intervals (host) and audit_collector.coverage (k8saudit). The rule
map is the widest: every stock k8saudit rule and every stock syscall rule
for the execution.
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
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'detect/falco'))
import audit_collector  # noqa: E402
import detector  # noqa: E402
import recorder  # noqa: E402

CPU = ['/usr/bin/taskset', '-c', '0-7,16-31']
PY = ['/usr/bin/python3', '-E', '-s', '-B']
ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT / '.cache/home'), 'LC_ALL': 'C'}
RUN = HERE / 'run'
OUTPUTS = ('expected-rules.jsonl', 'alerts.jsonl', 'alert-provenance.jsonl', 'alert-import.out', 'metrics.json', 'report.md',
           'alerts-detail.json', 'coverage.jsonl', 'explain.jsonl', 'checks.json')
SECRET = re.compile(rb'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----')
NOTES = (
    'Benign smoke, no attack technique: one execution laid out as an attacks/stratus/emulate.py run (namespace warden-lab, '
    "the wrapper's pod labels): a labelled busybox pod, a labelled ServiceAccount, `kubectl exec ... cat /etc/hostname`, "
    'then both deleted. T1609 names the exec only so the metrics accept the record.',
    'Rule map: every stock rule of k8s_audit_rules.yaml (plugins/k8saudit/v0.18.0) and the 25 stock syscall rules of '
    'Falco 0.45.2 for the execution (the widest map).',
    "Attribution: the alert's run label (warden.dev/run, warden_run_id) or its target namespace, inside the receipt's "
    'started_at..finished_at, which here, as in a wrapper run, includes the clean-up.',
    "Time to detect: from the receipt's started_at to the alert's event time (Falco's time = the audit event's stageTimestamp).",
)


def rows_of(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def pairs(path):
    return [(line.encode(), json.loads(line)) for line in Path(path).read_text().splitlines() if line.strip()]


def run(argv, check=True):
    result = subprocess.run(CPU + argv, cwd=ROOT, text=True, capture_output=True, env=ENV)
    if check and result.returncode != 0:
        raise SystemExit('%s failed (%d): %s' % (' '.join(argv[:8]), result.returncode, (result.stdout + result.stderr)[-3000:]))
    return result


def seconds(delta):
    return None if delta is None else round(delta / 1e9, 6)


def stock_k8saudit_rules():
    path = HERE / 'stock-k8saudit-rules.txt'
    if not path.exists():
        rules_file = ROOT / '.tools/falco-k8saudit/k8s_audit_rules.yaml'
        if detector.file_sha256(rules_file) != detector.K8SAUDIT_FILES['k8s_audit_rules.yaml']:
            raise SystemExit('the rules file is not the pinned one')
        names = re.findall(r'^- rule: (.+)$', rules_file.read_text(), re.M)
        path.write_text(''.join(name.strip() + '\n' for name in names))
    return [line for line in path.read_text().splitlines() if line.strip()]


def main():
    for name in OUTPUTS:
        if (HERE / name).exists():
            (HERE / name).unlink()
    window = json.loads((RUN / 'window.json').read_text())
    receipt = json.loads((RUN / 'receipt.json').read_text())
    execution = rows_of(RUN / 'executions.jsonl')[0]
    k8s_rules = stock_k8saudit_rules()
    syscall_rules = [r for r in (HERE.parent / 'atomic-20261114/stock-rules.txt').read_text().splitlines() if r.strip()]
    if len(syscall_rules) != 25 or len(set(k8s_rules)) != len(k8s_rules):
        raise SystemExit('stock rule lists are not as expected')
    (HERE / 'expected-rules.jsonl').write_text(''.join(
        json.dumps({'execution_id': execution['execution_id'], 'rule_id': r}, sort_keys=True) + '\n' for r in k8s_rules + syscall_rules))
    alerts_in = HERE / 'collector-k8saudit/alerts.jsonl'
    imported = run(PY + ['-m', 'detect.report.audit_alert_import', '--falco', str(alerts_in), '--receipt', str(RUN / 'receipt.json'),
                         '--expected-rules', str(HERE / 'expected-rules.jsonl'), '--out', str(HERE / 'alerts.jsonl'),
                         '--provenance', str(HERE / 'alert-provenance.jsonl')])
    (HERE / 'alert-import.out').write_text(imported.stdout + imported.stderr)
    metrics = run(PY + ['-m', 'detect.report.detection_metrics', '--executions', str(RUN / 'executions.jsonl'),
                        '--alerts', str(HERE / 'alerts.jsonl'), '--observed-until', window['end']])
    (HERE / 'metrics.json').write_text(metrics.stdout)
    run(PY + ['-m', 'detect.report.detection_report', '--metrics', str(HERE / 'metrics.json'), '--out', str(HERE / 'report.md')]
        + [arg for note in NOTES for arg in ('--note', note)])

    # Each imported alert: its audit event, when it was fed, when it reached alerts.jsonl.
    with gzip.open(HERE / 'audit-session.jsonl.gz', 'rb') as source:
        audit = [json.loads(line) for line in source if line.strip()]
    by_stage = {(a['auditID'], a['stageTimestamp']): a for a in audit}
    feed = rows_of(HERE / 'collector-k8saudit/feed.jsonl')
    fed = {(f['audit_id'], f['stage_timestamp']): f for f in feed}
    arrivals = {a['raw_event_sha256']: a for a in rows_of(HERE / 'collector-k8saudit/arrivals.jsonl')}
    start = recorder.ns(receipt['started_at'])
    detail = []
    for prov in rows_of(HERE / 'alert-provenance.jsonl'):
        event = prov['raw_event']
        stage_ts = recorder.ns(event['time'])
        line = None
        for (audit_id, stamp), candidate in by_stage.items():
            if audit_id == prov['audit_id'] and recorder.ns(stamp) == stage_ts:
                line = candidate
        feed_row = next((f for (audit_id, stamp), f in fed.items() if audit_id == prov['audit_id'] and recorder.ns(stamp) == stage_ts), None)
        arrival = arrivals.get(prov['raw_event_sha256'])
        received = recorder.ns(line['requestReceivedTimestamp']) if line else None
        detail.append({
            'alert_id': prov['alert_id'], 'rule': event['rule'], 'matched_by': prov['matched_by'], 'label': prov['label'],
            'namespace': prov['namespace'], 'audit_id': prov['audit_id'], 'verb': line and line.get('verb'),
            'stage': line and line.get('stage'), 'request_uri': line and line.get('requestURI'),
            'user_agent': (event['output_fields'] or {}).get('ka.useragent'),
            'request_received_at': line and line['requestReceivedTimestamp'], 'event_time': event['time'],
            'fed_at': feed_row and feed_row['fed_at'], 'read_at': arrival and arrival['read_at'],
            'written_at': arrival and arrival['written_at'],
            'start_to_request_received_s': seconds(received - start) if received else None,
            'start_to_event_s': seconds(stage_ts - start),
            'start_to_fed_s': seconds(recorder.ns(feed_row['fed_at']) - start) if feed_row else None,
            'start_to_alerts_file_s': seconds(recorder.ns(arrival['written_at']) - start) if arrival else None,
            'event_to_fed_s': seconds(recorder.ns(feed_row['fed_at']) - stage_ts) if feed_row else None,
            'fed_to_alerts_file_s': seconds(recorder.ns(arrival['written_at']) - recorder.ns(feed_row['fed_at']))
            if feed_row and arrival else None})
    detail.sort(key=lambda d: d['event_time'])
    (HERE / 'alerts-detail.json').write_text(json.dumps(detail, indent=1, sort_keys=True) + '\n')

    # Both instances' health over the window.
    with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as tmp:
        scratch = Path(tmp)

        def plain(directory, name):
            path = HERE / directory / name
            if path.exists():
                return path
            target = scratch / (directory + '-' + name)
            with gzip.open(str(path) + '.gz', 'rb') as source:
                target.write_bytes(source.read())
            return target

        explain_host, explain_audit = [], []
        host = recorder.intervals(pairs(plain('collector-host', 'heartbeats.jsonl')), pairs(plain('collector-host', 'health.jsonl')), [],
                                  source_id='falco-host', runtimes=('runc', 'gvisor'), start=window['start'], end=window['end'],
                                  period=3600, max_gap=90, snapshot_gap=150, explain=explain_host)
        audit_cov = audit_collector.coverage(pairs(plain('collector-k8saudit', 'heartbeats.jsonl')),
                                             pairs(plain('collector-k8saudit', 'health.jsonl')), feed,
                                             start=window['start'], end=window['end'], explain=explain_audit)
    (HERE / 'coverage.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in host + audit_cov))
    (HERE / 'explain.jsonl').write_text(''.join(json.dumps(dict(r, source_id=s), sort_keys=True) + '\n'
                                               for s, rs in (('falco-host', explain_host), ('falco-k8saudit', explain_audit))
                                               for r in rs))
    report = json.loads((HERE / 'metrics.json').read_text())
    compare = json.loads((HERE / 'host/host-compare.json').read_text())
    guards = json.loads((RUN / 'wrapper-guards.json').read_text())
    left = json.loads((RUN / 'left-after-run.json').read_text())
    beats = rows_of(HERE / 'collector-k8saudit/heartbeats.jsonl')
    host_beats = rows_of(HERE / 'collector-host/heartbeats.jsonl')
    leaked = []
    for path in sorted(HERE.rglob('*')):
        if path.is_file() and path.name != 'score.py':
            data = gzip.open(path).read() if path.suffix == '.gz' else path.read_bytes()
            if SECRET.search(data):
                leaked.append(str(path.relative_to(HERE)))
    checks = {
        'wrapper_guards_passed': all(guards[k] == 'passed' for k in ('guard_kubeconfig', 'guard_nodes', 'guard_namespace')),
        'kubeconfig_mode_0600': guards['kubeconfig_mode'] == '0o600',
        'run_succeeded': receipt['returncode'] == 0 and execution['outcome'] == 'succeeded',
        'cleanup_succeeded': receipt['cleanup_returncode'] == 0 and not left['objects'],
        'run_inside_window': recorder.ns(window['start']) <= start and recorder.ns(receipt['finished_at']) <= recorder.ns(window['end']),
        'detected': report['execution_detection']['numerator'] == 1,
        'attach_exec_pod_fired': any(d['rule'] == 'Attach/Exec Pod' for d in detail),
        'every_alert_joined_to_audit_feed_and_arrival': all(d['request_received_at'] and d['fed_at'] and d['written_at'] for d in detail),
        'host_coverage_healthy': all(r['healthy'] for r in host),
        'k8saudit_coverage_healthy': all(r['healthy'] for r in audit_cov),
        'dropped_events': sum(r['dropped_events'] for r in host + audit_cov),
        'no_module_or_sysctl_change': not compare['modules_added'] and not compare['modules_removed'] and not compare['sysctls_changed'],
        'no_token_or_private_key_in_evidence': not leaked,
    }
    # An alert the host collector cannot place waits 20 s before it is
    # dropped as unresolved, so one received before the cutoff can be
    # counted only in a later heartbeat than the one bracketing the window.
    end_ns = recorder.ns(window['end'])
    at_end = next(b for b in host_beats if recorder.ns(b['time']) >= end_ns)
    checks['host_pending_at_cutoff'] = at_end['counts'].get('pending', 0)
    checks['host_unresolved_after_cutoff'] = (host_beats[-1]['counts']['dropped_unresolved']
                                              - at_end['counts']['dropped_unresolved'])
    summary = {'window': window, 'checks': checks, 'leaked': leaked,
               'k8saudit_counts': beats[-1]['counts'], 'host_counts': host_beats[-1]['counts'],
               'execution_detection': report['execution_detection'], 'latency_ns': report['latency_ns'],
               'alerts': [{k: d[k] for k in ('rule', 'matched_by', 'start_to_event_s', 'start_to_alerts_file_s', 'event_to_fed_s',
                                              'fed_to_alerts_file_s')} for d in detail],
               'k8saudit_alerts_kept': sum(1 for _ in rows_of(alerts_in)),
               'host_alerts_kept': sum(1 for _ in rows_of(HERE / 'collector-host/alerts.jsonl'))
               if (HERE / 'collector-host/alerts.jsonl').exists() else 0,
               'audit_session_sha256': hashlib.sha256(gzip.open(HERE / 'audit-session.jsonl.gz').read()).hexdigest()}
    (HERE / 'checks.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
