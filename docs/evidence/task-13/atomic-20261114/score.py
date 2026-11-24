#!/usr/bin/env python3
"""Score the 2026-11-14 Atomic round (runc) against the online detector.

    python3 -I -B docs/evidence/task-13/atomic-20261114/score.py   # from the repository root

Inputs, all in this directory: run/window.json (the detector's first healthy
point and the cutoff: the time taken just before the last heartbeat flush
before down), run/runs.jsonl (drive.py's record of each run, with when each
of its container's alerts first appeared in the collector's alerts.jsonl),
runs/*/ (the wrapper's executions.jsonl, bindings.jsonl and receipt.json per
run), stock-rules.txt (the 25 rules of the pinned image's falco_rules.yaml)
and collector-host/ (the host collector's files as it wrote them; large ones
gzip'ed). The corpus round's executions and alerts
(../emulation-20261114/) join this round's for the coverage page. Outputs go
next to the inputs, and the page to docs/evidence/detection-coverage.md.

Every step is the runbook's own tool (docs/falco-detector.md): bindings.py,
alert_import, detection_metrics, detection_report, review.py groups, recorder
and observation. This script only feeds them and tabulates their outputs.
The rule map is every stock rule for every run, the widest map: any kept
alert on the run's container inside its execution counts, and the tables
name the rule. No narrower map has been reviewed.
"""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CORPUS = HERE.parent / 'emulation-20261114'
sys.path.insert(0, str(ROOT / 'detect/falco'))
sys.path.insert(0, str(ROOT / 'attacks/atomic'))
import emulate  # noqa: E402
import recorder  # noqa: E402
import review  # noqa: E402

CPU = ['/usr/bin/taskset', '-c', '0-7,16-31']
PY = ['/usr/bin/python3', '-E', '-s', '-B']
COLLECTOR = HERE / 'collector-host'
ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT / '.cache/home'), 'LC_ALL': 'C'}
CONTROL = '486e88ea-4f56-470f-9b57-3f4d73f39133'
# The coverage page's Scope section (detection_report.py --note).
SCOPE = (
    'Cohort: two rounds on 2026-11-14 under the same detector build. The Task 5 corpus: 14 probes once on runc and '
    'once on gVisor (28 runs; one reached its goal). The Atomic round: six reviewed official Linux Atomic Red Team '
    'tests, five runs each, on runc only (30 runs), each in its own container (ubuntu:24.04, no network, read-only '
    'root, no capabilities).',
    'The Atomic round includes T1082 Hostname Discovery as a control that no stock rule describes; its five '
    'successful runs are in the denominator of the rate. T1552.001 Find AWS credentials exited 1 in every run (find '
    'meets two directories that root cannot enter without capabilities), so it is a failed execution and not in the rate; '
    'counted as executed it would add 5 misses (20 of 30 with the control, 20 of 25 without). The two T1552.004 '
    'SSH-key searches meet the same two directories and succeed only because their scripts end in `exit 0`.',
    'Rule map: every one of the 25 stock rules of the pinned Falco 0.45.2 for every run (any kept alert on the '
    "run's container inside its execution counts). This is the widest map; no narrower map has been reviewed.",
    "Coverage: runc at host level; gVisor at host level only (a sandbox's own system calls are not seen); "
    'Firecracker not covered and not run.',
    "Time to detect runs from the execution's start to the alerted event's own time (Falco's `time`). The Atomic "
    "round's README also gives start to arrival in the collector's alerts.jsonl; the corpus round has no arrival times.",
    "Observed until is the Atomic round's cutoff. The corpus round's detector ran 15:27:48 to 15:30:46 UTC, so its "
    'undetected rows were observed only until then, not until this cutoff.',
    'Not run: Stratus Red Team. Its Kubernetes round on the kind audit lab is prepared and will be scored on k8saudit '
    'alerts only (the 48 stock k8s_audit_rules.yaml rules, not the 25 syscall rules); host syscall alerts from the kind '
    "lab's pods count as another container's and are not kept. Also not run: the Atomic round on gVisor or Firecracker. "
    "Task 12's Sigma rules are not in this scoring path; no seven-day normal window, so no false-positive count.",
)
OUTPUTS = ('bindings.jsonl', 'binding-errors.json', 'expected-rules.jsonl', 'alerts.jsonl', 'alert-provenance.jsonl',
           'alert-import.out', 'executions.jsonl', 'metrics.json', 'metrics-without-control.json',
           'metrics-both-rounds.json', 'runs.json', 'runs.md', 'tests.json', 'tests.md', 'review-groups.jsonl',
           'review-map-template.jsonl', 'coverage.jsonl', 'explain.jsonl', 'observation.json', 'checks.json')


def jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)


def rows_of(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def run(argv, check=True):
    result = subprocess.run(CPU + argv, cwd=ROOT, text=True, capture_output=True, env=ENV)
    if check and result.returncode != 0:
        raise SystemExit('%s failed (%d): %s' % (' '.join(argv[:8]), result.returncode, (result.stdout + result.stderr)[-3000:]))
    return result


def plain(name, scratch):
    """A collector file as a plain regular file (the tools read no gzip); empty if the collector wrote none."""
    if (COLLECTOR / name).exists():
        return COLLECTOR / name
    target = scratch / name
    if (COLLECTOR / (name + '.gz')).exists():
        with gzip.open(COLLECTOR / (name + '.gz'), 'rb') as source, open(target, 'wb') as out:
            shutil.copyfileobj(source, out)
    else:
        target.write_text('')
    return target


def ns(value):
    return recorder.ns(value)


def seconds(delta_ns):
    return None if delta_ns is None else round(delta_ns / 1e9, 3)


def rank(values, percent):
    """Nearest rank, as detect/report/detection_metrics.py computes p50/p95."""
    values = sorted(values)
    return values[(percent * len(values) + 99) // 100 - 1] if values else None


def spread(values):
    return {'n': len(values), 'min': seconds(min(values)) if values else None, 'p50': seconds(rank(values, 50)),
            'p95': seconds(rank(values, 95)), 'max': seconds(max(values)) if values else None}


def metrics(scratch, executions, alerts, cutoff):
    (scratch / 'ex.jsonl').write_text(jsonl(executions))
    ids = {e['execution_id'] for e in executions}
    (scratch / 'al.jsonl').write_text(jsonl(a for a in alerts if a['execution_id'] in ids))
    result = run(PY + ['-m', 'detect.report.detection_metrics', '--executions', str(scratch / 'ex.jsonl'),
                       '--alerts', str(scratch / 'al.jsonl'), '--observed-until', cutoff])
    return result.stdout


def main():
    for name in OUTPUTS:
        if (HERE / name).exists():
            (HERE / name).unlink()
    (ROOT / '.cache/test-tmp').mkdir(parents=True, exist_ok=True)
    window = json.loads((HERE / 'run/window.json').read_text())
    records = rows_of(HERE / 'run/runs.jsonl')
    rules = [line for line in (HERE / 'stock-rules.txt').read_text().splitlines() if line.strip()]
    if len(rules) != 25 or len(set(rules)) != 25:
        raise SystemExit('stock-rules.txt must name the 25 stock rules')
    runs = []
    for record in records:
        out = HERE / 'runs' / record['out']
        receipt = json.loads((out / 'receipt.json').read_text())
        execution = rows_of(out / 'executions.jsonl')[0] if (out / 'executions.jsonl').exists() else None
        wrapper_binding = rows_of(out / 'bindings.jsonl')[0] if (out / 'bindings.jsonl').exists() else None
        runs.append((record, receipt, execution, wrapper_binding))
    with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as tmp:
        scratch = Path(tmp)
        registry = plain('registry.jsonl', scratch)
        kept = plain('alerts.jsonl', scratch)
        platform = plain('platform-alerts.jsonl', scratch)
        scoping = plain('scoping.jsonl', scratch)

        # 1. Bindings: the container Falco reports, from the collector's
        # registry, narrowed to the execution's own interval.
        bound, errors = [], {}
        for record, receipt, execution, _ in runs:
            if execution is None:
                errors[record['run_id']] = 'no execution (the wrapper did not run the test)'
                continue
            result = run(PY + ['detect/falco/bindings.py', '--registry', str(registry), '--run-id', record['run_id'],
                               '--execution-id', execution['execution_id'], '--start', receipt['started_at'],
                               '--end', receipt['finished_at']], check=False)
            if result.returncode == 0:
                bound.append(json.loads(result.stdout))
            else:
                errors[execution['execution_id']] = result.stderr.strip()
        (HERE / 'bindings.jsonl').write_text(jsonl(bound))
        (HERE / 'binding-errors.json').write_text(json.dumps(errors, indent=1, sort_keys=True) + '\n')

        # 2. The widest rule map and the import of the kept alerts.
        (HERE / 'expected-rules.jsonl').write_text(jsonl({'execution_id': b['execution_id'], 'rule_id': r}
                                                         for b in bound for r in rules))
        imported = run(PY + ['-m', 'detect.report.alert_import', '--falco', str(kept), '--bindings', str(HERE / 'bindings.jsonl'),
                             '--expected-rules', str(HERE / 'expected-rules.jsonl'), '--out', str(HERE / 'alerts.jsonl'),
                             '--provenance', str(HERE / 'alert-provenance.jsonl')])
        (HERE / 'alert-import.out').write_text(imported.stdout + imported.stderr)

        # 3. Metrics: this round; this round without the control; both rounds (the page).
        executions = [execution for _, _, execution, _ in runs if execution]
        (HERE / 'executions.jsonl').write_text(jsonl(executions))
        alerts = rows_of(HERE / 'alerts.jsonl')
        reports = {}
        control_ids = {e['execution_id'] for (record, _, e, _) in runs if e and record['atomic_guid'] == CONTROL}
        for name, rows, extra in (('metrics.json', executions, []),
                                  ('metrics-without-control.json', [e for e in executions if e['execution_id'] not in control_ids], []),
                                  ('metrics-both-rounds.json', rows_of(CORPUS / 'executions.jsonl') + executions,
                                   rows_of(CORPUS / 'alerts.jsonl'))):
            text = metrics(scratch, rows, extra + alerts, window['end'])
            (HERE / name).write_text(text)
            reports[name] = json.loads(text)
        run(PY + ['-m', 'detect.report.detection_report', '--metrics', str(HERE / 'metrics-both-rounds.json'),
                  '--out', str(ROOT / 'docs/evidence/detection-coverage.md')]
            + [arg for note in SCOPE for arg in ('--note', note)])

        # 4. Per run and per test: outcome, the alerts on the run, the time
        # from its start to the first alert's event and to its arrival.
        detail = {row['execution_id']: row for row in reports['metrics.json']['executions']}
        by_execution = {}
        for a in alerts:
            by_execution.setdefault(a['execution_id'], []).append(a)
        binding_of = {b['execution_id']: b for b in bound}
        table = []
        for record, receipt, execution, wrapper_binding in runs:
            test = emulate.TESTS[record['atomic_guid']]
            eid = execution['execution_id'] if execution else None
            found = sorted(by_execution.get(eid, []), key=lambda a: ns(a['alerted_at']))
            arrival = {a['alert_sha256']: a for a in record.get('arrivals') or []}
            matched = [arrival.get(a['alert_id'].removeprefix('falco-')) for a in found]
            start = ns(receipt['started_at']) if execution else None
            row = detail.get(eid) or {}
            table.append({
                'index': record['index'], 'round': record['round'], 'atomic_guid': record['atomic_guid'],
                'technique': test['technique'], 'test': test['slug'], 'run_id': record['run_id'], 'execution_id': eid,
                'container_id': record['container_id'], 'started_at': receipt.get('started_at'),
                'finished_at': receipt.get('finished_at'), 'returncode': receipt.get('returncode'),
                'outcome': execution['outcome'] if execution else None, 'status': row.get('status'),
                'binding': binding_of.get(eid),
                'wrapper_binding_container_matches': bool(wrapper_binding and binding_of.get(eid)
                                                          and wrapper_binding['container_id'] == binding_of[eid]['container_id']),
                'alerts': [{'alert_id': a['alert_id'], 'rule_id': a['rule_id'], 'alerted_at': a['alerted_at'],
                            'arrived_at': m['observed_at'] if m else None} for a, m in zip(found, matched)],
                'arrivals_watched': len(arrival), 'watch_errors': record.get('watch_errors'),
                'event_after_start_s': seconds(ns(found[0]['alerted_at']) - start) if found else None,
                'arrival_after_start_s': (seconds(min(ns(m['observed_at']) for m in matched) - start)
                                          if found and all(matched) else None),
                'metrics_latency_s': seconds(row.get('latency_ns')),
            })
        (HERE / 'runs.json').write_text(json.dumps(table, indent=1, sort_keys=True) + '\n')
        lines = ['| # | Round | Atomic | Exit | Outcome | Status | Rules on the run | Event after start (s) | Arrival after start (s) |',
                 '|---|---|---|---|---|---|---|---|---|']
        for r in table:
            lines.append('| %d | %d | %s %s | %s | %s | %s | %s | %s | %s |' % (
                r['index'], r['round'], r['technique'], r['test'], r['returncode'], r['outcome'], r['status'],
                ', '.join(sorted({a['rule_id'] for a in r['alerts']})) or 'none',
                '–' if r['event_after_start_s'] is None else '%.3f' % r['event_after_start_s'],
                '–' if r['arrival_after_start_s'] is None else '%.3f' % r['arrival_after_start_s']))
        (HERE / 'runs.md').write_text('\n'.join(lines) + '\n')

        tests, event_all, arrival_all, delivery_all = [], [], [], []
        for guid, test in emulate.TESTS.items():
            mine = [r for r in table if r['atomic_guid'] == guid]
            ok = [r for r in mine if r['outcome'] == 'succeeded']
            hit = [r for r in ok if r['status'] == 'detected']
            event = [round(r['event_after_start_s'] * 1e9) for r in hit]
            arrival = [round(r['arrival_after_start_s'] * 1e9) for r in hit if r['arrival_after_start_s'] is not None]
            delivery = [ns(a['arrived_at']) - ns(a['alerted_at']) for r in hit for a in r['alerts'][:1] if a['arrived_at']]
            fired = {}
            for r in mine:
                for a in r['alerts']:
                    fired[a['rule_id']] = fired.get(a['rule_id'], 0) + 1
            event_all += event
            arrival_all += arrival
            delivery_all += delivery
            tests.append({'atomic_guid': guid, 'name': test['name'], 'technique': test['technique'], 'test': test['slug'],
                          'n': len(mine), 'succeeded': len(ok), 'detected': len(hit),
                          'alerts_on_failed_runs': sum(len(r['alerts']) for r in mine if r['outcome'] != 'succeeded'),
                          'rules_fired': fired, 'event_after_start': spread(event), 'arrival_after_start': spread(arrival),
                          'first_alert_delivery': spread(delivery)})
        pooled = {'event_after_start': spread(event_all), 'arrival_after_start': spread(arrival_all),
                  'first_alert_delivery': spread(delivery_all)}
        (HERE / 'tests.json').write_text(json.dumps({'tests': tests, 'pooled_detected_runs': pooled}, indent=1, sort_keys=True) + '\n')

        def cell(s, key):
            return '–' if s[key] is None else '%.3f' % s[key]
        lines = ['| Atomic (GUID) | n | Succeeded | Detected | Rules fired (alerts) | Event after start, s (min / p50 / max) | Arrival after start, s (min / p50 / max) |',
                 '|---|---|---|---|---|---|---|']
        for t in tests:
            e, a = t['event_after_start'], t['arrival_after_start']
            lines.append('| %s %s (`%s`) | %d | %d | %d | %s | %s / %s / %s | %s / %s / %s |' % (
                t['technique'], t['name'], t['atomic_guid'], t['n'], t['succeeded'], t['detected'],
                ', '.join('%s (%d)' % kv for kv in sorted(t['rules_fired'].items())) or 'none',
                cell(e, 'min'), cell(e, 'p50'), cell(e, 'max'), cell(a, 'min'), cell(a, 'p50'), cell(a, 'max')))
        (HERE / 'tests.md').write_text('\n'.join(lines) + '\n')

        # 5. The session's kept alerts as review groups (all unreviewed).
        run(PY + ['detect/falco/review.py', 'groups', '--alerts', str(kept), '--alerts', str(platform),
                  '--scoping', str(scoping), '--out', str(HERE / 'review-groups.jsonl'),
                  '--template', str(HERE / 'review-map-template.jsonl')])

        # 6. The detector's health over the runs: one record from the first
        # healthy point to the cutoff (no benign workload).
        heartbeats = [(line.encode(), json.loads(line)) for line in plain('heartbeats.jsonl', scratch).read_text().splitlines() if line.strip()]
        health = [(line.encode(), json.loads(line)) for line in plain('health.jsonl', scratch).read_text().splitlines() if line.strip()]
        explain = []
        coverage = recorder.intervals(heartbeats, health, [], source_id='falco-host', runtimes=('runc', 'gvisor'),
                                      start=window['start'], end=window['end'], period=3600, max_gap=90,
                                      snapshot_gap=150, explain=explain)
        (HERE / 'coverage.jsonl').write_text(jsonl(coverage))
        (HERE / 'explain.jsonl').write_text(jsonl(explain))
        (scratch / 'none.jsonl').write_text('')
        observed = run(PY + ['-m', 'detect.report.observation', '--coverage', str(HERE / 'coverage.jsonl'),
                             '--normal-alerts', str(scratch / 'none.jsonl'), '--source', 'falco-host',
                             '--start', window['start'], '--end', window['end'], '--observed-until', window['end']], check=False)
        (HERE / 'observation.json').write_text(observed.stdout + observed.stderr)

        counts = heartbeats[-1][1]['counts']
        platform_digests = {review.digest(p) for p in rows_of(platform)}
        registry_rows = rows_of(registry)
        died = {r['container_id'] for r in registry_rows if r.get('event') == 'die'}
        arrived = {a['alert_sha256'] for record, _, _, _ in runs for a in record.get('arrivals') or []}
        checks = {
            'thirty_runs_five_per_test': len(runs) == 30 and all(sum(1 for r in records if r['atomic_guid'] == g) == 5
                                                                  for g in emulate.TESTS),
            'binding_for_every_execution': not errors and len(bound) == len(executions) == len(runs),
            'wrapper_and_registry_bind_the_same_container': all(r['wrapper_binding_container_matches'] for r in table),
            'runs_inside_window': all(ns(window['start']) <= ns(r['started_at']) and ns(r['finished_at']) <= ns(window['end'])
                                      for r in table),
            'every_target_removed_before_cutoff': all(r['container_id'] in died and ns(r['removed_at']) < ns(window['end'])
                                                      for r in records),
            'every_imported_alert_arrival_watched': all(a['alert_id'].removeprefix('falco-') in arrived for a in alerts),
            'coverage_healthy': bool(coverage) and all(r['healthy'] for r in coverage),
            'coverage_dropped_events': sum(r['dropped_events'] for r in coverage),
            'collector_errors_drops_zero': all(counts[k] == 0 for k in ('collector_errors', 'collector_restarts', 'dropped_error',
                                                                         'dropped_unresolved', 'dropped_overflow', 'dropped_malformed')),
            'no_platform_alert_imported': not any(a['alert_id'].removeprefix('falco-') in platform_digests for a in alerts),
            'observation_exit_0': observed.returncode == 0,
        }
        summary = {'window': window, 'collector_counts': counts, 'checks': checks, 'alerts_imported': len(alerts),
                   'pooled_detected_runs': pooled,
                   'metrics': {name: {'execution_detection': m['execution_detection'], 'technique_detection': m['technique_detection'],
                                      'latency_ns': m['latency_ns'], 'execution_count': m['execution_count'],
                                      'alerts_on_failed_or_skipped_executions': m['alerts_on_failed_or_skipped_executions']}
                               for name, m in reports.items()}}
        (HERE / 'checks.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
        print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
