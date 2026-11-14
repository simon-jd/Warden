#!/usr/bin/env python3
"""Score the 2026-11-14 corpus runs (runc, gVisor) against the online detector.

    python3 -I -B docs/evidence/task-13/emulation-20261114/score.py   # from the repository root

Inputs, all in this directory: runc.json and gvisor.json (the matrix
reports), run/window.json (the detector's first healthy point, and the
cutoff: the time taken just before the last heartbeat flush before down, so
that flushed heartbeat brackets it), run/runc-lab-identity.json (the runc lab
session label), stock-rules.txt (the names of the 25 rules in the pinned
image's falco_rules.yaml) and collector-host/ (the host collector's files as
it wrote them; the two large ones gzip'ed). Outputs go next to them, and the
rendered page to docs/evidence/detection-coverage.md.

Every step is the runbook's own tool (docs/falco-detector.md,
attacks/README.md): bindings.py, alert_import, matrix render,
detection_metrics, detection_report, review.py groups, recorder and
observation. This script only feeds them and tabulates their outputs.

The reviewed rule map alert_import needs is every stock rule for every run:
any kept alert on the run's container inside its window counts, and the
table names the rule. No narrower map has been reviewed.
"""
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'detect/falco'))
import recorder  # noqa: E402
import review  # noqa: E402

CPU = ['/usr/bin/taskset', '-c', '0-7,16-31']
PY = ['/usr/bin/python3', '-E', '-s', '-B']
TASK5 = ROOT / 'docs/evidence/task-5/live-20261113'
COLLECTOR = HERE / 'collector-host'
ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(ROOT / '.cache/home'), 'LC_ALL': 'C'}
GOENV = {**ENV, 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOFLAGS': '-mod=readonly',
         'GOCACHE': str(ROOT / '.cache/go-build'), 'GOMODCACHE': str(ROOT / '.cache/go-mod'),
         'GOPATH': str(ROOT / '.cache/go'), 'TMPDIR': str(ROOT / '.cache/test-tmp')}
# The coverage page's Scope section (detection_report.py --note).
SCOPE = (
    'Cohort: the Task 5 corpus (14 probes) once on runc and once on gVisor, 2026-11-14, 28 runs. Only one run '
    'reached its goal (gVisor memory-exhaustion), so the detection rate below is over n=1.',
    'Rule map: every one of the 25 stock rules of the pinned Falco 0.45.2 for every run (any kept alert on the '
    "run's container inside its window counts); no narrower map has been reviewed.",
    'Coverage: runc at host level; gVisor at host level only (a sandbox\'s own system calls are not seen); '
    'Firecracker not covered and not run.',
    "Alert time is the alerted event's own time (Falco's `time`); the time Falco and the collector took to "
    'deliver an alert is not included.',
    'Not run: the Stratus Red Team and Atomic Red Team live emulations (the plan\'s Stratus AWS and GCP techniques '
    "are not wrapped); Task 12's Sigma rules are not in this scoring path; no seven-day normal window, so no "
    'false-positive count.',
)
OUTPUTS = ('bindings.jsonl', 'binding-errors.json', 'expected-rules.jsonl', 'alerts.jsonl', 'alert-provenance.jsonl',
           'alert-import.out', 'executions.jsonl', 'isolation-matrix.md', 'metrics.json', 'metrics-runc.json',
           'metrics-gvisor.json', 'cells.json', 'cells.md', 'review-groups.jsonl', 'review-map-template.jsonl',
           'coverage.jsonl', 'explain.jsonl', 'observation.json', 'checks.json')


def jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)


def rows_of(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def run(argv, env=ENV, check=True):
    result = subprocess.run(CPU + argv, cwd=ROOT, text=True, capture_output=True, env=env)
    if check and result.returncode != 0:
        raise SystemExit('%s failed (%d): %s' % (' '.join(argv[:8]), result.returncode, (result.stdout + result.stderr)[-3000:]))
    return result


def plain(name, scratch):
    """A collector file as a plain regular file (the tools read no gzip)."""
    if (COLLECTOR / name).exists():
        return COLLECTOR / name
    target = scratch / name
    with gzip.open(COLLECTOR / (name + '.gz'), 'rb') as source, open(target, 'wb') as out:
        shutil.copyfileobj(source, out)
    return target


def ns(value):
    return recorder.ns(value)


def seconds(delta_ns):
    return None if delta_ns is None else round(delta_ns / 1e9, 3)


def main():
    for name in OUTPUTS:
        if (HERE / name).exists():
            (HERE / name).unlink()
    (ROOT / '.cache/test-tmp').mkdir(parents=True, exist_ok=True)
    window = json.loads((HERE / 'run/window.json').read_text())
    session = json.loads((HERE / 'run/runc-lab-identity.json').read_text())['labels']['session']
    reports = {rt: json.loads((HERE / (rt + '.json')).read_text()) for rt in ('runc', 'gvisor')}
    task5 = {rt: {c['attack']: c['verdict'] for c in json.loads((TASK5 / (rt + '.json')).read_text())['cells']}
             for rt in ('runc', 'gvisor')}
    rules = [line for line in (HERE / 'stock-rules.txt').read_text().splitlines() if line.strip()]
    if len(rules) != 25 or len(set(rules)) != 25:
        raise SystemExit('stock-rules.txt must name the 25 stock rules')
    with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as tmp:
        scratch = Path(tmp)
        registry = plain('registry.jsonl', scratch)
        kept = plain('alerts.jsonl', scratch)
        platform = plain('platform-alerts.jsonl', scratch)
        scoping = plain('scoping.jsonl', scratch)

        # 1. Bindings: the container ID Falco reports for each run.
        bound, errors = [], {}
        for rt, report in reports.items():
            for cell in report['cells']:
                argv = PY + ['detect/falco/bindings.py', '--registry', str(registry), '--execution-id', cell['run_id']]
                if rt == 'runc':
                    # One outer lab container ran every runc test: each run gets its own window.
                    argv += ['--run-id', session, '--start', cell['started_at'], '--end', cell['finished_at']]
                else:
                    # The pod's warden.dev/run label is the run ID in lower case.
                    argv += ['--run-id', cell['run_id'].lower()]
                result = run(argv, check=False)
                if result.returncode == 0:
                    bound.append(json.loads(result.stdout))
                else:
                    errors[cell['run_id']] = result.stderr.strip()
        (HERE / 'bindings.jsonl').write_text(jsonl(bound))
        (HERE / 'binding-errors.json').write_text(json.dumps(errors, indent=1, sort_keys=True) + '\n')

        # 2. The rule map and the import of the kept alerts.
        (HERE / 'expected-rules.jsonl').write_text(jsonl({'execution_id': b['execution_id'], 'rule_id': r}
                                                         for b in bound for r in rules))
        imported = run(PY + ['-m', 'detect.report.alert_import', '--falco', str(kept), '--bindings', str(HERE / 'bindings.jsonl'),
                             '--expected-rules', str(HERE / 'expected-rules.jsonl'), '--out', str(HERE / 'alerts.jsonl'),
                             '--provenance', str(HERE / 'alert-provenance.jsonl')])
        (HERE / 'alert-import.out').write_text(imported.stdout + imported.stderr)

        # 3. The matrix with the alerts joined, and the executions it gives.
        run([str(ROOT / '.tools/go/bin/go'), 'run', '-buildvcs=false', './attacks/matrix/cmd/matrix', 'render',
             '-results', '%s,%s' % (HERE / 'runc.json', HERE / 'gvisor.json'), '-alerts', str(HERE / 'alerts.jsonl'),
             '-out', str(HERE / 'isolation-matrix.md'), '-executions', str(HERE / 'executions.jsonl')], env=GOENV)

        # 4. Metrics: all runs, then each runtime alone; the page from all runs.
        executions, alerts = rows_of(HERE / 'executions.jsonl'), rows_of(HERE / 'alerts.jsonl')
        metrics = {}
        for name, prefix in (('metrics.json', 'isolation-matrix/'), ('metrics-runc.json', 'isolation-matrix/runc/'),
                             ('metrics-gvisor.json', 'isolation-matrix/gvisor/')):
            ex = [e for e in executions if e['run_id'].startswith(prefix)]
            ids = {e['execution_id'] for e in ex}
            (scratch / 'ex.jsonl').write_text(jsonl(ex))
            (scratch / 'al.jsonl').write_text(jsonl(a for a in alerts if a['execution_id'] in ids))
            result = run(PY + ['-m', 'detect.report.detection_metrics', '--executions', str(scratch / 'ex.jsonl'),
                               '--alerts', str(scratch / 'al.jsonl'), '--observed-until', window['end']])
            (HERE / name).write_text(result.stdout)
            metrics[name] = json.loads(result.stdout)
        run(PY + ['-m', 'detect.report.detection_report', '--metrics', str(HERE / 'metrics.json'),
                  '--out', str(ROOT / 'docs/evidence/detection-coverage.md')]
            + [arg for note in SCOPE for arg in ('--note', note)])

        # 5. Per cell: verdicts, the alerts on the run, the time to the first.
        by_execution = {}
        for a in alerts:
            by_execution.setdefault(a['execution_id'], []).append(a)
        binding_of = {b['execution_id']: b for b in bound}
        platform_rows = rows_of(platform)
        cells = []
        for rt, report in reports.items():
            for cell in report['cells']:
                found = sorted(by_execution.get(cell['run_id'], []), key=lambda a: ns(a['alerted_at']))
                binding = binding_of.get(cell['run_id'])
                first = ns(found[0]['alerted_at']) - ns(cell['started_at']) if found else None
                sandbox_starts = None
                if rt == 'gvisor' and binding:
                    sandbox_starts = sum(1 for p in platform_rows
                                         if binding['container_id'].startswith((p.get('output_fields') or {}).get('container.id') or '-'))
                cells.append({'runtime': rt, 'attack': cell['attack'], 'technique': cell['technique'], 'run_id': cell['run_id'],
                              'started_at': cell['started_at'], 'finished_at': cell['finished_at'],
                              'verdict': cell['verdict'], 'task5_verdict': task5[rt].get(cell['attack']),
                              'exit_code': cell['exit']['Code'], 'bound_container': binding['container_id'][:12] if binding else None,
                              'binding': binding, 'alerts': [{'rule_id': a['rule_id'], 'alerted_at': a['alerted_at'],
                                                              'alert_id': a['alert_id']} for a in found],
                              'first_alert_after_start_s': seconds(first), 'platform_alerts_on_sandbox': sandbox_starts})
        (HERE / 'cells.json').write_text(json.dumps(cells, indent=1, sort_keys=True) + '\n')
        lines = ['| Probe | Runtime | Task 5 (11-13) | This run | Alert on the run | First alert after start (s) |',
                 '|---|---|---|---|---|---|']
        for c in sorted(cells, key=lambda c: (c['attack'], c['runtime'] != 'runc')):
            rules_seen = ', '.join(sorted({a['rule_id'] for a in c['alerts']})) or 'none'
            lines.append('| %s | %s | %s | %s | %s | %s |' % (c['attack'], 'runc' if c['runtime'] == 'runc' else 'gVisor',
                                                             c['task5_verdict'], c['verdict'], rules_seen,
                                                             '–' if c['first_alert_after_start_s'] is None else '%.3f' % c['first_alert_after_start_s']))
        (HERE / 'cells.md').write_text('\n'.join(lines) + '\n')

        # 6. The session's kept alerts as review groups (all unreviewed).
        run(PY + ['detect/falco/review.py', 'groups', '--alerts', str(kept), '--alerts', str(platform),
                  '--scoping', str(scoping), '--out', str(HERE / 'review-groups.jsonl'),
                  '--template', str(HERE / 'review-map-template.jsonl')])

        # 7. The detector's health over the runs: one record from the first
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
        platform_digests = {review.digest(p) for p in platform_rows}
        checks = {
            'binding_for_every_run': not errors and len(bound) == sum(len(r['cells']) for r in reports.values()),
            'runs_inside_window': all(ns(window['start']) <= ns(c['started_at']) and ns(c['finished_at']) <= ns(window['end'])
                                      for r in reports.values() for c in r['cells']),
            'coverage_healthy': bool(coverage) and all(r['healthy'] for r in coverage),
            'coverage_dropped_events': sum(r['dropped_events'] for r in coverage),
            'collector_errors_drops_zero': all(counts[k] == 0 for k in ('collector_errors', 'collector_restarts', 'dropped_error',
                                                                         'dropped_unresolved', 'dropped_overflow', 'dropped_malformed')),
            'no_platform_alert_imported': not any(a['alert_id'].removeprefix('falco-') in platform_digests for a in alerts),
            'every_gvisor_sandbox_seen_starting': all(c['platform_alerts_on_sandbox'] for c in cells if c['runtime'] == 'gvisor'),
            'observation_exit_0': observed.returncode == 0,
        }
        summary = {'window': window, 'runc_lab_session': session, 'collector_counts': counts, 'checks': checks,
                   'alerts_imported': len(alerts),
                   'per_runtime': {name: {'execution_detection': m['execution_detection'], 'latency_ns': m['latency_ns'],
                                          'alerts_on_failed_or_skipped_executions': m['alerts_on_failed_or_skipped_executions'],
                                          'execution_count': m['execution_count']} for name, m in metrics.items()}}
        (HERE / 'checks.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
        print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
