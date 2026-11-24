#!/usr/bin/env python3
"""Re-render docs/evidence/detection-coverage.md with the seven-day normal window.

    python3 -I -B docs/evidence/task-13/seven-day-20261116/render.py   # from the repository root

The detection side is exactly the Stratus round's page (../stratus-20261114/score.py):
the same three rounds' executions and alerts and the same cutoff. This script
adds the reviewed normal alerts of the seven-day window (normal-alerts.jsonl.gz,
written by review.py apply with review-map.jsonl) through detection_metrics.py's
--normal-alerts, checks that every other part of the report equals
../stratus-20261114/metrics-all-rounds.json, and renders the page with the
Stratus round's scope notes, its last note changed for the window. It writes
metrics-all-rounds-normal.json here.
"""
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
STRATUS = HERE.parent / 'stratus-20261114'
spec = importlib.util.spec_from_file_location('stratus_score', STRATUS / 'score.py')
score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(score)

OLD_LAST = score.SCOPE[-1]
assert OLD_LAST.endswith('no seven-day normal window, so no false-positive count.'), OLD_LAST
SCOPE = score.SCOPE[:-1] + (
    OLD_LAST.replace('; no seven-day normal window, so no false-positive count.', '.'),
    'Normal window: the seven-day window of 2026-11-16 06:22:36 to 2026-11-23 06:22:36 UTC on the host instance only '
    '(falco-host; no k8saudit, no kind lab), with Warden\'s hourly benign workload, the conformance suite on runc and on '
    'gVisor (177 runs each, all passed); 168 of 168 hourly slices healthy, no drops. The stock rules were not tuned. '
    'Dispositions are per group of rule, process and container class (review-map.jsonl, seven-day-20261116 README): the '
    '293,372 false positives are the labs\' own infrastructure, gVisor\'s runsc tracing its stubs with ptrace (276,549) and '
    'k3s running the binaries it unpacks (16,823 in 15 groups); the 177 true positives are the conformance '
    "probe's ptrace(PTRACE_TRACEME), which the rule describes.",
)


def main():
    plan = json.loads((HERE / 'plan.json').read_text())
    window = json.loads((STRATUS / 'run' / 'window.json').read_text())
    executions = (score.rows_of(score.CORPUS / 'executions.jsonl') + score.rows_of(score.ATOMIC / 'executions.jsonl')
                  + score.rows_of(STRATUS / 'executions.jsonl'))
    ids = {e['execution_id'] for e in executions}
    alerts = [a for a in score.rows_of(score.CORPUS / 'alerts.jsonl') + score.rows_of(score.ATOMIC / 'alerts.jsonl')
              + score.rows_of(STRATUS / 'alerts.jsonl') if a['execution_id'] in ids]
    with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as tmp:
        scratch = Path(tmp)
        (scratch / 'ex.jsonl').write_text(score.jsonl(executions))
        (scratch / 'al.jsonl').write_text(score.jsonl(alerts))
        with gzip.open(HERE / 'normal-alerts.jsonl.gz', 'rb') as source:
            (scratch / 'normal.jsonl').write_bytes(source.read())
        text = score.run(score.PY + ['-m', 'detect.report.detection_metrics', '--executions', str(scratch / 'ex.jsonl'),
                                     '--alerts', str(scratch / 'al.jsonl'), '--observed-until', window['end'],
                                     '--normal-alerts', str(scratch / 'normal.jsonl'), '--normal-start', plan['window_start'],
                                     '--normal-end', plan['window_end']]).stdout
    report = json.loads(text)
    before = json.loads((STRATUS / 'metrics-all-rounds.json').read_text())
    changed = sorted(k for k in set(report) | set(before) if report.get(k) != before.get(k))
    if changed != ['normal_window']:
        raise SystemExit('the detection side differs from metrics-all-rounds.json: %s' % changed)
    (HERE / 'metrics-all-rounds-normal.json').write_text(text)
    score.run(score.PY + ['-m', 'detect.report.detection_report', '--metrics', str(HERE / 'metrics-all-rounds-normal.json'),
                          '--out', str(ROOT / 'docs/evidence/detection-coverage.md')] + [a for n in SCOPE for a in ('--note', n)])
    print(json.dumps(report['normal_window'], sort_keys=True))


if __name__ == '__main__':
    main()
