# Execution, real alerts and observation accounting

`detection_metrics.py` computes detection rates and nearest-rank p50/p95 from
explicit execution/alert correlations. `detection_report.py` renders those
numbers. Existing synthetic fixtures verify arithmetic only; they are not live
attack or detector evidence.

The Task 13 wrappers emit real execution records with exactly
`execution_id`, `run_id`, `technique_id`, `executed_at`, `outcome`. Failed
commands remain `failed` and are excluded from successful-execution detection
rates. Neither wrapper emits an alert or treats a success marker as detection.

## Import independently collected Falco alerts

The online detector (`detect/falco`, [runbook](../../docs/falco-detector.md)) produces the inputs below: Warden containers' raw Falco alerts (`.cache/detect/data/<session>/<instance>/alerts.jsonl`), trusted bindings (`detect/falco/bindings.py`), the coverage intervals of the seven-day ledger (`detect/falco/recorder.py`), and the reviewed normal-alert dispositions (`detect/falco/review.py`: a person's group -> disposition map; unmapped groups stay `unreviewed`).

Capture actual Falco JSONL from an already authorized detector before starting
an emulation, and retain the raw export and collector health/drop counters.
`alert_import.py` accepts actual Falco events (`time`, `rule`, `output_fields`)
and explicit trusted bindings. A binding has exactly `execution_id`, `run_id`,
full 64-hex `container_id`, RFC3339 `start`, `end`. The Atomic wrapper writes
one binding; a collector may supply a reviewed longer observation interval
based on actual telemetry. Never invent alerts or widen bindings to make an
expected result appear detected.

```sh
python3 -B detect/report/alert_import.py \
  --falco /private/evidence/real-falco.jsonl \
  --bindings /private/evidence/atomic-run/bindings.jsonl \
  --expected-rules /private/evidence/reviewed-execution-rules.jsonl \
  --out /private/evidence/NEW-alerts.jsonl \
  --provenance /private/evidence/NEW-alert-provenance.jsonl
python3 -B detect/report/detection_metrics.py \
  --executions /private/evidence/atomic-run/executions.jsonl \
  --alerts /private/evidence/NEW-alerts.jsonl \
  --observed-until EXPLICIT_RFC3339_CUTOFF > /private/evidence/metrics.json
python3 -B detect/report/detection_report.py \
  --metrics /private/evidence/metrics.json --out /private/evidence/detection-coverage.md \
  --note "Cohort: what ran, and how many runs reached their goal"
```

Each `--note` is one line of the page's Scope section, above the rate: state the cohort's size, the rule map and what is not covered, so a rate over a small cohort is not read without them.

The reviewed rule map contains one JSON object per allowed pair, for example `{"execution_id":"exec-1","rule_id":"Terminal shell in container"}`. Review each rule against the attack objective before the run; events from other rules in the same container/time are excluded. This is still temporal association, not proof the alert was caused by the attack.

Bindings match the real Falco `container.id` at the event's timestamp. Short
IDs need at least 12 hex digits and must resolve unambiguously. Unbound,
host-only and out-of-interval events are not attributed. Exact duplicate raw
events deduplicate by canonical SHA256; provenance retains the original event.
Malformed data fails closed. The normalized metric timestamp is Falco's event
`time`, not a later dashboard receipt timestamp, so interpret latency in that
scope. Inputs/outputs use bounded JSONL ingestion and exclusive private output
files. Input authenticity and binding trust need external validation.

An empty source produces an empty alert file and **does not prove detector
coverage**. A metrics row saying `not_detected_by_cutoff` means no supplied
correlated alert by that time; a separate collector outage can explain it.
For Stratus, first establish API audit/Falco collection and obtain trusted pod
UID/container-to-run bindings from the unique `warden_run_id` label. Raw audit
requests alone are not alerts; run them through an actual configured detector
and retain its rule result. Do not relabel raw telemetry or expected events as
real detections.

## Seven-day normal-operation ledger

`observation.py` accounts for independently collected, reviewed normal-operation
intervals. It does not start a collector or infer past uptime from the current
clock. Each coverage JSONL record has exactly:

```json
{"source_id":"falco","start":"2026-11-01T00:00:00Z","end":"2026-11-01T00:05:00Z","healthy":true,"event_count":42,"workload_count":1,"dropped_events":0,"receipt":"collector-export-reference-or-digest"}
```

These sample values are **synthetic schema documentation**. The real collector
must substantiate interval endpoints, continuous health, event and normal
workload counts, zero drops and receipt references. Export short heartbeat
intervals so gaps remain visible. Supply every required source explicitly;
intervals for undeclared sources fail. Overlapping active intervals count once.
Any overlapping unhealthy/idle/dropped interval prevents a complete coverage
claim even if another interval overlaps it. Retain receipts externally; the
accounting tool cannot authenticate them.

Reviewed normal-alert JSONL uses the existing schema: `alert_id`, `rule_id`,
`alerted_at`, `disposition` (`false_positive`, `true_positive`, `unreviewed`).
Do not include emulation alerts in normal-operation data.

```sh
python3 -B detect/report/observation.py \
  --coverage /private/evidence/collector-coverage.jsonl \
  --normal-alerts /private/evidence/reviewed-normal-alerts.jsonl \
  --source falco --source kubernetes-audit \
  --start EXPLICIT_START --end EXPLICIT_END --observed-until EXPLICIT_CUTOFF \
  > /private/evidence/normal-observation.json
```

`false_positive_count` is **null** unless the supplied window is at least seven
days, every required source has complete healthy active coverage with positive
telemetry and workload counts and no dropped intervals, and every alert is
reviewed. Empty, idle, missing, short, gapped, unhealthy and unreviewed windows
cannot become “0 false positives.” Even eligible supplied ledgers retain
`coverage_verified=false`: source authenticity, continuous workload ground
truth and annotation correctness need independent review. Report the
observation JSON alongside the metrics page; the older page's supplied
annotation count alone does not establish a seven-day result. Never replace
`null` with zero or mark Task 13's seven-day evidence complete from fixtures.

```sh
python3 -B -m unittest attacks.atomic.test_emulate attacks.stratus.test_emulate \
  detect.report.test_alert_import detect.report.test_observation
```
