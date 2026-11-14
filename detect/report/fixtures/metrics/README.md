# Synthetic metrics fixtures

These inputs are synthetic and serve only the local arithmetic tests. They are not emulation, detector integration, provider provenance, deployment coverage, or normal-operation evidence.

Three successful executions represent three distinct techniques. Two are detected after exactly 2 and 9 seconds. Both detection rates are 2/3. Nearest-rank percentiles use sorted detected successful latencies and rank ceil(p*n): p50 = 2 seconds, p95 = 9 seconds. The third execution is undetected by the explicit cutoff and is right-censored.

## Interface

`compute_metrics(executions, alerts, observed_until, *, normal_alerts=None, normal_start=None, normal_end=None)` accepts iterables of dictionaries and an explicit RFC3339 cutoff. `normal_window_metrics(alerts=None, start=None, end=None)` is also independently callable. `read_jsonl(path)` performs bounded ingestion before decoding. `main(argv=None)` supports in-process CLI calls and returns 0 or 2 for successful analysis or invalid supplied data respectively. Argparse reports invalid CLI syntax with its usual exit status 2.

Execution records have exactly `execution_id`, `run_id`, `technique_id`, `executed_at`, `outcome`; outcomes are `succeeded`, `failed`, `skipped`. Alert records have exactly `alert_id`, `execution_id`, `rule_id`, `alerted_at`. Normal records have exactly `alert_id`, `rule_id`, `alerted_at`, `disposition`; dispositions are `false_positive`, `true_positive`, `unreviewed`. IDs are nonblank strings of at most 256 UTF-8 bytes. Technique validation checks syntax `Tdddd` or `Tdddd.ddd`, without asserting catalog authenticity. Duplicate event IDs must match every original field exactly, including timestamp spelling.

Each input is an explicit regular file; symlinks and special files are refused. Empty files represent empty cohorts. Nonempty JSONL records are capped at 65,536 bytes excluding the LF delimiter, files at 16 MiB including delimiters, and each input at 100,000 records before deduplication. Blank lines, duplicate object keys, malformed JSON, unknown/missing fields, invalid types, nonfinite values, and trailing content fail. The suite tests actual 65,536-byte record boundaries; smaller patched file/count constants exercise those branches without exceeding the test process's 2 MiB FSIZE limit.

All report timestamp fields ending `_ns` use exact integer nanoseconds from `0001-01-01T00:00:00Z`; latency, span and observation duration are exact integer nanosecond differences. RFC3339 numeric offsets normalize to UTC, 0–9 fractional digits are accepted, and dates outside UTC years 1–9999, leap seconds and naive dates are rejected. Lowercase `t`/`z` are accepted per RFC3339. No clock is consulted. Every execution/alert must be at or before the cutoff; correlation must resolve and alerts must not precede their execution. Normal annotations instead use their own explicit `[start,end)` window.

Reports are deterministic, ordered by execution ID and technique ID, and never mutate inputs. Within an execution, alerts sort by time then alert ID; the first alert sets latency for successful executions. Execution and technique detection rates retain numerators and denominators. Only successful executions and techniques having a successful execution enter those respective denominators. Per-technique rows also expose failed/skipped counts, detected successful counts, a detected flag, and the minimum successful latency. Excluded outcomes have `detected=null` and no latency; their correlated alerts are separately counted. Successful undetected rows have `status=not_detected_by_cutoff` and an explicit observation duration. Percentiles include only detected successful executions; zero latency is valid, missing latency is null. Empty denominators and empty percentiles are null.

Absent normal input produces `available=false` with no count. Supplied normal annotations deduplicate by full record, count each disposition separately, report span and the seven-day threshold, and always report `coverage_verified=false`. Endpoints and labels require external validation for continuous coverage and ground truth. Fixture values never establish normal-operation evidence.

Run from the repository root, with explicit file paths:

```sh
python3 -B detect/report/detection_metrics.py \
  --executions detect/report/fixtures/metrics/executions.jsonl \
  --alerts detect/report/fixtures/metrics/alerts.jsonl \
  --observed-until 2026-01-01T00:01:00Z
```

Optional `--normal-alerts PATH --normal-start TIMESTAMP --normal-end TIMESTAMP` must all be supplied together. Invalid input emits a concise error to stderr, returns nonzero and produces no partial successful JSON. Reports state `scope=provided-cohort` and explicitly limit provenance, right-censor interpretation, and deployment coverage.
