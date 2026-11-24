# Detection coverage

Observed until 2026-11-14T18:49:35.208506Z: 1 executions, 3 alerts.

## Scope

- Benign smoke, no attack technique: one execution laid out as an attacks/stratus/emulate.py run (namespace warden-lab, the wrapper's pod labels): a labelled busybox pod, a labelled ServiceAccount, `kubectl exec ... cat /etc/hostname`, then both deleted. T1609 names the exec only so the metrics accept the record.
- Rule map: every stock rule of k8s_audit_rules.yaml (plugins/k8saudit/v0.18.0) and the 25 stock syscall rules of Falco 0.45.2 for the execution (the widest map).
- Attribution: the alert's run label (warden.dev/run, warden_run_id) or its target namespace, inside the receipt's started_at..finished_at, which here, as in a wrapper run, includes the clean-up.
- Time to detect: from the receipt's started_at to the alert's event time (Falco's time = the audit event's stageTimestamp).

## Detection rate

| Measure | Detected | Of | Rate |
|---|---|---|---|
| Successful executions | 1 | 1 | 100.0% |
| Techniques with a successful execution | 1 | 1 | 100.0% |

Alerts on failed or skipped executions: 0.

## Time to detect

Over the 1 detected successful executions (nearest-rank): p50 0.371 s, p95 0.371 s.

## False positives in normal operation

No normal-operation window was supplied, so there is no false-positive count.

## Per technique

| Technique | Successful | Detected | Failed | Skipped | Fastest detection (s) |
|---|---|---|---|---|---|
| T1609 | 1 | 1 | 0 | 0 | 0.371 |

## Per execution

| Execution | Run | Technique | Outcome | Status | Executed (UTC) | Time to detect (s) | First alert |
|---|---|---|---|---|---|---|---|
| `smoke-993ab7fa4afc10927db207f2` | smoke-993ab7fa4afc10927db207f2 | T1609 | succeeded | detected | 2026-11-14T18:49:15.667929Z | 0.371 | falco-a88f310c3bf01295408447dd89a11cd869590d01e5576f0f90b479422b8688bc |

## Limits

- Analysis of supplied cohort only; no provider provenance or authentication is asserted.
- Undetected executions are right-censored at the supplied cutoff, not permanent misses.
- Fixture or supplied data does not establish real emulation, integration or deployment coverage.
- Normal-operation data unavailable; no false-positive count inferred.
