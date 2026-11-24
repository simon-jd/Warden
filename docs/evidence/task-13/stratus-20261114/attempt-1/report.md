# Detection coverage

Observed until 2026-11-14T20:17:27.891423Z: 2 executions, 4 alerts.

## Scope

- The Stratus round alone: eight Kubernetes techniques of Stratus Red Team v2.38.0, five runs each, on the kind audit lab; k8saudit alerts only, against all 48 stock k8s_audit_rules.yaml rules (the widest map).
- No stock rule is written for dump-secrets (T1552.007) or create-token (T1098); create-admin-clusterrole (T1098.006) fails on Kubernetes 1.24 and later. T1611 is privileged-pod and hostpath-volume together.

## Detection rate

| Measure | Detected | Of | Rate |
|---|---|---|---|
| Successful executions | 1 | 1 | 100.0% |
| Techniques with a successful execution | 1 | 1 | 100.0% |

Alerts on failed or skipped executions: 3.

## Time to detect

Over the 1 detected successful executions (nearest-rank): p50 3.092 s, p95 3.092 s.

## False positives in normal operation

No normal-operation window was supplied, so there is no false-positive count.

## Per technique

| Technique | Successful | Detected | Failed | Skipped | Fastest detection (s) |
|---|---|---|---|---|---|
| T1098.006 | 0 | 0 | 1 | 0 | – |
| T1611 | 1 | 1 | 0 | 0 | 3.092 |

## Per execution

| Execution | Run | Technique | Outcome | Status | Executed (UTC) | Time to detect (s) | First alert |
|---|---|---|---|---|---|---|---|
| `stratus-1005d2e4-5233-4f52-b7b1-cdd98bed5ecc` | stratus-1005d2e4-5233-4f52-b7b1-cdd98bed5ecc | T1611 | succeeded | detected | 2026-11-14T20:16:14.969283Z | 3.092 | falco-bac87d0cf6eecfe0bc07b90dd71b68b2cda2b1af93d096e4eb1ba3bd247b49d9 |
| `stratus-eb23baf0-9c03-4891-9643-9bd4e4563af4` | stratus-eb23baf0-9c03-4891-9643-9bd4e4563af4 | T1098.006 | failed | excluded_outcome | 2026-11-14T19:59:56.110615Z | – | falco-1e395e66d01baf7b75f2316ff5aa977c1ca44f12ce0680aa04700b82c122765a |

## Limits

- Analysis of supplied cohort only; no provider provenance or authentication is asserted.
- Undetected executions are right-censored at the supplied cutoff, not permanent misses.
- Fixture or supplied data does not establish real emulation, integration or deployment coverage.
- Normal-operation data unavailable; no false-positive count inferred.
