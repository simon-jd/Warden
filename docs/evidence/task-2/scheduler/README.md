# Task 2 scheduler/API/logs core evidence

Implementation: `77e4e057eb074b39ceb5396ea09d74e824a8b41b`. Verification date: 2026-10-23 America/Los_Angeles / 2026-10-24 UTC. Code was committed before this evidence package. Final test runs exercised exactly the implementation tree; `git diff --exit-code 77e4e057... -- controlplane runtimes/gate scripts/test-postgres.sh` returned 0 after commit. No dependency changes or repeated vulnerability scan.

This is real disposable PostgreSQL 18 with controlled runtime boundary fakes and real cross-process file locks, not a container-isolation or actual API→runc acceptance claim. The separate [seven real guest passes](../lab-live/README.md) do not fill the remaining API→runc/quiescence integration gate. Production auth remains fail closed until Task 6. Original Task 2 and overall Goal remain open.

## Final checks

| Command | Result | Evidence |
|---|---|---|
| `scripts/test-postgres.sh test -p 1 ./controlplane/... ./runtimes/gate -count=1 -v` | PASS, 53 top-level / 66 including subcases; no SKIP | [test-final.txt](test-final.txt) |
| `scripts/test-postgres.sh test -p 1 -race ./controlplane/... ./runtimes/gate -count=1 -v` | PASS, same count; no race report / SKIP | [race-final.txt](race-final.txt) |
| `scripts/go.sh vet ./controlplane/... ./runtimes/gate` | exit 0, no output | [vet-final.txt](vet-final.txt) |
| `scripts/check-test-postgres-cleanup.sh` | exact owned container and captured anonymous volume absent | [postgres-cleanup.txt](postgres-cleanup.txt) |
| `git diff --check` | exit 0 | checked before source and evidence commits |

The top-level count includes the dedicated child-worker test entrypoint, which is exercised by `TestIndependentProcessesExecuteOnce` in four independent OS processes. Package parallelism is one during final checks to keep the disposable PostgreSQL fixture within its 512MiB / no additional swap / 128-pid / 2-CPU limits. No persistent service or volume is retained. Final own-tag container listing was empty. Project `.cache` remained approximately 2.2 GiB; Azure estimate for this substep is $0.

## Covered behavior

- One durable claim/Start across goroutines and independent processes; repeated idempotency keys never launch again.
- Policy recheck from the stored tenant immediately before guarded Start; unavailable policy and missing driver fail closed.
- Real session termination before gate entry rejects a delayed stale Start after successful Reap; termination inside the gate leaves cleanup pending until the in-flight call releases it.
- Valid active owners are not stolen; stale writes, terminal-overwrite attempts and false successful transitions are rejected.
- Node affinity includes persistent random gate authority; new/replaced directories cannot impersonate the old authority. Descriptor lifecycle is tested.
- Reap-only recovery for durable starting/running states, retryable cleanup failure, and migration from the actual shipped version-1 DDL without changing its runs/audit hash.
- Natural/nonzero/OOM/timeout/Start/Wait/log failures, shutdown Kill, missing/partial/binary/truncated logs and a 1MiB aggregate persistence cap.
- Tenant-filtered run/log API, committed HTTP request cancellation, useful exit metadata, terminal/log/audit rollback on injected audit failure, hash verification, and no audit lock held across a waiting guest.
- Claim commit deadline via a real deferred PostgreSQL trigger never permits Start.

## Creation ambiguity remains an explicit integration gate

A database session lock plus a file lock around the client call does **not** prove a canceled containerd creation RPC has stopped on the server. The wrapper persists `launching` before the call; only successful acknowledgement followed by fsync changes it to `started`. Start error or worker death during creation conservatively leaves an uncertain identity.

Reap durably revokes the identity before exact cleanup. An uncertain identity remains uncertain across retries and worker restarts even when the underlying Reap returns success/not-found. The API reports `failed`, `cleanup_pending=true`, and `runtime_start_ambiguous` initially / `creation_outcome_unknown` during recovery. No clean cgroup or successful interrupted completion is fabricated. This version has no automatic uncertainty-clearing API: proving quiescence of the **original** owned daemon and reconciling delayed creation are required later Task 2 integration work. Never delete or rotate markers to clear this condition.

The pinned containerd source supports this conservative choice: shim `Init.Start`/`Delete` use a process mutex, but task-service `Create` calls `runc.NewContainer` before publishing the container in its service map. Therefore an early not-found cannot prove no delayed creation remains. No runtime/lab wrapper changes or capability lab rerun were made here.

## TDD and configuration

`red-*.txt` record observed behavioral failures before their fixes; intermediate `green-*.txt` show scoped results. The final logs supersede intermediate runs. `fixture-directory-mode-failure.txt` preserves a test setup failure: the temporary directory needed explicit mode 0700; corrected fixture and gate tests pass in the final logs. Self-review found and fixed terminal overwrite, false clean success, directory replacement, file descriptor leak, stalled snapshot close, interrupted empty-log misreporting, binary JSONB loss, partial Start handle collection and ambiguous remote creation handling.

[README deployment configuration and final API schema](../../../../README.md#task-2持久调度恢复与日志) documents the explicit scheduler enablement, private persistent gate directory, trusted original daemon identity, fixed secure defaults, bounded lifecycle and JSON log encoding. See [full implementation report](report.md) and [verification manifest](verification.json).

## First-review fix round

[Round 1 report and SHA-bound evidence](round-1/README.md): implementation `ea41312035b38207f6e2aa3215a5e8d104178a7e` fixes the late snapshot cleanup race and adds actual delayed remote-resource materialization/recovery coverage. Normal/race checks pass 55 top-level entries / 68 including subcases; vet and exact fixture cleanup pass. Awaiting independent re-review; the candidate-window Minor and stated Task 2 integration gates remain open.
