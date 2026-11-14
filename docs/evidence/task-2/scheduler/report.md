# Task 2 scheduler implementation report

Date: 2026-10-23 America/Los_Angeles (final checks 2026-10-24 UTC).
Implementation commit: `77e4e057eb074b39ceb5396ea09d74e824a8b41b`.
Status: scoped durable core implemented and locally verified; awaiting controller independent review. Original Task 2 and overall Goal are not marked complete.

## Delivered

- Additive migration 2 expands the legacy queued-only schema with terminal/result/log/cleanup metadata and durable execution generation, backend owner and runtime-node authority. Version-1 migration compatibility and audit hash preservation are tested using the shipped original DDL.
- A claim owns a dedicated non-reconnecting PostgreSQL session advisory lock and commits its durable intent before Start. All later writes run on that session, check generation/PID and legal predecessor, and atomically include safe audit metadata. A commit error never yields a launch-capable claim. No row/audit-head transaction remains open through execution.
- Session loss cancels active work; recovery obtains exclusive ownership and invokes Reap for the original RunID only. No execution retry invents a new ID. Terminal writes cannot be overwritten even by the same recovery owner after completion.
- A private filesystem gate uses stable per-run flock files and fsynced launch/revocation markers. It permanently consumes launch identities, prevents stale delayed starts after recovery, bounds lock waits, and persists an independent random node authority. Registry drivers must share the same authority. Replacing the directory is detected; reopening a new directory with the same node label does not authorize recovery of the old node.
- Scheduler workers have explicit bounded concurrency/polling and operation deadlines, independent of HTTP request context. Normal signal shutdown kills/reaps owned handles and records interruption without inventing trusted exit evidence. Production main retains a nil verifier; all HTTP calls remain unauthorized until Task 6.
- Trusted JSON config explicitly enables scheduler and maps runc to the dedicated verified daemon/socket/cgroup/image inputs. Unavailable backends fail closed without fallback. Runtime code, capability lab wrapper, existing dependency versions and cloud infrastructure were not changed.
- Persisted log snapshots retain at most 1MiB of aggregate string content, account for runtime plus scheduler dropped bytes, distinguish pending/not-started/complete/partial/lost, close stalled snapshots on timeout, and encode NUL/invalid UTF-8 as explicit Base64 rather than losing bytes or failing PostgreSQL JSONB commits. Tenant-filtered GET exposes the durable final result and log metadata; internal error text stays out of API and audit.
- PostgreSQL fixture readiness now checks TCP, avoiding the image's temporary Unix-socket initialization server. Its exact-owned disposable container is capped at 512MiB/no additional swap, 128 pids, 2 CPUs; trap cleanup still removes only that container and its own anonymous volume.

## Architectural boundary retained, not claimed resolved

The controller identified that containerd RPC cancellation does not imply server quiescence. The pinned shim process Start/Delete mutex helps order acknowledged task operations, but service Create can run `runc.NewContainer` before publishing its service entry. A delayed creation may therefore be invisible to an early Reap.

The gate now persists `launching` before entering the external Start boundary and only records `started` after a successful acknowledgement. Any error/crash in that interval remains ambiguous. Reap still attempts exact cleanup, but it cannot clear ambiguity merely because resources are currently absent. The uncertain marker survives retry/restart, and the API remains `failed` with `cleanup_pending=true` and explicit `runtime_start_ambiguous` / `creation_outcome_unknown` codes. A successful underlying Reap does not turn this into terminal-clean interruption.

This core deliberately does not orchestrate daemon restarts or expose a marker-clearing endpoint. Proving the original owned daemon is quiescent and reconciling delayed creation is a required subsequent, independently reviewed Task 2 integration gate. Do not delete/rotate/copy markers or substitute another daemon to claim cleanup. Runtime adapters must honor their context and snapshot-close contracts; the supplied runc adapter has bounded internal cleanup. If a node or its original gate state is unavailable, its jobs cannot be declared recovered from another node.

## Validation and fault models

Final commands:

```
scripts/test-postgres.sh test -p 1 ./controlplane/... ./runtimes/gate -count=1 -v
scripts/test-postgres.sh test -p 1 -race ./controlplane/... ./runtimes/gate -count=1 -v
scripts/go.sh vet ./controlplane/... ./runtimes/gate
scripts/check-test-postgres-cleanup.sh
git diff --check
```

Both normal and race runs passed 53 top-level test entries (including the subprocess helper), 66 entries with subcases, with no SKIP or race report. Vet exited 0. The cleanup probe captured the exact fixture container/anonymous volume and verified both absent. Final own-tag container listing was empty. No dependency changes warranted a fresh vulnerability scan.

Behavioral boundary fakes replace only Runtime/Handle external operations. Database transactions, advisory locks, schema migrations, stored policy/tenant checks, HTTP handling, audit hashing, filesystem fsync/flock and independent process contention run for real. Tests terminate the actual claimed PostgreSQL backend before or during a blocked launch; use a deferred commit trigger to make claim commit time out; reject a terminal audit insert to verify rollback of result/logs; and preserve a remotely ambiguous Start through successful Reap attempts and restart of the gate wrapper. They do not prove real container isolation, a live authenticated production endpoint, or actual API→runc execution. Separate seven-guest lab evidence remains valid but distinct.

TDD evidence includes behavioral RED→GREEN cycles for durable claims, missing scheduling/API logs, persistent gate revocation, legal terminal transitions, node authority and directory replacement, reader timeout close, interrupted logs, binary output preservation, descriptor lifecycle, ambiguous creation and partially returned handle cleanup. Final source was committed only after those checks passed, and subsequent code-only diff against its SHA was empty. README/STATUS/evidence are committed separately with the implementation SHA.

## Self-review and resources

No subagents/reviewer were spawned. The controller will perform independent review. Self-review fixes are listed in the evidence README; all final relevant checks include them. Existing Task 1 behavior continues to pass. No Task 2 checkbox, Goal completion, push, Azure/GPU/SaaS action, long-lived credential, unknown-volume cleanup, global prune or shared daemon modification occurred. Azure estimate remains $0; project cache is approximately 2.2GiB and no test service is resident after cleanup.

Remaining work: controller core review; separately reviewed actual API→runc integration; independently established original-daemon quiescence/reconciliation for ambiguous creation. Production authentication remains intentionally unavailable until Task 6.
