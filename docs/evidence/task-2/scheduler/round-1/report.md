# Scheduler review fix round 1

Date: 2026-10-23 America/Los_Angeles / 2026-10-24 UTC.
Reviewed base: `08b0383`; controller review archive: `21abfc2`.
Implementation: `ea41312035b38207f6e2aa3215a5e8d104178a7e`.
Status: both Important findings addressed and locally verified; ready for independent re-review. Task 2 and overall Goal remain open.

## Finding 1: late snapshot publication leaked cleanup ownership

The original collector published a reader into a buffered channel. The timeout branch checked that channel once and could return while it was empty; a producer resumed afterward, published into the abandoned buffer, then blocked forever in Read with nobody left to Close it.

The fix creates the deadline before starting collection and uses an unbuffered handshake to transfer the close function to the timeout owner. Before that transfer, the producer owns cleanup and closes a late reader when the canceled context wins. After transfer, the caller owns timeout cleanup. A shared `sync.Once` protects normal and timeout close paths from concurrent/double Close calls and preserves the close error.

`TestLateSnapshotPublicationClosesReaderAndCollectorExits` uses Go's standard `testing/synctest` and a controlled publication barrier. The test waits for the collector's deadline response before releasing the reader, so late publication is deterministic and does not depend on sleeps or scheduling luck. Assertions run before fixture cleanup and check that the late reader is closed and no started Read remains blocked; the synctest bubble also waits for all collection goroutines to exit. Its RED run failed with both `late snapshot reader has no cleanup owner` and `late snapshot read goroutine is still blocked`. The same test passes after the fix. The existing real-Postgres stalled-reader test continues to cover the already-published reader path and durable lost-log/error state.

The regression models a delayed publication at the Runtime/Handle boundary; no production test hook or generic fault-injection framework was added. Snapshot providers must still honor the existing return/Close contract; this change cannot forcibly terminate a Logs implementation that never returns or a Close implementation that never completes.

## Finding 2: delayed remote creation needed actual materialization

`TestLateRemoteCreationIsReapedByNewWorkerWithoutClearingAmbiguity` adds a stateful external runtime model rather than another unconditional error/nil stub. Its backend state outlives the driver adapter, gate object and worker. Start records the actual RunID, submits a pending asynchronous creation, then returns a lost-response error. The first successful Reap records that the resource is absent. Only after the scheduler has durably recorded failed/pending does the test release the server creation, and it verifies the same-run resource actually exists.

A new driver adapter, reopened persistent gate and new scheduler/store wrapper then recover from real PostgreSQL state. The second Reap observes and removes that late resource using exactly the original RunID, while an unrelated backend resource remains present. Another new worker performs an absent Reap afterward. Across all three durable generations, Start is called exactly once, node authority is unchanged, the audit chain verifies, no result/cgroup-clean evidence is fabricated, and every outcome stays failed with cleanup_pending. Initial error code is runtime_start_ambiguous; recovery remains creation_outcome_unknown.

This was a coverage gap in an already conservative gate, so no runtime/gate production behavior changed for this finding. The new meaningful late-materialization test passes with the existing ambiguity protocol. It does not prove containerd quiescence or real container isolation.

## Validation

| Command | Result | Artifact |
|---|---|---|
| `scripts/go.sh test ./controlplane/internal/scheduler -run TestLateSnapshotPublicationClosesReaderAndCollectorExits -count=1 -v` before/after fix | expected behavioral RED, then GREEN | red-late-snapshot.txt / green-late-snapshot.txt |
| `scripts/test-postgres.sh test ./controlplane/internal/scheduler -run 'TestLateSnapshotPublicationClosesReaderAndCollectorExits\|TestLogSnapshotDeadlineClosesReaderAndMarksLost\|TestLateRemoteCreationIsReapedByNewWorkerWithoutClearingAmbiguity' -count=1 -v` | PASS | green-focused.txt |
| `scripts/test-postgres.sh test -p 1 ./controlplane/... ./runtimes/gate -count=1 -v` | PASS: 55 top-level, 68 including subcases; no SKIP | test-final.txt |
| `scripts/test-postgres.sh test -p 1 -race ./controlplane/... ./runtimes/gate -count=1 -v` | same PASS counts; no race report | race-final.txt |
| `scripts/go.sh vet ./controlplane/... ./runtimes/gate` | exit 0 | vet-final.txt |
| `scripts/check-test-postgres-cleanup.sh` | exact owned container and captured anonymous volume absent | postgres-cleanup.txt |
| `git diff --check` | exit 0 | checked before commits |

Top-level counts include the existing subprocess worker entrypoint. PostgreSQL was real and privately provisioned by the existing harness, capped at 512MiB/no extra swap, 128 pids and 2 CPU. Final own-tag fixture container listing was empty. The code commit preceded this evidence package; final tests exercised the identical source tree immediately before commit, and the post-commit code-only diff against the implementation SHA was empty. verification.json binds raw logs by SHA-256.

## Remaining boundaries and scope

The fixed 128-candidate window Minor is intentionally deferred to final review, as directed. No candidate scheduling expansion or daemon orchestration was implemented. Actual API→runc acceptance and proof/reconciliation of ambiguous creation on the original daemon remain separate Task 2 integration gates. Unknown creation remains visible and cannot be cleared by an absent Reap or a worker restart. Production auth remains fail closed until Task 6.

No dependencies, runtime driver, gate implementation or lab wrapper changed, so no vulnerability rescan or seven-guest capability rerun was performed. No subagents, Azure/GPU/SaaS action, shared-service modification, push, long-lived credential, unknown-resource cleanup or Task 2/Goal completion claim. Estimated Azure cost for this round: $0. Test services and their exact owned data volumes were removed.
