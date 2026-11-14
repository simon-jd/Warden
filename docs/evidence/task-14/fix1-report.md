# Original Task14 fix1/5: I1 directory-entry durability

The initial independent review found0 Critical/1 Important/0 Minor and judged the local component Needs fixes. Root accepted I1 and authorized this first continuous fix round. The focused fix is implemented and root accepted the new semantic RED and single affected cover. The required independent I1 re-review is still pending. Original Task14, genuine identity/action/containment acceptance and the Goal remain OPEN.

Fix1 BASE:955ef5da9d0044ab7ec1d8d4db31c8cd38286175.
Fix1 SOURCE:d00bb72e9d68b6b5c818c88be9f54432df34fb6a.
SOURCE contains exactly4 changed paths and36574 file bytes: respond/executor.go7915B, ledger.go7080B, ledger_test.go15193B, README.md6386B. The complete seven-file component is62619B; actions.go, executor_test.go, example playbook, go.mod and go.sum are unchanged. The separate EVIDENCE packet contains20 paths/100182 bytes. Full EVIDENCE SHA and empty-index/ownership checks are returned in final handoff; no circular self-commit hash is embedded.

The [fix1 inventory](fix1-author-inventory-20261025.json) contains all source hashes, exact20-path evidence list and hashes of18 underlying artifacts/82517B. Inventory6178B and this report have no self-reference hash; the commit/final handoff bind them. The ignored task-14-fix1-report.md and public fix1-report.md are byte-identical. Old report.md, ignored old report, initial3-assertion RED,81PASS original cover, original formatter receipts, prior evidence and initial failed review remain unchanged. Root rulings/native-events/review/STATUS/root-handoff, oldTask16/BP and existing dirty files are excluded from these commits.

I1 was a real initialization-order gap. An opener could create a regular journal and pause before flock/parent-directory fsync. A second cooperating opener could win the lock on that existing pathname, skip the created-only directory sync, fsync an intent and call the client. The creator could then fail its lock attempt. File fsync alone does not confirm parent directory-entry durability; losing the pathname after a crash could defeat durable attempt suppression.

The minimal behavior fix preserves created-file f.Sync and separately requires successful parent-directory fsync after every successful flock and existing ownership/mode/link/type/size validation. The existing-path opener now fails with ErrStorage before any intent/client when directory sync fails. README states this requirement. No action set, authentication, dedup, retry, replay, Close policy, public interface or configuration bypass was added.

The only seam is non-exported/per-instance ledgerInit with beforeLock(created) and syncDir(fd); production zero values call real operations, and Config has no bypass/global hook. Executor carries that private initialization value. The single new test TestJournalCreationDurabilityBeforeClient has failure/success subcases. A real creator opens a fresh private temporary file and pauses before flock. A second executor opens the actual existing path and obtains the lock. Failure must call directory-sync once, return ErrStorage, leave the journal empty and invoke no client. Success must perform real syscall.Fsync on the parent while the file is still empty, then allow the recorded client. The creator has a3s barrier context; deferred release and at most3s completion wait precede fixture Close, with explicit SETUP_OR_CLEANUP_FAILURE failure tags. Kernel I/O cannot be forcibly interrupted; setup/cleanup uncertainty must not be accepted as RED. This models unconfirmed creation durability and real interleaving, not a physical power-loss experiment.

The old created-only condition was deliberately preserved while adding the seam/regression. Root executed exactly one new RED before approving the condition fix:

| Stage | Actual result | Preserved originals |
|---|---|---|
| Focused RED | Fresh9bf6f0 known0; sole b8ce2a/session15114 ->7150de known1;7.395517730s. Exact3 FAIL=parent+2 subcases,0 PASS/0 SKIP, exactly2 FIX1_RED_REQUIRED markers. Both subcases observed syncs=0/mutations=1. No setup/cleanup/build failure; stderr0; own group absent; nine inputs/freeze unchanged. | [stdout977B](fix1-red-first-20261025/stdout.raw), [status1188B](fix1-red-first-20261025/status.json), [request2385B](fix1-red-first-20261025/request.json), plus3 source snapshots/freeze in the same8-file directory |
| Final affected cover | Fresh1ef006 known0; sole5609cf/session90514 ->5a392f known0;7.991837832s caller elapsed. Exact34 PASS=7 top tests+27 named subcases,0 FAIL/0 SKIP. stderr0; own group absent; nine inputs/freeze unchanged. Package test time0.579s is not containment latency. | [stdout4660B](fix1-cover-first-20261025/stdout.raw), [status1193B](fix1-cover-first-20261025/status.json), [request2655B](fix1-cover-first-20261025/request.json) |

RED stdout SHA256:8e91cf74510983d297545fa2444695ae18de0d878a62c2fabfd6164cb089fd3d.
Cover stdout SHA256:789f2390c8ed37b9e04ee569c7392d38cbe6891942826f24966443a13ae0d0bd.
Regression15193B SHA2564720fec3b18c3f4602632084f6a016c7b2ffcb131026d0828e0d72356e70290e is identical between accepted RED and final cover. No source/test change followed final cover. There was no new formatter, preliminary GREEN, duplicate test, full81 rerun, oldTask12/11/16 execution, broad ./..., race install or download.

The [final frozen list](fix1-author-artifacts-20261025/task-14-fix1-cover-freeze.json) selects only:
- TestJournalCreationDurabilityBeforeClient (new creation barrier/failure/success).
- TestConcurrentDuplicateAndCloseRetainsLock (ownership and reopen).
- TestDurableIncompleteIntentSuppressesRestart (existing unresolved durable state).
- TestDurableBindingConflictAndTenantKeys (completed-state reopen/binding).
- TestCorruptJournalFailsClosedWithoutRepair (existing initialization failure).
- TestPrivateJournalPathAndPermissions (validation before initialization).
- TestPartialWriteAndSyncFailuresSuppressAttempts (uncertain-state reopening).

These are direct initialization/lock/reopen/failure consequences of I1. Approval, parser, preview, capacity and unrelated original81 cases were not re-executed. Parent tests and named subcases are counted once each; loop assertions are not extra reported cases. Recording clients/authority remain local contracts, not genuine external actions/authentication.

Six unchanged author copies preserve exact [RED caller](fix1-author-artifacts-20261025/task-14-fix1-red-caller.md), [7374B actual RED body](fix1-author-artifacts-20261025/task-14-fix1-red-command.py.txt), [2353B RED freeze](fix1-author-artifacts-20261025/task-14-fix1-red-freeze.json), [cover caller](fix1-author-artifacts-20261025/task-14-fix1-cover-caller.md), [7339B actual cover body](fix1-author-artifacts-20261025/task-14-fix1-cover-command.py.txt) and3553B cover freeze. The Markdown documents were inert proposals, not directly executed files. Root executed the extracted identical Python files. Root retained full native requests/results/polls in its own fix1-red-native-events and fix1-cover-native-events JSON; they were read for literal launcher accuracy and excluded from this author's stage.

The actual test launchers, workdir /home/postedism/Desktop/Warden, were:
```
/usr/bin/timeout --signal=TERM --kill-after=4s 86s /usr/bin/python3 -I -B /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task-14-fix1-red-command.py.txt
/usr/bin/timeout --signal=TERM --kill-after=4s 86s /usr/bin/python3 -I -B /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task-14-fix1-cover-command.py.txt
```
Each launched the existing fixed cached Go1.26.10 bin/go with test -mod=readonly -buildvcs=false -vet=off -p=1 -parallel=1 -count=1 -timeout=20s -run <exact anchored list> -v ./respond. Exact argv/env are in the two request.json originals. RED anchors only the new top test; cover anchors exactly the7 names above. Separate new .cache/task14-fix1-red-20261025-a and task14-fix1-cover-20261025-a namespaces protect cache/tmp/GOPATH/modcache/raw evidence. No old RED/cover namespace was mutated or reused as cache.

Both fresh guards used this literal root-owned command, independently before the respective test launcher:
```
ulimit -c 0
ulimit -n 64
ulimit -v 262144
ulimit -f 8192
ulimit -t 20
/usr/bin/timeout --signal=TERM --kill-after=5s 40s /usr/bin/python3 -I -B scripts/azure_guard.py preflight --additional-bytes 6073741824 --service-memory-bytes 11000000000 --download-bytes 0
```
RED R4589907968+Q5000000000+1073741824=10663649792B; cover R4650119168+Q+new=10723860992B, both<=12000000000B. New namespace allocations61186048B/61190144B and post MemAvailable85835063296B/85486526464B are recorded. New resident reservation2,000,000,000B plus old UNKNOWN9,000,000,000B counts toward16GB. Complete new disk reservation1,073,741,824B includes source/cache/tmp/run/evidence and is not a hard filesystem quota. Sampling can overshoot; reservations are not measured aggregate RSS quotas.

The tested process-control body retains WNOWAIT/direct-leader ownership through all group signals, bounded cleanup and read-only post-reap group checks. Whole90s includes kill grace; absolute setup8/work70/signals82/reap84/status85 targets are unchanged. Missing status/blocked kernel I/O/uncertain descendants means STOP UNKNOWN, not a retry or guaranteed cleanup. CPU60/AS4GiB/FSIZE256MiB are per-process; raw combined64KiB output cap differs from compile-file size. GOMAXPROCS2/-p1/GOMEMLIMIT512MiB are cooperative. GOPROXY/GOSUMDB off, GOTOOLCHAIN local, GOENV/GOWORK off, CGO disabled, GOVCS off, telemetry mode off with private TEST_TELEMETRY_DIR/XDG_CONFIG_HOME; HOME/host umask unchanged. No Docker/go.sh/automatic toolchain or services.

Local SOURCE stage5b1ea5 and commit5d1002 were approved known0 through the normal require_escalated path for read-only .git. Exact4-path stage was checked before commit; hooks/signing/automatic maintenance disabled, no push. There was no new automatic approval rejection or bypass. EVIDENCE uses only its exact20-path inventory. Full parent chain, committed path/byte counts, empty index, report mirror SHA and returned SOURCE/Git/index ownership are supplied at final handoff after its separate commit.

The remaining limits are unchanged: durable Unknown suppresses attempts, not exactly-once external effects, automatic recovery or guaranteed successful containment. Trusted local fsync/flock and no hostile same-UID replacement are prerequisites; manual reconciliation/adapter idempotency remain needed. Contexts require cooperative ports/storage. Real OIDC/second-identity approval storage/current revocation, controlplane tenant suspension, Task8 Vault/Azure credentials, Azure/Kubernetes adapters, multistep execution, Task13 alert provenance/detection and genuine replay/action timing are OPEN. No time-to-contain report was generated and no fullTask14/Goal completion is claimed.

Warden-only/Q5GB/private scene/old UNKNOWN9GB remain unchanged. No real attack, cloud/network provisioning, GPU, runtime service, host k3s/iptables/sysctl or publication occurred. Azure-only/$6/precreate cumulative<=$5.40/own rg-warden-lab/tags/TTL and immutable rg-mlinfra-westus remain binding. OldTask6 spent allowances, Task11 BP FAILED/no retry, stoppedTask16 and existing dirty source/evidence are untouched. This remains original continuous fix1/5; no reset or second round is implied. Stop for root's one targeted independent I1 review of exact955ef5d..EVIDENCE.
