# Task9 final implementation and local validation report

Status: DONE_WITH_CONCERNS. The local component is implemented; root accepted semantic RED, first GREEN (17 top-level/30 including subcases) and the single affected migration-v2 check on unchanged product bytes. Source acceptance and independent Spec+Quality review are pending. This is not deployment or whole-project completion. The author created no commits. Root source commit 1eb3ccb257d5faffa35a6438c550639b4fe76859 contains eight verified product paths unchanged from the freezes; index is empty. Root owns evidence commits and independent review. Original review base f83a41b8d5dd7f5a976852785a31aeee01596a19. Mandated SDD was followed without children; root alone executed each separately admitted frozen caller.

## Implemented

The original Request(user,role,duration,reason), Approve(id,approver), Expire interfaces now implement a tenant-bound durable workflow. Requests require canonical nonblank bounded identities/reasons, a trusted configured alias, positive duration <=2h and authenticated authorization. Configuration is cloned. Approval denies the requester, verifies the approver principal and separately rechecks requester membership/permission to grant the alias both before intent and immediately before activation. Maintenance is separately authorized through the caller port. No route accepts strings as credentials.

Duration starts at first approval intent, never request time; retries never extend it. Timestamps round downward to PostgreSQL microseconds; tiny windows can expire before activation, with no access. Equality expires. Dedicated per-request session advisory locks serialize writers without holding the Task1 audit-head lock during remote work. Failed/ambiguous lock acquisition and unlock discard the session. State predicates provide a second DB fence.

Approval durably commits grant_pending with jit.approval_intent, reserves an empty binding, persists its UID/version, rechecks policy/deadline/session, then activates conditionally. Confirmed activation commits active and jit.granted in the same transaction through the real audit.AppendTx. Any later failure attempts removal, including ambiguous provider replies or DB/audit failure. Restart and approval retry never resume incomplete activation. Durable grant_pending/revoke_pending is reconciled to removal; tombstones forbid regrant. Removal still proceeds best-effort if DB intent/audit fails, leaving the earlier durable row for recovery. Confirmed external absence precedes atomic expired plus jit.expired; failed expiry audit remains retryable without duplicating the event. A persisted grant_confirmed flag distinguishes an audited grant from uncertain cleanup.

Expire processes at most64 eligible tenant rows and collects failures. Persisted sequence ordering rotates attempted rows, so a permanently failing batch cannot starve later expired grants or reset fairness on restart. This minimal bookkeeping stays in migration003; it does not introduce a controller framework. Migration003 adds durable state/constraints, grant confirmation and sequence/index. Existing001/002, audit implementation, canonical JSON, module/dependency files are unchanged. The previously prepared store embed/list and version-two migration test remain unchanged.

KubernetesBindings implements the explicit production HTTP adapter port, not deployment. It takes a trusted HTTPS endpoint, injected TLS-validating RoundTripper and bounded bearer-token provider. It never discovers kubeconfig, host credentials, HOME or environment configuration. Direct RoundTrip cannot follow redirects. Responses are <=64KiB, canonical duplicate/trailing-data checked and exact-key/owner/target/role/subject checked; empty subjects may be omitted by Kubernetes. Reserve POSTs no subjects. Activate uses one UID/version-conditional PUT and never retries ambiguity. Remove validates current ownership, PUTs empty subjects with the current version, DELETEs with UID/version preconditions, and confirms absence; bounded conflicts retry three times within2s. Credentials/raw provider error bodies are not exposed. A fixture proves protocol handling only.

## TDD evidence

RED was executed by root, not re-run by this preparation. The retained root-ruling and all raw evidence are in docs/evidence/task-9/business-first-red-c-20261026/. Sole e13247/session9752→003bd2 completed in18.7645s, wrapper0/Go1. Command:

`/sdk/bin/go test -mod=readonly -buildvcs=false -vet=off -p=1 -parallel=1 -count=1 -timeout=18s -run "^(TestSelfApprovalRejected|TestGrantExpiresAndBindingRemoved|TestAuditRecordedForGrantAndExpiry)$" -v ./controlplane/internal/jit`

All three reached the intended assertions after successful durable Request: self-approval expected ErrSelfApproval, approved request lacked external grant, real audit lacked grant/expiry. Real Task1 PostgreSQL Verify completed. No build/startup/connection/skip/OOM failure was counted as RED. The preimplementation source snapshots, F/M and consumed callers are immutable.

FIRST_GREEN: root executed exactly once, 4f18a3/session27587→9b3f45 known0. Whole caller23.259077s, Go0, package0.987s. All17 frozen top-level tests passed, 30 including subcases, with no FAIL/SKIP and real Task1 PostgreSQL Verify. Exact command:

`/sdk/bin/go test -mod=readonly -buildvcs=false -vet=off -p=1 -parallel=1 -count=1 -timeout=18s -run "^(TestSelfApprovalRejected|TestGrantExpiresAndBindingRemoved|TestAuditRecordedForGrantAndExpiry|TestRequestBoundariesAndTenantIsolation|TestApprovalClockRetryAndExpiryFence|TestAuditFailuresRollbackAndRemoveAccess|TestRestartRevokesAmbiguousOperations|TestExpiryAuditRetryAfterExternalDeletion|TestDeadlineDuringReservationPreventsActivation|TestConcurrentReconciliationCannotActivateTwice|TestMaintenanceRequiresTrustedAuthorization|TestRequesterMembershipRecheckedBeforeActivation|TestExpiryBatchFailureDoesNotStarveLaterGrants|TestKubernetesBindingLifecycleAndFencing|TestKubernetesStrictResponseValidation|TestKubernetesRemovalRejectsForeignUIDAndUnconfirmedDeletion|TestKubernetesTransportErrorsDoNotRetryActivation)$" -v ./controlplane/internal/jit`

Relevant actual stdout (all top-level/subcase output retained in canonical events/raw):

```text
--- PASS: TestSelfApprovalRejected (0.04s)
--- PASS: TestGrantExpiresAndBindingRemoved (0.04s)
    jit_test.go:134: Task1 PostgreSQL audit Verify completed
--- PASS: TestAuditRecordedForGrantAndExpiry (0.07s)
PASS
ok  	warden/controlplane/internal/jit	0.987s
```

The original three test names and business assertions remain. Fixture changes only strengthen reservation fencing and explicitly implement trusted grant/maintenance authorizations. Fourteen added top-level tests cover duration/tenant/identity rejection; approval-time expiry and no-extension retries; real audit-trigger request/intent/grant rollback; ambiguous reservation/activation and restart; deletion-before-audit retry; deadline during reservation; concurrent approve/reconcile; denied maintenance; revoked requester before activation; starvation of later rows by a failing64-row batch; and four HTTP adapter lifecycle/fencing/strict-response/foreign-UID/deletion/transport cases. These are directly affected behavior, not unrelated packages. Every DB test still uses real testutil.Database and never skips absent PG. Trigger faults exercise the actual Task1 audit transaction and Verify, not a substitute chain.

## Accepted GREEN receipt

Canonical evidence: docs/evidence/task-9/first-green-a-20261026/{root-ruling.md,status.json,events.json}, with20 CLI events and40 raw streams totaling11667B. PG final PID1 was postgres and pg_isready succeeded; final PG Running=true/OOMKilled=false/Error empty, Go exited0/OOMKilled=false/Error empty. Both exact name/owner/CID bindings were checked before rm-f-v0 and final exact-name absence; all owned CLI groups were known cleaned. All15 source/projection/F/M/originalF/SDK/module hashes were unchanged. Namespace .cache/task9-first-green-20261026-a retains9531392B. Both test success and cleanup were required.

Actual GREEN Go stderr315B consisted of these six file-proxy notifications. Network none and GOPROXY=file:///proxy were enforced; these were not internet downloads:

```text
go: downloading github.com/jackc/pgx/v5 v5.11.0
go: downloading github.com/jackc/puddle/v2 v2.2.2
go: downloading github.com/jackc/pgpassfile v1.0.0
go: downloading github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761
go: downloading golang.org/x/text v0.43.0
go: downloading golang.org/x/sync v0.24.0
```

## Accepted migration-v2 preservation cover

Root executed exactly once, 75a442/session80903→202f71 known0, whole caller24.45512s, Go0/package0.059s. Exact command:

`/sdk/bin/go test -mod=readonly -buildvcs=false -vet=off -p=1 -parallel=1 -count=1 -timeout=18s -run "^TestJITMigrationPreservesVersionTwoRunsAndAudit$" -v ./controlplane/internal/store`

Actual stdout:

```text
=== RUN   TestJITMigrationPreservesVersionTwoRunsAndAudit
--- PASS: TestJITMigrationPreservesVersionTwoRunsAndAudit (0.06s)
PASS
ok  	warden/controlplane/internal/store	0.059s
```

The unchanged test reconstructs an actual version-two database, persists a legacy queued run and Task1 audit event, applies migration003 twice, checks the run/spec and prior audit hash unchanged, calls real audit.Log.Verify(1,1), and verifies the JIT table is empty. It has no special Verify log; its PASS means Verify returned nil. No JIT, old migration-v1, audit, runs or gate suite was rerun.

Migration Go stderr356B contained the same six notices above plus the exact seventh line `go: downloading golang.org/x/sys v0.49.0`. The cached archive's streamed Hash1 matched the existing go.sum; no download or module edit occurred. The17-file isolated projection includes unchanged runs/{runs,execution,policy}.go, runtimes/runtime.go and runtimes/gate/{admission,gate,retirement}.go solely to compile whole dependency packages. This test calls Normalize/Create/Get and never invokes gate/retirement/driver operations. No private state, old PID or host cgroup inspection occurred.

Root FULLREAD accepted20 events/40 raw streams7038B, exact test PASS, healthy PG/Go State, both positively bound own CIDs removed with final exact-name absence, and all owned CLI groups cleaned. All17 source/projection hashes, first-GREEN15 product pins, F/M/originalF and all materials including x/sys remained unchanged. Namespace .cache/task9-migration-v2-cover-20261026-a retains11649024B. Canonical root archive: docs/evidence/task-9/migration-v2-cover-a-20261026/{root-ruling.md,status.json,events.json}; its retained native Go event was also read for this report.

PG logs are preserved, not called pristine: locale-not-found/no-usable-locales notices, local trust authentication warnings, socket chmod Operation not permitted in migration startup, checkpoint messages, and expected injected audit failures in GREEN remain in captured streams. These did not prevent final postgres readiness/test success. No warning was hidden or used to guess a configuration change.

## Source and self-review

Changed since accepted RED: controlplane/internal/jit/jit.go, jit_test.go, added bindings.go, bindings_test.go, README.md; and controlplane/internal/store/migrations/003_jit.sql. The source diff is against the retained accepted-RED snapshot, with new files explicitly marked. Store.go and migration_test.go are included in the source freeze but unchanged in this phase. Task10 detect/dns_exfil, old detect/tests, vuln, firecracker, Task15 products, root records and index are untouched.

Static self-review checked transactional ordering, commit ambiguity, session disposal, late activation fences, tenant predicates, constructor config copy, exact expiry equality, real audit payload identity, bounded external replies, complete-body validation and recovery fairness. It corrected potential pooled-session lock retention, Kubernetes omitted-empty subjects, target membership rechecking and failed-batch starvation before freezing. Existing cached pgx source confirms Conn.Ping/Hijack interfaces. No Go compiler, formatter, tests, containers, live API, downloads or Git operations ran during author preparation. Root then executed only the frozen admitted callers described above; exact projected sources compiled and passed. No product mutation or formatter ran between the two validations. Independent Spec+Quality review remains pending; these tests do not establish every possible failure schedule.

## Frozen packets and resources

All packet paths share .superpowers/sdd/2-warden-security-plan/task-9-first-green-20261026-a: .py.txt, -caller.diff (against CONSUMED_NEVER_EXECUTE c), -source.diff, -source-freeze.json and -packet-freeze.json. The full report is task-9-report.md. The new source freeze pins15 files and17 top-level tests. Runtime checks source before projection and after cleanup; the original RED F and unchanged M also remain pinned. Context HEAD is recorded without an obsolete HEAD-equality gate.

Fresh runtime namespace .cache/task9-first-green-20261026-a was filesystem-absent in preparation; root must recheck fresh. PG/Go names warden-task9-green-20261026-a-pg/-go are proved exactly absent before creation. Random owner, CID-file/name/label/ID checks, complete State/PG tail80 capture on success/failure, WNOWAIT CLI-group cleanup, CID-only rm-f-v and final exact-name absence match the consumed c protocol. PG uses the validated single env argv POSTGRES_INITDB_ARGS=-c dynamic_shared_memory_type=mmap and local logger max-size1m/max-file1/compress=false. Network none, no ports, nonroot, readonly, cap-drop, no-new-privileges and immutable image77f585...f60a1873 remain exact. No probe or image/material download is authorized.

Whole90/work65/Go59/cleanup82/status85/raw131072 caps are unchanged. GREEN requires all17 exact top-level PASS, Go0/package success, original real Task1 Verify message, no skip/fail/build failure, permitted six local-file-proxy notices only, healthy PG/Go State, unchanged sources and both known cleanups. Unknown/error is never GREEN and does not permit an unchanged retry. Cached Go1.26.10 SDK is readonly; pinned modules are copied only to the bounded private proxy. Missing/hash-mismatched material stops.

Full new disk remains1,750,780,416B = daemon image1,000,000,000 + Go work472MiB494,927,872 + PG data/tmp200MiB209,715,200 + two shm1MiB2,097,152 + host source/proxy/raw/evidence/Git/index/daemon40MiB41,943,040 + new logger2MiB2,097,152. Global admission: freshR + Q5,000,000,000 + retained tmp131072 + existing logger hold2097152 + Task15 CODE524288 + publication1048576 + fullnew <=12e9. Thus freshR<=5,245,418,496B; all retained failures, RED N9465856B, prior validation94208B, Task10 prep57344B and this phase's source/prep are charged inR, with no deletion credit. Root must measure fresh, not reuse the prior margin. Both exact admitted runs completed within the unchanged caps. The migration projection plus proxy was10,383,021B, inside the16MiB copy cap; module expansion/build/cache/tmp/output shared472MiB. This proves these runs completed, not a guarantee for unrelated workloads.

Resident new6,500,000,000B includes Go1GiB + PG512MiB + one CLI AS4GiB + parent256MiB =6,174,015,488B plus325,984,512B daemon/cleanup allowance. Old UNKNOWN9e9 remains untouched; total15.5GB<=16GB. Go472MiB tmpfs is inside its1GiB cgroup; GOMEMLIMIT is not the hard bound. Preparation/source allocation before this final report update was cumulative net229376B, conservative245760B including preexisting source, against the original262144B cap. Final report growth is recorded below.

Migration packet paths share .superpowers/sdd/2-warden-security-plan/task-9-migration-v2-cover-20261026-a: .py.txt, -caller.diff, -source-freeze.json, -material-supplement.json, .md and -packet-freeze.json. Historical callers and pins remain immutable. Root migration fresh3faa97 at2026-10-26T08:18:11Z measuredR5,113,339,904 +holds5,003,801,088 +fullnew1,750,780,416 =11,867,921,408B <=12e9. This is the recorded past admission, not a gate for any future operation. Retained namespaces/evidence remain charged inR with no deletion credit.

## Immutable failure history and provenance

Root's first Git wrapper returned128 with cause unconfirmed; its retained native failure is not a source/test failure. The later fully captured source commit succeeded; no cause is inferred.

The first two business harness attempts never ran semantic tests: one stopped on the absence receipt's single newline, the second at pg_not_ready. The latter's original PG failure cause remains UNKNOWN. Separately allowed diagnostics first hit local logger compression/max-file1 incompatibility, then directly observed initdb POSIX shared-memory ENOSPC after logger correction, and finally reached readiness with the exact mmap initdb env. The metadata attempt's literal-indicator mismatch remains UNKNOWN_FAILURE; captured help supported `-c, --set NAME=VALUE`, which the coordinating parent independently ruled semantically sufficient. No historical failure was rewritten as PASS or silently replayed. Later semantic RED, GREEN and migration cover have separate immutable receipts.

The first GREEN start reaper received an automatic approval rejection for scope uncertainty, preserved in docs/evidence/azure-budget/reaper-task9-first-green-start-rejection-20261026.json. After read-only committed-equality/scope proof, root submitted the exact same command through the original normal path and it was allowed once; reaper2ea2b0→167afc confirmed the lab RG absent. This grants no alternate entry or automatic retry after a new rejection. No author operation created cloud resources or changed host/GPU/terms/publication permissions.

Semantic prerequisite provenance is source=coordinator_agent, human_response=false, grounded_in_existing_user_scope=true, under append-only correction1e57affb96a066db11de8373919ab85b2d36d0d1f4b8940e3bde70e91d231373. Old mistaken direct-user labels, quotes, files and receipts remain immutable. Prior business2/2 plus restored1/1, diagnostics3/3, metadata1/1, FIRST_GREEN1/1 and migration cover1/1 remain spent. No review-loop reset or Task15 quota reset is implied.

The original11850B preparation report, SHA25636889d7491e586a7d3cae6e85b411a7756ebe0ebdd8ee2537d0c630c661548dd, is preserved exactly at docs/evidence/task-9/first-green-a-20261026/author-source-preparation-report.md. Historical packet entries for task-9-report.md resolve that preserved preparation snapshot. This current main report supersedes it after accepted actuals; historical packet pins were not rewritten.

## Open prerequisites and safe handback

Production authenticated identity mapping, reviewed least-privilege Roles/credentials, actual Kubernetes RBAC/UID/version/no-create-on-update acceptance and supervised startup/periodic expiry deployment remain OPEN. HTTP adapter source and injected transport fixtures do not establish these facts. Scheduler/API outages may retain access beyond TTL; expiry annotations enforce nothing independently. README states these limits. No unchanged audit/store package or unrelated whole-project suite was rerun; validation scope is exactly the commands above.

Root owns the final SOURCE/EVIDENCE commits, index and independent Spec+Quality review under the original maximum five-round loop. No source acceptance or task-complete claim is made here. Only the main report changed in this final phase; all product bytes, original main-report snapshot, historical callers/freezes and evidence remain unchanged.

Final report allocation: report20480B replaces12288B, delta8192B; cumulative net237568B and conservative253952B. Original total allowance262144B remains unchanged; directory growth is zero. No new artifact was created for this update. The author returns SAFE handback and stops.
