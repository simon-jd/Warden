# Task9 proposal — first phase only

Read brief, Task1 contracts, API/authn/scheduler, Task14 caller. SOURCE needs root admission.

## Scope and interfaces

Create `controlplane/internal/jit/{jit.go,bindings.go,jit_test.go,bindings_test.go,README.md}`; append `store/migrations/003_jit.sql`, its embed/list in `store.go`, and focused `store/migration_test.go` case. Preserve old migrations/audit/module/deps/evidence/legacy dirty. No API/main/scheduler edits; prerequisites below.

Service implements `Request(user,role string,d time.Duration,reason string)(string,error)`, `Approve(id,approver string)error`, `Expire()error`; methods bounded. Constructor: tenant, pgxpool, trusted config, authenticated-caller port, bindings, clock; nil fails closed. UTC production/fake test clock.

Request: 0<d<=2h, bounded nonblank identity/reason, configured alias, random ID. Trusted alias maps namespace+Role. All SQL tenant-bound; cross-tenant/unknown IDs indistinguishable. Canonical user IDs prevent alias self-approval. Approval rechecks membership/policy, freezes approver/target/expiry. Duration starts at first committed approval, never extended on retry. `now>=expires_at` expires, checked again immediately before activation.

Caller port binds user/approver to authenticated principal, maps issuer/subject to active tenant member and authorizes request/approval separately. Strings are not credentials; no allow-all. Separate trusted maintenance instance. `tenant.Claims` currently has TenantID only; `authn.Claims` has Issuer/Subject but no membership; main passes nil verifier. No real-route claim. Exclude escalation-capable roles.

## Persistence, audit and error ordering

003 creates jit_requests: ID, tenant, requester, alias/reason, duration_ns CHECK<=2h, created_at, nullable approver/approved_at/expires_at, frozen namespace/role/subject, unique deterministic binding_name, nullable UID/resourceVersion, state, safe last_error. Consistency CHECKs + pending-expiry index. States requested/grant_pending/active/revoke_pending/expired; retain terminal tombstones. Migration preserves runs/audit; reappliable.

Bounded per-request PostgreSQL session advisory lock serializes approval/expiry on dedicated connection, reliably released/discarded. Short row-lock transactions call actual `audit.AppendTx(ctx,tx,audit.Event{TenantID:...,Type:...,RunID:"",Payload:...})`; commit state/event together. No audit_head lock across HTTP. Payload: request, actors, target, reason, times/outcome; no tokens. Test actual `(&audit.Log{Pool:pool}).Verify(1,head)`. No substitute audit.

Commit grant_pending+approval/intent event BEFORE access. Reserve deterministic RoleBinding with EMPTY subjects, persist its UID/resourceVersion, then conditionally update that exact version to the frozen User subject after policy/deadline recheck. Never recreate a granting object after ambiguous activation. Confirmed activation -> transaction active+`jit.granted`; success only after commit. Pre-activation audit failure gives no access; post-activation failure returns error, revokes best-effort, retains recovery. Resolve unknown commit by row read.

Timeout/malformed reply/session loss/restart with grant_pending -> revoke_pending, no unattended grant completion. Expire handles incomplete grants immediately and active rows at expiry, batch64, bounded locks, collected errors. Active same-approver retries only before deadline; no ambiguous/expired regrant.

Revoke clears subjects with current UID/version, DELETEs with UID precondition, confirms absence, then atomically expired+`jit.expired`. Clearing fences stale activation; late empty reservation grants nothing. Never overwrite/delete foreign bindings. Bounded conflict retries; ambiguity stays pending. Audit failure after deletion retries absence check then appends once under row lock. Expiry event distinguishes known grant from uncertain attempt. Never mark expired on delete failure. Genuine K8s acceptance must verify late conditional PUT cannot recreate deleted binding; transport fixture is not that proof.

## Binding port and production prerequisites

Port Reserve/Activate/Remove: immutable target+UID/version. Standard-net/http RBACv1 RoleBinding adapter, trusted HTTPS endpoint/CA/credentials; no kubeconfig/host/env discovery. No redirects; deadlines/body caps. Strict JSON rejects duplicates, case aliases, trailing data and contradictory kind/apiVersion/metadata/roleRef/subjects while allowing documented server metadata. 409 reconciles ownership; 404 means absence only on validated removal lookup; 401/403/5xx fail. Random-ID name, tenant/request/expiry annotations; persisted cleanup target. Test via injected RoundTripper.

RoleBinding expiry annotation itself enforces NOTHING. Require identity mapping, least-privilege credentials/policy, supervised startup+periodic Expire, monitoring/retry and reconciliation before readiness. scheduler.Run handles runs only; no new controller framework. Scheduler crash/API outage can leave access past deadline; durable recovery is not exact-time external revocation. Acceptance needs real RBAC/removal/restart/fault tests and admitted scheduling (or external expiry). Fixtures prove neither identity nor RBAC.

## RED and final focused cover

RED: compilable fail-closed stubs, real testutil.Database (PG required, no skip), original names:

- TestSelfApprovalRejected: successful valid Request first, specific self-approval denial and zero activation.
- TestGrantExpiresAndBindingRemoved: approval, inspect binding, fake time before/equal expiry, prove removal.
- TestAuditRecordedForGrantAndExpiry: inspect real canonical events for grant/expiry tenant/actors/times and Verify full chain.

Behavioral failures only; freeze source/raw output.

Related tests: duration/identity/policy/tenant, concurrent approval/expiry, restart, request rollback, audit failure before/after activation, ambiguous/stale PUT, deletion/audit retry, no extension, malformed responses. Upgrade real v2 with run/audit, reapply003. One final same-source cover: jit package, new migration test + existing TestExecutionMigrationPreservesVersionOneRunsAndAudit, existing audit package. Freeze names before admission.

## Resources / next prep

Task1 `review-1-components.log`: PG18.6 ID `sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873`. Current availability/digest/architecture/allocated storage UNKNOWN. Next separately root-admitted metadata: bounded `docker image inspect` this exact ID, output only ID/RepoDigests/Size/Architecture/declared volumes. No pull/service. Size is not allocation; root must account external layers via bounded metadata. Missing image blocks real-PG tests, no fake audit.

Fresh-measure R (~5.03GB stale); retain Q=5,000,000,000B + >=128KiB/future actual check for four Task15 /tmp trees. Require R+Q+external retained allocations+entire additional peak<=12,000,000,000B. Additional<=1GiB includes retained RED/GREEN caches, binaries/temp, PG data/WAL, Docker layer/logs, source/output and all overlaps/tmpfs. Candidate only: Go caches/temp512MiB TOTAL across runs, PG256MiB, source/output16MiB, reserve240MiB. Metadata/enforceable caps must justify allocations or STOP. No fit claim; polling is not quota.

Only verified existing pinned Go1.26.10/offline necessary module subset; unchanged go.mod/go.sum. No host-Go assumption, download or historical go.sh/test-postgres.sh (mutable tags/unbounded) execution. Adapt Task14 pattern only after admission: PG readiness+cleanup AND Go within90s total; output/hashes/status caps, UNKNOWN STOP. Daemon children need owned-container cleanup beyond Go group signals. Root FULLREADs then freshly admits EACH material/test caller via normal require_escalated; no new runner framework.

Old Task16 resident9,000,000,000B remains UNKNOWN/untouched. All new resident<=7,000,000,000B remainder of16GB: candidate Go4GiB+PG512MiB+caller/overhead, subject to actual enforcement. No old scans/signals/quiescence/third call. AZURE-BUDGET: Warden$6/$5.40 Retail gate, own RG/tags/TTL, protected rg-mlinfra-westus; no cloud actions. No Task15 products touched. Root owns Git/records/reviews; fix cap5, old caps unchanged.
