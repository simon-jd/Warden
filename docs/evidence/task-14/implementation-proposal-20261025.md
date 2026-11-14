# Task14 bounded implementation proposal

Proposal only. No execution/source/Git authority; root owns admission. Task12 Approved0C0I1M; fixes first. Only Tasks1/2 accepted; Task14 open.

## Smallest useful slice / exact prospective files
Create respond/actions.go, respond/executor.go, respond/ledger.go, respond/executor_test.go, respond/ledger_test.go and respond/playbooks/suspend-tenant.yaml. Only these edits. Call SuspendTenant(ctx,tenantID) error with durable attempt suppression; recording clients prove local behavior. No controller/service/real adapter.

Keep original Playbook{ID,Trigger,Steps,RequiresApproval} and Handle(alert Alert,dryRun bool)(Result,error). Add HandleContext for cancellation; Handle uses finite timeout. New Alert DTO: ID/rule/tenant/target/requester credential/approval proof; detection integration absent. Copy input/config; never log/result/fingerprint credentials.

## Strict playbook/action contract
JSON syntax in .yaml (YAML1.2 subset), standard library only. Reject duplicate/unknown keys, wrong types, trailing values, required nulls, input>16KiB, general YAML/anchors/tags. IDs: ASCII [A-Za-z0-9_-], 1..128 bytes. Require exact rule/trigger, one step, RequiresApproval=true, pinned tenant, typed tenant target equal to alert tenant. No commands/URLs/templates/wildcards/endpoints.

Known names: RevokeVaultLease, DisableAzureServicePrincipalCredential, IsolatePod, CordonNode, SuspendTenant. Only SuspendTenant supported; others Unsupported before state/client changes. Reject unknown and obsolete DisableAWSAccessKey/DisableGCPServiceAccountKey. Deliberate Azure replacement: one Vault-issued service-principal credential, not whole account. Missing primary facts: exact Graph operation/permissions and Vault Azure lease/credential mapping/lifetime. No SDK assertion. Pod label is not policy enforcement; cordon is not eviction.

## Distinct authenticated second identity
Read-only authority verifies requester AND approval under ctx; returns authenticated issuer/subject, current roles, issued/expiry and authenticated tenant/alert/rule/playbook/step-hash/action/resource binding. Compare all fields. Check revocation/authorization, resolve aliases, require distinct stable authorized principals; never trust boolean/caller subject/token presence.

Nil authority/client, absent proof, verifier failure, empty/same/aliased identity, wrong binding/role/tenant, future issue, expiry<=now or lifetime>5min fail closed: zero calls/state changes. Recheck expiry/ctx before action. Tests prove boundary enforcement, not real authentication; no production wiring. Preview only reports approval needed.

## Concrete durable attempt ledger
One trusted configured private local ledger, never alert-selected. Linux stdlib: reject symlinks/nonregular files; owned directory0700/file0600. Open/create lazily after actual authorization; nonblocking lifetime exclusive flock until Close; contention fails closed. Fsync directory on creation. Require local fsync semantics/no external writers/replacement; no distributed guarantee.

Mutex protects reservation/append, released for client call. Key=(tenantID,alertID); fingerprint=rule/playbook/ordered actions/exact target. Changed binding conflicts; pending duplicate InProgress; terminal duplicate no-op/saved summary. Authenticate duplicates; tenant keys/credentials/targets isolated.

Completely write/fsync bounded checksummed intent BEFORE client call; fsync completion. Limit1024 keys/1MiB, reserve completion space. Full rejects new keys; no eviction/expiry/reset/retry. Replay locked: incomplete intent=Unknown, permanently suppress repeat. Bad ordering/checksum/size/torn tail or I/O/lock failure fails closed; no automatic repair/truncation. Checksum is not authenticity. Intent-sync failure: no client call, poison/close ledger. Completion-sync failure: Unknown, poison live ledger; durable intent suppresses restart.

Crash before sync: no call. After sync: missed action or unknown external outcome. Restart suppresses attempts, may miss containment; no exactly-once effects/recovery. Adapter idempotency/reconciliation remain gaps.

Dry-run: structural preview only; zero authority/client calls, file open/create/lock/write, dedup mutations, approval consumption or audit. Constructor creates nothing. Preview then actual calls once; preview never claims Completed/authorized.

## Context / ambiguous failures
Total<=5s, authority<=1s, client<=2s within parent/approval expiry. Check cancellation before reserve/call. Pre-reserve: no state; post-intent/pre-call: durable Cancelled, no retries. Error/timeout after call starts: Unknown, no retry. Success: Completed. Bound/redact errors/results.

No detached goroutines. File I/O/noncooperative client cannot be forcibly canceled: require local bounded storage/cooperative clients; outer runner bounds tests. No live SLA/rollback.

## Actual tests and TDD admission
Original mandatory tests in executor_test.go:
- TestPlaybookIdempotentPerAlert: execute twice, client exactly once; second no-op.
- TestDestructiveRequiresApproval: missing authority/proof and false RequiresApproval block; valid distinct authenticated approval executes.
- TestDryRunMakesNoChanges: repeated previews leave directory/dedup unchanged, authority/client counts zero; actual then executes once.

Subtests: barrier concurrent duplicate exactly once/InProgress; changed binding; tenant isolation; copied input; strict parser; unsupported/obsolete action; all approval bindings/alias/role/TTL failures; verifier error/cancel; pre-reserve/pre-call cancel; cooperative deadline; ambiguous failure no retry; capacity. Deterministic clock/barriers, no sleeps/services.

ledger_test.go: real temp-file reopen suppresses completed/incomplete attempts; lock contention; corrupt/torn/out-of-order records; permissions/symlinks; capacity. Narrow private I/O fault seam proves no call before intent-sync and Unknown on completion-sync failure. Local durability, not live evidence.

Root must later freeze/FULLREAD/admit FIRST TDD caller/inputs. No execution permission here. Red for missing implementation, then green behavior. Prospective command:
go test -mod=readonly -p=1 -parallel=2 -count=1 -timeout=20s ./respond
Require already installed/admitted Go 1.26.10 (go.mod), Linux flock/local fsync, GOTOOLCHAIN=local, GOPROXY=off, GOSUMDB=off, GOMAXPROCS=2, isolated project caches, no download. Outer30s timeout/5s kill grace, memory<=512MiB, output<=64KiB, new cache/disk<=128MiB. Prerequisites unverified. scripts/go.sh inadmissible: golang:1.26.8-bookworm, GOTOOLCHAIN=auto, Docker/host network can fetch newer toolchain. Makefile only Azure budget tests; detect.yml Python-only. No broad ./... tests, race installation or runner extension.

## Open integration / acceptance
docs/evidence/README.md:54 requires verbatim: "genuine replay/action timestamps and outcome, dry-run, durable idempotency and second-identity approval evidence". Local tests cannot close acceptance. Task8 identity/respond absent. Vault short-lived Azure credentials, real SuspendTenant store/API, trusted approval authority/storage, Vault/Azure/K8s adapters and isolation enforcement are unimplemented.

tenant.Claims exposes only TenantID; API only run routes. Root respond cannot import controlplane/internal packages. audit.Log.Append uses PostgreSQL and its own Background10s context; no cancellable response audit adapter. Task13 live attack/detection open: no proven alert provenance/integration or replay/outcome/timing. Fixtures not live proof; no evidence/commit/fullTask14 closure.

Constraints: Warden only; attacks warden-lab only; Azure only, $6 cap, precreate Retail API ledger cumulative<=$5.40; rg-warden-lab with project/owner/ttl/est_usd_per_hour tags; rg-mlinfra-westus immutable. No host k3s/iptables/sysctl change, GPU, runtime services, public push/publication. Disk12GB; Q5GB unreleased/private scene unchanged; oldTask16 UNKNOWN9GB reserve counts toward16GB services. OldTask6 allowances spent; BPTask11 FAILED/no retry; Task16 batch stopped, no reuse/extension. Dirty scripts/firecracker_code.py, vuln/, detect/tests/, public docs, STATUS, old evidence/plan untouched.
