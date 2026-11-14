# Task4 final-round staged recovery and diagnostics rulings

Historical preimplementation proposal followed by binding controller amendments. Only A code/native fixture tests are currently authorized; no actual helper, private content read, ownership change, B code or new boot has run.

# Task4 fix round5/5 — proposal only

Status: NEEDS_CONTEXT — controller ruling required before implementation or execution.

Current controller HEAD is `596658c1b0748cbc2ba1a2960aaa95683f725b60` on `implementation/warden`; FIX_BASE is `a683b6e580200ec522012f59c30a029a83a3922d`. Runtime source remains `95fa55dc0ce97d3e1b99a255a84f80e96972c71f`, evidence `caf9c445bdefc93388de357f1a4c1a26a14c028a`. This ignored proposal is the only write. No tests, containers, device operations, private scene reads, recovery, preparation, or implementation have run in this handoff.

## 1. Established diagnosis and an irrecoverable evidence limit

The named public third-boot evidence establishes the first actual jailer/Firecracker1.17.0 and Linux6.18.54+ start, successful InstanceStart204, then VMM exit before agentReady. Device-policy passed. It establishes neither guest readiness nor the exit cause. No panic, signal, seccomp, OOM, or other causal diagnosis is justified.

The checked source explains why the public diagnostic cannot answer the causal question:

* `runtimes/firecracker/vm.go:46–62` stores a maximum **1MiB prefix in memory**. Both original jailer/VMM stdout and stderr go to this same buffer at lines213–216. There is no file sink, Firecracker `/logger` configuration, or separate guest-console file in the fixed boot path.
* `vm.go:83–89` emits only the first4096 bytes of that buffer in a start error. The public third-boot log is consistent with that exact prefix. It does not imply that the kernel stopped at the last printed prefix line.
* `runtimes/firecracker/process.go` calls `cmd.Wait()` in the original owner and stores its result in `ownedProcess.waitErr`. The readiness failure returns a generic error; the original wait status is not serialized. `Stop` can accept an ExitError as an already-exited child while still enforcing its original pidfd checks. The unknown Gate outcome remains unknown.
* `scripts/firecracker_lab.py` saves the bounded attach stream to `device-attach.log`; a failed `DeviceGate.run()` does not reach the successful `run.log`/container-wait path. The attach stream can contain only diagnostics that the worker emitted. It cannot recover un-emitted bytes from the worker's memory. The original Docker container is gone.

Consequently **there is no justified root-scene log-retrieval helper to run**. Do not invent `vmm.log`, search the private tree for log names, inspect host daemon storage, read global logs or `/proc`, or reopen a reused PID. The original in-memory tail and precise VMM WaitStatus are irrecoverable through the authorized surviving evidence. A surviving outer exit1 would still be the test/outer result, not the VMM exit status.

The minimum diagnostic now is a source/public-evidence report with explicit fields:

```
vmm_started=true
guest_kernel_started=true
agent_ready=false
vmm_tail=unavailable_not_persisted
vmm_wait_status=unavailable_original_owner_gone
original_retirement=cleanup_pending
creation_outcome=unknown
```

No additional root reader is needed to prove absence of a log that the source never created. If the controller identifies another already-existing, exact, source-configured artifact, its name and provenance must first be established; only then could a nofollow regular-file tail read be proposed. Such a read would be at most8192 raw bytes from a file capped1MiB, strict owner/mode/nlink checks, bounded JSON escaping and a16384-byte total stdout cap, with `missing`, `oversized`, `unsafe_identity`, or `available` enums. No arbitrary filename or “find logs” input is acceptable.

For any future preserved tail, printable terminal text alone is insufficient sanitization. Drop API request-body lines and all non-allowlisted text; permit fixed event enums, bounded numeric errno/status/signal fields, and narrowly matched kernel/agent error messages with explicit truncation/drop counts. No raw environment, nonce, protocol frame, tenant stdout, arbitrary path, or credential-bearing line is published. An exit signal is an observed termination mechanism, not proof of who caused it. A kernel panic/error line can locate a failure but cannot prove full host/root cause or retirement.

The Go standard-library documentation says Wait waits for process completion and associated I/O copying, and releases associated resources; the version currently served was1.27.3, so this is a contract reference, not a matched1.26.10 implementation audit: https://pkg.go.dev/os/exec#Cmd.Wait . Linux wait interfaces report child status; a new unrelated helper does not inherit the old ownership or wait record: https://www.man7.org/linux/man-pages/man2/waitpid.2.html . The source-specific irrecoverability conclusion above follows primarily from Warden's inspected data flow. Attempts to fetch pinned1.26.10 documentation and FC1.17 logging documentation failed; neither is claimed verified.

## 2. Exact scene authentication

Use the existing project Docker lock with no concurrent builds/live work or controller writes. Only the following historical original identity is eligible; every value must be revalidated immediately before an admitted operation:

* Parent: `/home/postedism/Desktop/Warden/.cache/warden-lab/docker-firecracker-89c9296e79ce14c5dd30e0d5e4772f1d`, dev66307/inode56377605/UID1000/mode0700.
* Sole live child: `live`, dev66307/inode56377608/**current UID0**/mode0700. Its original binding's UID1000 records the pre-start state; do not mistake that historical field for the present expected owner.
* Source95fa55d, mode `boot`, full original labels: project `warden`, owner `codex-warden`, task `firecracker`, session `89c9296e79ce14c5dd30e0d5e4772f1d`, ttl `2026-10-24T23:22:48.630773+00:00`.
* Original CID `360a5600d95920d39dc8c482dc60df635ec26e0a9580770e6612358ee817c078`; image `sha256:31f091d0b413b74df4d0b7ea43da1e827b2e2ed2a9c37ec62e583ee505f82938`.
* Receipt's exact scope `/sys/fs/cgroup/system.slice/docker-360a5600d95920d39dc8c482dc60df635ec26e0a9580770e6612358ee817c078.scope`, original target30:2116013/UID0 and parent30:75/UID0; policy version/hash match the accepted fixed policy. Require matching original receipt and original absence record, fresh exact parent identity, and exact entry ENOENT. Any replacement, missing receipt, parent drift, permission error, or uncertain lookup stops. The original target FD is gone; do not claim that a new descriptor recreates its proof.
* Original `charge.json` must remain the accepted schema, reserved_bytes5000000000, released=false. Authenticate the original identity/binding/receipt/absence/charge files as private ordinary-owned, single-link, bounded regular files through the held parent FD. Require consistency with the public snapshot, not just a matching directory name. Fresh exact original full-label image/container absence and project-wide own-object accounting must agree.

Walk parent ancestors with nofollow directory FDs; reject aliases, unexpected ownership/modes, and realpath drift. Keep a fresh O_PATH|O_DIRECTORY|O_NOFOLLOW FD for the root-owned live directory and the parent FD. Recheck path-to-held-FD equality before create, before start, after helper exit, and before any accounting decision. This is a new recovery identity chain, clearly distinguished from the lost original runtime-owner FD chain.

## 3. Necessary-recovery admission, not a passing ordinary guard

`scripts/k3s_lab.py:accounting` and `scripts/azure_guard.py:preflight` were inspected as references. They charge the whole readable project, own images as2×Size+64MB, and outstanding reservations. Current Task3 source has **no unreadable-subtree exception**. Controller confirmed the earlier Task3 recovery used a complete readable measurement. Leave both files and their semantics unchanged.

The old4,013,940,736-byte project total is historical and cannot admit this operation. Implement a Task4-only exact-scene calculation, with no CLI exclude-path or generic skip option. It may account the one authenticated opaque live subtree against its already-booked5GB reservation. Every other project path must be freshly counted using the ordinary guard's allocated-byte convention, including all `.git`, caches, packages, metadata, and ignored files. Count each regular-file pathname as the ordinary guard does; do not deduplicate hardlinks to make it look smaller. Any second unreadable subtree, unexpected symlink redirect, changed anchor, or unaccounted object stops.

Why the existing reservation can conservatively cover this particular opaque subtree: the bound is the sealed **single boot** path, not a generic VM workload. `Open` copies exactly the three immutable assets: kernel27,893,008 + agent33,554,432 + payload33,554,432 =95,001,872 bytes. `boot` hardlinks those into at most one jail, and jailer copies the3,676,680-byte FC executable. Even counting both link pathnames conservatively gives193,680,424 data bytes. The fixed driver creates only the node owner, gate controls/one RunID, allocator state/lock/one RunID, and one run record; use a conservative16×65536-byte journal allowance plus64×65536-byte allocation/metadata slack. There is no boot-mode snapshot API, file log, tenant writable host bind, or successful tenant EXEC. The source-configured file data total is therefore below256,000,000 bytes, far below the existing5GB envelope. This is a conservative **source-path estimate**, not a measurement or a filesystem quota; failures/drift that contradict that sealed single-boot premise invalidate admission. Do not cite this as proof of the actual opaque size. The helper's initial RO inventory must independently total allocated blocks and reject any entry/type/count/size outside the fixed schema or any actual opaque usage exceeding the existing5GB bound, before mutation. If the controller considers the source premise insufficient, stop; do not weaken the ordinary guard.

Define fresh values `R` = entire readable rest of project, `Q` = existing5000000000 scene charge, `O` = all other outstanding charges, `E` = all current Warden-owned image charges2×Size+64MB, and `H` = conservative prospective helper growth. Admit only:

```
R + Q + O + E + H <= 12,000,000,000 bytes
other resident services + helper hard memory + host allowance <= 16,000,000,000 bytes
```

`Q` is counted once as the bound covering the excluded live subtree; do not add a fictional zero or subtract Q from the outside total. The project rest includes the original parent files and package/cache material outside live. Retain Q through every unknown result. Do not call this an ordinary `azure_guard preflight` pass. After ownership restoration, the ordinary guard resumes counting the now-readable live bytes **and** outstanding Q according to its unchanged conservative rules.

For a concrete helper that does not require a Go build, propose a sealed Python-only scratch image using the already installed root-owned `/usr/bin/python3` resolved target, its bounded standard-library/ELF dependency closure, and the fixed reviewed recovery module. This follows the existing Python packaging approach in the named Task3 source without importing Task3 runtime code, installing packages, downloading anything, or granting a host interpreter root authority. Hash each copied public root-owned input; reject mutable/non-root inputs, unknown ABI, unsafe aliases and overflow. No arbitrary package/path selection. Hard ceilings: staged runtime/module files128,000,000B; archive160,000,000B; imported helper image160,000,000B; all helper caches/logs/evidence/overlay growth64,000,000B. Thus H=128M+160M+(2×160M+64M)+64M=**736,000,000B**, reduced only by an explicit recalculation that still counts already materialized files in R and actual images in E. No memory-sized tar byte arrays; stream bounded packaging. Packaging/helper are sequential, hard helper memory=swap256,000,000B, CPU1, PIDs32, tmpfs16MiB within that memory; charge1GB host allowance plus declared services. Fresh admission before staging, import, and start; no concurrent live/build.

The cached Go image `sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d` could reduce packaging only if an existing suitable interpreter and its identity are independently established. That is presently unverified. Do not run `go run`, compile a bootstrap helper, pull, install, or introduce an interpreter as an automatic fallback. The Python scratch package above is the concrete requested ruling; if its ceilings or ABI cannot be met, stop with the exact reason.

Keep the old5GB charge schema unchanged. The transient helper growth envelope is recorded in the scoped recovery admission receipt, under the held project lock, with exact helper labels/immutable image/CID and unfinished state. It is not a new shared reservation denomination. On interruption retain Q, preserve the helper envelope/objects, and refuse ordinary work until those exact helper objects are reconciled; never discard an uncertain helper charge because its create response was lost. Account all actual own images and containers afresh. No global Docker listing beyond project-owned scope, prune, host cgroup writes, new devices, or external host filesystem mutation.

## 4. Minimum physical recovery: retain the old node and restore traversal

The recovery is to make the stopped scene traversable by the ordinary guard. **Do not delete original data** merely to regain admission. Preserve all durable authority, consumed RunID, allocation state, journals and assets in their original files. No log read or credentials export is needed for that operation.

Implement one fixed exact-scene entrypoint with strict `inspect` and `restore-traversal` modes, never arbitrary arguments or commands. Initially launch a capless root `inspect` helper with RO root/private PID, mount, IPC and cgroup namespaces/network-none/NNP, no devices, no Docker socket or source/home/cgroup binds, and exactly one initial **RO rprivate realpath bind** of the authenticated live directory to `/session`. Docker inspect must match the sealed image, complete helper labels, fixed entrypoint, exact resources and unique mount. In-container code first opens `/session` with NOFOLLOW, verifies dev66307/ino56377608/UID0/mode0700 against the held host identity and its own bounded mountinfo, rejects submounts/shared propagation, and verifies its mount namespace differs from the host. No content or descendant operation precedes this check.

Inspect only this source-derived closed shape, using FD-relative nofollow metadata operations and bounded directory reads (maximum64 entries total, maximum16 directories, depth<=6):

* `node/{gate,uids,runs,assets,snapshots}`, `node/owner`; `jails` and optionally its empty `firecracker` child.
* Root-owned0700 directories only. `node/snapshots` must be empty. There must be no remaining jail for public original RunID `7J2G4KCYZWPQ3B53EV4TR2RXAI`; any nonempty jail, different run, high-UID directory, device, symlink, FIFO, socket, mount, unknown entry, or special mode stops. The successful driver-local teardown suggested by the error string is not assumed; inspect must establish this shape.
* Gate files limited to `node`, `admission`, `retirement`, `admission-sealed`, and the original RunID; UID files limited to `state`, `lock`, and that RunID; runs contains only that RunID. Required source-created entries must exist; optional control-file existence must follow the inspected source's allowed failure stage. Metadata files must be root-owned0600, regular, single-link, <=65536B. `node/retired` must remain absent. Do not parse or emit their private contents.
* `node/assets` contains exactly the three known root-owned0444 regular assets with source-bound sizes, each nlink1 in this deliberately strict recovered shape. Do not chmod/chown/open them for writing. Any residual hardlink or unexpected inode alias stops rather than broadening the cleanup.

Emit only a bounded schema receipt: anchor identities, selected relative-name enums, numeric metadata/block totals, counts, and pass/refusal enums; totalstdout<=16384B, stderr<=4096B, no full tree/raw files. Persist the complete bounded expected-identity manifest privately in the ordinary-owned parent for the subsequent fixed restore mode. A partial or malformed receipt authorizes nothing.

After that prevalidated shape, `restore-traversal` may use only two of the already approved eight capabilities: **SYS_ADMIN solely for the verified private bind RO→RW remount; CHOWN solely for directory fchown**. It retains the existing trusted-outer LSM exception only because the fixed private remount needs it; this is a requested narrowly justified recovery ruling, not an assumed allowance. It gets no KVM, DAC_OVERRIDE, SETUID/GID, MKNOD, KILL, NET_ADMIN or CAP_BPF. Initial bind is still RO. Before any mutation repeat the host and in-container identity/RO/mount/private-namespace checks and complete schema validation. Hold every selected directory FD and an O_PATH|NOFOLLOW FD for every allowed regular file, compare the private inventory and file metadata again, then perform the fixed private remount preserving mount identity and every other VFS flag. Any required additional cap/LSM change stops.

Fchown **only those held directory FDs** from0:0 to1000:1000, deepest-first and live last; keep modes0700. Never recursive chown/chmod on filenames; no file inode is an ownership target, including immutable/shared material. Original file contents/owners/modes/links and all Gate markers remain unchanged. Compare file identity/size/blocks/owner/mode/nlink/mtime/ctime before and after using the already-held FDs; report this as metadata corroboration, not a new cryptographic content read. Recheck directory identities, restored owners/modes and parent binding; fsync modified directories and parent. The helper must not need pathname traversal through a directory after giving its0700 ownership to1000: its own afterchecks use held FDs, and the ordinary host UID1000 performs the subsequent fresh path walk. An interrupted partial restore is explicitly incomplete, Q remains charged, and only the same exact authenticated recovery can be considered later—never broaden expected owners automatically.

Retain the whole old node indefinitely at this exact path as administrative quarantine. `Open` already requires a fresh `node` mkdir; the retained node cannot be re-opened as a new lab session. Its changed directory owner also fails the old root-owned private-state contract. No API registration occurred. Do not clone/reset its Gate or allocator, reuse its RunID/authority, fabricate `known-owner-retired`, clear an ambiguous marker, or construct scheduler Reconciliation. The physical recovery receipt beside live must say `original_owner_retirement=cleanup_pending`, `creation_outcome=unknown`, `never_reopen=true`. It is administrative provenance and cannot be passed as a Gate/API proof.

Remove only the exact new helper container/image/staging objects through full-label and immutable-ID checks. Retain source/evidence/provenance. Fresh exact original scope absence/parent identity and original-object absence checks must still pass. Run the **unchanged full ordinary guard**, with full original Q still included, and record all own objects, all reservations, actual readable project allocation and six protected sysctl equality. This restores honest ordinary code-test admission; a failure stops.

No original private file is deleted in this minimal plan, so no lossy archive replaces consumed-state journals. If that strict shape cannot be recovered without deletion or owner/cap expansion, return the bounded metadata to the controller; an exact additional recovery ruling is required.

## 5. Accounting release is a distinct decision

Proposal default: **retain5000000000 and released=false throughout physical recovery and ordinary postflight**. Ownership restoration is not original process/FD/data retirement, and does not authorize `record_charge(...released=True)`.

This has a practical consequence: current tests may fit with Q plus512MB code-cache allowance, but another new5GB boot reservation on top of Q and roughly4GB project would exceed12GB. Do not silently omit the old charge to run it.

If the controller wants future boot admission after this recovery, it must expressly rule on **physical accounting release for this permanently quarantined, never-registered lab node**, distinct from unresolved Gate/API retirement. A possible reviewed release condition is: all original and helper objects absent; exact original cgroup absence chain corroborated; entire old scene readable and fully included in an ordinary full-project total; durable originals retained; old session never reopened; no process can legitimately continue writing this closed scene; all unknown helper activity settled; auxiliary physical-recovery provenance persisted/fsynced. Only then would the host update the original accounting charge using the existing accepted schema and an explicit physical-only release receipt, and run a fresh ordinary full postflight. The source and all reports must continue to state original owner/FD retirement unproved and creation unknown. If those conditions cannot be established or that separation is not authorized, Q stays and actual boot remains resource-blocked. No quota/cap waiver is requested.

## 6. Disjoint work and review sequence within the final round

**A — necessary recovery only.** After ruling, implement only the exact-scene Python recovery/admission/packaging and its focused host-Python tests; no Go edits/build/test containers, no boot/package prepare. Meaningful finite TDD must cover actual temp-directory/FD identity replacement, alias/hardlink/type/owner/count bounds, unreadable-rest failure, exact single charged-subtree arithmetic, double-count prevention, private mount validation, mutation ordering/partial failure, unchanged journal/asset metadata, absent original receipt/object/cgroup refusal, retained Q on every uncertainty, and scoped helper cleanup. Mount/chown/Docker actual operations remain mocked in unit tests. One scoped independent safety/code review covers this A implementation and execution plan. Controller then executes only the reviewed recovery. Source/evidence freeze precedes execution; actual recovery evidence is appended separately. Do not repeat Task3, SQL, runc, or broad unchanged Go suites.

**B — preserve future diagnostic evidence, then evidence-led causal adjudication.** Only after A and a passing ordinary full postflight may Go-changing focused tests use unchanged `scripts/firecracker_code.py` and its ordinary fresh guard: pinned image, netnone/capless/UID1000/RO source,2GB memory=swap, CPU2/PIDs256, GOMAXPROCS2/GOMEMLIMIT1500MiB, go test -p1, all own images/reservations plus512MB cache allowance. No recovery admission is accepted by this Go profile.

The established code defect to fix first is diagnostic loss: use a separate bounded VMM diagnostic tail/ring (do not change tenant boundedLog semantics); collect original wait result after original done/I/O completion; emit/persist a small sanitized source/RunID-bound failure record with explicit wait/exit/signal/unknown enums, pre-cleanup phase, fixed tail bound and drop counts. Never relabel a cleanup SIGKILL as the spontaneous failure cause. Preserve original Popen/pidfd/cgroup closure checks, existing ErrAmbiguous/cleanup_pending behavior, official FC seccomp, guest limits/default deny and all profiles. Tests should drive a real harmless child that emits more than the old4096-byte prefix then a final sentinel/nonzero status, exercise bounded capture and sanitization, and distinguish natural completion, unknown/non-exit wait error and cleanup-induced termination. One finite covering run for the affected FC package after focused RED/GREEN; no repeated broad unchanged suites.

There is **no established causal guest/VMM fix yet**. Do not change kernel arguments, guest mounts, syscall filters, limits, caps, or timeouts on a guess. After B is frozen, one necessary independent review covers only the new diagnostic/causal delta and unchanged runtime constraints it touches, relying on A's already completed review and actual recovery evidence rather than rerunning it. This is one final round with two disjoint dependency scopes, not a sixth loop or a reset.

Only the controller, after any authorized physical charge release, fresh ordinary guard, new-source prepare/package verification and scoped review, can rule on one further actual attempt that preserves the evidence needed to decide I7. Instrumentation is not a causal fix or guaranteed successful boot. If it fails, stop at the five-round cap and adjudicate from the newly captured actual evidence; do not automatically edit/retry in a sixth same-core cycle. If a further causal patch/execution is outside that cap ruling, report the cause and remaining work instead of treating observability as completion.

Required controller decisions now: authorize/reject A's exact admission and two-stage helper/ownership restoration; decide whether the optional separate physical-accounting release is admissible while Gate ambiguity stays; authorize/reject B's bounded diagnostic repair and the precise final-cap actual-evidence opportunity. The default until ruling is no further action.

All default payload limits remain512MiB/CPU1/PIDs128/300s, outer eight-cap/KVM-only policy unchanged, no new device or BPF authority, no host tuning, budget increase, cloud/GPU action or Task3 bootstrap. Azure committed estimate remains$0.00. Task4 actual guest/conformance/snapshot/capacity/API retirement, Task3 Ready/old five-round cap, and Goal remain OPEN.


## Controller ruling: staged final round, implement A only now

The complete task-4-round-5-proposal.md is incorporated with these binding amendments. No actual helper, image import, private read, remount/chown, Go build/test container or new boot is authorized to the implementer. Implement A and finite host-Python fixture tests, then freeze source/evidence/report for the single independent A safety/code review. Controller alone executes the reviewed A sequence. B must wait for actual A and ordinary full postflight.

Ruling: Approve A's exact-scene recovery admission, bounded Python scratch package, capless RO inventory and two-cap directory-only restoration for implementation/review — the original tail/WaitStatus are irrecoverable, but retained root-owned directories prevent honest ordinary admission; restoring traversal preserves all consumed state and avoids data deletion — if any source-bound inventory/bound/premise is wrong, the helper must refuse and keep Q/its own envelope, costing bounded recovery rework rather than widening scope.

- Keep original scene identities/source/labels/receipt/CG absence and Q=5e9 exactly as proposed. R must be a fresh complete ordinary-convention count of every other project path, including .git/caches and actual new artifacts. Only this fixed live dev/ino can be covered by Q once; no CLI exclude/general skip/ordinary-guard modification. Document the single boot's sub256MB source estimate and distinguish it from actual size or diskquota. RO inventory must reject actual blocks>Q, schema/type/owner/link/alias/count/depth mismatch before mutation. Unknown other unreadability or scene drift refuses. H=736e6 plus all actual ownimages/othercharges/services must fit12e9/16e9 before each material/import/start. Keep original Q throughout A and all failures; track uncertain helper objects/envelope under the project lock. No alternate interpreter/image/install/download fallback.
- Package only bounded immutable root-owned public interpreter/stdlib/ELF inputs and reviewed module; every copied input hashed, no user site/config/secrets, no filecaps/xattrs/PAX escape, no host root/usr/home/source/CG mounts. Stream stagedfiles<=128M/archive<=160M/helperimage<=160M/growth<=64M. Exact helper256M memory=swap/CPU1/PIDs32/tmpfs16MiB/logbounds/NNP/privateNS/netnone/ROroot. Inspect capdropALL/defaultLSM/no devices; restore onlySYS_ADMIN+CHOWN and the existing AppArmor/seccomp unconfined exception solely for guarded private bind remount. No additional capabilities or device grants.
- The restore inventory needs a concrete ingress while retaining one sole host session bind. Use a fixed immutable /expected-inventory.json embedded in the restore scratch image by the reviewed ordinary-UID packager after the bounded inspect receipt is validated/fsynced. Keep the original host inventory private and check exact bytes/hash on embedding; metadata only, no private file bodies. Container validates that fixed regular read-only inventory's schema/source/anchor/digest, not an arbitrary path/command. Count every actual prior tar/image in R/E plus prospective H at the transition; no unaccounted duplicate runtime/image. Remove only exact inspected helper objects/staging after success or known failure. No extra host mount or generic stdin/config interface.
- Match the exact source-created failure-stage schema in code/tests before using it. Do not broaden owner/name/link sets to make a fixture or live tree pass. Retain files, assets, authority, consumedRunID and all Gate markers; no reading their bodies, chmod/chown on file inodes, recursive chown, deletion or retired/reconciliation marker. Hold read-capable directory FDs (for fchown/fsync) and O_PATH regular-file FDs; deepest-first directory fchown and live last, same inodes/modes0700, afterchecks through held FDs when root no longer owns traversable directories. Any unexpected nonempty jail/highUID/special/symlink/mount stops with bounded metadata only. Partial changes remain incomplete/Qcharged; do not silently accept mixed owners.
- Read-only inspect and restore actual operations stay controller-only after safety review. If observed shape differs, return bounded refusal evidence for an exact necessary-recovery amendment, with no guest/core retry. No fabricated old log or exitstatus retrieval.

Ruling: Permit a separate controller-only physical accounting release after A's explicit conditions — once the entire permanently quarantined scene is readable and counted, Q no longer needs to represent opaque disk growth, while Gate/owner ambiguity still forbids runtime reconciliation — if any inactive/quarantine premise is false, Q remains; the cost is blocked newboot admission rather than false retirement.

A implementation must NOT automatically release Q. Controller requires exact original/helper objects absent, settled helper envelope, original CG absence chain and parent identity freshly corroborated, all original files retained and metadata unchanged, directory restoration/provenance fsynced, old node administratively never reopened/registered and consumed RunID/authority retained, no legitimate writer, and unchanged ordinary fullguard with actual entire tree PLUS Q included. Then under the existing lock/accepted record_charge schema controller may explicitly set only physical released=true, write a physical-only receipt that says original_owner_retirement=cleanup_pending/creation_outcome=unknown/never_reopen=true, and repeat ordinary fullpostflight. This conveys no Gate/VM/API proof. Any unknown refuses release.

Ruling: Approve B's bounded diagnostic evidence repair as a later dependency scope, conditional on A success/ordinaryguard — better evidence is the only justified change while the cause is unknown — it costs one finite final diagnostic opportunity, not a promised causal fix, Task4 acceptance or sixth loop.

After actual A postflight, controller separately resumes B. Keep tenant boundedLog semantics unchanged; isolate fixed VMM tail/ring and original done/WaitStatus capture. Public record is bounded, source/RunID/phase-bound and sanitized; drop API bodies/environment/nonce/protocol/tenant output/arbitrary paths, label console observations as untrusted and distinct from original-process waitstatus. A signal is a termination observation, not inferred cause; never mistake cleanup kill for spontaneous exit. No original owner/proof/ambiguity weakening. Use approved unchanged ordinary2GB code profile, focused real-child RED/GREEN and one finite covering affected-FC run only. B gets one disjoint new-delta review relying on A's previous review and actual evidence, not a duplicate recovery review.

Only after B review/newsourceprepare/fresh ordinary guard and any physical-only Qrelease may controller authorize at most ONE final diagnostic boot opportunity to capture new actual evidence. It is explicitly an evidence-gathering attempt, not a guessed kernel/limit/cap/timeout fix. A failure reaches the Task4 five-round breaker: no further causal edits or boot retry in a sixth same-core cycle; adjudicate I7 and continue independent tasks with Task4 OPEN. Before that attempt the execution report must include the bounded failure-retention/necessary physical-recovery plan; cleanup after cap may use only separately authenticated exact-scene scope, no new core patch/retry. Original Task3 cap/Ready, APIretirement and overallGoal remain OPEN.

## Cap adjudication: unresolved recovery-operation accounting

The A safety review at078329d found an Important defect in the newly introduced
recovery coordinator: cleanup can set H settled after a lost import response and
currently empty object listings. The finding is real and load-bearing for safe
physical recovery. The complete A source/execution gate is NOT PASS, and no A
operation may run with this defect. Original I7, Task4 actual acceptance and the
five-round count remain open/unchanged; this is the cap adjudication, not a sixth
VMM repair round or a completed-task claim.

Ruling: allow exactly one conservative necessary-recovery safety amendment before
execution, then one check of that delta by the same A reviewer — the unresolved
operation must remain charged, and correcting a new cleanup transition is needed
before later independent work can regain ordinary admission — if the amendment is
wrong or remains unverified, A stays unexecuted and Q/H stay reserved; no additional
VM opportunity or causal change is earned.

The correction may only refuse cleanup/settlement for unresolved import/create/
start states, including missing immutable IDs and empty current listings. Empty
lists are not a terminal operation observation. Use a closed conservative state
policy: retain H/Q and durable pending state without delete/unlink/save-to-settled
or a new discovery/daemon-cancellation protocol. Pre-daemon material-only cleanup
and genuinely completed/validated successful cleanup may remain available, with
coherent identities/state and all existing exact-object checks. Inconsistent
settled/pending records must refuse too. No timeout/retry/authority expansion.

Controller source inspection identified create-pending with cid=None as the same
uncertainty boundary, not a second independently tested reviewer finding. Include
it and start-pending in the same refusal rule. A finite native RED/GREEN must prove
those pending cases do not mutate/delete/settle even with empty listings, and that
known terminal/pre-daemon legitimate cleanup still works. Cover only the amended
host recovery module; unchanged helper/mount/Go/Task3 suites need no rerun.
Preserve old source/evidence and append the report; freeze source/evidence before
the existing reviewer checks only this delta and its new breakage. No actual
package/helper/private-scene/Go/B or boot operation is authorized by this amendment.

This deliberately conservative amendment may leave unresolved helper accounting
reserved indefinitely. Any future actual pending operation requires its own exact
physical-recovery evidence/ruling; it must not be turned into another core loop.

