# Fixed controller operation recorders — reviewable call plan, not actual admission

2026-10-25. Source `835600b611b631502b158b5037b8078921277f10`; dispatch BASE `86d8d1424f77113722a826b1e9cecda7da26d67b`. [D1–D3 ruling](continuation-controller-operations-rulings.md) and [preserved proposal](continuation-controller-operations-proposal.md) remain binding. Product continuation4c369be/I1 source review PASS does not approve these new recorders or any actual operation. Overall Task6 BASE84018/fix2used/Q5GB/Goal OPEN remain.

## Exact reviewed surfaces

Only `identity_cache_capture.py`, `identity_cache_maintenance.py`, `identity_cache_observe.py` and `test_identity_cache_control.py` were added under scripts. The two operation entrypoints reject arguments. Observer accepts exactly one of four literals. All new files are regular UID/GID1000, single-link0644; bootstrap checks the exact observe source SHA before compiling its bytes. Observer's canonical149source-name-set SHA is `214713166a6c684864818a69c64e449e70eef6c3ff04c08b97a360b60fec1383`; admission must contain all149actual source hashes. Project modules execute from verified source bytes in dependency order, bypassing unverified pyc. Maintenance additionally refuses an existing `scripts/__pycache__` before launching its unchanged product CLI; -B alone prevents writes, not reads. No bytecode/cache deletion is authorized by that refusal.

| Fixed cwd `/home/postedism/Desktop/Warden`, argv | Code budget / limits |
|---|---|
| `python3 -B scripts/identity_cache_observe.py capture-preprobe` |180s, CPU60s/AS256MiB/FSIZE1MiB|
| `python3 -B scripts/identity_cache_capture.py` |90s; capture function must return before entry+80, finalization within original90; CPU75s/AS512MiB/FSIZE32MiB|
| `python3 -B scripts/identity_cache_observe.py capture-postflight` |180s, same observer limits; only after independent terminal gate|
| `python3 -B scripts/identity_cache_observe.py continue-preprobe` |180s, same observer limits|
| `python3 -B scripts/identity_cache_maintenance.py` |600s; absolute580/585/590/600 cutoffs; parent CPU60s/AS256MiB/FSIZE1MiB|
| `python3 -B scripts/identity_cache_observe.py continue-postflight` |180s, same observer limits; only after independent terminal gate|

Maintenance's only child argv is `['python3','-B','scripts/identity_cache_continue.py']`; child CPU540s/AS512MiB/FSIZE1MiB. Popen uses fixed cwd, stdin DEVNULL, merged stdout/stderr PIPE, close_fds, start_new_session, no shell; environment exactly `{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}`. Only its fixed single-threaded preexec resource setter runs before exec. Neither actual Python/Docker binary trust nor interpreter-startup timing has been established by fixtures; the future outer invoker must establish them before actual admission.

Capture is entirely in process and starts no child. It writes a durable exclusive public launch before calling the reviewed capture function. A returned/raised function is known in-process terminal; a normal caught exception produces a failure receipt when the original deadline permits. Direct timeout/signal exit retains partial records; no late receipt is synthesized. Successful function return alone is not approval.

## Authority and fixed public artifacts

All paths below are under `docs/evidence/task-6/`, using prefix `controller-cache-continuation-v1-20261025-`. Controller alone provides `capture-admission.json`, `continue-admission.json`, `capture-outer-result.json`, `continue-outer-result.json`. This source stage created none of those real files. Recorders do not perform Git, create authority, manufacture outerexit0 or reset/retry records.

Admission exact keys: version(int1), stage(capture/continue), source_commit(40hex), source_hashes(exact149canonical names→SHA256), review_sha256, ruling_sha256, writer_basis(nonempty<=4096UTF8bytes), clock_identity(machine_id/boot_id), policy(exact stage POLICY dict), outer_invoker_sha256. Each hash is64lowerhex. `policy` is compared via canonical JSON, not permissive numeric equality. Controller exclusively creates/commits admission after source/call review and the corresponding actual-stage ruling. Admission precedes fresh preprobe and does not reference an absent preprobe, avoiding a cycle.

The controller must separately supply and freeze `controller-cache-continuation-outer-invoker-20261025.py`. Its exact bytes must match admission.outer_invoker_sha256 before these recorders accept authority. This invoker is **not implemented by this four-file source stage**. Its implementation/tool integration/source review is an actual-blocking gate, specified concretely below; no assumed file/hash/default exists.

Recorders exclusively create0600, nofollow, bounded records: capture-preprobe/launch/summary/receipt/postflight; continue-preprobe/launch/receipt/pending/postflight; plus continue.log. Public JSON is<=65536B; log<=1MiB. Created FD/fullmetadata/intendedbytes survive filefsync+parentfsync+readback before authority is returned, following I1. Existing partial/new state is retained; no replace/reset or automatic invocation follows. Launch binds actual fresh preprobe bytes/proof, admission proof, source hashes/commit, writer basis, clock identity, fixed command, limits, originalexit-15/180second history and Q_released=false.

Preprobe completion contains the monotonic observation time and the admitted same host/boot identity. Launch requires age0..60seconds, checked again both before and after launch durability. Negative age, bool/nonnumeric time, changed source/record, different boot or unknown identity refuses. UTC is evidence only. No ctime author inference.

Maintenance production `EXPECTED_APPROVAL_SHA256` and `EXPECTED_APPROVAL_BYTES` remain **None** and refuse before private reads/Popen. After successful capture postflight only, controller copies the original seven-field summary into existing `cache-continuation-checkpoint-approval-20261025.json`, changing only state to approved, durably writes and commits it. Then change only the two maintenance constants to the real raw approval hash/length, freeze the changed149source manifest, and obtain constant-only scoped review. The eight unchanged product source/test hashes in the private checkpoint remain unchanged. Do not recapture, modify private binding or silently reuse the capture admission/window.

## Separate locks and observations

Preprobe holds the unchanged project docker.lock only while taking observations. It releases it before capture/main independently acquire the same lock. Postflight acquires it only after independent terminal proof. No nested lock, borrowed FD or trust/state/accounting override exists. A controller-established continuous writer-free window bridges these separate holds; lock ownership alone does not exclude legacy non-locking go.sh. All known prior project operations must be terminal, other agents idle/read-only, and no legacy writer or service started. Capture, constant-only source change and maintenance are separate windows; do not change source during capture/postflight.

The only temporary production binding is `recovery.docker` to a narrower read-only adapter, restored in finally. It accepts exactly existing container/image ls flags with project=warden or the exact original OLD_LABELS set. Inspect IDs must first appear in that adapter's scoped listing and have exact ID syntax. No Docker mutation, broad selector, arbitrary socket/env, old PID discovery or global host/GPU/container scan. Every CLI is its own held Popen with cleanenv, fixed `/usr/bin/docker --host=unix:///var/run/docker.sock`, bounded1MiB output and remaining absolute deadline; at most30s per call including run/TERM/KILL-wait, reserving final observer time. Unknown CLI terminal stops subsequent observations; sending a signal is never proof of exit. Failure attempts only an incomplete/unknown public probe record when time permits; a partial/existing record is never rewritten.

Read-only interfaces remain Scene(cleanup=True), pinned original inspect inventory SHA55f96e5b…/helper SHA72675e91…, helper.validate_inventory, full_postflight(scene,0,inventory), current_charges/image_charge; fixed inspect and restore-traversal state_read(source0c7dedbf…) with settled/success/complete/releasedfalse and helper_absent. Never source_sha/phase_binding/execute_phase/cleanup_phase/restore or recovery CLI. Guard includes full ordinary R + allQ/charges + owned-image accounting +96,000,000 <=12e9; resident within16e9 with existing1GB native allowance. No charge created/released. Source/evidence and metadata are part of ordinary R.

Fresh sibling digests use sorted lstat names/fullmetadata/blocks without atime, body reads or symlink following for firecracker-code/go-mod/warden-lab. Authorized crypto explains why firecracker-code no longer equals10:07; each new stage's fresh before/after siblings must match. Original22scene, phase-state hashes, journals/Q/sixsysctls and project-owned objects remain protected. Actual source ancestor/mode acceptance and host/resource facts are unverified by generated fixtures.

## Required future outer invoker — concrete design and current gap

This section specifies a review target, not an implemented or admitted command. No new outer process/command may be started merely because this plan exists. Controller will freeze the exact invoker source and the exact tool call, then independently review both.

1. **Fixed interface:** invoker accepts only the six table operations, as enumerated constants, with no user path/command/selector. For capture/maintenance, the actual recorders' argv must exactly equal the table. For observations, use exactly the corresponding literal mode. Fixed cwd and cleanenv are the same constants above. No shell expansion, inherited PYTHONPATH/Docker context, network environment or retry. Validate ordinary UID1000, trusted fixed Python/Docker binaries and exact frozen recorders/admission before creating a child; include that work in the outer budget.
2. **Entry clock before target interpreter:** a trusted already-running controller/tool owner must take host monotonic start before creating the outer invoker/target interpreter, bind same machine/boot, and apply the90/600/180 absolute deadline from that instant. The invoker must receive that immutable deadline through a fixed reviewed mechanism (for example, a preopened fixed FD containing only the controller-owned operation/start/deadline/boot envelope); no arbitrary environment timeout override. This caller/FD integration is **not implemented or verified here**. Merely starting a Python script that calls monotonic after imports does not establish startup-inclusive timing. The exact tool/caller source and envelope checks must be supplied for review; absent that, actual remains closed.
3. **One owned target:** Popen once with the fixed argv/cwd/env, close_fds and dedicated new process group, bounded nonblocking output; register the live Popen as soon as it returns. Source/admission/launch failures do not retry. Popen startup/exception without a returned handle is unknown; do not infer no process was started. Preserve the independent tool outcome and prohibit postflight until terminal is established separately. No rediscovery/signaling from old numeric PIDs.
4. **Absolute outer supervision:** use only remaining budget, never a new90/600/180 after launch. Capture's internal phase deadline is80/90; maintenance's internal phases580/585/590/600; observer's internal total180. Outer owner must stop a still-live recorder before its absolute total, with termination/wait/final-output budget preallocated inside that total. A proposed conservative outer schedule is capture TERM80/KILL85/wait90, maintenance TERM590/KILL595/wait600, observer TERM170/KILL175/wait180, all from the trusted pre-spawn outer start. These outer cutoffs can shorten effective internal grace when startup consumes time; they cannot extend it. A known timely normal exit/receipt permits success, while forced termination is failure/unknown. Controller must explicitly review/accept these exact outer cutoffs before actual; they are not silently treated as already implemented in the inner scripts.
5. **Nested owned children:** outer owns the recorder Popen; recorder separately owns maintenance or read-only Docker CLI process groups. Outer recorder exit or a group signal alone does not prove those nested children terminal. Normal inner receipt must contain actual known poll/wait result; outer validates it against its own known recorder/tool exit and exact immutable launch/receipt/source bytes. If the recorder is killed, its startup handle is unknown, or receipt is absent/partial/inconsistent, outer must record child_terminal=false/unknown even when its own recorder has exited. Do not inspect cache/private state, run another probe, ordinary guard, new charge or next actual until controller establishes terminal safely. No all-process scan or blind numeric-PID kill is allowed. This is retained unknown, not guaranteed cleanup.
6. **Bounded output/finalization:** outer collector also streams at most1MiB, marks overflow as failure, and leaves time for its own bounded receipt/output. No unbounded communicate, wait, read, log fsync or source rehash after the deadline. Kernel D-state or a blocking launch/fsync can defeat successful completion; hard deadline plus missing record is unknown, never a late manufactured exit0. Its source must prove the owned-child fallback and include synthetic delayed-start/terminal/overflow/finalization tests before review. The current fixtures test only inner code with fake children/clocks.
7. **Independent result recording:** after the tool reports a known actual terminal, controller creates the fixed outer-result JSON from that real tool result and verified inner files. This is an independent later controller evidence action, not a second operation, replay or extension of child time. Keep actual raw tool result, timestamps, hashes and full command. No recorder may self-write its outer result. Probe tool terminal must likewise be corroborated before controller admits capture/maintenance; a probe JSON path alone is not permission.

Current gap is specific: no frozen startup-envelope provider, outer-invoker source, exact tool call, independent outer result or nested-child terminal evidence exists from this stage. The four source files deliberately require future invoker/admission metadata and the maintenance real pins are absent. This source/plan review may assess these gates, but cannot claim them passed or execute anything. Parent256MiB+maintenance child512MiB leaves less than1GB for an outer invoker; any future outer allowance must be explicitly bounded within the remaining original1GB, not silently added as another service. A proposed AS128MiB outer would put these caps at896MiB total; actual resident/objects still need fresh guard.

## Independent terminal and postflight protocol

Outer-result exact fields are version, stage, producer=`controller-tool-result`, terminal, exit_code, child_terminal, child_exit_code, launch_sha256, receipt_sha256, source_commit, outer_invoker_sha256, command, clock_identity, started_monotonic_ns, ended_monotonic_ns. Capture has no child and child_exit_code=null; maintenance requires exact integer child exit matching the inner receipt. Both require terminal=true and matching bindings before private/cache/guard work. Outer elapsed must be nonnegative and <=90/600, start no later than recorder entry, end no earlier than its receipt. Exit must match the inner success/failure classification. Unknown/absent/inconsistent outer or own receipt refuses before postflight observations. The source never converts stdout, file existence or sent signal into terminal proof.

Known nonzero terminal permits only separately admitted read-only failure audit and ordinary guard, with incomplete state. If the unchanged strict scanner refuses partial layout, record refusal; no relaxed scanner/recovery retry. Success validates oldintent/checkpoint identity/hash/binding, capture summary or realapproval, exact new PREPARED/READY/RESULT schema/hash links/counts, root/256buckets/metadata identities/targetmodes and absence of derived entries/aliases. No target body reads. It also verifies preserved source/siblings/phase states/Q/objects and ordinary resources. Public output is digests/counts/status, never private bodies.

Capture postflight never writes approval. Maintenance postflight never creates/releases a charge or starts PG/material. Only a separate later fresh standard3,000,000,000+allQ+image+ordinaryR evaluation with explicit resident envelope may be considered; do not reuse old hardcoded8GB/3.768GB formulas. Original180secondtimeout, privateintent/partialpermissions, Q5GB, Task3/4 counts, Task5actual42cells and deferred M1/old-cache-fsync/crypto-concurrency remain untouched.

## 2026-10-25 fix3 appendix — current layout and timing correction

This dated appendix supersedes the earlier three-entry layout,149-source bindings and inherited resource arrangement for future review. The original16915bytes above remain verbatim (SHA256 `897445b1f09923df9795e8863c230448d0c10ece0bda1ce684c930a6f28d2162`). [Fix3 ruling](controller-operations-fix3-rulings.md) resolves the plan-mandated duplicated bootstrap. Source is `61477c02d3bb482af9d0cf3233312e5c53dcca4c`, dispatchBASE `b7682d02eb7d78712f819adca38da07dae0b694f`, scopedFIX_BASE e9acbe412e699da32a0546de7e98527ba87eae83, original Task6 fix3/5. This remains a source/call-plan review target, not actual admission.

The sole entry is now `scripts/identity_cache_control.py`; fixed cwd remains `/home/postedism/Desktop/Warden`, cleanenv exactly `{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}`. The six exact argv are:

- `['python3','-B','scripts/identity_cache_control.py','capture-preprobe']`
- `['python3','-B','scripts/identity_cache_control.py','capture']`
- `['python3','-B','scripts/identity_cache_control.py','capture-postflight']`
- `['python3','-B','scripts/identity_cache_control.py','continue-preprobe']`
- `['python3','-B','scripts/identity_cache_control.py','continue']`
- `['python3','-B','scripts/identity_cache_control.py','continue-postflight']`

Only these six literals are accepted; no arbitrary path/callable/command. The original three files are passive implementations; direct execution now explicitly fails before imports/operation. Bootstrap has one bounded nofollow/held-FD/metadata/SHA loader, pins observer SHA256 `6d3d310478bf8c080a4cc0915a3b701803e3a24e51a4b98559178230f4746dc2`, then compiles verified bytes. It does not import unchecked project code or pyc. Observer verifies all150source bytes from the exact canonical set before compiling either of the two fixed operation modules; this allowlist is rechecked before compilation. The new name-set SHA is `f61b1c1e7613ee67e38bd9f31a6b023f34df39e4d805ef7f6f5bb9907aa7f079`. No circular embedded hash or self-authentication claim: the future independently reviewed caller must authenticate the sole top-level bootstrap before executing it. That caller remains absent/unverified.

Fresh future admissions, launches and outer results must bind150sources and the new command/policy. No historical146/149manifest is rewritten. Public admission/source validation may precede maintenance's absent-pin refusal under D1; `EXPECTED_APPROVAL_SHA256`/`EXPECTED_APPROVAL_BYTES` still live in maintenance and are None. They refuse before preparation, private reads, launch or Popen. After actual capture approval, the separately reviewed constant-only change and150source freeze remain required. The product child argv remains exactly `['python3','-B','scripts/identity_cache_continue.py']` and absolute580/585/590/600 supervision remains.

Maintenance parent effective CPU60/AS256MiB/FSIZE1MiB is unchanged. Its fixed CPU soft/hard pair is60/540, AS256/512MiB, FSIZE1/1MiB; the extra hard ceilings exist only for fork inheritance. Policy adds `cpu_hard_seconds:540` and `address_hard_bytes:536870912`; exact admission/launch policy binds those fields. All inherited hard ceilings are checked first, with RLIM_INFINITY handled, before any setrlimit; inadequate ceilings refuse before process creation without privileged raises/rollback. SIGXCPU directly exits124. The child callback sets CPU540/540,AS512/512MiB,FSIZE1/1MiB within those inherited ceilings. No parent code raises its effective soft limits. Capture/observer effective limits remain75CPU/512MiB/32MiB and60CPU/256MiB/1MiB. CPU handler exit can leave an already spawned child unknown; it is not terminal proof or permission to probe afterward.

The proposed future outerAS128MiB must be an effective soft limit, with hard ceilings sufficient for the chosen target and descendants (CPU>=540/AS>=512MiB, capture FSIZE>=32MiB). It must not inherit a hard128MiB ceiling into a larger target. Proposed896MiB aggregate outer+maintenance parent+child still needs fresh ordinary guard within original1GB native allowance. Docker is a Go CLI whose viability under observer256MiB remains unknown; neither fixtures nor this plan prove it can run there. Do not enlarge its envelope or execute it to resolve that fact without separate admission/review.

Before postflight imports/private/guard work, strict launch parsing now binds stage/state/call/source/policy/writer/clock/history/Q and exact admission/preprobe proofs. Current admission proof authenticates its review/ruling/writer bytes; same-byte inode replacement is rejected. The same retained preprobe bytes supply preservation facts, with rechecks before imports, under the lock before private work, and after observations; a new mutable baseline is not accepted. No fresh60second age is imposed on postflight. Independent outer terminal proof, separate lock/writer windows, no target-body reads, original scene/Q/charge limits and all former actual gates remain.

Timing scope correction: the original seven fixture wrappers captured wall_start after imports and armed a fresh45seconds after setup. They do **not** establish the earlier claimed complete setup/whole-invocation45second envelope. Preserve their logs/receipts/wrappers and behavior results. The four new fix3 wrappers measure entry immediately after importing time, set end=entry+45, import minimal os/signal, and arm only remaining positive time; exhausted setup directly exits124. Other imports, argument/resource setup, manifests/snapshots/tests/postrecords/output flush use that same deadline. Final cancellation checks it again. Exact running-prefix generated tests exercise8seconds→37seconds,45/46seconds→exit124, and late final flush→no timer cancellation. Interpreter startup and essential pre-timer bootstrap still lack an external hard bound; source, mocks and a short successful run do not close that gap. Actual outer invoker/call review and separately admitted operation remain mandatory. No actual caller was implemented in fix3.

## 2026-10-25 fixed invoker source appendix — no actual admission

Source `a87b85072e0fb279d5337c077a30bfcbb8efcd62`, dispatchBASE `8184e9659a0d28a392dea64859f04f92005f2ed6`. This appendix supersedes the earlier unavailable provider-FD requirement and the statement that the passive invoker is absent, under [the D1/D2 ruling and one-use clarification](controller-invoker-rulings.md). The preceding 22986 bytes are preserved exactly, SHA256 `88f51ddbcc5d6ca026e9749e14ba1cdf9e52a797679d610f106f25c4d7aef123`. Original Task6 fix3/5 used, Q5GB, history and actual gates remain. This is the exact-call review proposal, not permission to run it.

**Single entry and independent trust.** The six outer argv are exactly `['python3','-B','scripts/identity_cache_control.py','supervise',MODE]`, where MODE is one of `capture-preprobe`, `capture`, `capture-postflight`, `continue-preprobe`, `continue`, `continue-postflight`. No seventh mode or material operation exists. The six target argv remain the six four-element lists in the fix3 appendix. The fixed docs invoker is passive: direct execution refuses before imports/actions. The sole bootstrap verifies observer SHA256 `5926ffbb8ac467983ecc8fbaf3f712831a86cb088da62fe4c4e5f9aff83247aa`; Controller verifies150source names/hashes and retains/rechecks the admission-pinned invoker before compiling its bytes and calling only `run(control, mode)`. Invoker SHA256 is `b53163ed24cd8e31cc76dfb25de6b59efc8da9e39f33eb50a0b780ad27e8f4c8`. Bootstrap SHA256 `9715beb32d23cd1da9ae0f27fad96b096d44cbbab84ff7966ed2624358bde177` must be authenticated by the separately reviewed caller, not by its own claim. Actual binary/ancestor trust is still unverified.

**Concrete future tool invocation.** For each separately admitted literal MODE, root may submit for independent review the following fixed `exec_command` shape; this document does not execute it or authorize substitution from user input:

```text
cmd = exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py supervise capture-preprobe
workdir = /home/postedism/Desktop/Warden
shell = /bin/bash
login = false
tty = false
yield_time_ms = 1000
max_output_tokens = 2000
```

The other five separately frozen calls change only the final literal to `capture`, `capture-postflight`, `continue-preprobe`, `continue`, or `continue-postflight`. No shell variable, interpolation, arbitrary path or inherited environment is allowed. Shell `exec` then env `exec` preserve the command process PID and kernel birth across initialization; source assumptions about those trusted binaries and provider process semantics require later verification. `/usr/bin/env`, `/bin/bash`, PATH resolution and Python trust have not been established here. Tool queue latency before kernel process creation is unbounded and outside the claimed process-lifetime budget. `yield_time_ms` is not a timeout. The live returned tool session may be polled only with empty stdin through `write_stdin`; it is not a source of permission to signal rediscovered PIDs or retry an unknown launch. Raw initial/yield/final tool records must be preserved independently. No provider FD or tool deadline field is assumed.

**Conservative lifetime and both clocks.** Earliest Python entry records real MONOTONIC nanoseconds, then arms the remaining original allowance. After verified public source loading, the invoker reads only bounded own `/proc/self/stat`, `/proc/self/timens_offsets`, own time/time_for_children namespace identities, SC_CLK_TCK and the same-process MONOTONIC/BOOTTIME bracket. These future reads have not occurred in this stage. The source accepts only Linux, the stated monotonic implementation, zero namespace offsets, matching current/child namespace,52-field stat layout and100Hz ticks. It subtracts one complete tick from the birth tick and maps that BOOTTIME lower bound to MONOTONIC using the conservative bracket edge. The stored `budget_start_monotonic_lower_ns` is explicitly a lower bound, not a sampled start or invented precision. Entry/observed/current fields remain actual MONOTONIC samples. Sampling uncertainty is bounded to100ms; float callback cutoffs round down with a1microsecond margin. Invalid layout, tick rate, ordering, identity or namespace refuses.

Every guarded check/arm/run/TERM/KILL/drain/finalization uses independent remaining MONOTONIC and BOOTTIME cutoffs. Nonoverlapping clock-offset intervals (including suspend), namespace changes, reversed samples or own process identity changes refuse, with unknown state retained. This cannot turn suspended time into a fresh phase. Public read-only bootstrap verification and minimal timer/resource setup precede retrospective birth validation and are charged. No envelope/claim/private work/operation launch/Popen follows an exhausted or unknown budget. Kernel uninterruptible calls and interpreter/essential timer bootstrap still have no demonstrated physical-stop bound. A late result is rejected, even if exit0 or a complete-looking file exists.

| Mode | Original total from conservative origin | Outer run / TERM grace / final bound | Existing inner phases |
|---|---:|---|---|
| capture |90s|80 /85 /90|80 /90|
| continue |600s|590 /595 /600|580 /585 /590 /600|
| four probes |180s|170 /175 /180|same total180|

These are absolute cutoffs, not successive allowances. A recorder must have known terminal before its outer run cutoff to be classified as normal; output must reach EOF before the drain cutoff, with all public proof checks/fsync/output completed within the original total. The outer schedule can shorten useful inner finalization/grace. Partial spawn, unknown wait/EOF, overflow, late flush, altered source/authority or forced recorder death does not prove nested maintenance/CLI child terminal. Only the held Popen can be signaled; there is no PID discovery. Output streams to a fixed exclusive0600 log, bounded1MiB, with held-FD/metadata/hash and parent-fsync readback. Unknown state and partial files remain; no retry or automatic audit follows.

**Effective and inherited ceilings.** Supervisor soft CPU10s/AS128MiB/FSIZE1MiB, hard CPU540s/AS512MiB/FSIZE32MiB. All ceilings validate before any change. Only target preexec raises target soft values inside those inherited hard ceilings; then the target installs its fixed final policy. Maintenance's unchanged callback can still set CPU540/AS512MiB/FSIZE1MiB for its child. Supervisor soft limits never rise. Capture target75CPU/512MiB/32MiB; continue target60CPU/256MiB/1MiB (CPU540/AS512MiB hard); probes60CPU/256MiB/1MiB. Candidate outer+continue+child AS sum896MiB fits the original1GB native allowance numerically, not as measured RSS/host headroom. CPU/AS failure may leave nested ownership unknown. Docker CLI viability/config behavior remains unverified; no CLI/material test or replacement adapter is implemented by this stage.

**One-use public evidence.** With existing prefix `controller-cache-continuation-v1-20261025-`, each of the six modes has exactly `MODE-deadline.json`, `MODE-deadline-accepted.json`, `MODE-supervisor.log`, `MODE-supervisor.json`. Envelopes and claims are<=4096B, exclusive0600 via existing held-FD/file-fsync/parent-fsync/readback. The envelope strictly binds mode/stage/targetargv/source manifest/admission full proof/invoker full proof/host-clock/birth evidence/origin/cutoffs. Target validates authority and shortens its original budget, then exclusively creates its claim with the same envelope proof and real target-entry sample before private/preparation/launch/Popen. Existing or partial claims refuse without deletion or replacement. The continue target's verified None-pin check runs before claim creation. Launch, preprobe, postflight and supervisor validation retain/recheck full envelope and claim proofs; same-byte inode replacement and in-place alterations refuse. No envelope or claim is new authority. Supervisor output is only `recorder-terminal-tool-reconciliation-pending`, never an outer-result or approval.

**Independent actual terminal acceptance remains unimplemented.** After awaiting a known real tool terminal, a separately frozen/reviewed controller command must sample trusted host MONOTONIC on the same machine/boot. Its sample is a conservative upper bound on terminal time, including controller scheduling delay. Whole elapsed is that upper-bound sample minus the envelope's conservative origin lower bound; exceeding90/600/180 rejects. API `wall_time_seconds` is not proven complete command lifetime, and the invoker's own final sample precedes interpreter exit; neither is sufficient alone. The independent sampler/result writer and exact calls are not supplied or executed here and remain actual-blocking gates. Do not infer timely terminal from a supervisor JSON file, stdout, exit0 or poll yield.

For capture/continue the existing strict outer-result schema is retained. `started_monotonic_ns` must equal the envelope lower bound and is labelled as such in separate timing/tool evidence; `ended_monotonic_ns` is the actual independent post-terminal sample, labelled as the terminal upper bound. The target command remains in its `command` field; separate raw tool evidence must record the distinct supervise argv. Clock/source/invoker/launch/receipt hashes, known child terminal/exit, recorder/tool outcome and same claim/envelope proofs must agree. Probe results need the same independent terminal/timing reconciliation before a subsequent operation can be admitted. Unknown/late/disagreeing outcomes prohibit postflight/private audit/guard/next operation; no self-written success, inferred cleanup or after-the-fact extension is permitted.

All earlier independent source/call review, actual-stage admission, continuous no-writer window, fresh preprobe<=60s, separate locks, strict public/private authority, original22scene/siblings/Q5GB preservation, ordinary guard and constant-only real approval pin review remain. Admissions precede preprobe; no existing record is replayed. Real None pins remain and no actual authority/envelope/claim/launch was created in this source stage. Later PG/material/new3GB remains closed. This source adds at most six1MiB supervisor logs, six64KiB supervisor records and twelve4KiB envelope/claim files (6,733,824B logical worst case), accounted in ordinaryR and the existing96MB record reserve, not as a new charge. Filesystem allocation, real resident headroom and complete actual guard are still unknown. Current source/mock evidence and review do not complete Task6 or Goal.

## 2026-10-25 fixed four-GET appendix — source only, no socket admission

Source `b2b348205bdb3fbd4573ab04237c1a9e166371e2`, immutable dispatchBASE `4e197bd899a768449bb5b19dace8b5e88b9b713d`. The preceding33536bytes remain verbatim, SHA256 `d68ca5aa148be8727915598b4559cad4a3a55b7274018cbf1a8321a920e0d2f9`; prospective prefix record is controller-readonly-api-source-plan-prefix.json. This appendix changes the observer transport under [the public ruling](controller-readonly-docker-api-rulings.md), following independent invoker source PASS. It does not admit any actual socket/observer/material/capture/maintenance. Original Task6/fix3of5/Q5/history/caps remain.

Only ReadOnlyDocker/helpers/imports, the bootstrap observer SHA and relevant generated fixtures changed. New observer SHA256 `244bef82a1672d88054e177bf1bf2d66d2aa982a72d86051ac749fc797a322e3`, bootstrap SHA256 `8c3af61861d94b489dd39d6679d39d93f9f14636cb8dbae88f965e888a4c6e64`. Current150source manifests must bind these bytes; canonical names and existing two docs controller hashes remain unchanged. No new target/controller action, material entry, reconcile entry or independent result writer exists. Capture/maintenance, real None pins, product8/shared recovery/guard/charges/crypto are unchanged. All earlier actual source/binary/clock/authority/no-writer/terminal/resource gates remain.

ReadOnlyDocker retains the recovery.docker callable interface and the same temporary binding/finally restoration. It no longer starts Docker CLI children. Existing exact image/container ls args for project=warden or OLD_LABELS map to API1.45 `/images/json?all=1&filters=F` or `/containers/json?all=1&filters=F`; F percent-encodes compact sorted label conjunction JSON. Existing exact scoped inspect IDs map to `/images/sha256:HEX64/json` or `/containers/HEX64/json`. All paths have `/v1.45` prefix. No mutation/info/ping/version/negotiation/retry/fallback exists. Lists validate every item's exact unique Id and all requested Labels, <=1000; only successful complete requests replace that kind/scope's current ID set. Inspect requires current same-kind provenance, exact Id and Config.Labels matching all retained qualifying scopes. Return LF IDs or bounded JSON [object], preserving fields for unchanged downstream checks, without printing Config.Env/body data. A mismatch rejects the whole result, not apparent absence. These are sequential observations, not an atomic snapshot guarantee.

Each request sends exactly `GET URI HTTP/1.0\r\nHost: docker\r\nConnection: close\r\nAccept: application/json\r\n\r\n` on a fresh AF_UNIX stream to `/run/docker.sock`. Source pins socket dev29/ino4756/uid0/gid115/type socket/mode0660/nlink1 from root's separately preserved read-only metadata; this worker made no host re-observation. Root-controlled nofollow ancestor FDs/path identities and stable dev/ino/uid/gid/mode bind `/` and `/run`; unrelated directory timestamp changes are permitted. Full socket metadata is retained/rechecked around the request. SO_PEERCRED must report uid0 and remain identical within the request; no PID discovery or executable attestation follows. Socket FD inode is not compared to pathname inode. Root-admin/no-replacement trust remains; pin change refuses before connect and requires fresh metadata/constant-only review. `/var/run` correspondence was separately established by root; the adapter uses no alias resolution.

Strict HTTP subset: status200 HTTP/1.0 or1.1, header<=65536 including delimiter, body<=1048576,total<=1114112, bounded recv independent of Content-Length. Reject malformed CRLF/token/control/folding, duplicate critical headers, TE/Trailer/Upgrade, unsupported Content-Type/encoding/connection, signed/comma/oversized/inconsistent length or surplus data. Content-Type must be application/json with optional UTF-8 charset. Require actual orderly EOF even when CL is present, strict UTF8 and one JSON value without duplicate keys, NaN or trailing nonwhitespace. Absent CL+complete JSON relies on the explicitly accepted trusted local single-JSON server assumption. EOF/close does not prove daemon handler termination; no mutation or project-owned process is created by these GETs.

For integer timeout1..30, request end E=min(actual now+timeout, original observer end-10); require E-now>10. I/O ends E-10, validation/close E-5, serialization/return E. Existing actual MONOTONIC plus BOOTTIME guard checks/arms every phase and before/after work; select receives remaining absolute budget, partial progress never renews it. Ordinary error/suspend/clock/identity/framing/close uncertainty invalidates the adapter and clears provenance; no next call/retry. The one held socket is closed in finally, never registered as a child signal target. Original total is restored only while still valid. Known close is required for returned data; process death/close is not daemon internal completion. Existing outer recorder/tool proof is still required. Legacy unknown-probe field owned_cli_terminal is unchanged and refers to CLI ownership, not socket/handler proof; incomplete probe state cannot become normal completion.

The future30second material command remains a separate source/exact-call/review/admission stage. Candidate literal argv is `['python3','-B','scripts/identity_cache_control.py','material-four-get']`, cleanenv PATH=/usr/bin:/bin,LANG=C,LC_ALL=C, fixed cwd /home/postedism/Desktop/Warden, one verified passive material module through the same loader. Current bootstrap rejects that action. A future fixed tool cmd could be `exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-four-get`, shell=/bin/bash,login=false,tty=false,yield_time_ms=1000; shell/env/Python trust and exact source pins still need review. Yield is not a deadline.

Proposed material limits CPU5/AS128MiB/64KiB output, conservative birth-origin total30s, receipt25 and independent terminal acceptance30. Use at most two project lists followed by one lexicographically first existing ID inspect per nonempty kind. With this unchanged adapter and a30s Deadline, its nested reserves tighten actual GET I/O to at most origin+10, validation/close+15, returned values+20; these are stricter than the proposal's outer I/O20/close22 maxima. Do not remove reserves, create a fresh request30, extend the total or increase limits to fill coverage. Slow startup/requests may refuse. Empty inspect slots must be NOT EXERCISED, never PASS; no object creation/pull/old-ID fallback. Record only exclusive bounded material counts/hashes/status/peer/source/clock/tool facts, not raw bodies, preprobe names, private cache/guard/charge/Q actions. Failure stops and retains evidence. Installed API/framing/socket/resource compatibility remains unknown.

The separate independent post-tool-terminal MONOTONIC sampler/result writer remains required and unimplemented by this source. Tool wall_time is not full lifetime; this adapter and supervisor cannot self-authorize outer success. Future reconcile/material discussions are not implemented authority. Known tool terminal and a trusted later actual MONOTONIC upper bound must corroborate the conservative origin and immutable source/envelope/claim/result chain before another actual can be considered. Source/mock PASS alone is not actual admission or Task6/Goal completion.

## 2026-10-25 independent terminal source / exact caller appendix — no actual admission

Source `a05d077cd4885b5ddc662e0a8854ba0a8208b7da`, dispatchBASE `0766662fd4dd88b9e77812554909898a71b96e13`, under [R1–R4 and implementation resolution](controller-terminal-reconcile-rulings.md). Original40886-byte prefix remains verbatim, SHA256 `9fc37f2f9803ed5b5492356f527b9abf6ae2e21b52267981c52a799c7fee405c`. This appendix supersedes the statement that independent reconciliation source is absent. Actual invocation remains CLOSED, requiring independent source/mock/exact-call review and all separate admissions. Original3/5/Q5/scene22/history/caps remain.

Only the five authorized existing files changed. Bootstrap SHA `20754530fbaab07a27a6d0ec343dee2ac2239dcd28401eb844058184619fc199`, observer SHA `9389182719aa261afe491e1b3620e1b62781035c258f2f34a360e29352adbceb`, passive invoker SHA `a59651fe438f1f035d73b4d319e9ee5a47217c82e56a8016402df3ece7fa256d`. Names150/other147/product8/capture/maintenance/None pins/shared components are unchanged. New admissions must bind the frozen source150 and invoker bytes; no historical capture→continue pin/source handoff is implemented.

The sole new action is `['python3','-B','scripts/identity_cache_control.py','reconcile',MODE]`, the same six literal modes. Earliest bootstrap samples U=real MONOTONIC, B=real BOOTTIME, A=real MONOTONIC before source imports; all actions still use the one verified loader. Reconcile takes separate30s/CPU5/AS128MiB/FSIZE1MiB policy, then shortens its deadline from verified own birth and enforces both clocks through final output. New PID/birth evidence stays separate from historical supervisor identity. It does not adopt an operation envelope/claim, load recovery/guard modules, observe Docker/private data, spawn/signal, clean, approve or release Q.

Reconcile reconstructs strict raw tool events, full supervisor/envelope/claim/authority/source/log/target proofs. Six fixed public logs may be empty through a dedicated strict reader; generic nonempty source/private reads are unchanged. It checks normal recorder terminal/known nested outcome, all historical stamps<=U, both old-operation bounds U-M0 and B-B0<=90/600/180, bracket width<=100ms and common clock-offset intersection. Public verification/fsync consumes metadata30, never extends the operation. Outer schema stays unchanged, M0 is explicitly a lower-bound start, U an independent terminal upper bound. Marker metadata_end_ns is sampled before its durable commit, not claimed as interpreter/tool terminal. Final checks, deadline.finish and root's actual reconcile exit remain mandatory.

Outer is written first, terminal marker last, with retained input rechecks around each. Existing/partial/orphan files are never overwritten or retried. Markers have all R3 fields, including full raw/supervisor/result/envelope/claim/admission/invoker proofs and separate timing. Known failure is evidence only. preprobe incomplete-or-unknown-retain remains unknown; complete postflight incomplete/1 may be known-failure. preparation requires the corresponding preprobe known-success and original<=60s age; launch adds exact preprobe_terminal full Proof; launch_binding and outer_gate reconstruct the chain before private/import/guard. The operation marker does not prove reconcile's own terminal. A late final flush can leave a marker while reconcile fails; root must reject it regardless of appearance.

### Frozen future tool protocol

The following is proposed caller text, **not executed**. Actual bootstrap/binary/parent/UID1000 trust, root quiescence, source/admission identity, fixed clocks, resources, writer/scene/Q and eligibility remain separate gates. `yield_time_ms` and `wall_time_seconds` are not deadlines/lifetime. No provider FD or signature is invented. Root is the external authority for complete awaited tool history; same-UID hostile writers are excluded by continuous quiescence, not proven by metadata.

Use functions.exec with the common prelude below pasted into each relevant cell. MODE is frozen to one reviewed literal per operation; its five siblings are capture, capture-postflight, continue-preprobe, continue, continue-postflight. No arbitrary command/argument/environment. Store keys retain each phase across cells; no automatic relaunch/cancellation. Each poll is an individual empty45s wait, at most31 polls/32 events per chain. Preserve every request/return immediately, including unsuccessful validation. Transport uncertainty retains available memory/transcript and stops without valid raw authority. No truncation/overflow may be trimmed into success.

```javascript
const MODE='capture-preprobe';
const W='/home/postedism/Desktop/Warden';
const P='controller-cache-continuation-v1-20261025-';
const PUB=W+'/docs/evidence/task-6/';
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
const key=phase=>P+MODE+'-'+phase;
function bytes(s){let n=0;for(const c of s){const v=c.codePointAt(0);n+=v<128?1:v<2048?2:v<65536?3:4;}return n;}
function request(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,tty:false,
 yield_time_ms:1000,max_output_tokens:max,sandbox_permissions:'require_escalated',justification:WHY};}
function operation(action){return request('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py '+action+' '+MODE);}
function response(r,max){
 const allowed=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
 if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!allowed.includes(k))||
 typeof r.output!=='string'||bytes(r.output)>65536||typeof r.wall_time_seconds!=='number'||
 !Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('unknown response');
 if('chunk_id'in r&&(typeof r.chunk_id!=='string'||r.chunk_id.length<1||r.chunk_id.length>128))throw Error('chunk');
 if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||r.original_token_count<0||r.original_token_count>max))throw Error('truncation');
 if('exit_code'in r){if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('unknown terminal');return 'terminal';}
 if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('unknown session');return 'running';
}
async function first(phase,req){
 if(load(key(phase))!==undefined)throw Error('existing no retry');
 const s={request:req,events:[],state:'awaiting'};store(key(phase),s);
 try{const r=await tools.exec_command(req);s.events.push({seq:0,tool:'exec_command',request:req,response:r});
 store(key(phase),s);s.state=response(r,req.max_output_tokens);store(key(phase),s);}
 catch(e){s.state='unknown';store(key(phase),s);throw e;}
}
async function poll(phase){
 const s=load(key(phase));if(!s||s.state!=='running'||s.events.length>=32)throw Error('stop');
 const id=s.events[0].response.session_id,last=s.events[s.events.length-1].response;
 if(last.session_id!==id||'exit_code'in last)throw Error('changed session');
 const req={session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000};
 try{const r=await tools.write_stdin(req);s.events.push({seq:s.events.length,tool:'write_stdin',request:req,response:r});
 store(key(phase),s);s.state=response(r,2000);if(s.state==='running'&&r.session_id!==id)throw Error('changed session');store(key(phase),s);}
 catch(e){s.state='unknown';store(key(phase),s);throw e;}
}
function terminal(phase,zero=false){const s=load(key(phase));if(!s||s.state!=='terminal'||
 (zero&&s.events[s.events.length-1].response.exit_code!==0))throw Error('terminal required');return s;}
async function add(suffix,body){
 if(!body.endsWith('\n')||bytes(body)>65536)throw Error('record overflow');
 const result=await tools.apply_patch('*** Begin Patch\n*** Add File: '+PUB+P+MODE+suffix+'\n'+
 body.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch');
 store(key('patch'+suffix),result);text(result);
}
```

Cell1: `await first('supervise',operation('supervise'));`. Later cells only if its stored state is running: `await poll('supervise');`. Immediate terminal has one event; running chain must end in integer0/1 with no session echo. Unknown/124/forced/ambiguous exits stop. The exact request has require_escalated/WHY and no prefix_rule; ordinaryUID1000 must still be verified independently. Approval rejection, if any, must be preserved explicitly rather than replaced by another profile.

After known supervise terminal, use the fixed five-public-record collector below. Its body is assigned to `readerBody` as an exact literal in a separate root cell (including the frozen MODE literal). Then `await first('reader',request("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000));`. Reader polls use the common exact45s/2000 shape and their own session/transcript. Reader's alarm5 after minimal imports/CPU2/AS128MiB/FSIZE1MiB is metadata containment, not a whole-startup/physical5s guarantee; every delay still counts before U.

```python
import os,stat,json,hashlib,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):resource.setrlimit(k,(n,n))
M='capture-preprobe';S=M.split('-')[0]
W='/home/postedism/Desktop/Warden';D='docs/evidence/task-6/'
P='controller-cache-continuation-v1-20261025-'
I='controller-cache-continuation-outer-invoker-20261025.py'
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
held=[]
def read(name):
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for part in (W+'/'+D+name).split('/')[1:-1]:
  g=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=g
  s=os.fstat(f);assert s.st_uid in (0,1000) and not s.st_mode&0o022
 h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=f);s=os.fstat(h)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and 0<s.st_size<=65536
 b=b''
 while len(b)<=65536:
  c=os.read(h,65537-len(b))
  if not c:break
  b+=c
 assert len(b)==s.st_size
 held.append((f,h,name,meta(s)))
 return b,{'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':meta(s)}
out={}
for k,n in [('admission',P+S+'-admission.json'),('invoker',I),('envelope',P+M+'-deadline.json'),('claim',P+M+'-deadline-accepted.json'),('supervisor',P+M+'-supervisor.json')]:
 b,out[k]=read(n)
 if k=='envelope':
  v=json.loads(b)
  for field in ('source_commit','source_manifest_sha256','clock_identity'):out[field]=v[field]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
for suffix in ('-root-tool.json','-root-proof-reader-tool.json','-root-reconcile-tool.json'):
 try:os.stat(P+M+suffix,dir_fd=held[0][0],follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('existing root transcript')
print(json.dumps(out,separators=(',',':')),flush=True)
```

This collector reads exactly five public bodies, holds their FDs and rechecks metadata; the added absence checks read no sixth body. It is caller text, not an unchecked project import, product action or second loader. The reconciler independently re-reads/validates all proofs/source bindings. Root maintains fresh absence/quiescence through each structured AddFile. AddFile is workflow exclusivity, not O_EXCL. Any unexpected existing/partial file, uncertain patch result, overflow or provider error stops without overwrite/delete/retry. Root inspects the actual apply_patch result before issuing the next cell; no invented success field or automatic action follows.

**Lossless proof handling:** metadata contains nanosecond integers above JS safe precision. Do not JSON.parse→JSON.stringify proof numbers or reconstruct clocks from a JS preview. Retain collector output text verbatim; parse only to reject malformed structure, and splice its exact object members into the raw record. Tool events' output strings remain exact strings. API session/exit/token fields require Number.isSafeInteger; generated seq/index are bounded0..31 and therefore safe. Python reconciliation performs the strict integer/proof comparison. No extra cover was run for this caller-text correction.

```javascript
const reader=terminal('reader',true), sup=terminal('supervise');
const proofText=reader.events.map(e=>e.response.output).join('');
if(bytes(proofText)>16384||!proofText.startsWith('{')||!proofText.endsWith('}\n'))throw Error('collector output');
const preview=JSON.parse(proofText); // structural view only; never serialize its numeric proofs
const fields=['admission','invoker','envelope','claim','supervisor','source_commit','source_manifest_sha256','clock_identity'];
if(Object.keys(preview).length!==8||fields.some(k=>!(k in preview)))throw Error('collector keys');
const head=JSON.stringify({version:1,origin:'root-controller-actual-tool',mode:MODE,stage:MODE.split('-')[0]});
const tail=JSON.stringify({events:sup.events,terminal_event_index:sup.events.length-1,
 root_assertion:'awaited-terminal-before-record-before-reconcile'});
const body=head.slice(0,-1)+','+proofText.slice(1,-2)+','+tail.slice(1)+'\n';
store(key('raw-body'),body);
const supplemental={version:1,producer:'root-controller-actual-tool',mode:MODE,phase:'proof-reader',
 budget:{alarm_after_import_seconds:5,cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,
 whole_startup_bound_proven:false,max_events:32,record_bytes:65536},
 events:reader.events,terminal_event_index:reader.events.length-1};
await add('-root-proof-reader-tool.json',JSON.stringify(supplemental)+'\n');
// In the NEXT cell after known successful patch, common prelude then:
// await add('-root-tool.json',load(key('raw-body')));
```

The raw keys/types exactly match the source R1 validator. Its size includes newline and every event. Root's assertion is external causal trust, not source authentication. A malformed record is retained and refused, never repaired into a new attempt. After both known patch completions, separate cell: `await first('reconcile',operation('reconcile'));`, then its own empty45s polls. No operation target runs again. A reader/patch/scheduling delay can make U too late and cause refusal; do not subtract it or extend90/600/180.

Under the controller's A resolution, matching marker proof means the reviewed writer's sole normal terminal output associated with the exact reconcile MODE request; it is **not** an independent post-exit disk reread. Require actual reconcile exit0, strict sole canonical stdout and retain its full raw chain. Inspect proof decimals losslessly; there is no sixth public read/helper. The next separately authorized consumer re-reads and validates the on-disk marker and entire chain under continuous quiescence. Any mismatch/extra stdout/late/unknown exit stops.

```javascript
const r=terminal('reconcile',true), output=r.events.map(e=>e.response.output).join('');
const match=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[([0-9]+(?:,[0-9]+){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(output);
if(!match)throw Error('sole fixed marker output required');
const n=BigInt(match[2]),m=match[3].split(',').map(v=>BigInt(v));
if(n>16384n||m[0]<=0n||m[1]<=0n||m[2]!==1000n||m[3]!==1000n||m[4]!==33152n||m[5]!==1n||m[6]!==n)throw Error('marker proof shape');
store(key('normal-marker-proof-json'),match[1]); // exact decimal bytes, no numeric conversion
const transcript={version:1,producer:'root-controller-actual-tool',mode:MODE,phase:'reconcile',
 budget:{wall_seconds:30,cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,
 whole_physical_stop_proven:false,max_events:32,record_bytes:65536},
 events:r.events,terminal_event_index:r.events.length-1,marker_proof_json:match[1]};
await add('-root-reconcile-tool.json',JSON.stringify(transcript)+'\n');
```

After known transcript write, root may separately consider the next action; this script grants none. Supplemental reader/reconcile records are external evidence, not marker authority or a recursive sampler: six each<=64KiB add786432B logical within existing96MB reserve/ordinaryR. Original six raw+six marker bound480KiB remains separate. Their own writing/scheduling delays after U do not retroactively change the accepted old terminal upper bound, and can stale a preprobe before launch. Source rechecks original<=60s freshness. Current quiescence, complete actual resource/disk/resident guards and all operational eligibility remain unmeasured/unadmitted here.

The source-only tests include one preserved failed GREEN that accidentally reached bounded own-clock `/proc`/namespace reads due to a fixture mock ending early; it is not described as entirely fake. Persistent fail-closed sentinels and fresh fake-deadline consumers fixed that fixture, subsequent generated tests and unique frozen177-case cover passed. See the full substage report for exact history; source PASS is not actual terminal/material/cache/PG eligibility or Task6 completion.

## Original Task6 round4 terminal reconciliation source correction — 2026-10-25

Append-only correction after preserving the full58113-byte plan prefix SHA256 917294228a266353c105294ee13c68ada4c9952a7f3fe56ad4f91dab1efeb745, including the unchanged17227-byte exact-caller appendix. Dispatch/source-evidence BASE is c2436684c511bf2ae92982fb8141b1b7d0c41ee9; the scoped re-review FIX_BASE remains bb7224cdc9ce4106b39c3a7ddad514d9e5ac6175, the previous independent review's HEAD. Original Task6 round4/5, all actual gates and Q5GB remain open.

Source candidate 2c911c8ca2b8148f47380bab53c732ed0bc17f62 changes only the two existing docs paths below. Canonical150 names/bodies, bootstrap/observer/testcontrol, product8/capture/maintenance/None pins/shared recovery/guard/charges/crypto are unchanged from dispatch. history retains outer_gate's operation_success and requires the normal postflight/root/recorder exit classification to match. validate_target already binds full postflight state to recorder exit. reconcile rechecks all retained Records and sources after flushed marker-Proof stdout within the same metadata deadline, before return0.

| Source | Bytes | SHA256 |
|---|---:|---|
| docs/evidence/task-6/controller-cache-continuation-outer-invoker-20261025.py | 26016 | bd10c55befc5b29e28bed7844a01a28ab843a22d79cc5e25c9761402ac379563 |
| docs/evidence/task-6/test_controller_cache_continuation_invoker_20261025.py | 57668 | fee4ef5b707539994cbd0ab2191c0ec57fbe19d8e4f71bf5ed66b847bf97efa0 |

No exact command/request/poll/collector/marker schema, source-name list, resource policy or call order is changed. The previous source/invoker hashes describe their historic version; this append identifies the new source candidate for separate source review/freeze. Any later actual admission must bind the separately authorized frozen source identity and current invoker proof; this appendix grants none. The caller-parser M1 and three older Minors remain deferred; the caller text is preserved verbatim.

Generated evidence: fix4-red-01 has7 methods/11 expected assertion failures/0errors/0skips; focused green-01 has12PASS; unique frozen cover-01 has74PASS,0failures/errors/skips. Cover runs only the dedicated invoker fixture file (5 InvokerTests,10 ClockTests,25 GeneratedInvokerTests,34 ReconcileTests), excluding imported111 controller methods. All complete runs have equal prospective150+2 pre/post maps and only changed docs snapshots against dispatch. See controller-terminal-reconcile-fix4-artifact-sizes.json and the appended substage report. No actual caller, public authority record, private operation, host/proc/socket/peer/CLI/native child/cloud/resource/publication action or new approval follows.

## Four-GET material SOURCE/mock freeze and exact future ONE caller — 2026-10-25

This append preserves the complete60832-byte plan prefix SHA256 8aa73aeb2bb2a5156cb4b0f53c726985322fb653ec5ce4e6336a2816ac26df99. Immutable source/evidence dispatchBASE b5780a09cb3c0a81b37207dca31ad5c2103c4395; SOURCE 2f0bb21f7cad5eaf0d5f1a7d05cc058138eb8460. Root M1–M8 and the separate pure-mock fixture clarification govern this source stage. Original Task6 round4/5, four deferred Minors and all actual gates remain open. The following caller is frozen text for separate review, never actual authority or an executed actual caller.

Only the five existing source paths changed. All150 canonical names remain;147 canonical bodies equal BASE. Product8/capture/maintenance/Nonepins/shared recovery/guard/charges/crypto remain unchanged. MaterialContext shares exact source/heldRecord/invoker checks while exposing only fixed public material records. Existing Controller six-mode policy/admission semantics are preserved. The two material literal entries use the same bootstrap and independent metadata policy; project-only GET scope never imports operational recovery. Successful receipt only; failures/late/partial/unknown states refuse normal reconciliation. Material reconciliation independently binds the original true-terminal upper bound to30s, with no operation envelope, automatic successor or extra allowance.

| Source | Bytes | SHA256 |
|---|---:|---|
| scripts/identity_cache_control.py | 5684 | b0d50167c80a66b3f6e1858ae4a5ff97f24dd74f79898236ecbd1c6f1bff6457 |
| scripts/identity_cache_observe.py | 76030 | 85faa1129c1772df6368f22cc69140ece57aaaadcbf1e3fe91e5dd68aad41299 |
| scripts/test_identity_cache_control.py | 90732 | 64216df2d3a2a6a174e8a6439a97fd222222a535226f428f489948100ae67623 |
| docs/evidence/task-6/controller-cache-continuation-outer-invoker-20261025.py | 37144 | 13d302f6d1a4e04dda727c6c855410585cfea889b9761bd6d2dae716bfb25541 |
| docs/evidence/task-6/test_controller_cache_continuation_invoker_20261025.py | 77993 | 69f77e01060ae9eea4888278578150d27fb9dbbece039524197ffb5e544ceb77 |

Shared birth-origin policy remains wall30/CPU5/AS134217728/FSIZE1048576/output65536, phase ends10IO/15close/20return/25receipt/30independent terminal. GET outputs summarized for the receipt retain compatible bounds0..1048576; output65536 bounds the public tool-output/transcript channel. Metadata reconciliation has its own30s policy and never extends the original30s. M6 list selected-ID hashes bind deterministic reviewed producer selection to inspect; no claim to recover membership/order cryptographically from output hashes. Deadline helper brackets the complete Record/source batch, preserving earlier semantics rather than adding a per-Record deadline check. Post-flush retained Record/source checks remain present for both terminal families.

Frozen ONE caller: 10842 bytes, SHA256 58095573ef0f31c78429d9dd5169ced6ea58c5c23f04526b651f73b1eb8b73b1. Embedded three-proof collector body: 1855 bytes, SHA256 a9399f32eae83ada51191bfc36d8d70de914041c93f6b4ef4011a652e522bee3. Its only reads remain admission/invoker/receipt plus three output-absence checks; it is not run here. Compared with the accepted proposal, exactJSON also rejects array-owned extra properties to prevent loss of invalid actual values, and the patch-profile comment records root's existing calibration. No old caller appendix or deferred M1 is edited.

Future actual admission must separately bind the reviewed SOURCE/current invoker/source150, root-held absence/quiescence, trusted UID1000/native binary/ancestors/clock/limits/resource profile and exact patch calibration. Only root may establish the real one-shot-admitted interlock. This script never establishes it; no implementation-time actual admission/raw/interlock was created. Normal apply_patch response must be exactly an ordinary Object.prototype object with zero own keys, calibrated as{}; all other returns/throws stop. Workflow AddFile exclusivity is not O_EXCL/durability/readback. Root retains the actual outer isolate and request/return history across yields, never restarts it.

The normal records remain admission/root-tool/root-proof-reader-tool/root-reconcile-tool<=65536 each and receipt/terminal<=16384 each,294912 logical bytes. Optional diagnostic-tool<=4194304 yields4489216 total, all within existing96MB public reserve/ordinaryR and no new charge. Failure envelope keys exactly version,mode,authority,state,reason,chains,patch_events,Q_released; version1/mode material-four-get/authorityfalse/state unknown-no-authority/Qfalse. Chains get/reader/reconcile are null or1..32 ordered actual events; normal events require response, failure-only pending may appear only last. patch_events is required, ordered,<=4, and only its last may be pending. Reasons are the fixed script enum. Original malformed values remain unchanged or stay in the outer record when exact JSON cannot represent them; no trimming, synthetic response, fabricated C/proof or normal marker. Destinations are consumed before awaits, and at most one failure-save is attempted. Its own final actual return remains only in the outer/store record, never recursively rewritten. Root still requires normal reconcile exit0 with sole canonical lossless marker proof, and separately authorizes any successor.

Complete frozen future caller (do not run without that separate actual gate):

```js
// @exec: {"yield_time_ms": 30000, "max_output_tokens": 2000}
const W='/home/postedism/Desktop/Warden';
const D=W+'/docs/evidence/task-6/';
const P='controller-cache-continuation-v1-20261025-material-';
const K=s=>P+s;
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
if(load(K('one-shot-admitted'))!==true||load(K('one-shot'))!==undefined)
  throw Error('not admitted or already attempted');
// Root's prior absence checks cover these outputs, receipt and terminal;
// admission/invoker are existing verified inputs. No absence is inferred here.
const free=new Set(['root-tool.json','root-proof-reader-tool.json',
  'root-reconcile-tool.json','diagnostic-tool.json']);
const S={state:'active',chains:{get:null,reader:null,reconcile:null},patch_events:[]};
function persist(){store(K('one-shot'),S);}
persist();
function bytes(s){let n=0;for(const c of s){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function req(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,
  tty:false,yield_time_ms:1000,max_output_tokens:max,
  sandbox_permissions:'require_escalated',justification:WHY};}
const getRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-four-get');
const reconcileRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-reconcile');
const readerBody=String.raw`import os,stat,json,hashlib,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):resource.setrlimit(k,(n,n))
D='/home/postedism/Desktop/Warden/docs/evidence/task-6/';P='controller-cache-continuation-v1-20261025-material-'
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
held=[];out={}
for key,name in [('admission',P+'admission.json'),('invoker','controller-cache-continuation-outer-invoker-20261025.py'),('receipt',P+'receipt.json')]:
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for part in D.strip('/').split('/'):
  g=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=g
  s=os.fstat(f);assert s.st_uid in (0,1000) and not s.st_mode&0o022
 h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=f);s=os.fstat(h);cap=16384 if key=='receipt' else 65536
 assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and 0<s.st_size<=cap
 b=b''
 while len(b)<=cap:
  c=os.read(h,cap+1-len(b))
  if not c:break
  b+=c
 assert len(b)==s.st_size
 held.append((f,h,name,meta(s)));out[key]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':meta(s)}
 if key=='receipt':
  v=json.loads(b)
  for k in ('source_commit','source_manifest_sha256','clock_identity'):out[k]=v[k]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
for n in ('root-tool.json','root-proof-reader-tool.json','root-reconcile-tool.json'):
 try:os.stat(P+n,dir_fd=f,follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('existing')
print(json.dumps(out,separators=(',',':')),flush=True)`;
const readerRequest=req("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000);
function response(r,max){
  const keys=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
  if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!keys.includes(k))||
     typeof r.output!=='string'||bytes(r.output)>65536||
     !Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');
  if('chunk_id'in r&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');
  if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||
     r.original_token_count<0||r.original_token_count>max))throw Error('truncated');
  if('exit_code'in r){
    if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('exit');
    return 'terminal';
  }
  if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');
  return 'running';
}
let reason='get-unknown';
async function nativeCall(p,tool,q){
  const events=S.chains[p];
  if(events.length>=32)throw Error('event bound');
  const e={seq:events.length,tool,request:q};
  events.push(e);persist(); // outbound request survives a rejected Promise
  const r=await(tool==='exec_command'?tools.exec_command(q):tools.write_stdin(q));
  e.response=r;persist(); // actual returned value, even if subsequently refused
  return response(r,q.max_output_tokens);
}
async function run(p,q){
  if(S.chains[p]!==null)throw Error('no retry');
  S.chains[p]=[];reason=p+'-unknown';persist();
  let state=await nativeCall(p,'exec_command',q);
  const events=S.chains[p];
  const id=state==='running'?events[0].response.session_id:undefined;
  while(state==='running'){
    if(events.length>=32||events.at(-1).response.session_id!==id)throw Error('poll bound/session');
    state=await nativeCall(p,'write_stdin',{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000});
    if(state==='running'&&events.at(-1).response.session_id!==id)throw Error('session changed');
  }
  if(events.some(e=>!Object.hasOwn(e,'response')))throw Error('incomplete normal chain');
  if(events.at(-1).response.exit_code!==0){reason=p+'-nonzero';throw Error('nonzero');}
  return events;
}
async function checkedPatch(suffix,body,cap){
  if(!free.has(suffix)||!body.endsWith('\n')||bytes(body)>cap)throw Error('patch gate');
  const request='*** Begin Patch\n*** Add File: '+D+P+suffix+'\n'+
    body.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch';
  free.delete(suffix); // consume even if the following call throws
  const e={seq:S.patch_events.length,tool:'apply_patch',request};
  S.patch_events.push(e);persist();
  const r=await tools.apply_patch(request);
  e.response=r;persist();
  // M8 ordinary-object/empty-key normal return profile was calibrated by root; no disk readback.
  notify({patch_seq:e.seq,actual_return:r});
  if(r===null||typeof r!=='object'||Array.isArray(r)||
     Object.getPrototypeOf(r)!==Object.prototype||Reflect.ownKeys(r).length!==0)
    throw Error('unexpected patch return');
}
// Refuse lossy JSON serialization of available tool data. Never strip fields.
function exactJSON(v){
  function check(x){
    if(x===null||typeof x==='string'||typeof x==='boolean')return;
    if(typeof x==='number'){if(!Number.isFinite(x))throw Error('nonfinite');return;}
    if(Array.isArray(x)){if(Reflect.ownKeys(x).length!==x.length+1)throw Error('array properties');for(let i=0;i<x.length;i++){if(!Object.hasOwn(x,i))throw Error('hole');check(x[i]);}return;}
    if(typeof x!=='object'||Object.getPrototypeOf(x)!==Object.prototype||
       Reflect.ownKeys(x).length!==Object.keys(x).length)throw Error('not plain JSON');
    for(const k of Object.keys(x))check(x[k]);
  }
  check(v);return JSON.stringify(v);
}
function readerTranscript(events){return {version:1,mode:'material-four-get',phase:'reader',
  events,terminal_event_index:events.length-1,budget:{alarm_after_import_seconds:5,
  cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
function reconcileTranscript(events,proof){return {version:1,mode:'material-four-get',phase:'reconcile',
  events,terminal_event_index:events.length-1,marker_proof_json:proof,budget:{wall_seconds:30,
  cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
async function failureSave(){
  const reasons=['get-nonzero','get-unknown','receipt-unavailable-or-invalid',
    'reader-nonzero','reader-unknown','reconcile-nonzero','reconcile-unknown',
    'invalid-marker','recording-failure'];
  if(!reasons.includes(reason))throw Error('failure reason');
  const body=exactJSON({version:1,mode:'material-four-get',authority:false,
    state:'unknown-no-authority',reason,chains:S.chains,
    patch_events:S.patch_events,Q_released:false})+'\n';
  const small=free.has('root-proof-reader-tool.json')&&bytes(body)<=65536;
  const suffix=small?'root-proof-reader-tool.json':'diagnostic-tool.json';
  const cap=small?65536:4194304;
  if(!free.has(suffix)||bytes(body)>cap)throw Error('retain outer record only');
  await checkedPatch(suffix,body,cap); // exactly one failure-save attempt
}
try{
  const es=await run('get',getRequest);
  const rs=await run('reader',readerRequest);
  reason='receipt-unavailable-or-invalid';
  const t=rs.map(e=>e.response.output).join('');
  if(bytes(t)>16384||!t.startsWith('{')||!t.endsWith('}\n'))throw Error('collector output');
  const p=JSON.parse(t); // structural preview only; never serialize p
  const keys=['admission','invoker','receipt','source_commit','source_manifest_sha256','clock_identity'];
  if(p===null||typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==6||
     keys.some(k=>!Object.hasOwn(p,k)))throw Error('collector keys');
  const h=exactJSON({version:1,mode:'material-four-get',origin:'root-controller-actual-tool'});
  const z=exactJSON({events:es,terminal_event_index:es.length-1,
    root_assertion:'awaited-terminal-before-record-before-reconcile'});
  const raw=h.slice(0,-1)+','+t.slice(1,-2)+','+z.slice(1)+'\n';
  // Proof/clock JSON member text is spliced unchanged; final Python validates it.
  reason='recording-failure';
  await checkedPatch('root-proof-reader-tool.json',exactJSON(readerTranscript(rs))+'\n',65536);
  await checkedPatch('root-tool.json',raw,65536);
  const re=await run('reconcile',reconcileRequest);
  reason='invalid-marker';
  const out=re.map(e=>e.response.output).join('');
  const m=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(out);
  if(!m)throw Error('sole canonical marker');
  const n=BigInt(m[2]),v=m[3].split(',').map(BigInt);
  if(n>16384n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||
     v[4]!==33152n||v[5]!==1n||v[6]!==n)throw Error('marker proof');
  reason='recording-failure';
  await checkedPatch('root-reconcile-tool.json',exactJSON(reconcileTranscript(re,m[1]))+'\n',65536);
  S.state='normal-chain-recorded';persist();
  text({state:S.state,authority:false,Q_released:false});
}catch(error){
  S.state='stopped-unknown';persist();
  try{await failureSave();}
  catch(retentionError){S.state='stopped-unknown-outer-retention-only';persist();}
  text({state:S.state,reason,authority:false,Q_released:false});
}
```

Generated validation:18 new Python methods focused GREEN; single frozen affected cover203PASS (111 controller+74 prior dedicated+18 new), plus18 finite isolated JS cases using this exact candidate. JS caller tools/store/load/notify/text are all parameter-shadowed local fakes; no real nested tool/interlock/FS/network/proc/clock/service. The JS isolate is not evidence for nativeCPU/AS/45s containment. Full prospective150+2 and candidate/fixture pre/post hashes agree; source/mock report and separate controller-four-get-material-artifact-sizes.json record all failures, commands, outputs and limits. No actual API/peer/clock/durability/headroom/causality compatibility is claimed. Task6/Goal OPEN; scene22/Q5000000000 releasedfalse and original Task3/4/Azure/host/publication caps unchanged.


## Original Task6 fix5/5: sole replacement material caller

This complete caller explicitly supersedes every earlier material caller in this plan. Earlier text remains historical. Actual admission/interlocks/data remain absent and root-owned; generated fixture PASS is not actual authority. F1–F6 and the unchanged original limits apply. Unsupported native values are stored first and refused before property reads or disk serialization; no getter/hook/negative-zero normalization. Material native commands and collector body remain unchanged. The exact replacement candidate below is byte-identical to controller-caller-integrity-fix5-material-candidate.js.

```javascript
// @exec: {"yield_time_ms": 30000, "max_output_tokens": 2000}
const W='/home/postedism/Desktop/Warden';
const D=W+'/docs/evidence/task-6/';
const P='controller-cache-continuation-v1-20261025-material-';
const K=s=>P+s;
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
if(load(K('one-shot-admitted'))!==true||load(K('one-shot'))!==undefined)
  throw Error('not admitted or already attempted');
// Root's prior absence checks cover these outputs, receipt and terminal;
// admission/invoker are existing verified inputs. No absence is inferred here.
const free=new Set(['root-tool.json','root-proof-reader-tool.json',
  'root-reconcile-tool.json','diagnostic-tool.json']);
const S={state:'active',chains:{get:null,reader:null,reconcile:null},patch_events:[]};
function persist(){store(K('one-shot'),S);}
persist();
function bytes(s){let n=0;for(const c of s){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function req(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,
  tty:false,yield_time_ms:1000,max_output_tokens:max,
  sandbox_permissions:'require_escalated',justification:WHY};}
const getRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-four-get');
const reconcileRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-reconcile');
const readerBody=String.raw`import os,stat,json,hashlib,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):resource.setrlimit(k,(n,n))
D='/home/postedism/Desktop/Warden/docs/evidence/task-6/';P='controller-cache-continuation-v1-20261025-material-'
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
held=[];out={}
for key,name in [('admission',P+'admission.json'),('invoker','controller-cache-continuation-outer-invoker-20261025.py'),('receipt',P+'receipt.json')]:
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for part in D.strip('/').split('/'):
  g=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=g
  s=os.fstat(f);assert s.st_uid in (0,1000) and not s.st_mode&0o022
 h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=f);s=os.fstat(h);cap=16384 if key=='receipt' else 65536
 assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and 0<s.st_size<=cap
 b=b''
 while len(b)<=cap:
  c=os.read(h,cap+1-len(b))
  if not c:break
  b+=c
 assert len(b)==s.st_size
 held.append((f,h,name,meta(s)));out[key]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':meta(s)}
 if key=='receipt':
  v=json.loads(b)
  for k in ('source_commit','source_manifest_sha256','clock_identity'):out[k]=v[k]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
for n in ('root-tool.json','root-proof-reader-tool.json','root-reconcile-tool.json'):
 try:os.stat(P+n,dir_fd=f,follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('existing')
print(json.dumps(out,separators=(',',':')),flush=True)`;
const readerRequest=req("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000);
function response(r,max){
  exactJSON(r); // Retain first; refuse unsupported values before reading fields.
  const keys=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
  if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!keys.includes(k))||
     typeof r.output!=='string'||bytes(r.output)>65536||
     !Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');
  if('chunk_id'in r&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');
  if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||
     r.original_token_count<0||r.original_token_count>max))throw Error('truncated');
  if('exit_code'in r){
    if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('exit');
    return 'terminal';
  }
  if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');
  return 'running';
}
let reason='get-unknown';
async function nativeCall(p,tool,q){
  const events=S.chains[p];
  if(events.length>=32)throw Error('event bound');
  const e={seq:events.length,tool,request:q};
  events.push(e);persist(); // outbound request survives a rejected Promise
  const r=await(tool==='exec_command'?tools.exec_command(q):tools.write_stdin(q));
  e.response=r;persist(); // actual returned value, even if subsequently refused
  return response(r,q.max_output_tokens);
}
async function run(p,q){
  if(S.chains[p]!==null)throw Error('no retry');
  S.chains[p]=[];reason=p+'-unknown';persist();
  let state=await nativeCall(p,'exec_command',q);
  const events=S.chains[p];
  const id=state==='running'?events[0].response.session_id:undefined;
  while(state==='running'){
    if(events.length>=32||events.at(-1).response.session_id!==id)throw Error('poll bound/session');
    state=await nativeCall(p,'write_stdin',{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000});
    if(state==='running'&&events.at(-1).response.session_id!==id)throw Error('session changed');
  }
  if(events.some(e=>!Object.hasOwn(e,'response')))throw Error('incomplete normal chain');
  if(events.at(-1).response.exit_code!==0){reason=p+'-nonzero';throw Error('nonzero');}
  return events;
}
async function checkedPatch(suffix,body,cap){
  if(!free.has(suffix)||!body.endsWith('\n')||bytes(body)>cap)throw Error('patch gate');
  const request='*** Begin Patch\n*** Add File: '+D+P+suffix+'\n'+
    body.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch';
  free.delete(suffix); // consume even if the following call throws
  const e={seq:S.patch_events.length,tool:'apply_patch',request};
  S.patch_events.push(e);persist();
  const r=await tools.apply_patch(request);
  e.response=r;persist();
  // M8 ordinary-object/empty-key normal return profile was calibrated by root; no disk readback.
  notify({patch_seq:e.seq,actual_return:r});
  if(r===null||typeof r!=='object'||Array.isArray(r)||
     Object.getPrototypeOf(r)!==Object.prototype||Reflect.ownKeys(r).length!==0)
    throw Error('unexpected patch return');
}
// Refuse lossy JSON serialization of available tool data. Never strip fields.
function exactJSON(value){
 const seen=new Set();
 function check(v){
  if(v===null||typeof v==='string'||typeof v==='boolean')return;
  if(typeof v==='number'){
   if(!Number.isFinite(v)||Object.is(v,-0))throw Error('unrepresentable number');return;
  }
  if(typeof v!=='object'||seen.has(v))throw Error('unserializable');
  const array=Array.isArray(v),proto=Object.getPrototypeOf(v);
  if(proto!==(array?Array.prototype:Object.prototype))throw Error('nonplain');
  for(let p=v;p!==null;p=Object.getPrototypeOf(p))
   if(Object.getOwnPropertyDescriptor(p,'toJSON'))throw Error('serialization hook');
  seen.add(v);
  const keys=Reflect.ownKeys(v);
  if(array){
   const n=Object.getOwnPropertyDescriptor(v,'length').value;
   if(keys.length!==n+1)throw Error('array fields');
   for(let i=0;i<n;i++){
    const d=Object.getOwnPropertyDescriptor(v,String(i));
    if(!d||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('array data');
    check(d.value);
   }
  }else{
   for(const k of keys){
    const d=Object.getOwnPropertyDescriptor(v,k);
    if(typeof k!=='string'||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('object data');
    check(d.value);
   }
  }
  seen.delete(v);
 }
 check(value);return JSON.stringify(value);
}
function readerTranscript(events){return {version:1,mode:'material-four-get',phase:'reader',
  events,terminal_event_index:events.length-1,budget:{alarm_after_import_seconds:5,
  cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
function reconcileTranscript(events,proof){return {version:1,mode:'material-four-get',phase:'reconcile',
  events,terminal_event_index:events.length-1,marker_proof_json:proof,budget:{wall_seconds:30,
  cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
async function failureSave(){
  const reasons=['get-nonzero','get-unknown','receipt-unavailable-or-invalid',
    'reader-nonzero','reader-unknown','reconcile-nonzero','reconcile-unknown',
    'invalid-marker','recording-failure'];
  if(!reasons.includes(reason))throw Error('failure reason');
  const body=exactJSON({version:1,mode:'material-four-get',authority:false,
    state:'unknown-no-authority',reason,chains:S.chains,
    patch_events:S.patch_events,Q_released:false})+'\n';
  const small=free.has('root-proof-reader-tool.json')&&bytes(body)<=65536;
  const suffix=small?'root-proof-reader-tool.json':'diagnostic-tool.json';
  const cap=small?65536:4194304;
  if(!free.has(suffix)||bytes(body)>cap)throw Error('retain outer record only');
  await checkedPatch(suffix,body,cap); // exactly one failure-save attempt
}
try{
  const es=await run('get',getRequest);
  const rs=await run('reader',readerRequest);
  reason='receipt-unavailable-or-invalid';
  const t=rs.map(e=>e.response.output).join('');
  if(bytes(t)>16384||!t.startsWith('{')||!t.endsWith('}\n'))throw Error('collector output');
  const p=JSON.parse(t); // structural preview only; never serialize p
  const keys=['admission','invoker','receipt','source_commit','source_manifest_sha256','clock_identity'];
  if(p===null||typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==6||
     keys.some(k=>!Object.hasOwn(p,k)))throw Error('collector keys');
  const h=exactJSON({version:1,mode:'material-four-get',origin:'root-controller-actual-tool'});
  const z=exactJSON({events:es,terminal_event_index:es.length-1,
    root_assertion:'awaited-terminal-before-record-before-reconcile'});
  const raw=h.slice(0,-1)+','+t.slice(1,-2)+','+z.slice(1)+'\n';
  // Proof/clock JSON member text is spliced unchanged; final Python validates it.
  reason='recording-failure';
  await checkedPatch('root-proof-reader-tool.json',exactJSON(readerTranscript(rs))+'\n',65536);
  await checkedPatch('root-tool.json',raw,65536);
  const re=await run('reconcile',reconcileRequest);
  reason='invalid-marker';
  const out=re.map(e=>e.response.output).join('');
  const m=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(out);
  if(!m)throw Error('sole canonical marker');
  const n=BigInt(m[2]),v=m[3].split(',').map(BigInt);
  if(n>16384n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||
     v[4]!==33152n||v[5]!==1n||v[6]!==n)throw Error('marker proof');
  reason='recording-failure';
  await checkedPatch('root-reconcile-tool.json',exactJSON(reconcileTranscript(re,m[1]))+'\n',65536);
  S.state='normal-chain-recorded';persist();
  text({state:S.state,authority:false,Q_released:false});
}catch(error){
  S.state='stopped-unknown';persist();
  try{await failureSave();}
  catch(retentionError){S.state='stopped-unknown-outer-retention-only';persist();}
  text({state:S.state,reason,authority:false,Q_released:false});
}
```


## Superseding coordinator metadata r1 candidate — separate ONE allowance

Exact new caller below uses the fresh coord-metadata-r1 material namespace, one proof-bound fixed two-FD metadata finalizer, and a separate native metadata event chain. Prior candidates and the consumed actual failure remain history. This candidate is prospective only: source/fixture PASS cannot admit a real attempt. Root must receive one independent PASS and prove every new runtime destination absent before any ONE fresh actual admission; no automatic capture. Original 30 seconds and other gates remain. Any failed or uncertain verification/review/attempt stops this allowance.

```javascript
// @exec: {"yield_time_ms": 30000, "max_output_tokens": 2000}
const W='/home/postedism/Desktop/Warden';
const D=W+'/docs/evidence/task-6/';
const P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-';
const K=s=>P+s;
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
if(load(K('one-shot-admitted'))!==true||load(K('one-shot'))!==undefined)
  throw Error('not admitted or already attempted');
// Root's prior absence checks cover these outputs, receipt and terminal;
// admission/invoker are existing verified inputs. No absence is inferred here.
const free=new Set(['root-tool.json','root-proof-reader-tool.json',
  'root-reconcile-tool.json','diagnostic-tool.json']);
const S={state:'active',chains:{get:null,reader:null,metadata:null,reconcile:null},patch_events:[]};
function persist(){store(K('one-shot'),S);}
persist();
function bytes(s){let n=0;for(const c of s){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function req(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,
  tty:false,yield_time_ms:1000,max_output_tokens:max,
  sandbox_permissions:'require_escalated',justification:WHY};}
const getRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-four-get');
const reconcileRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-reconcile');
const readerBody=String.raw`import os,stat,json,hashlib,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):resource.setrlimit(k,(n,n))
D='/home/postedism/Desktop/Warden/docs/evidence/task-6/';P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-'
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
held=[];out={}
for key,name in [('admission',P+'admission.json'),('invoker','controller-cache-continuation-outer-invoker-20261025.py'),('receipt',P+'receipt.json')]:
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for part in D.strip('/').split('/'):
  g=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=g
  s=os.fstat(f);assert s.st_uid in (0,1000) and not s.st_mode&0o022
 h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=f);s=os.fstat(h);cap=16384 if key=='receipt' else 65536
 assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and 0<s.st_size<=cap
 b=b''
 while len(b)<=cap:
  c=os.read(h,cap+1-len(b))
  if not c:break
  b+=c
 assert len(b)==s.st_size
 held.append((f,h,name,meta(s)));out[key]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':meta(s)}
 if key=='receipt':
  v=json.loads(b)
  for k in ('source_commit','source_manifest_sha256','clock_identity'):out[k]=v[k]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
for n in ('root-tool.json','root-proof-reader-tool.json','root-reconcile-tool.json'):
 try:os.stat(P+n,dir_fd=f,follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('existing')
print(json.dumps(out,separators=(',',':')),flush=True)`;
const readerRequest=req("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000);
const metadataBody=String.raw`import time
M0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()
import os,sys,signal,resource
def need(ok):
 if not ok:raise ValueError('material metadata refusal')
need(0<=A0-M0<=100000000)
me=M0+5000000000;be=B0+5000000000;lo=B0-A0;hi=B0-M0;fm=A0;fb=B0
def check():
 global lo,hi,fm,fb
 u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
 need(0<=a-u<=100000000 and fm<=u<=a<me and fb<=b<be)
 lo=max(lo,b-a);hi=min(hi,b-u);need(lo<=hi);fm=a;fb=b
 return a,b
def arm():
 a,b=check();signal.setitimer(signal.ITIMER_REAL,min(me-a,be-b)/1000000000)
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));arm()
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):
 soft,hard=resource.getrlimit(k);need(hard==resource.RLIM_INFINITY or hard>=n);resource.setrlimit(k,(n,n))
import json,hashlib,stat
def pairs(items):
 value={}
 for k,v in items:need(k not in value);value[k]=v
 return value
def bad(_):raise ValueError('noninteger JSON')
def parse(s):return json.loads(s,object_pairs_hook=pairs,parse_float=bad,parse_constant=bad)
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
fds=[];dirs=[];records=[]
def keep(fd):fds.append(fd);return fd
def parents():
 check()
 for parent,name,fd,before in dirs:
  now=meta(os.fstat(fd));need(now==before)
  if parent is not None:need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==now)
 check()
def same(record):
 check();parents();fd,name,data,m=record
 need(meta(os.fstat(fd))==m==meta(os.stat(name,dir_fd=public,follow_symlinks=False)))
 need(os.pread(fd,65537,0)==data)
 need(meta(os.fstat(fd))==m==meta(os.stat(name,dir_fd=public,follow_symlinks=False)));check()
def all_same():
 for record in records:same(record)
def read(name,cap,modes,want=None):
 check();parents()
 fd=keep(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=public));s=os.fstat(fd)
 need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_dev==os.fstat(public).st_dev and stat.S_IMODE(s.st_mode) in modes and 0<s.st_size<=cap)
 data=os.pread(fd,cap+1,0);need(len(data)==s.st_size and (want is None or data==want))
 record=[fd,name,data,meta(s)];same(record);records.append(record);return record
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and len(sys.argv)==2)
 value=parse(sys.argv[1]);need(type(value) is dict and set(value)=={'collector','raw','reader'} and all(type(v) is str for v in value.values()))
 intended=[value['raw'].encode(),value['reader'].encode()];need(all(0<len(v)<=65536 and v.endswith(b'\n') for v in intended))
 collected=parse(value['collector']);expected=collected['receipt']
 need(type(expected) is dict and set(expected)=={'bytes','metadata','sha256'} and type(expected['bytes']) is int and type(expected['metadata']) is list and len(expected['metadata'])==10 and all(type(x) is int for x in expected['metadata']))
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 public=keep(os.open('/',flags));s=os.fstat(public);need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((None,None,public,meta(s)))
 for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)
  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))
 P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-'
 receipt=read(P+'receipt.json',16384,(0o600,0o644))
 need(expected=={'bytes':len(receipt[2]),'metadata':receipt[3],'sha256':hashlib.sha256(receipt[2]).hexdigest()})
 received=parse(receipt[2]);need(received['clock_identity']==collected['clock_identity'])
 timing=received['timing'];origin=timing['origin'];first=origin['sample'];last=timing['final_sample']
 names=('monotonic_before_ns','boottime_ns','monotonic_after_ns')
 values=[origin['budget_start_monotonic_lower_ns'],first['birth_boot_lower_ns'],timing['ended_monotonic_ns']]+[s[n] for s in (first,last) for n in names]
 need(all(type(x) is int and x>=0 for x in values))
 need(origin['budget_start_monotonic_lower_ns']<=first['monotonic_before_ns']<=first['monotonic_after_ns']<=last['monotonic_before_ns']<=last['monotonic_after_ns']<=timing['ended_monotonic_ns'])
 need(first['birth_boot_lower_ns']<=first['boottime_ns']<=last['boottime_ns']<=B0 and last['monotonic_after_ns']<=M0)
 for sample in (first,last):
  need(sample['monotonic_after_ns']-sample['monotonic_before_ns']<=100000000)
  lo=max(lo,sample['boottime_ns']-sample['monotonic_after_ns']);hi=min(hi,sample['boottime_ns']-sample['monotonic_before_ns'])
 need(lo<=hi)
 me=min(me,origin['budget_start_monotonic_lower_ns']+30000000000);be=min(be,first['birth_boot_lower_ns']+30000000000);arm()
 targets=[read(P+name,65536,(0o600,0o644,0o664),want) for name,want in zip(('root-tool.json','root-proof-reader-tool.json'),intended)]
 need(targets[0][3][:2]!=targets[1][3][:2]);all_same()
 for record in targets:
  all_same();check();before=record[3];os.fchmod(record[0],0o600);check();after=meta(os.fstat(record[0]))
  need(after[4]==stat.S_IFREG|0o600 and all(after[i]==before[i] for i in (0,1,2,3,5,6,7,9)))
  record[3]=after;os.fsync(record[0]);check();all_same()
 all_same();sys.stdout.write('{"state":"material-metadata-finalized","authority":false}\n');sys.stdout.flush();all_same()
finally:
 for fd in reversed(fds):check();os.close(fd);check()
check()
`;
function shellQuote(s){return "'"+s.replaceAll("'","'\\''")+"'";}
async function finalizeMetadata(collector,raw,reader){
 reason='metadata-unknown';
 if(S.chains.metadata!==null)throw Error('metadata consumed');
 const data=exactJSON({collector,raw,reader});
 const cmd="exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B - "+shellQuote(data)+" <<'PY'\n"+metadataBody+"PY";
 if(bytes(cmd)>65536)throw Error('metadata command bound');
 S.chains.metadata=[];persist();
 const state=await nativeCall('metadata','exec_command',{...req(cmd),yield_time_ms:10000});
 const r=S.chains.metadata.at(-1).response;
 if(state!=='terminal')throw Error('metadata session unknown');
 if(r.exit_code!==0){reason='metadata-nonzero';throw Error('metadata nonzero');}
 if(r.output!=='{"state":"material-metadata-finalized","authority":false}\n')throw Error('metadata output');
}
function response(r,max){
  exactJSON(r); // Retain first; refuse unsupported values before reading fields.
  const keys=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
  if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!keys.includes(k))||
     typeof r.output!=='string'||bytes(r.output)>65536||
     !Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');
  if('chunk_id'in r&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');
  if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||
     r.original_token_count<0||r.original_token_count>max))throw Error('truncated');
  if('exit_code'in r){
    if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('exit');
    return 'terminal';
  }
  if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');
  return 'running';
}
let reason='get-unknown';
async function nativeCall(p,tool,q){
  const events=S.chains[p];
  if(events.length>=32)throw Error('event bound');
  const e={seq:events.length,tool,request:q};
  events.push(e);persist(); // outbound request survives a rejected Promise
  let r;
  if(p==='metadata'){
    try{r=await tools.exec_command(q);}
    catch(error){e.thrown=error;persist();throw error;} // original rejection; no response invented
  }else r=await(tool==='exec_command'?tools.exec_command(q):tools.write_stdin(q));
  e.response=r;persist(); // actual returned value, even if subsequently refused
  return response(r,q.max_output_tokens);
}
async function run(p,q){
  if(S.chains[p]!==null)throw Error('no retry');
  S.chains[p]=[];reason=p+'-unknown';persist();
  let state=await nativeCall(p,'exec_command',q);
  const events=S.chains[p];
  const id=state==='running'?events[0].response.session_id:undefined;
  while(state==='running'){
    if(events.length>=32||events.at(-1).response.session_id!==id)throw Error('poll bound/session');
    state=await nativeCall(p,'write_stdin',{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000});
    if(state==='running'&&events.at(-1).response.session_id!==id)throw Error('session changed');
  }
  if(events.some(e=>!Object.hasOwn(e,'response')))throw Error('incomplete normal chain');
  if(events.at(-1).response.exit_code!==0){reason=p+'-nonzero';throw Error('nonzero');}
  return events;
}
async function checkedPatch(suffix,body,cap){
  if(!free.has(suffix)||!body.endsWith('\n')||bytes(body)>cap)throw Error('patch gate');
  const request='*** Begin Patch\n*** Add File: '+D+P+suffix+'\n'+
    body.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch';
  free.delete(suffix); // consume even if the following call throws
  const e={seq:S.patch_events.length,tool:'apply_patch',request};
  S.patch_events.push(e);persist();
  const r=await tools.apply_patch(request);
  e.response=r;persist();
  // M8 ordinary-object/empty-key normal return profile was calibrated by root; no disk readback.
  notify({patch_seq:e.seq,actual_return:r});
  if(r===null||typeof r!=='object'||Array.isArray(r)||
     Object.getPrototypeOf(r)!==Object.prototype||Reflect.ownKeys(r).length!==0)
    throw Error('unexpected patch return');
}
// Refuse lossy JSON serialization of available tool data. Never strip fields.
function exactJSON(value){
 const seen=new Set();
 function check(v){
  if(v===null||typeof v==='string'||typeof v==='boolean')return;
  if(typeof v==='number'){
   if(!Number.isFinite(v)||Object.is(v,-0))throw Error('unrepresentable number');return;
  }
  if(typeof v!=='object'||seen.has(v))throw Error('unserializable');
  const array=Array.isArray(v),proto=Object.getPrototypeOf(v);
  if(proto!==(array?Array.prototype:Object.prototype))throw Error('nonplain');
  for(let p=v;p!==null;p=Object.getPrototypeOf(p))
   if(Object.getOwnPropertyDescriptor(p,'toJSON'))throw Error('serialization hook');
  seen.add(v);
  const keys=Reflect.ownKeys(v);
  if(array){
   const n=Object.getOwnPropertyDescriptor(v,'length').value;
   if(keys.length!==n+1)throw Error('array fields');
   for(let i=0;i<n;i++){
    const d=Object.getOwnPropertyDescriptor(v,String(i));
    if(!d||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('array data');
    check(d.value);
   }
  }else{
   for(const k of keys){
    const d=Object.getOwnPropertyDescriptor(v,k);
    if(typeof k!=='string'||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('object data');
    check(d.value);
   }
  }
  seen.delete(v);
 }
 check(value);return JSON.stringify(value);
}
function readerTranscript(events){return {version:1,mode:'material-four-get',phase:'reader',
  events,terminal_event_index:events.length-1,budget:{alarm_after_import_seconds:5,
  cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
function reconcileTranscript(events,proof){return {version:1,mode:'material-four-get',phase:'reconcile',
  events,terminal_event_index:events.length-1,marker_proof_json:proof,budget:{wall_seconds:30,
  cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
async function failureSave(){
  const reasons=['get-nonzero','get-unknown','receipt-unavailable-or-invalid',
    'reader-nonzero','reader-unknown','metadata-nonzero','metadata-unknown',
    'reconcile-nonzero','reconcile-unknown',
    'invalid-marker','recording-failure'];
  if(!reasons.includes(reason))throw Error('failure reason');
  const body=exactJSON({version:1,mode:'material-four-get',authority:false,
    state:'unknown-no-authority',reason,chains:S.chains,
    patch_events:S.patch_events,Q_released:false})+'\n';
  const small=free.has('root-proof-reader-tool.json')&&bytes(body)<=65536;
  const suffix=small?'root-proof-reader-tool.json':'diagnostic-tool.json';
  const cap=small?65536:4194304;
  if(!free.has(suffix)||bytes(body)>cap)throw Error('retain outer record only');
  await checkedPatch(suffix,body,cap); // exactly one failure-save attempt
}
try{
  const es=await run('get',getRequest);
  const rs=await run('reader',readerRequest);
  reason='receipt-unavailable-or-invalid';
  const t=rs.map(e=>e.response.output).join('');
  if(bytes(t)>16384||!t.startsWith('{')||!t.endsWith('}\n'))throw Error('collector output');
  const p=JSON.parse(t); // structural preview only; never serialize p
  const keys=['admission','invoker','receipt','source_commit','source_manifest_sha256','clock_identity'];
  if(p===null||typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==6||
     keys.some(k=>!Object.hasOwn(p,k)))throw Error('collector keys');
  const h=exactJSON({version:1,mode:'material-four-get',origin:'root-controller-actual-tool'});
  const z=exactJSON({events:es,terminal_event_index:es.length-1,
    root_assertion:'awaited-terminal-before-record-before-reconcile'});
  const raw=h.slice(0,-1)+','+t.slice(1,-2)+','+z.slice(1)+'\n';
  // Proof/clock JSON member text is spliced unchanged; final Python validates it.
  reason='recording-failure';
  const readerText=exactJSON(readerTranscript(rs))+'\n';
  await checkedPatch('root-proof-reader-tool.json',readerText,65536);
  await checkedPatch('root-tool.json',raw,65536);
  await finalizeMetadata(t,raw,readerText);
  const re=await run('reconcile',reconcileRequest);
  reason='invalid-marker';
  const out=re.map(e=>e.response.output).join('');
  const m=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(out);
  if(!m)throw Error('sole canonical marker');
  const n=BigInt(m[2]),v=m[3].split(',').map(BigInt);
  if(n>16384n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||
     v[4]!==33152n||v[5]!==1n||v[6]!==n)throw Error('marker proof');
  reason='recording-failure';
  await checkedPatch('root-reconcile-tool.json',exactJSON(reconcileTranscript(re,m[1]))+'\n',65536);
  S.state='normal-chain-recorded';persist();
  text({state:S.state,authority:false,Q_released:false});
}catch(error){
  S.state='stopped-unknown';persist();
  try{await failureSave();}
  catch(retentionError){S.state='stopped-unknown-outer-retention-only';persist();}
  text({state:S.state,reason,authority:false,Q_released:false});
}
```


## Separately authorized six-mode metadata compatibility caller

Full superseding prospective caller below. Original5/5 and material1/1 stay consumed; this separate scope has one affected cover and one independent directed review. Actual gates remain closed pending original descendant/quiescence and fresh per-stage admission evidence.

# Six-mode fixed raw metadata caller - separately authorized scope completion

Complete superseding cell protocol below. Freeze MODE in the common prelude and M in the unchanged collector to the SAME one reviewed literal before use. The six closed modes have exactly one fresh raw mutation target each: capture-preprobe(180s), capture(90s), capture-postflight(180s), continue-preprobe(180s), continue(600s), continue-postflight(180s), under the existing fixed prefix. Each root-tool path is separately proved absent/owned before its original AddFile. No old/unknown file, material attempt or supplemental transcript is finalized.

The new helper binds the original envelope Proof from original collector text, exact intended raw bytes, original dual-clock deadline and held FDs. Local5/CPU2/AS128MiB/FSIZE1MiB does not extend the operation; native yield10000 is only scheduling. No observer/reader/authority/umask change. Unsupported original metadata values remain outer-only; no lossy failure record or new authority is invented. Root must retain outer state including pending/throw/session evidence. Actual gates and unknown prior Task16 descendants/quiescence remain unresolved. No automatic successor or actual admission follows this source artifact. Original5/5 and material1/1 remain consumed. This scope has only one affected cover and one independent review; any failure/unknown stops without repair.

## Exact common prelude and separately admitted cells

The following is proposed caller text, **not executed**. Actual bootstrap/binary/parent/UID1000 trust, root quiescence, source/admission identity, fixed clocks, resources, writer/scene/Q and eligibility remain separate gates. `yield_time_ms` and `wall_time_seconds` are not deadlines/lifetime. No provider FD or signature is invented. Root is the external authority for complete awaited tool history; same-UID hostile writers are excluded by continuous quiescence, not proven by metadata.

Use functions.exec with the common prelude below pasted into each relevant cell. MODE is frozen to one reviewed literal per operation; its five siblings are capture, capture-postflight, continue-preprobe, continue, continue-postflight. No arbitrary command/argument/environment. Store keys retain each phase across cells; no automatic relaunch/cancellation. Each poll is an individual empty45s wait, at most31 polls/32 events per chain. Preserve every request/return immediately, including unsuccessful validation. Transport uncertainty retains available memory/transcript and stops without valid raw authority. No truncation/overflow may be trimmed into success.

```javascript
const MODE='capture-preprobe';
const W='/home/postedism/Desktop/Warden';
const P='controller-cache-continuation-v1-20261025-';
const PUB=W+'/docs/evidence/task-6/';
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
const key=phase=>P+MODE+'-'+phase;
function bytes(s){let n=0;for(const c of s){const v=c.codePointAt(0);n+=v<128?1:v<2048?2:v<65536?3:4;}return n;}
function request(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,tty:false,
 yield_time_ms:1000,max_output_tokens:max,sandbox_permissions:'require_escalated',justification:WHY};}
function operation(action){if(action==='reconcile')metadataTerminal();return request('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py '+action+' '+MODE);}
function response(r,max){
 const allowed=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
 if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!allowed.includes(k))||
 typeof r.output!=='string'||bytes(r.output)>65536||typeof r.wall_time_seconds!=='number'||
 !Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('unknown response');
 if('chunk_id'in r&&(typeof r.chunk_id!=='string'||r.chunk_id.length<1||r.chunk_id.length>128))throw Error('chunk');
 if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||r.original_token_count<0||r.original_token_count>max))throw Error('truncation');
 if('exit_code'in r){if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('unknown terminal');return 'terminal';}
 if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('unknown session');return 'running';
}
async function first(phase,req){
 if(load(key(phase))!==undefined)throw Error('existing no retry');
 const s={request:req,events:[],state:'awaiting'};store(key(phase),s);
 try{const r=await tools.exec_command(req);s.events.push({seq:0,tool:'exec_command',request:req,response:r});
 store(key(phase),s);s.state=response(r,req.max_output_tokens);store(key(phase),s);}
 catch(e){s.state='unknown';store(key(phase),s);throw e;}
}
async function poll(phase){
 const s=load(key(phase));if(!s||s.state!=='running'||s.events.length>=32)throw Error('stop');
 const id=s.events[0].response.session_id,last=s.events[s.events.length-1].response;
 if(last.session_id!==id||'exit_code'in last)throw Error('changed session');
 const req={session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000};
 try{const r=await tools.write_stdin(req);s.events.push({seq:s.events.length,tool:'write_stdin',request:req,response:r});
 store(key(phase),s);s.state=response(r,2000);if(s.state==='running'&&r.session_id!==id)throw Error('changed session');store(key(phase),s);}
 catch(e){s.state='unknown';store(key(phase),s);throw e;}
}
function terminal(phase,zero=false){const s=load(key(phase));if(!s||s.state!=='terminal'||
 (zero&&s.events[s.events.length-1].response.exit_code!==0))throw Error('terminal required');return s;}
async function add(suffix,body){
 if(!body.endsWith('\n')||bytes(body)>65536)throw Error('record overflow');
 const result=await tools.apply_patch('*** Begin Patch\n*** Add File: '+PUB+P+MODE+suffix+'\n'+
 body.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch');
 store(key('patch'+suffix),result);text(result);
}
// Fixed metadata step only; original supervise/reader/raw/reconcile schemas stay unchanged.
const METADATA_SECONDS=Object.freeze({"capture-preprobe":180,"capture":90,"capture-postflight":180,"continue-preprobe":180,"continue":600,"continue-postflight":180});
if(!Object.hasOwn(METADATA_SECONDS,MODE))throw Error('fixed metadata mode');
const metadataBody=String.raw`import time
M0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()
import os,sys,signal,resource
def need(ok):
 if not ok:raise ValueError('six-mode metadata refusal')
need(0<=A0-M0<=100000000)
me=M0+5000000000;be=B0+5000000000;lo=B0-A0;hi=B0-M0;fm=A0;fb=B0
def check():
 global lo,hi,fm,fb
 u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
 need(0<=a-u<=100000000 and fm<=u<=a<me and fb<=b<be)
 lo=max(lo,b-a);hi=min(hi,b-u);need(lo<=hi);fm=a;fb=b
 return a,b
def arm():
 a,b=check();signal.setitimer(signal.ITIMER_REAL,min(me-a,be-b)/1000000000)
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));arm()
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):
 soft,hard=resource.getrlimit(k);need(hard==resource.RLIM_INFINITY or hard>=n);resource.setrlimit(k,(n,n))
import json,hashlib,stat
def pairs(items):
 value={}
 for k,v in items:need(k not in value);value[k]=v
 return value
def bad(_):raise ValueError('noninteger JSON')
def parse(s):return json.loads(s,object_pairs_hook=pairs,parse_float=bad,parse_constant=bad)
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
fds=[];dirs=[];records=[]
def keep(fd):fds.append(fd);return fd
def parents():
 check()
 for parent,name,fd,before in dirs:
  now=meta(os.fstat(fd));need(now==before)
  if parent is not None:need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==now)
 check()
def same(record):
 check();parents();fd,name,data,m=record
 need(meta(os.fstat(fd))==m==meta(os.stat(name,dir_fd=public,follow_symlinks=False)))
 need(os.pread(fd,65537,0)==data)
 need(meta(os.fstat(fd))==m==meta(os.stat(name,dir_fd=public,follow_symlinks=False)));check()
def all_same():
 for record in records:same(record)
def read(name,cap,modes,want=None):
 check();parents()
 fd=keep(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=public));s=os.fstat(fd)
 need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_dev==os.fstat(public).st_dev and stat.S_IMODE(s.st_mode) in modes and 0<s.st_size<=cap)
 data=os.pread(fd,cap+1,0);need(len(data)==s.st_size and (want is None or data==want))
 record=[fd,name,data,meta(s)];same(record);records.append(record);return record
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and len(sys.argv)==2)
 value=parse(sys.argv[1]);need(type(value) is dict and set(value)=={'collector','raw'} and all(type(v) is str for v in value.values()))
 intended=value['raw'].encode();need(0<len(intended)<=65536 and intended.endswith(b'\n'))
 collected=parse(value['collector']);expected=collected['envelope']
 need(type(expected) is dict and set(expected)=={'bytes','metadata','sha256'} and type(expected['bytes']) is int and type(expected['metadata']) is list and len(expected['metadata'])==10 and all(type(x) is int for x in expected['metadata']))
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 public=keep(os.open('/',flags));s=os.fstat(public);need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((None,None,public,meta(s)))
 for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)
  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))
 P='controller-cache-continuation-v1-20261025-';M='${MODE}'
 SECONDS={"capture-preprobe":180,"capture":90,"capture-postflight":180,"continue-preprobe":180,"continue":600,"continue-postflight":180}
 need(M in SECONDS);T=SECONDS[M]
 envelope=read(P+M+'-deadline.json',4096,(0o600,0o644))
 need(expected=={'bytes':len(envelope[2]),'metadata':envelope[3],'sha256':hashlib.sha256(envelope[2]).hexdigest()})
 received=parse(envelope[2]);need(received['mode']==M and received['stage']==M.split('-')[0] and type(received['wall_seconds']) is int and received['wall_seconds']==T)
 need(all(received[k]==collected[k] for k in ('source_commit','source_manifest_sha256','clock_identity')))
 timing=received['timing'];need(type(timing) is dict and set(timing)=={'sample','budget_start_monotonic_lower_ns','outer_entry_monotonic_ns'})
 first=timing['sample'];names=('pid','hz','birth_ticks','birth_boot_lower_ns','monotonic_before_ns','boottime_ns','monotonic_after_ns')
 need(type(first) is dict and set(first)==set(names)|{'namespace'})
 values=[timing['budget_start_monotonic_lower_ns'],timing['outer_entry_monotonic_ns']]+[first[k] for k in names]
 need(all(type(x) is int and 0<=x<10**18 for x in values))
 need(first['pid']>0 and first['hz']==100 and first['birth_ticks']>0 and first['birth_boot_lower_ns']==first['birth_ticks']*1000000000//100-1000000000//100)
 need(type(first['namespace']) is list and len(first['namespace'])==2 and all(type(x) is int and x>=0 for x in first['namespace']))
 start=first['birth_boot_lower_ns']-(first['boottime_ns']-first['monotonic_before_ns'])
 need(start==timing['budget_start_monotonic_lower_ns'] and 0<=start<=timing['outer_entry_monotonic_ns']<=first['monotonic_after_ns'])
 need(0<=first['monotonic_before_ns']<=first['monotonic_after_ns']<=M0 and first['monotonic_after_ns']-first['monotonic_before_ns']<=100000000)
 need(first['monotonic_before_ns']<=first['boottime_ns']<=B0 and first['birth_boot_lower_ns']<=first['boottime_ns'])
 lo=max(lo,first['boottime_ns']-first['monotonic_after_ns']);hi=min(hi,first['boottime_ns']-first['monotonic_before_ns']);need(lo<=hi)
 next_me=min(me,start+T*1000000000);next_be=min(be,first['birth_boot_lower_ns']+T*1000000000)
 a,b=check();need(a<next_me and b<next_be)
 me=next_me;be=next_be;arm()
 target=read(P+M+'-root-tool.json',65536,(0o600,0o644,0o664),intended);all_same()
 for record in (target,):
  all_same();check();before=record[3];os.fchmod(record[0],0o600);check();after=meta(os.fstat(record[0]))
  need(after[4]==stat.S_IFREG|0o600 and all(after[i]==before[i] for i in (0,1,2,3,5,6,7,9)))
  record[3]=after;os.fsync(record[0]);check();all_same()
 all_same();sys.stdout.write('{"state":"six-mode-metadata-finalized","authority":false}\n');sys.stdout.flush();all_same()
finally:
 for fd in reversed(fds):check();os.close(fd);check()
check()
`;
function exactJSON(value){
 const seen=new Set();
 function check(v){
  if(v===null||typeof v==='string'||typeof v==='boolean')return;
  if(typeof v==='number'){
   if(!Number.isFinite(v)||Object.is(v,-0))throw Error('unrepresentable number');return;
  }
  if(typeof v!=='object'||seen.has(v))throw Error('unserializable');
  const array=Array.isArray(v),proto=Object.getPrototypeOf(v);
  if(proto!==(array?Array.prototype:Object.prototype))throw Error('nonplain');
  for(let p=v;p!==null;p=Object.getPrototypeOf(p))
   if(Object.getOwnPropertyDescriptor(p,'toJSON'))throw Error('serialization hook');
  seen.add(v);
  const keys=Reflect.ownKeys(v);
  if(array){
   const n=Object.getOwnPropertyDescriptor(v,'length').value;
   if(keys.length!==n+1)throw Error('array fields');
   for(let i=0;i<n;i++){
    const d=Object.getOwnPropertyDescriptor(v,String(i));
    if(!d||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('array data');
    check(d.value);
   }
  }else{
   for(const k of keys){
    const d=Object.getOwnPropertyDescriptor(v,k);
    if(typeof k!=='string'||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('object data');
    check(d.value);
   }
  }
  seen.delete(v);
 }
 check(value);return JSON.stringify(value);
}

function shellQuote(s){return "'"+s.replaceAll("'","'\\''")+"'";}
function metadataTerminal(){
 const s=load(key('metadata'));exactJSON(s);
 if(s.state!=='terminal'||s.events.length!==1||s.events[0].response.exit_code!==0||
    s.events[0].response.output!=='{"state":"six-mode-metadata-finalized","authority":false}\n')throw Error('metadata terminal required');
}
async function finalizeMetadata(){
 if(load(key('metadata'))!==undefined)throw Error('metadata consumed');
 const s={state:'preparing',events:[]};store(key('metadata'),s);
 try{
  const patch=load(key('patch-root-tool.json'));exactJSON(patch);
  if(patch===null||typeof patch!=='object'||Array.isArray(patch)||Object.getPrototypeOf(patch)!==Object.prototype||Reflect.ownKeys(patch).length!==0)throw Error('known raw patch required');
  const reader=terminal('reader',true),collector=reader.events.map(e=>e.response.output).join(''),raw=load(key('raw-body'));
  if(typeof raw!=='string'||!raw.endsWith('\n')||bytes(raw)>65536||bytes(collector)>16384)throw Error('metadata inputs');
  const data=exactJSON({collector,raw});
  const cmd="exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B - "+shellQuote(data)+" <<'PY'\n"+metadataBody+"PY";
  if(bytes(cmd)>65536)throw Error('metadata command bound');
  const req={...request(cmd),yield_time_ms:10000},e={seq:0,tool:'exec_command',request:req};
  s.request=req;s.events.push(e);s.state='awaiting';store(key('metadata'),s);
  let r;
  try{r=await tools.exec_command(req);}
  catch(error){e.thrown=error;store(key('metadata'),s);throw error;}
  e.response=r;store(key('metadata'),s);exactJSON(r);
  if(response(r,req.max_output_tokens)!=='terminal'||r.exit_code!==0||r.output!=='{"state":"six-mode-metadata-finalized","authority":false}\n')throw Error('metadata unknown');
  s.state='terminal';store(key('metadata'),s);
  text({state:'metadata-finalized',authority:false,Q_released:false});
 }catch(error){s.state='unknown';store(key('metadata'),s);throw error;}
}

```

Cell1: `await first('supervise',operation('supervise'));`. Later cells only if its stored state is running: `await poll('supervise');`. Immediate terminal has one event; running chain must end in integer0/1 with no session echo. Unknown/124/forced/ambiguous exits stop. The exact request has require_escalated/WHY and no prefix_rule; ordinaryUID1000 must still be verified independently. Approval rejection, if any, must be preserved explicitly rather than replaced by another profile.

After known supervise terminal, use the fixed five-public-record collector below. Its body is assigned to `readerBody` as an exact literal in a separate root cell (including the frozen MODE literal). Then `await first('reader',request("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000));`. Reader polls use the common exact45s/2000 shape and their own session/transcript. Reader's alarm5 after minimal imports/CPU2/AS128MiB/FSIZE1MiB is metadata containment, not a whole-startup/physical5s guarantee; every delay still counts before U.

```python
import os,stat,json,hashlib,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):resource.setrlimit(k,(n,n))
M='capture-preprobe';S=M.split('-')[0]
W='/home/postedism/Desktop/Warden';D='docs/evidence/task-6/'
P='controller-cache-continuation-v1-20261025-'
I='controller-cache-continuation-outer-invoker-20261025.py'
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
held=[]
def read(name):
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for part in (W+'/'+D+name).split('/')[1:-1]:
  g=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=g
  s=os.fstat(f);assert s.st_uid in (0,1000) and not s.st_mode&0o022
 h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=f);s=os.fstat(h)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and 0<s.st_size<=65536
 b=b''
 while len(b)<=65536:
  c=os.read(h,65537-len(b))
  if not c:break
  b+=c
 assert len(b)==s.st_size
 held.append((f,h,name,meta(s)))
 return b,{'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':meta(s)}
out={}
for k,n in [('admission',P+S+'-admission.json'),('invoker',I),('envelope',P+M+'-deadline.json'),('claim',P+M+'-deadline-accepted.json'),('supervisor',P+M+'-supervisor.json')]:
 b,out[k]=read(n)
 if k=='envelope':
  v=json.loads(b)
  for field in ('source_commit','source_manifest_sha256','clock_identity'):out[field]=v[field]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
for suffix in ('-root-tool.json','-root-proof-reader-tool.json','-root-reconcile-tool.json'):
 try:os.stat(P+M+suffix,dir_fd=held[0][0],follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('existing root transcript')
print(json.dumps(out,separators=(',',':')),flush=True)
```

This collector reads exactly five public bodies, holds their FDs and rechecks metadata; the added absence checks read no sixth body. It is caller text, not an unchecked project import, product action or second loader. The reconciler independently re-reads/validates all proofs/source bindings. Root maintains fresh absence/quiescence through each structured AddFile. AddFile is workflow exclusivity, not O_EXCL. Any unexpected existing/partial file, uncertain patch result, overflow or provider error stops without overwrite/delete/retry. Root inspects the actual apply_patch result before issuing the next cell; no invented success field or automatic action follows.

**Lossless proof handling:** metadata contains nanosecond integers above JS safe precision. Do not JSON.parse→JSON.stringify proof numbers or reconstruct clocks from a JS preview. Retain collector output text verbatim; parse only to reject malformed structure, and splice its exact object members into the raw record. Tool events' output strings remain exact strings. API session/exit/token fields require Number.isSafeInteger; generated seq/index are bounded0..31 and therefore safe. Python reconciliation performs the strict integer/proof comparison. No extra cover was run for this caller-text correction.

```javascript
const reader=terminal('reader',true), sup=terminal('supervise');
const proofText=reader.events.map(e=>e.response.output).join('');
if(bytes(proofText)>16384||!proofText.startsWith('{')||!proofText.endsWith('}\n'))throw Error('collector output');
const preview=JSON.parse(proofText); // structural view only; never serialize its numeric proofs
const fields=['admission','invoker','envelope','claim','supervisor','source_commit','source_manifest_sha256','clock_identity'];
if(Object.keys(preview).length!==8||fields.some(k=>!(k in preview)))throw Error('collector keys');
const head=JSON.stringify({version:1,origin:'root-controller-actual-tool',mode:MODE,stage:MODE.split('-')[0]});
const tail=JSON.stringify({events:sup.events,terminal_event_index:sup.events.length-1,
 root_assertion:'awaited-terminal-before-record-before-reconcile'});
const body=head.slice(0,-1)+','+proofText.slice(1,-2)+','+tail.slice(1)+'\n';
store(key('raw-body'),body);
const supplemental={version:1,producer:'root-controller-actual-tool',mode:MODE,phase:'proof-reader',
 budget:{alarm_after_import_seconds:5,cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,
 whole_startup_bound_proven:false,max_events:32,record_bytes:65536},
 events:reader.events,terminal_event_index:reader.events.length-1};
await add('-root-proof-reader-tool.json',JSON.stringify(supplemental)+'\n');
// In the NEXT cell after known successful patch, common prelude then:
// await add('-root-tool.json',load(key('raw-body')));
```

The raw keys/types exactly match the source R1 validator. Its size includes newline and every event. Root's assertion is external causal trust, not source authentication. A malformed record is retained and refused, never repaired into a new attempt. After both known patch completions, a separate cell with the same common prelude executes ONLY `await finalizeMetadata();`. This consumes key('metadata') once. Its original request, actual return or original thrown value are retained before validation. Require known normal0 and exact sole nonauthority output. Session/nonzero/throw/unsupported/uncertain stops, with no metadata poll/retry/reconcile. Only after that terminal, a separately issued cell may execute `await first('reconcile',operation('reconcile'));`, then its own empty45s polls. operation('reconcile') now rejects unless metadata is terminal. No operation target runs again. A reader/patch/scheduling delay can make U too late and cause refusal; do not subtract it or extend90/600/180.

Under the controller's A resolution, matching marker proof means the reviewed writer's sole normal terminal output associated with the exact reconcile MODE request; it is **not** an independent post-exit disk reread. Require actual reconcile exit0, strict sole canonical stdout and retain its full raw chain. Inspect proof decimals losslessly; there is no sixth public read/helper. The next separately authorized consumer re-reads and validates the on-disk marker and entire chain under continuous quiescence. Any mismatch/extra stdout/late/unknown exit stops.

```javascript
const r=terminal('reconcile',true), output=r.events.map(e=>e.response.output).join('');
const match=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[([0-9]+(?:,[0-9]+){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(output);
if(!match)throw Error('sole fixed marker output required');
const n=BigInt(match[2]),m=match[3].split(',').map(v=>BigInt(v));
if(n>16384n||m[0]<=0n||m[1]<=0n||m[2]!==1000n||m[3]!==1000n||m[4]!==33152n||m[5]!==1n||m[6]!==n)throw Error('marker proof shape');
store(key('normal-marker-proof-json'),match[1]); // exact decimal bytes, no numeric conversion
const transcript={version:1,producer:'root-controller-actual-tool',mode:MODE,phase:'reconcile',
 budget:{wall_seconds:30,cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,
 whole_physical_stop_proven:false,max_events:32,record_bytes:65536},
 events:r.events,terminal_event_index:r.events.length-1,marker_proof_json:match[1]};
await add('-root-reconcile-tool.json',JSON.stringify(transcript)+'\n');
```

After known transcript write, root may separately consider the next action; this script grants none. Supplemental reader/reconcile records are external evidence, not marker authority or a recursive sampler: six each<=64KiB add786432B logical within existing96MB reserve/ordinaryR. Original six raw+six marker bound480KiB remains separate. Their own writing/scheduling delays after U do not retroactively change the accepted old terminal upper bound, and can stale a preprobe before launch. Source rechecks original<=60s freshness. Current quiescence, complete actual resource/disk/resident guards and all operational eligibility remain unmeasured/unadmitted here.

The source-only tests include one preserved failed GREEN that accidentally reached bounded own-clock `/proc`/namespace reads due to a fixture mock ending early; it is not described as entirely fake. Persistent fail-closed sentinels and fresh fake-deadline consumers fixed that fixture, subsequent generated tests and unique frozen177-case cover passed. See the full substage report for exact history; source PASS is not actual terminal/material/cache/PG eligibility or Task6 completion.
