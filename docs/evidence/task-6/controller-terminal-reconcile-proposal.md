# Post-terminal reconciliation — NEEDS_CONTEXT

2026-10-25. Subagent design, not human/actual/admission. Read brief,D1/D2,report/plan/review; stable a87b850 Git interfaces/unchanged invoker only. Only ignored proposal written, no source/Git/tests/native/private/children. Original3/5/Q5/caps/Task6+Goal OPEN unchanged.

## Entry and causal trust

Future literal `identity_cache_control.py reconcile MODE`, same six modes/cwd/cleanenv. Sole loader→Controller(stage,metadata_deadline)→load_invoker()→passive reconcile(control,mode,entry_clock). Reuse envelope/history_deadline/validate_target/Record/durable; no run/adoption/claim/load_modules/private/guard. No third loader/providerFD/signature. Root freezes bootstrap/exact call.

Authority: root supervise→all real returns→await terminal→exclusive raw record→reconcile. Source cannot authenticate tools; ctime/UID/producer/output/wall_time cannot prove order. Root quiescence excludes hostile same-UID writers; proofs detect replacement, not agents. Source/test author cannot mint actual inputs/authority.

Existing prefix P; six `MODE-root-tool.json`≤64KiB, six `MODE-terminal.json`≤16KiB. One-use/no overwrite/delete/retry; partial retained. Existing stage-outer-result schema unchanged.

## Raw schema and root procedure

Exact top keys:

```
version:1,origin:"root-controller-actual-tool",mode,stage,
source_commit,source_manifest_sha256,
admission:Proof,invoker:Proof,envelope:Proof,claim:Proof,
supervisor:Proof,clock_identity:{machine_id,boot_id},
events:[{seq,tool,request,response}],terminal_event_index,
root_assertion:"awaited-terminal-before-record-before-reconcile"
```

Proof=`{sha256,bytes,metadata[10]}`, matched fully; manifest hashes exact150. Strict keys/types/bounds,bool≠int. events1..32,seq0..n-1,terminal=n-1;64KiB overflow refuses, no trimming.

Event0 exec_command request preserves cmd/workdir/shell/login/tty/yield_time_ms/max_output_tokens/explicit permission fields, matching frozen supervise MODE. Later only write_stdin(original session,empty chars,fixed wait). Preserve raw output/chunk_id/wall_time_seconds/original_token_count/exit_code/session_id when supplied, documented optional keys/types only; no defaults. Unknown shape refuses.

Immediate: one integer-exit/no-session return. Session: initial session/no exit; polls same ID; final integer exit/no running state. Final same-ID echo only if reviewed provider semantics says terminal. Missing poll/input/new exec/event-after-terminal/cancel/error/ambiguity refuses. Root attests completeness; seq isn't authentication. Accept tool0/1 matching recorder; wall_time never lifetime.

Root design pseudocode (not run):

```
events=[]
r=await tools.exec_command(FROZEN_REQUEST)
events.push({seq:0,tool:"exec_command",request:FROZEN_REQUEST,response:r})
// Poll only returned session; append all real request/returns, no relaunch.
// After terminal bind proofs/check fixed path absent under quiescence.
// apply_patch Add File receives JSON.stringify(record)+LF as literal text,
// never shell JSON/backticks/$(). Await write, then reconcile and its terminal.
```

Root reads only public proofs. Add File is workflow-exclusive under quiescence, not O_EXCL; uncertain absence/no-overwrite stops. Input readback pinned,0600/0644 single-link UID/GID1000; outputs existing durable O_EXCL0600/fsync/readback. Unknown terminal retains transcript only.

## Timing without extending operation

Earliest ENTRY_NS=MONOTONIC U after causal terminal is upper bound. Immediately BOOTTIME B then MONOTONIC A before loading; save real samples. Verified OwnClock later checks implementation/boot/zero-offset namespace/order. Namespace stable since entry is fixed-entry/no-setns assumption.

Envelope M0=budget_start_monotonic_lower_ns, B0=sample.birth_boot_lower_ns, T=90/600/180. Require `0≤U-M0≤T*NS`, `0≤B-B0≤T*NS`, `0≤A-U≤100ms`. Compare [B-A,B-U] with original offset interval [boot-after,boot-before], supervisor last sample and verified current sample: same namespace/boot, ordered samples, common intersection. Reuse ClockBudget mechanics without requiring new process PID/birth equal old supervisor. BOOTTIME bound prevents tolerated sampling uncertainty extending deadline; discontinuity/unknown refuses. Actual monotonic fields remain actual, never synthetic adjusted now.

Claim/launch/receipt/supervisor samples≤U; last bracket before entry. Pre-exit receipt isn't U. Await/write/scheduling delay may reject timely work; never subtract it/restart budget.

Metadata separately30s whole-command CPU5/AS128MiB/FSIZE1MiB, D1 birth/dual-clock/inherited ceilings. Verification/fsync charged separately; operation uses U/B, no extension. Store metadata-end separately; suspend/failure no usable marker. Pre-interpreter physical stop unproved. Root awaits reconcile terminal before next action, no recursive sampler.

## Proof validation and final commit

Hold/recheck raw,supervisor,admission,invoker,150 sources,envelope,claim,launch/receipt/full probe. Strict supervisor schema/bindings/outcome/log hash≤1MiB; assign historic envelope, no adoption. Reuse validate_target/history_deadline; compare tool/recorder/receipt exits. Forced death/partial Popen/late EOF/overflow/missing receipt/nonterminal never proves child terminal. No discovery/signals/cleanup.

For capture/continue write only existing outer_gate keys:

```
version:1,stage,producer:"controller-tool-result",terminal:true,
exit_code:agreed recorder0|1,child_terminal:true,
child_exit_code:null(capture)|exact int(continue),
launch_sha256,receipt_sha256,source_commit,outer_invoker_sha256,
command:original target argv,clock_identity,
started_monotonic_ns:M0,ended_monotonic_ns:U
```

Sidecar labels start lower/end upper bound. Known inner nonzero/timeout/overflow permits failure only; unknown prohibits outer. No automatic audit.

Final marker exact keys:

```
version:1,mode,stage,state:"known-success"|"known-failure",
source_commit,source_manifest_sha256,admission,invoker,
envelope,claim,root_tool,supervisor,result:Proof,clock_identity,
timing:{start_lower_ns,terminal_upper_ns,entry_boot_ns,
 entry_after_ns,verified_sample,metadata_end_ns},
tool_exit_code,child_exit_code,Q_released:false
```

All authority fields are full Proofs, numeric types strict; result=outer Proof for operations/full probe Proof for probes; probe child_exit_code=null. Reconstruct timing from bound evidence. Write marker LAST, rechecking inputs before/after each durable output. Orphan outer unusable; no cyclic hashes. Probes: preprobe-complete/0 or postflight-success/0 gives success; valid incomplete/1 can record known-failure, not progression. Unknown retains existing artifacts; no extra pending record needed.

## Before next operation

terminal_gate(mode) validates raw+marker+history. preparation requires preprobe known-success before private/preparation/launch, retaining≤60s age; launch_binding retains marker proof. outer_gate requires exact operation marker before postflight private/cache/guard/imports. Probe progression requires marker AND root-awaited reconcile terminal. Capture→continue source/pin change needs separate reviewed historical handoff. None pins/admission/approval unchanged.

## Later bounded scope

Later edits: bootstrap dispatch/bracket, observer gates/validators/suffixes, passive invoker writer, existing relevant controller/invoker fixtures. Preserve150 names/product8/capture/maintenance/shared recovery/guard/None pins. Raw+markers≤480KiB. Root-raw+terminal proof bindings require plan adoption/new150+controller2 hashes and independent source/mock/exact-call review after4GET handoff. No current API expansion.

Fake cases: direct/session/missing-wrong-poll/optional fields/nonzero; numeric/schema/size; wrong bindings/replay; late U/90-600-180 boundaries/suspend/namespace/receipt>U; null-vs-int; forced/unknown/EOF; inode/body replacement each write; orphan/partial/no retry; stale-age/progression. No tests now.

NEEDS_CONTEXT: rule causal/raw trust, entry bracket/metadata budget, marker gates/history; source/mock/exact-call review then separate admission. No charge/Q release/host/cloud/GPU/publication.
