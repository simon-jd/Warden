# Four-GET material — NEEDS_CONTEXT

2026-10-25 subagent design, not human/actual. Basis:b2b348205bdb3fbd4573ab04237c1a9e166371e2/ce10703 + accepted plans/rulings. No in-progress source read.

## Minimal integration

After terminal PASS/ruling:existing bootstrap/observer/controller fixture/docs invoker/docs fixture; new module adds pins/loader. Add material-four-get/material-reconcile. Distinct MaterialContext reuses extracted150/Record/recheck/invoker helpers. Controller/six modes/admission policy unchanged. No envelope/preparation/recovery/guard. Sole verified bootstrap and existing pinned invoker loader; no third loader/cap increase.

D=docs/evidence/task-6/; P=controller-cache-continuation-v1-20261025-. All suffixes below fixed D+P. material-admission.json <=65536B keys exactly:
version,mode,authority,source_commit,source_hashes,review_sha256,ruling_sha256,writer_basis,clock_identity,outer_invoker_sha256,policy.
version1/mode material-four-get/authority readonly-four-get-only; commit hex40; current150 names/SHA/body hashes/2MB bounds; review/ruling/invoker hex64; writer_basis1..4096UTF8; existing clock schema. Policy exactly {wall_seconds:30,cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,output_bytes:65536,phase_seconds:[10,15,20,25,30]}.

Root freezes future reviewed150+invoker/bootstrap/review/ruling under same-UID quiescence; hashes cannot authenticate writers. No admission here. Source-only material needs no capture admission/ordinary guard/API compatibility and grants no private/operation/charge/Q authority.

## Fixed execution

ReadOnlyDocker project-only constructor, no recovery import; existing callers unchanged. Project image list→container list→lexicographic first image inspect if nonempty→same for container. Retain all/quiet/nontrunc/API1.45/AND+returnedLabels/same-kind provenance/Id/Config.Labels/LF-ID/[object]. Empty inspect=not-exercised; no oldIDs/OLD_LABELS/create/pull/retry; non-atomic. Socket/peer/framing unchanged. Success-summary accessor only200/peer/output size/hash/selected ID hash. No Env/body/traceback/Popen/signals/PID discovery/child ownership/mutation.

Earliest U/B/A/ENTRY_NS and OwnClock birth derive M0/B0. End=M0+30<=ENTRY+30; CPU5/AS128MiB/FSIZE1MiB/output64KiB, no hard raise. Shared ClockBudget/deadline, unchanged E=min(now+30,end-10), E-now>10: I/O<=M0+10, validate/close15, return20, receipt/rechecks25, independent terminal30. No renewal. Cold setup may refuse; collector/write/queue delay charged,25 guarantees no reconcile reserve. D1 startup/uninterruptible physical stop unproved.

## Records

Strict keys/types/duplicate-key/NaN rejection; bool!=int. Existing Proof/Record/durable O_EXCL0600/fsync/readback. Root admission/raw regularUID/GID1000,nlink1,0600/0644/trusted ancestors; no overwrite/retry.
C=expanded keys version,mode,source_commit,source_manifest_sha256,admission,invoker,clock_identity; version1/mode material-four-get/full bindings.

material-receipt.json <=16384B keys C plus state,timing,slots,reason,Q_released. Q=false; state observed-success/known-failure; reason null/fixed enum. timing={origin:existing timing_from_birth value,final_sample:OwnClockSample,ended_monotonic_ns:int}, valid derivation/ordering/both-clock phase25.
slots exactly four, keys route,state,count,selected_id_sha256,output_bytes,output_sha256,http_status,peer.
route image-list/container-list/image-inspect/container-inspect; state ok/not-exercised/failed/not-reached. ok: count list0..1000 or inspect1, output_bytes0..1048576 (0 only empty LF list), output hash hex64,status200,peer[positive pid,0,nonnegative gid]; selected hash only inspect. Other fields null for non-ok. Empty list requires corresponding inspect not-exercised; failure makes later slots not-reached. Known-failure requires timely closure/normal error. Ambiguity unusable; stdout receipt-Proof is not terminal.

material-root-tool.json <=65536B keys C plus origin,receipt,events,terminal_event_index,root_assertion. Fixed origin root-controller-actual-tool/assertion awaited-terminal-before-record-before-reconcile. Accepted strict pure event validator, material literals,1..32 events; immediate exit/no-session or original-session chain then exit/no-session. Error/echoed session/truncation/overflow/incomplete chain refuses. Exit0=observed-success,1=known-failure,otherwise unknown. No capture envelope/claim/supervisor.

material-terminal.json <=16384B keys C plus state,receipt,root_tool,timing,tool_exit_code,Q_released. state known-success/known-failure; Q=false. timing is the exact accepted terminal timing schema. Pure clock/proof validators with literal T30 require0<=U-M0<=30NS,0<=B-B0<=30NS,0<=A-U<=100ms; historic stamps<=U; common original/receipt/early/current offset intervals, same host/boot/namespace. Sampler PID/birth separate; no-setns assumed. Reconcile separate30/CPU5/AS128/FSIZE1MiB never extends material30. Marker last/recheck inputs. Success only exercised routes; orphan/final-check failure unusable.

## Future caller

Native cmd literal:
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py ACTION
ACTION frozen material-four-get/material-reconcile; argv exactly python3,-B,scripts/identity_cache_control.py,ACTION.
Request fields: workdir:/home/postedism/Desktop/Warden,shell:/bin/bash,login:false,tty:false,yield_time_ms:1000,max_output_tokens:2000,sandbox_permissions:require_escalated,justification:以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。
prefix_rule absent. OrdinaryUID1000, not sudo; rejection preserved/stops, no bypass.

Separate-cell functions store/load retains exact request/every actual response. Poll pending original session_id,chars:"",yield_time_ms45000,max_output_tokens2000,max31; no relaunch/post-terminal poll. After known terminal, accepted stdlib proof collector reads only material admission/invoker/receipt, derives source/clock, checks raw absence. Same FD/path/64KiB checks,alarm5/CPU2/AS128/FSIZE1MiB/native fields,initial output4000. Future appendix must freeze stdin script/request/hash; no new loader/startup proof.

Collector exit0/full JSON→stored events/proofs JSON.stringify+LF<=65536UTF8→structured apply_patch Add File after fresh absence/quiescence→material-reconcile. No shell JSON; exclusivity!=O_EXCL, uncertainty stops. Real U/B/A follows terminal/raw; API wall_time!=lifetime. Preserve complete collector/reconcile chains:material-root-proof-reader-tool.json/material-root-reconcile-tool.json<=65536B each. Root requires normal reconcile exit0/matching marker Proof before separately authorized next action. No recursive sampler/automatic retry; unknown/late/partial/overflow retains evidence/stops.

Six files<=294912B (4x64KiB+2x16KiB), existing96MB reserve/ordinaryR; allocated bytes separately. Root causality/quiescence assumed, not authenticated.

## Gates

Generated-only cases:capture unchanged/150 pins/replacements/forbidden imports;empty/mixed/full kinds/IDs/labels/fake transport;failure/close/shared phase edges;schema/proof/replay/tool optional/chains/overflow;boot/namespace/suspend/late stamps;exit mismatch/known-unknown/orphans/recheck/no successor. Independent five-file/context/privacy/validator/writer/exact-call review; RED/GREEN/one frozen cover/150+2 maps/failure history; no native/socket fixtures.

Future checks:binary/shell/env integrity,UID/GID1000,ancestors/absence/quiescence,OwnClock ABI/host/boot/namespace,socket metadata/admin trust,CPU/AS/disk/resident/public reserve. API1.45/framing/peer/viability remain test unknowns. Resource uncertainty is not mocked guard/private qualification.

Decisions:five-file shared verification/project-only summary; six schemas/paths/conditional30s; material-reconcile/caller; source/mock/exact-call dispatch after terminal PASS. Source pins/collector bytes need freeze. Current terminal/names150/product8/capturemaintenance/Nonepins/sharedguards unchanged. Preserve3/5/three Minors/Task3-4caps/old timeout/scene22/Q5/Azure$6/90%ledger/12GBdisk/16GBresident/GPUflock/nohostk3siptables/nopublication. No actual compatibility claim; Task6/Goal OPEN.
