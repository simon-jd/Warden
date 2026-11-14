# Fixed cache continuation: separate capture and execution plan

2026-10-25. This is a review artifact, not actual admission. Dispatch BASE `333dfa155ed1670ebceff3c20fb0228c365f17d3`; overall Task6 BASE84018e512d78156283ae64aab62ccb76d5d20801/fix1of5 remain. Binding authority: [controller rulings](cache-continuation-controller-rulings.md), preserved [proposal](cache-continuation-proposal.md), [old timeout](cache-operation-20261025.md). Old entry/source/journals/history, crypto and shared trust/recovery/accounting code remain unchanged. New source is only `scripts/identity_cache_continue.py` and its generated private test module. Frozen hashes/commit and run evidence are in [substage report](cache-continuation-substage-report.md).

## Separate future gates

1. Independent reviewer accepts frozen new source, private fixture evidence and this exact plan, including controller capture/launch/postflight responsibilities. Source review and fixture PASS are not actual capture/maintenance approval, human/second-identity approval, or durability evidence about the live filesystem. This is the already classified fixed offline-rebuildable development-cache maintenance; original Task14 response dry-run/second-identity rules remain unchanged.
2. Controller separately admits **one metadata capture**, using fresh ordinary UID/EUID/GID1000 and the unchanged trusted ancestry/lock checks. Source/public-history/old-intent/known-terminal facts and writer-free window must be established. No host/other-project inventory is added. The old command was terminal -15 after its original180seconds; do not relaunch/signal its PID or rewrite that history.
3. The capture callable only creates the fixed private checkpoint once. Controller validates its result, durably records actual public hashes/aggregate facts, and separately creates/commits the fixed public approval document. Capture does not create approval. The approval document is currently absent; do not manufacture an anticipated SHA/default approval.
4. After capture, controller separately admits **one continuation** with its own durable public launch-intent, fresh resources and writer-free window, bound to the exact committed approval bytes and frozen source. No automatic call from capture, no retry, no reset. Actual public recorders are controller-owned stages; none are run or asserted complete by this source substage.

## Capturing the precise checkpoint

The sole future controller callable is `identity_cache_continue.capture_checkpoint(writer_basis)` after import through the fixed reviewed Warden scripts path. The argument is only a nonempty UTF8 explanation <=4096bytes of controller-established quiescence; there is no path, UID, hash, mode, selector or retry argument. CLI does not expose capture. A controller recorder should call this exact callable, not a generic executable/string-eval interface. Its future source and call must also be reviewed before actual capture.

The callable holds the existing `.cache/warden-lab/docker.lock` throughout. It refuses any existing public approval or any of the four new private names, and refuses the old result. Old intent length must be exactly4,573,737 before body read; its exact SHA must be `cbc9e3aad72189cf1a048ee1a30270ea43dce2925823563c283fecd3dcf65e5e` before any cache scan. It is metadata only: no cache data body is read. Metadata reads are bounded, nofollow, UID/GID1000, same-device, single-link, trusted-mode, with FD/path/size/blocks/fingerprint rechecks. Unknown/partial metadata remains in place.

Pinned old engine/shared source and three public history files are checked. Original result must have known wait=-15, timed_out=true, no recorder error, exact old command and matching source hashes before/after. Audit must retain incomplete/no-result/180second facts. Original trusted cache-parent identity/mode and exact lab/lock metadata are checked against the pinned public preflight. The original process's PID is evidence only; no signals/process launch occur in this module.

Fresh scan retains the original fixed Go layout and bounds, then compares all22,682 ordered records to old intent:260directories and22,422files; exactly first19,160target entries, remaining3,522original entries. Prefix permits only original mode→exact target and ctime differences; all stable identity/type/link/size/mtime fields remain equal. Suffix full fingerprint includingctime must equal original. Whole names/order/target types/inode uniqueness/link counts/layout must agree; no missing/new/alias/mixed-state fallback. No ctime execution-window inference is used without clock continuity evidence.

The checkpoint contains complete ordered metadata `[dev,ino,uid,gid,fullmode,nlink,size,mtime_ns,ctime_ns,blocks]`, targetmode, relative paths, binding, full root/cache/lab/lock metadata, writer_basis and UTC captured_at. Its filename is `.cache/identity-cache-continuation-v1-checkpoint.json`, <=16,000,000bytes,0600/exclusive/nofollow/file+parentfsync. It rechecks cache and original authority before/after writing. Failure preserves the checkpoint, including partial bytes; do not capture again. Public output only returns the summary/digest/schema below, not live entries or old private journal contents. Controller must preserve private body locally and must not commit it.

The full `.cache` parent fingerprint is recorded but later only its identity/type/mode/nlink fields must match: adding the fixed private checkpoint/journals necessarily changes that directory's size/times/blocks. Root, lab and lock remain exact; live path-to-held-FD rechecks remain. This limited parent-metadata expectation does not permit different target names or cache contents.

## Exact future approval schema

Fixed path: `docs/evidence/task-6/cache-continuation-checkpoint-approval-20261025.json`. <=65,536bytes, strict unique JSON keys, ordinary UID1000/single-link regular/nofollow/trusted ancestry; no environment/path override. Controller copies the capture summary into this record only after actual capture and its independent checks, changing only state from `checkpoint-captured-not-approved` to `approved`. Preserve actual fields; placeholders below are documentation, not an admissible record:

```json
{
  "version": 1,
  "state": "approved",
  "binding": {
    "operation": "task6-cache-continuation-v1",
    "source_hashes": {"<all six fixed original sources plus both new files>": "<actual SHA256>"},
    "history_hashes": {"<all three exact fixed public history paths>": "<pinned SHA256>"},
    "old_intent_sha256": "cbc9e3aad72189cf1a048ee1a30270ea43dce2925823563c283fecd3dcf65e5e",
    "old_intent_bytes": 4573737,
    "original_exit_code": -15,
    "original_timeout_seconds": 180,
    "counts": {"entries":22682,"directories":260,"files":22422,"prefix":19160}
  },
  "writer_basis": "<actual controller-established basis, not a fixture>",
  "captured_at": "<actual UTC capture timestamp>",
  "checkpoint_sha256": "<actual 64 lowercase hex characters>",
  "checkpoint_bytes": "<actual JSON integer, not this string>"
}
```

There are no additional keys/defaults. Binding dictionaries must exactly equal freshly verified source/history/constants. Source hashes include both new source and test files; changes after capture invalidate the binding. All checkpoint numeric metadata fields must be exact JSON integers, not booleans. Controller must pin the committed public approval file's own byte SHA in the future launch recorder and keep it and the checkpoint immutable through the writer-free window. There is no claim of resistance to a malicious same-UID writer who can rewrite trusted source/approval.

## Future single continuation command and phases

After the distinct execution admission, the only command is `python3 -B scripts/identity_cache_continue.py` from the fixed Warden checkout. No arguments are accepted. No main/private capture invocation is authorized now.

The entrypoint refuses missing approval before reading any private journal body. Under the same existing project lock it validates approval binding, checkpoint length/hash/schema, old intent and original stable state, exact prefix, and complete live metadata equality to the checkpoint. It refuses any PREPARED/READY/RESULT or old result, including symlinks/partial files.

It creates `.cache/identity-cache-continuation-v1-intent.json` (`prepared-not-completed`) exclusively0600 and durably fsyncs file and parent before target mutation. It rechecks all authorities, paths/held ancestors, complete cache and checkpoint. It then visits every target in original order: already-target entries receive **no redundant chmod**, suffix entries only narrow to0700directories/executables or0600regular, and **all22,682targets receive fsync**. Every FD/path/identity/stable field is checked around mutation/fsync. Errors retain permission changes and journal; no rollback.

After complete fsync, it reopens the original strict CachePlan, requires identical full metadata and exacttarget modes, and fsyncs parent. It refuses any newly appeared READY/RESULT, writes `.cache/identity-cache-continuation-v1-ready.json` (`ready-not-completed`) durably, rechecks authorities and complete strict plan, and again refuses an unexpected RESULT. Only then does the original strict engine remove accepted derived entries and empty executable directories, preserving root/256buckets/original root metadata. No `RemoveAll`, arbitrary tree, other cache or resource is involved.

Original strict deletion's full postcheck and remaining-directory/parent fsync precede `.cache/identity-cache-continuation-v1-result.json` (`completed`). New stage files are each<=65,536bytes, exclusive0600/nofollow with file+parentfsync. Result binds source/history/approval/checkpoint and prepared/ready hashes plus removal counts. It never creates the old result or changes the old intent. Exit0 alone is not success: require durable valid new result and independent postflight. Any existing new stage journal prevents a second invocation; a READY record is not automatic resume authority.

## Time, resources and failure protocol

The future controller recorder must durably create its public launch-intent **before** child creation, including current source/approval hashes, original terminal evidence, resource/scene/writer facts and the fixed command. Even interruption before private prepared is not a blind new launch opportunity. Source module itself never launches/signals processes or changes charges.

One new operation wall envelope is<=600seconds, not a revision of old180seconds:590seconds run, then SIGTERM to this still-owned child/process group, up to5seconds, then SIGKILL and up to5seconds wait. Unknown final wait outcome remains pending; do not run concurrent postflight or other project operations until known terminal. Never signal the old PID, use global kills or relaunch. Recorder should provide <=60second elapsed/phase heartbeats without rereading cache bodies; module prints sparse syncing counts every30seconds when its loop progresses. Blocking filesystem calls/unchanged strict deletion cannot promise in-process heartbeat delivery, so the outer recorder owns wall supervision. Output bounded1MiB; no per-file body or persistent progress log.

Re-fsyncing already-target items is required because original kill may fall between chmod and completed fsync. Approximate old throughput gives a planning estimate of~216seconds for22,682sync targets plus suffix chmod, rechecks and deletion;600seconds is not a success guarantee. Disk stalls must fail/retain, not trigger relaxed fsync, extra runtime, more parallelism or a second opportunity.

Fresh ordinary full R + all outstanding Q/charges + ordinary owned-image accounting +96,000,000B maintenance headroom must fit12e9. Resident memory including original1GB host allowance must fit16e9. New private metadata fits16MB+three64KiB receipts and bounded1MiB log; all source/evidence already contributes to ordinary R. No new canonical charge/schema or standard3GB admission is created. Directory FD/Go layout/file/byte limits are unchanged. Q5GB and all original unknown/never_reopen/cleanup_pending states remain retained; do not hardcode actual inventory/counts as resource proof.

## Controller pre/post observations

For capture and execution independently, controller confirms all known project writers terminal and no legacy go-build writer, including non-locking go.sh; lock alone is insufficient. Acquire fresh three-sibling complete metadata baseline under the same lock. Current firecracker-code legitimately changed through authorized crypto runs, so do not demand the10:07historical digest; explain that delta from known receipts. go-mod and warden-lab remain subject to existing facts. New operation before/after sibling digests must match.

Keep original22scene metadata, journals/Q, owner-retirement unknown, sixsysctls and project-owned objects unchanged using the existing controller observation mechanism. Do not edit/reexecute old recovery or scan unrelated projects/host objects. Capture/continuation code contains no Docker or guard call; these controller checks remain external, reviewed and separately admitted.

After known terminal, record full source hashes, old intent/checkpoint/approval immutability, new journal facts, target metadata, siblings/original scene/Q/sysctls/owned objects and ordinary full resource guard. Failure/partial/result-fsync ambiguity is not success, and no retry/reset follows. Successful exit0+durable completed+independent postflight permits only separate evaluation of ordinary R+allQ/charges+ownimage+**new standard3,000,000,000B** under12e9 and memory limits. It does not authorize charge creation, PG/material/SQL/SCIM, cloud/identity/token, VM/host configuration, push or publication. Unlinked block statistics are not proof of whole-project reclamation.

Original cache fsync-fixture Minor and crypto concurrency Minor remain visibly deferred for their own scopes; new failure fixtures do not retroactively test those old paths. Task3/4 original opportunity counts, Task5actual42cells, Task6fix1of5 and full Goal remain unchanged/open.
