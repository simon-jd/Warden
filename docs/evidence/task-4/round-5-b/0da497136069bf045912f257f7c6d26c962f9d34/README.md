# Task4 final round5, resumed B: bounded VMM failure diagnostics

**DONE_WITH_CONCERNS — code and finite tests only.** Source/tested commit:
`0da497136069bf045912f257f7c6d26c962f9d34`; BASE and actual parent:
`f40934a5a3e6bc5f2d741120bcc5448ba996cd12`. Evidence is committed separately.
This report is appended to the original ignored task-4-report.md. Controller
performs independent new-delta review. No sixth causal round, VM boot, Q release,
new preparation, recovery operation, host configuration or cloud/GPU action ran.

A's previously committed actual traversal recovery/ordinary postflight is the
dependency premise, not retested here. Original scene/journals/authority/RunID
and Q5,000,000,000B remain retained; owner retirement is cleanup_pending,
creation outcome unknown and old node never-reopen. Original unpersisted tail /
WaitStatus remain irrecoverable. B improves evidence from future original owners;
it does not diagnose or repair the old VMM exit cause. Task4, Task3, matrix and
Goal acceptance remain open. No new boot is authorized, and retained Q prevents
assuming another5GB reservation fits.

## Six-file implementation

- `runtimes/firecracker/diagnostic.go`: a separate fixed16KiB VMM ring; snapshot
  readers copy at most16KiB. It counts dropped bytes and rejects cut first/last
  lines. Public console observations contain retained/dropped/partial byte and
  rejected-line counts, truncation, `untrusted=true`, and at most four fixed
  event enums: kernel panic, reboot requested, power down requested, agent init
  requested. An optional narrowly formatted kernel timestamp is stripped only
  for recognition. All unknown lines, arbitrary paths, API/protocol/environment/
  nonce/tenant bytes and suffix text are omitted. The console is not proof of a
  cause or trusted guest state.
- `process.go`: observation fields record cleanup involvement separately from
  pidfd signal result (`not_attempted`, `sent`, `already_absent`, `error`). The
  original `cmd.Wait`/done publication is unchanged; status is inspected only
  after done, which follows original Wait and its I/O copy completion. Known
  exited/signaled statuses come from that original ProcessState/WaitStatus.
  Missing owner, pending completion, absent status or non-exit Wait error never
  becomes exit0 or successful I/O. Signal names are fixed enums, with unknown
  retained for unlisted signals. A cleanup request before known completion is
  conservatively `cleanup_may_have_terminated`; it is never a causal inference.
- `vm.go`: VMM stdout/stderr use the new ring; tenant boundedLog and Logs retain
  their exact old1MiB prefix semantics. Startup/collect failure records are made
  after retire completes or refuses, so they include final available original
  Wait/I/O and console observations. Fixed phase labels identify preparation,
  jailer/API/guest readiness, API operation, bind/exec and collect boundaries.
  Original source SHA and RunID are validated fixed-length bindings; invalid
  bindings/phases become `unknown`. Failure type is a small error enum, never
  `err.Error()` or a generic string fallback. Root cause always remains unknown.
- `retire` now uses a named error return plus a diagnostic-only deferred wrapper
  and calls `process.noteCleanup()` before the existing cgroup kill. All original
  kill-empty, original-child Stop, reap, pidfd poll/close, scope removal, owned
  jail removal and retired-flag checks remain. Its public error is the bounded
  JSON envelope; Unwrap retains the original errors.Join chain for errors.Is/As.
  Driver.Reap/Kill and subsequent errors.Join therefore cannot reprint its raw
  original I/O/path error. `cleanup=complete/pending` describes this local retire
  result only, never opaque Gate/API/node retirement. ErrCleanupPending and
  ErrAmbiguous semantics remain unchanged.
- `diagnostic_test.go`: seven focused real-process/stream and bounded-schema tests
  described below. It is never a VM. `lab_test.go` changes exactly the approved
  TestFirecrackerBoot Wait-failure output line: keep the same success predicate,
  including exact `PASS uid\n` comparison, but print only the safe diagnostic
  envelope plus bounded exit/boolean/log-length/read-error-enum values. Neither
  raw tenant bytes nor original `e`/`re` formatting can bypass sanitization.
  Snapshot/conformance output branches are unchanged and were not executed.
- `scripts/firecracker_code.py`: only a fixed `diagnostics` selector and1GB host
  allowance are added. The selector is the controller-corrected literal
  `go test -p 1 -count=1 -v -run '^TestVMMDiagnostic' ./runtimes/firecracker`.
  No arbitrary command/regex/path option, capability/profile/bind/network/timeout
  change. Existing `code` mode supplies the sole final covering run.

## Public output retention boundary

No new node file, disk logger, path input or persistence authority is added.
The bounded error JSON is printed by the existing worker/lab error path and
retained by the unchanged controller attach path. Each record is below4KiB:
all strings are fixed enums or40/26-character bindings, numeric fields have
finite machine widths, and the console event list has at most four entries.
`bootFailure` stays below8KiB and puts the record first; its test supplies a full
1MiB tenant log and secret-bearing error text without emitting either.

For the sole separately gated `boot` mode, the device receipt is at most4KiB,
VMM console goes only to the private ring, and the selected worker runs one
TestFirecrackerBoot. Startup/Wait failures now emit one bounded diagnostic plus
fixed test/cleanup framing, rather than a quoted1MiB tenant log. This normal
failure path remains far below DeviceGate's unchanged1MiB attach ceiling.
The unchanged execute `finally` saves `device-attach.log` before object cleanup,
including when DeviceGate's nonzero child wait raises before run.log is written.
The ring/status record does not survive abrupt loss of its original worker
before emission, an attach transport loss, or an unrelated catastrophic output
failure; those stay unknown. No failed-original-owner status is reconstructed.

## Finite TDD and exactly one committed-source covering

All invocations used the approved ordinary UID1000 capless/no-network/RO-source
code profile, pinned local image
`sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d`,
fixed cached Go1.26.10 (also asserted by the diagnostic fixture), memory=swap2GB,
CPU2/PIDs256, GOMAXPROCS2, GOMEMLIMIT1500MiB, GOPROXYoff and umask0077. No pull,
install, arbitrary host Go or scripts/go.sh invocation occurred. Inspection
receipts include actual bounds, RO project/RW scoped cache mounts and cleanup.
[run-fixed.py](run-fixed.py) records exact guards/sysctls and exclusive logs for
the four finite invocations; it is an execution record, not a request to rerun.

1. [Pre-execution note](pre-execution-note.md): initial sandbox accounting refused
   trusted parent ownership before container creation. Authorized ordinary-host
   execution retained all checks. The first actual selector used the brief's
   literal `-p1` and failed Go command parsing before tests (`no Go files in
   /workspace`); [red.log](red.log)/[receipt](red.json) preserve this setup failure.
   Controller acknowledged the brief transcription error and approved only the
   literal correction to `-p 1`. It is not behavioral RED.
2. Genuine RED, before diagnostic production edits:
   `python3 -B scripts/firecracker_code.py diagnostics`, executed through the
   ordinary-host wrapper's `red-behavior` pass. [Log](red-behavior.log) /
   [receipt](red-behavior.json): two expected failing tests, one helper fixture
   PASS, exit1, FC0.014s. A harmless original child wrote over1MiB then the final
   allowlisted sentinel and exited23; old retention was1,048,576-byte prefix with
   `final=false`. A real net.Pipe protocol decoder rejected a secret-named field;
   old public error exposed that name and lacked the source/RunID/phase envelope.
3. Focused GREEN, same fixed diagnostics command: [log](green.log) /
   [receipt](green.json), **7 PASS**, exit0, FC0.018s. Includes bounded tail and
   sanitization; natural original exit23; actual cleanup SIGKILL; missing/pending
   owner/status; a real original child exiting0 whose output writer creates a
   non-exit Wait error (still unknown/I/O-unconfirmed/cleanup_pending); old tenant
   prefix retention; safe errors.Join/retire output; and boot output bounds.
   Synthetic incomplete ownedProcess values exercise otherwise unavailable
   owner/status states only; no adopted PID or forged retirement proof is used.
4. Source committed first. Then exactly one
   `python3 -B scripts/firecracker_code.py code` at0da4971:
   [cover.log](cover.log)/[receipt](cover.json), **59 PASS, 4 explicit live SKIP**,
   exit0. FC0.314s; guest0.005s; three command packages have no test files. The
   skipped cases are FirecrackerCapacity, FirecrackerConformance, FirecrackerBoot
   and SnapshotRestoreFasterThanBoot. Original pidfd/reap/FD-leak and ambiguous
   Gate-retirement tests passed. No actual device/VM/guest workload, broad SQL/
   runc/recovery suite, repeated covering run or historical evidence crawl ran.

## Fresh accounting and exact cleanup

Every run's ordinary preflight counted the full project, Q5GB, all own images
(actual0) and512MB new cache/output allowance; declared resident allowance was
2GB code+1GB host. All totals were below12GB/16GB. Every postflight counted the
actual entire project plus retained Q and1GB host allowance, with no own container
or image remaining. The six protected sysctls matched before/after each run.

| Pass | Preflight actual R | Additional Q+allowance | Postflight actual R | Removed exact code container |
| --- | ---: | ---: | ---: | --- |
| Selector setup failure | 4,182,736,896 | 5,512,000,000 | 4,182,740,992 | `d0a5f99ed08c115a0dc509aad00c33e1163a5679556f963381f72dc3691c845a` |
| Genuine RED | 4,182,757,376 | 5,512,000,000 | 4,185,387,008 | `994bfe5720db56b0e3436df82cfbb98ac9ee8653fd732e290a306a4ee99adfe9` |
| Focused GREEN | 4,185,419,776 | 5,512,000,000 | 4,188,286,976 | `2c11bb3c311baa5df16c9897d3535c3d579cdb6ea498e102633a478067d08d4c` |
| Committed covering | 4,188,356,608 | 5,512,000,000 | 4,191,244,288 | `20375e8ff8a0b9df20237f788cef4598bcaa632c2b31401f5944ef755c5224c8` |

The last observed ordinary total is9,191,244,288B including Q, before this new
small evidence bundle/Git growth. These observations are not future boot admission.
Original live scene and journals were never opened by tests. No charge was
rewritten, no host setting changed and no old A artifact/index was rechecked.

## Narrow verification and handoff

[verify-command.py](verify-command.py), [manifest](source-verification.json), and
[output](source-verification.log) verify the six committed source files, original
startOwned, exact tenant boundedLog, Wait/Kill/Timings, original Stop checks after
removing observational bookkeeping, original retire checks after removing its
diagnostic defer/note, and the one approved boot assertion line. The Python
profile AST differs only by the literal selector and host allowance. Thirteen
runtime/Gate/device/guard interfaces match BASE; no old recovery/index is read.
The verifier also authenticates this bundle's four own run receipts against
bounds, exact create/remove IDs, Q-inclusive guards, test counts and sysctls.
Source/authored evidence modes are0644. Raw logs are retained without editing.

Self-review found no remaining implementation blocker. Unknown console lines
are intentionally discarded, so a future record may remain causally inconclusive;
no signal or untrusted event alone proves cause. The review still needs to assess
this new diagnostic/error surface. A real VMM/attach path was not executed, and
the original failure remains unresolved. Controller's unrelated coordination
and Task5 documentation edits remain unstaged and outside these commits. After
evidence freeze, Git/index ownership returns to controller for scoped B review.
