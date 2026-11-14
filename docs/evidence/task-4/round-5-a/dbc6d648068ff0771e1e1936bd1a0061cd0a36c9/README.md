# Task4 fix round5/5 — A implementation handoff

**DONE_WITH_CONCERNS for A code/native fixtures only.** Source and tested commit:
`dbc6d648068ff0771e1e1936bd1a0061cd0a36c9`; parent:
`ef7fd7b83bd9d7989c4246f6be1137868b2f9984`; FIX_BASE:
`a683b6e580200ec522012f59c30a029a83a3922d`. This directory is committed separately
as evidence after the source. The controller's next step is one independent A
safety/source review, not actual acceptance. No implementation or test of B ran.

## Result and unchanged authority

The new fixed host coordinator and sealed helper implement the reviewed exact
stopped-scene admission, capless RO metadata inventory, immutable inventory
ingress into a separate restore image, and held-FD directory-only restoration.
The complete22-entry required schema, its source95 creation/cleanup derivation,
resource calculation, exact commands and per-stage failure rules are in
[the source runbook](../../../../firecracker-recovery.md).

Each material/import/create/start transition freshly counts R and E plus the
whole736MB helper envelope. Only the fixed live dev/inode is covered once by
the existing5GB Q; any other unreadability stops. All ordinary guard code is
unchanged. The final recovery path counts the readable entire tree **plus Q**
using that guard, checks protected sysctls, retained metadata and independent
original/helper object and scope absence. The fixed program cannot release Q.
Labels/envelope/source/known IDs are fsynced before mutations; lost responses
preserve uncertainty. Separate cleanup can remove only exact stopped helper
objects and its own tar, never retry, kill a running helper, or settle Gate.

The original third boot did start actual VMM/guest kernel and then exit before
Ready; cause stays unknown. The old prefix buffer and original WaitStatus were
memory-only and are irrecoverable. No private body reader or fake log recovery
was added. Original owner retirement stays `cleanup_pending`, creation outcome
unknown, the consumed RunID/authority survive, and the old node must never be
reopened or registered. Physical traversal recovery is not original Gate,
Popen/pidfd, VM or API retirement evidence.

## Finite native verification

All invocations used umask0077/Python `-B`. At committed source `dbc6d64`, exactly
one final affected-suite command ran:

```sh
PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery test_firecracker_recovery_init
```

[Unedited covering output](python-tests.log): **25 PASS, exit0,0.056s**. No
unchanged Firecracker Python, Go, Task3, SQL/runc or other broad suite was run.
Tests use ordinary-UID temp files and real O_PATH/directory FDs, sparse asset
fixtures, tiny streamed tar fixtures, literal/mocked Docker/ABI transcripts and
harmless original Python child pipes for bounded output/timeout/reap. All chown,
remount, Docker and ordinary full-postflight calls are mocked. Tests verify real
temporary inode replacement, unknown entries, special/link/mode/size refusal,
immutable inventory embedding, directory-only mutation order, partial-failure
RO remount attempt, resource/permission profiles, lost-create retention and Q
included in the postflight call. These are not kernel mount/CHOWN, Docker ABI,
real recovery, actual guard or retirement acceptances.

Focused RED/GREEN history is retained unedited and belongs to the working tree,
not to the frozen source. Fail-closed positive-path stubs first refused valid
inventory/mount, restore/ingress, accounting/package, profile, command/ABI/cleanup,
anchor and workflow cases. Corresponding `history-*-green.log` files record the
small selected follow-ups, culminating in the finite covering run above.

- [Focused inventory RED](history-focused-inventory-red.log) has two expected
  failures before implementation; [GREEN](history-inventory-green.log) has two
  PASS. [Restore RED](history-restore-red.log) has two expected failures.
- [Host RED](history-host-red.log), [profile RED](history-profile-red.log),
  [boundary RED](history-boundary-red.log) and [anchor RED](history-anchor-red.log)
  cover the new fixed functions before their positive behavior existed; their
  matching GREEN files are preserved. Profile/runtime gives three selected
  PASS, command/ABI/cleanup three PASS, and anchor one PASS.
- [Atime RED](history-atime-red.log) is a real production-comparison defect:
  atime-only changes from reading a source were incorrectly treated as content
  identity changes. Comparing the explicit metadata fields while excluding
  atime produced [one PASS](history-atime-green.log), while preserving checks
  for inode, owner, mode, links, size, blocks, mtime and ctime.
- [Workflow RED](history-workflow-red.log) records one positive-receipt failure
  and one fail-closed-stub error; [GREEN](history-workflow-green.log) has two PASS,
  including durable full labels/H/Q before a simulated lost create response.
  [Refusal RED](history-refusal-red.log) is a missing-evidence stub error;
  [GREEN](history-refusal-green.log) proves bounded enum evidence is saved while
  arbitrary loader/fixture text is not copied. Postflight and archive-ingress
  focused GREEN logs add validation coverage; they are not claimed as distinct
  behavioral RED observations.

Two historical fixture/harness problems are explicitly **not** production RED:
[initial inventory log](history-inventory-red.log) mixed dependent missing-stub
errors with failures and its shell wrapper accidentally returned cat's exit0;
the subsequent focused RED corrected the wrapper and observed exit1. The
[initial helper follow-up](history-helper-green.log) failed an alleged negative
case because sparse files actually had zero allocated blocks and the fixture's
"wrong" value was also zero. Changing only that test value to measured+1 made
it a real negative; [the next12-test result](history-host-green.log) passed. Both
original logs remain, with no claim that either established a production bug.

## Provenance, resource limits and remaining work

[Source manifest](source-manifest.json) binds five new source/doc/test files and
59 unchanged runtime/Gate/interface/profile files. No existing runtime, Gate,
ordinary guard, Task3 helper or Go code changed. [Public integrity verifier](verify-command.py)
ran once using `python3 -B` and confirms **176 prior tracked Task4 files byte/mode
identical**, plus all11 old artifact indexes /143 referenced entries matching
their published lengths and hashes. [Result](old-evidence-verification.json)
and [output](evidence-verification.log) include controller live evidence and the
round5 ruling. `git diff --cached --check` passed before source commit.

There was **no** actual installed-runtime packaging, ldd/ABI probe, image
import/create/start, Docker query/mutation, private scene inventory/read,
remount/chown, cgroup/device/BPF/KVM operation, Go container/test, prepare or VM.
Only explicitly authorized native fixtures and public source/evidence were
accessed. No host setting, budget, cloud/GPU or Task3 cap change occurred. The
controller's separate Azure checkpoint is its evidence, not implementer execution.

No fresh full-tree/ordinary admission is claimed: the last accepted public
postflight still reports root-owned live unreadable and Q=5GB unreleased. The
736MB figure is a prospective conservative helper envelope, not measured
runtime growth or a test peak. Actual existing Python/ELF closure, Docker Config,
mount ABI and source-derived scene shape remain unverified until controller
execution after independent review; unknowns refuse without fallback or schema
widening. Any partial recovery/running helper remains quarantined and charged.

The runbook's order is inspect, bounded receipt review, restore, unchanged full
postflight; any failure stops. A always retains Q. A separate controller-only
physical accounting decision requires all ruling conditions and carries no
Gate proof. B must be separately resumed after actual A and ordinary postflight;
only then can its bounded diagnostic repair/tests/review precede at most one
final evidence boot. Unknown boot cause is not guessed, and the Task4 five-round
cap does not permit a sixth same-core repair/retry. Task4/Task3 Ready/API retirement
and the overall Goal remain OPEN.

Evidence formatting note: the unedited history-helper-green.log retains one unittest progress-line trailing space before its failure output. The evidence whitespace check excludes raw *.log files; source and authored evidence pass. The log was not normalized.
