# Third physical operation: exact dual-history binding, implementation only

**DONE_WITH_CONCERNS for host code/native fixtures only.** Source and tested
commit: `0c7dedbf38499ee991f879e93e43b9f5df9bb7f4`; actual parent:
`05110d80665c2bb9dab8d8affdb3604f5bc8bf95`; previous review HEAD/FIX_BASE:
`2b86368b294b8621c91204bf5449066b12e83cc1`. Evidence is a separate commit after
source. This section is appended to the existing ignored task-4 report. The
[final controller ruling](../../controller-third-recovery-rulings.md) authorizes
implementation, finite fixtures and scoped review only. No actual third scene
operation is authorized or claimed here.

## Exact change and preserved history

Only the host coordinator, its affected test classes and recovery runbook changed.
The fixed new root is `recovery-a-py314-static-v1` under the original scene. The
old `recovery-a` (source8c) and `recovery-a-py314-v1` (sourceba8) remain immutable,
unsuccessful pre-daemon histories; they cannot be selected for execution or
cleanup by this source. No retry/version/history/workdir option exists.

The unchanged first `predecessor()` authenticates its existing two-record shape.
New `second_operation_document` is a closed ba8 historical constructor, with the
literal old kind/name/policy/source, original scene/source95, held old root
identity tuple, fresh first snapshot, historical initial admission and fixed
Q/H. It does not call the new-source constructor. New `second_predecessor`
authenticates exactly old root operation.json and inspect state/provenance/
material-admission records. It requires ordinary private directories and bounded
canonical single-link0600 records, exact source/helper/labels/objects-settled
state, unsuccessful/null IDs/Q5GB false/H736MB, and fresh full-label object
absence. Its old provenance must still bind old operation hash/metadata and the
first state hash. Initial and material admissions are independently validated;
legitimate different measurements are accepted. It never writes old records.

The second snapshot binds all four record hashes and metadata, current root/
phase metadata and source/helper/labels. Held FD/path identities, shapes and
records are rechecked. New `histories()` reads first, validates second against
it, then rereads first and requires canonical equality. New operation kind is
`physical-recovery-history-operation-v1`, containing `history={first,second}`;
new per-phase provenance uses `history_sha256`. The unchanged16384B bound also
limits the new encoded operation. Subsequent commands/transitions reauthenticate
both histories against the immutable new operation and provenance. The workflow
change is exactly `predecessor()` to `histories()` at initial admission.

The original first validator, admission/accounting, material/ABI/parser, I8,
helper/schema22/init, profiles, new-phase exclusive creation, cleanup selectors,
ordinary guard, Go/Task3/B/Gate/VMM code remain unchanged. A lost daemon response
continues to retain pending state, all applicable H and Q. An old-history drift
can block future work/cleanup; it cannot be repaired, reset or adopted here.

## Finite native TDD

All tests use tiny ordinary-owned temporary fixtures; Docker/object queries,
packaging/ABI and external execution boundaries are mocked. No real old history
or live subtree is read. Python uses `-B`; committed-source covering uses
umask0077. Raw logs are retained without editing.

1. Genuine behavioral RED at the existing `operation_read` boundary, before
   production changes:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.HistoryBindingTests.test_existing_operation_read_refuses_a_first_only_historical_document
   ```

   [Output](history-binding-red.log):1 test, **2 expected failures**, exit1,
   0.004s. The old reader accepted a first-only historical-schema document when
   second history was missing and when it existed but was unbound. Both failures
   are missing refusals at an existing method, not missing-method/setup errors.

2. Focused GREEN for the affected history/operation/workflow classes:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.HistoryBindingTests test_firecracker_recovery.OperationBindingTests test_firecracker_recovery.WorkflowTests
   ```

   [Output](history-binding-green.log):**19 PASS**, exit0,0.171s.

3. Exactly one covering of the same three affected classes after source commit
   at0c7dedb, with the same explicit command above:
   [output](python-tests.log), **19 PASS**, exit0,0.147s. No other host classes,
   material/parser/helper/Go/Task3 suites or historical test crawls were run.

The eight HistoryBindingTests cover the old boundary, legitimate two-history
binding with all six old files' bytes/metadata unchanged, distinct historical
admissions, closed old operation/provenance fields, terminal state/labels/Q/H,
object presence, missing/extra/link/mode/size/noncanonical/replacement refusals,
first-after-second drift and final rereads of each of four second records, later
second-history drift, and unchanged metadata size bound. Wrong state refuses
before new root/admission. The six OperationBindingTests retain first-validator
cases and exercise new root/phase exclusivity, operation/provenance/source drift,
FD pinning and repeated real fixture-tree block counting including both histories,
a retained public-package stand-in and new growth, plus all reservations/image
charges/full H. The five WorkflowTests include a real fixture durable phase
with mocked lost create response: pending state/H/Q survive and both histories
remain byte/metadata-identical. Restore refuses a new inspect that lacks this
operation's complete successful inventory. Existing physical-only receipt and
ordinary-plus-Q postflight fixtures remain covered; neither is actual evidence.

## Narrow source and evidence integrity

Run:

```sh
python3 -B docs/evidence/task-4/recovery-third-operation/0c7dedbf38499ee991f879e93e43b9f5df9bb7f4/verify-command.py
```

The [manifest](source-verification.json) and [output](source-verification.log)
verify exactly three source files against the committed source, three changed
existing functions (`operation_document`, `operation_read`, `execute_phase`),
three fixed additions and only the fixed WORK/SECOND_WORK/SECOND_SOURCE declaration
delta. The other48 functions/two classes and all remaining host AST are identical
to parent. The execute_phase AST differs by just one reader call. All test AST
outside the three named classes is unchanged. Fourteen helper/runtime/Gate/shared/
guard file bindings match parent and source. Only the immediate prior static-ABI
source index and its seven artifacts are checked; zero older indices are followed.
The named dual-history ruling and two public prerequisite JSON files also match
parent/source. Authored source/evidence files are0644; whitespace checks pass.

## Prerequisites, execution order and remaining concerns

The controller's already committed public closure-v2 and sealed-package-v2 at
d8f54d9 establish public host3.14.4/50deps/648inputs and successful public archive
construction:649 files,66,120,203 file bytes,66,662,400 tar bytes,
SHA25656f3570940a3119e7e9fe818fbe8e85c6e6d846f65d911e82445e58d40c09b61.
No implementer actual scan/ABI/ldd/closure/package ran. The retained public tar
and package.json remain in fresh R and cannot replace the new operation's own
durable state/provenance/material path. Historical R4,085,985,280+Q5GB+H736MB
=9,821,985,280 is not future admission or an ordinary guard pass.

The [source runbook](../../../../firecracker-recovery.md) gives the exact command
order. First obtain scoped independent review PASS and a separate controller
ruling for third actual. Under quarantine/no concurrent writers/project lock,
reauthenticate clean source/helper/original identities/records/CG/object absence,
both immutable histories and fresh all-R + all outstanding charges (Q once) +
all owned image charges + full new H736MB; declared services plus1.256GB must
fit16GB and disk12GB. Old recorded H stays736MB; retained old growth0 depends on
both exact authenticated pre-daemon settlements plus fresh full-label absence.
All actual old/new/public-package/Git/cache/evidence bytes count. Unknown actual
private shape/identity or labels refuse without inventing values.

Only then may the controller separately authorize one `inspect` at the fixed
third root. It must complete with actual exact22-schema inventory and own helper
absence before the same operation's exclusive `restore-traversal`; restore
requires ordinary whole-tree-plus-Q postflight, then an independent `postflight`
receipt. Commands keep the existing `--reviewed-exact-scene` and honest
`--other-service-memory-bytes` declaration. Missing/inconsistent history refuses;
partial root/provenance failures have no generic reset/cleanup path; pending
import/create/start never settle from empty lists/CLI exit/returned IDs/stopped
objects. Failure retains Q/applicable H and all history, with no fourth root or
automatic retry. Successful physical restoration never proves old Gate/Popen/
pidfd retirement. Any physical-only Q release remains a separate conditional
controller decision after actual recovery and ordinary postflight; this code
never releases Q.

Actual scratch ABI, helper profile, private history/schema22 and remount/chown
remain unverified. Ordinary guard still refuses root-owned live; original Q5GB
is unreleased, owner retirement cleanup_pending, creation unknown, node
never-reopen. The original VMM exit cause is unknown; unpersisted tail/WaitStatus
are irrecoverable. I7/Task4 acceptance remain open at causal round5, Task3 cap is
unchanged, B/Go/VM gates remain. No daemon/private scene/Go/cloud/GPU/VM/host-budget
mutation, actual physical operation, extra boot, cap reset or subagent occurred.
Source/evidence freeze is for scoped review, not actual acceptance.
