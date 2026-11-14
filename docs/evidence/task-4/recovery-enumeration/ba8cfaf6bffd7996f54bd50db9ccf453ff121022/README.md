# I9 necessary nofollow enumeration amendment

**DONE_WITH_CONCERNS for code/native fixtures only.** Source/tested commit:
`ba8cfaf6bffd7996f54bd50db9ccf453ff121022`; actual parent:
`ebd7496eb50d734cd9f137cbebea3036796cbc73`; previous material review HEAD/FIX_BASE:
`36c5856285c3b8b450b72004919e2d45e3bc5edc`. This evidence is committed separately
after source. The [I9 finding](../../review-recovery-material.md) and
[final cap adjudication](../../controller-recovery-material-rulings.md) govern
this single necessary physical-recovery safety amendment. Source05505be was not
executed on the actual runtime or scene; no actual attempt is being retried.

## Correction

The reviewer correctly identified that `os.walk(followlinks=False)` still calls
default-following `DirEntry.is_dir()` before the caller can omit a link. The
previous os.stat/os.open fixture guards missed this internal target lookup, so
their historical PASS did not establish the promised boundary.

Only `select_stdlib` changes in production code. It now obtains names from
`os.scandir` on held directory FDs and classifies each through explicit
FD-relative `os.stat(..., follow_symlinks=False)`. It never calls DirEntry
classification. Child directories are opened with O_NOFOLLOW, their held metadata
must equal the observed entry and retain trusted ownership/modes, and parent
metadata is checked after enumeration. Known aliases/object entries must still
match their authenticated own metadata. Unknown links/types refuse before target
lookup; existing exclusions apply to actual directories. Fixed names, alias copy,
object/header rule, byte/count caps and all remaining material behavior stay.

No host ABI, predecessor/operation, helper, profile, admission, pending cleanup,
I8, guard, Go/B/Task3 or runtime logic changes. The existing new fixed operation
root and inspect-once rule remain. No new operation, cap reset or boot is added.

## Finite verification

Every invocation used umask0077, `PYTHONPATH=scripts`, and Python `-B`. All trees
were isolated ordinary-UID temporary fixtures. Real scandir entries are wrapped
so default or explicit following `is_dir`, `is_file` and `stat` calls fail before
underlying target lookup. Separate guards forbid explicit omitted-target opens,
stats/resolution and require nofollow stat of the links themselves. No omitted
system target was accessed, including during RED.

1. Before any production edit, exactly one isolated RED:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.MaterialPolicyTests.test_enumeration_never_implicitly_follows_omitted_link_targets
   ```

   [Output](history-enumeration-red.log):1 FAIL/exit1/0.003s. The stack passes
   through the old `select_stdlib` and Python's frozen os.walk into the real-entry
   guard: `following DirEntry.is_dir for sitecustomize.py`. This is the exact
   implicit-following behavioral failure, not a missing API or fixture setup error.

2. After the minimal correction, the new regression and two related enumeration
   cases only:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.MaterialPolicyTests.test_enumeration_never_implicitly_follows_omitted_link_targets test_firecracker_recovery.MaterialPolicyTests.test_nofollow_enumeration_refuses_unknown_links_and_types_and_keeps_directory_exclusions test_firecracker_recovery.MaterialPolicyTests.test_nofollow_enumeration_rejects_directory_replacement_before_descent
   ```

   [Output](history-enumeration-green.log):3 PASS/exit0/0.011s. Five subcases in
   the second test cover unknown file link, directory link, excluded-name directory
   link, FIFO and a real excluded directory containing an unvisited link. The last
   test replaces a directory between nofollow entry stat and held child open;
   identity drift refuses descent. No following DirEntry call is accepted.

3. Exactly one committed-source affected-class covering atba8cfaf:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.MaterialPolicyTests
   ```

   [Output](python-tests.log):**12 PASS/exit0/0.034s**, the previous nine material
   tests plus three new enumeration tests. No whole host module, operation,
   unchanged helper, Go, Task3 or historical suite was rerun. Prior34PASS is
   historical source055 evidence, not a fresh full-suite claim for this source.

## Integrity and execution limits

Run `python3 -B docs/evidence/task-4/recovery-enumeration/ba8cfaf6bffd7996f54bd50db9ccf453ff121022/verify-command.py`.
The [manifest](source-verification.json) and [output](source-verification.log)
verify exactly three authorized changed files; only select_stdlib differs in the
host AST, with all50 other top-level host functions, constants/classes and imports
unchanged. Only the new material guard and three new test methods differ in the
test AST. Fourteen selected helper/runtime/Gate/shared/guard files match the
previous material source. The immediate prior material index and its11 artifacts
match indexed hashes/lengths and parent-commit bytes. Neither its older15-artifact
references nor the176-file history were traversed again. Source/authored evidence
are0644; source and authored evidence whitespace checks pass. Logs are unedited.

No actual system scan, ABI/version/import/closure probe, system package, Docker,
private predecessor/live access, recovery, remount/chown, Go/B/VM/cloud/GPU,
budget/host change or Q release occurred. Native tiny package fixtures and mocked
ABI/ldd calls in the authorized class remain fixture-only. Original Q5GB stays;
ordinary full guard still lacks a pass because the scene remains root-owned.
Original owner/Gate/API retirement and creation ambiguity remain unresolved;
tail/WaitStatus remain irrecoverable. I7 and overall Task4 acceptance remain OPEN
at round5; Task3 cap is unchanged. This is not a sixth VMM causal repair loop.

After the same reviewer's scoped I9/new-delta PASS, controller alone may freshly
authenticate/admit the existing new fixed inspect once. Real host/scratch ABI,
closure/package, predecessor shape, inventory, remount/chown and ordinary full
postflight are still unverified. The [existing runbook](../../../../firecracker-recovery.md)
retains stop-on-unknown, no-reset, pending H retention and unreleased Q. The original
physical-accounting, B and final-boot gates are unchanged by these fixture results.
