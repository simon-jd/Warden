# Exact successful static dependency result — parser-only amendment

**DONE_WITH_CONCERNS for code/parser fixtures only.** Source and tested commit:
`d8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7`; actual parent:
`1493f522be2ec95d34591f4f6d59796a21a3e059`; previous reviewer HEAD/FIX_BASE:
`9aa87b2c5bf6b485cdb0ea6f182153edbf4835e0`. Evidence is committed separately
after source; the existing ignored task report receives this same section.

## Evidence and exact correction

The [controller diagnostic](../../public-abi-diagnostic-v1.json) at sourceba8
stopped on its third dependency call for the authenticated public extension
`_testsinglephase.cpython-314-x86_64-linux-gnu.so`: exit0,19 stdout bytes
`\tstatically linked\n`, empty stderr. The diagnostic separately recorded a
validated3.14.4 host ABI receipt. Its fresh R+Q+H was9,754,376,704B; this historical
value is not admission for any new action. No phase/archive/daemon mutation or
live descendant access accompanied that public diagnostic.

Under the [final exact ruling](../../controller-recovery-material-rulings.md),
production code adds one line in `dependencies`: code0 with normalized stdout
exactly `statically linked` and entirely empty stderr returns an empty dependency
set. The existing64KiB combined output bound runs first. No additional line,
different literal, whitespace-only stderr or mixed dependency/static output is
accepted by this branch. All previous nonzero-exit handling, dynamic path parsing,
missing-library and unknown-output refusals remain unchanged.

Only the parser, its dedicated test class and a three-line runbook explanation
change. The existing dynamic-dependency parser test moves unchanged from
BoundaryTests into DependencyParserTests so its covering run excludes unrelated
command/Docker fixtures. No material selection/omission, I9 enumeration, ABI
program, predecessor/operation, helper/profile, admission, I8 cleanup, guard,
Go/B/Task3/Gate or VMM logic changes. Existing failed-settled8c/ba8 phases are not
reset or rewritten. No new operation root or boot opportunity is provided.

## Finite parser verification

All invocations used umask0077, `PYTHONPATH=scripts`, and Python `-B`. Inputs are
literal bytes in memory; no runtime ABI/ldd or subprocess command is executed by
these parser tests.

1. Genuine focused RED before the implementation edit:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.DependencyParserTests.test_observed_zero_exit_static_output_has_no_dependencies
   ```

   [Output](history-static-red.log):1 expected error/exit1/0.001s. The existing
   parser raises `Refusal: unknown_python_abi` on the exact observed bytes. This
   is the old behavioral rejection, not a missing method or fixture setup error.

2. Minimal focused GREEN for four new parser methods:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.DependencyParserTests.test_observed_zero_exit_static_output_has_no_dependencies test_firecracker_recovery.DependencyParserTests.test_normalized_literal_keeps_the_existing_output_bound test_firecracker_recovery.DependencyParserTests.test_zero_exit_rejects_any_static_stderr_and_nonliteral_output test_firecracker_recovery.DependencyParserTests.test_existing_nonzero_cases_remain_unchanged
   ```

   [Output](history-static-green.log):4 PASS/exit0/0.001s. Cases cover exact and
   whitespace-normalized literal, exact64KiB/oversized boundaries, nonempty and
   whitespace-only stderr, empty/different/mixed stdout, and preserved positive/
   negative nonzero cases.

3. Exactly one committed-source affected parser-class covering atd8f54d9:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.DependencyParserTests
   ```

   [Output](python-tests.log):**5 PASS/exit0/0.001s**, including the unchanged
   relocated dynamic-dependency/missing-library test. No other host, material,
   operation, helper, Go, Task3 or historical suite was rerun.

## Narrow integrity and remaining gates

Run `python3 -B docs/evidence/task-4/recovery-static-abi/d8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7/verify-command.py`.
The [manifest](source-verification.json) and [output](source-verification.log)
verify exactly three authorized files. Removing the single expected new AST
branch makes the entire host AST identical to parent; all50 other functions and
all other nodes remain unchanged. The relocated parser test is AST-identical;
all non-parser test AST remains unchanged. Fourteen helper/runtime/Gate/shared/
guard bindings match prior source. The immediate prior enumeration-source index
and its7 artifacts match indexed lengths/hashes and parent bytes. No older11/15/
176-artifact chain was followed. The actual diagnostic JSON also matches parent,
and the fixture's exact19 bytes/empty stderr match its recorded SHA256/lengths.
Source/authored evidence are0644; whitespace checks pass; logs are unedited.

The implementer ran no actual system scan, ABI/ldd/closure, system package,
Docker, private predecessor/live access, operation, Go/B/VM/cloud/GPU or host/
budget action. Original Q5GB remains; ordinary full guard remains blocked by the
root-owned scene. Original retirement/creation ambiguity, I7 and overall Task4
acceptance remain OPEN at causal round5; Task3 cap is unchanged. The VMM exit
cause remains unknown and its unpersisted tail/WaitStatus remain irrecoverable.

Same-reviewer parser/new-delta review must precede controller's one potential
public-only closure validation with fresh admission/deadline. No new-source
closure or scratch ABI success is claimed here. A complete public closure is
only a material prerequisite: a third physical operation needs its own concrete
immutable-history/execution ruling and review. Existing roots cannot be reused,
and this parser amendment does not authorize another scene operation or boot.
