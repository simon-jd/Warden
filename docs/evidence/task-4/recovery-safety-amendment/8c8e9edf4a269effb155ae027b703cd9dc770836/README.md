# Necessary recovery safety amendment — pending-operation settlement

**DONE_WITH_CONCERNS for the authorized narrow code amendment.** Source/tested
commit `8c8e9edf4a269effb155ae027b703cd9dc770836`; actual parent
`ed65c4757a23678a0845d4184c32d1ab0f179d78`; previous A reviewer HEAD/FIX_BASE
`078329de70abb59bfdce20840d52dac30482a374`. Evidence is committed separately after
the source. This is the controller's one conservative necessary-recovery safety
amendment, followed by one review of this delta by the same A reviewer. It is
not a sixth VMM causal repair round or an additional boot opportunity.

## Correction

The review demonstrated that an unresolved import could be marked settled from
currently empty object lists after only the local CLI exited. The controller
identified create/start as the same uncertainty boundary. The old coordinator
could remove staging and save `objects-settled` without a terminal observation.
Q remained booked, but that did not justify settling the separate736MB H.

The host coordinator now validates a closed state/identity policy on both state
read and cleanup entry. `import-pending`, `create-pending` and `start-pending`
always refuse before any object discovery, deletion, unlink or state write,
even with known IDs or currently empty/stopped objects. H, Q, the original
pending record and staging remain unchanged. Inconsistent settled/success
flags, missing required IDs, mixed IDs and unknown shapes also refuse.

Legitimate cleanup remains narrowly available. `material-pending` requires both
IDs absent, false flags and no exact-label objects; only its own bounded staging
can be removed. Unexpected objects contradict the pre-daemon premise and refuse.
`result-validated` requires both immutable IDs and false flags; the existing
exact ownership/stopped-object/scope checks can clean up this positively
validated successful result. `objects-settled` and `complete` permit only their
coherent flags/IDs and absence rechecks, with no rewrite or deletion. The
coordinator no longer discovers and fills a missing ID during cleanup.

No daemon cancellation, polling, retry, timeout, proof-input or authority scheme
was added. Pending H may remain reserved indefinitely. The original5GB Q is
never released; original owner retirement remains cleanup_pending, creation
outcome unknown and the old node permanently quarantined. The full closed table
and exact refusal semantics are in [the runbook](../../../../firecracker-recovery.md).

## Finite TDD and committed-source verification

All runs used umask0077 and Python `-B`. New fixtures use real ordinary-UID
temporary private state/tar files, the actual cleanup functions and mocked
Docker/object/cgroup boundaries. Chown and remount are never invoked. Q/H and
the on-disk and in-memory original state are checked unchanged on refusal.

1. **Real RED before production edits**, against the actual prior coordinator
   with only the new test present:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.CleanupStateTests.test_pending_operations_never_settle_from_empty_or_known_lists
   ```

   [Unedited output](history-pending-red.log): exit1, one test with **10 expected
   subcase failures**, all `Refusal not raised`. Cases cover import with absent
   or known image, create with absent or known CID, and start with both IDs;
   each is paired with empty or known matching current object lists. These are
   real prior-code behavioral failures, not fail-closed stubs or fixture errors.

2. **Focused GREEN** after the cleanup/state correction:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.CleanupStateTests
   ```

   [Unedited output](history-state-green.log): **4 PASS /34 subcases, exit0,
   0.022s**. Ten pending cases now refuse without even querying Docker;
   18 malformed/inconsistent cases refuse both state read and direct cleanup;
   five positive cases retain pre-daemon/validated/settled/complete behavior;
   one case rejects unexpected objects in pre-daemon state. Positives use real
   fixture tar unlink/state persistence and mocked exact-object deletion.

3. **Exactly one committed-source host covering run at8c8e9ed**:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery
   ```

   [Unedited output](python-tests.log): **19 PASS, exit0,0.065s**. The unchanged
   helper test module and old Firecracker/Go/SQL/runc/Task3 suites were not rerun.
   Earlier25PASS remains historical evidence atdbc6d648, not a claimed new run.

The [narrow verifier](verify-command.py), run once as `python3 -B` using its exact
repository path, confirms precisely the three authorized changed paths and
current source hashes/modes. Only `state_read`, `cleanup_phase` and the new
`validate_phase_state` differ in the host implementation; all35 other host
functions and other top-level AST nodes match the parent. Fourteen selected
helper/test/runtime/Gate/profile/ordinary-guard bindings match original A source.
[Verification output](source-verification.log) and [manifest](source-verification.json)
record this. No176-file historical evidence crawl was repeated. Source
`git diff --check` passed. Raw RED output retains unittest's original trailing
progress-line space; authored evidence whitespace checks exclude raw log files.

## Execution limits and handoff

No actual package/ABI probe, Docker query/mutation, private scene inventory or
read, helper/remount/chown, Go operation, B implementation/test, boot, cloud/GPU,
budget/host setting or charge release ran. Existing tiny host packaging fixtures
remain fixture-only. The helper/init, profile, resource caps, schema22, runtime,
shared Docker helpers and ordinary guard are unchanged. Source dbc6d648 and
evidence3b1c3f4 are immutable history; this directory overwrites no old artifact.

No fresh ordinary guard pass is claimed. The last accepted stopped-scene record
still reports unreadable root-owned live and Q=5GB unreleased. Unknown actual
Python/ELF packaging, Docker configuration, mount/chown ABI, scene shape and
ordinary postflight remain unverified. The complete A execution gate stays
unexecuted until the same reviewer checks this delta. If it fails, A stays
unexecuted and Q/H remain reserved. Pending actual operations would require
separate exact physical-recovery evidence/ruling, without another core loop.
Original I7/Task4 acceptance, owner/creation ambiguity, Task3 Ready and API
retirement remain OPEN; this amendment earns no new boot attempt.
