# Exact Python3.14 material and operation binding — native implementation evidence

**DONE_WITH_CONCERNS for code/native fixtures only.** Source and tested commit:
`05505bebb316a180c39e6e75f4a101e3c57224f1`; actual parent:
`0af30b0fae2f844651d37b996c455782b11bdaa2`; previous A reviewer HEAD/FIX_BASE:
`96b20165e1bf1ba24e71e11b5487a9cc637692c0`. This directory is the later separate
evidence commit. Original runtime95 and recovery8c history remain unchanged.

## Result and precise scope

Only the host coordinator, its native test module and runbook changed. The
[material ruling](../../controller-recovery-material-rulings.md) and controller's
pre-freeze exact python.o supplement govern this work. That supplement is at
`.superpowers/sdd/2-warden-security-plan/task-4-python314-object-material-ruling.md`;
controller will archive its ruling/public-header evidence after this handoff.
The implementer did not rerun that public-header probe.

The package policy authenticates exactly three Python3.14 symlinks. It copies the
fixed public sysconfig sibling under both canonical/alias regular names, hashes
and charges both, and omits the exact sitecustomize and development-link names
without accessing their targets. Unknown aliases, changed ownership/link/type,
missing entries, unsafe target metadata/xattrs, dependency conflicts and cap
overflow refuse. Only the fixed11504B development python.o is additionally omitted
after0:0/0644/nlink1/no-xattr, stable FD/path identity and its exact20-byte ELF
header/hash check. It is neither copied nor passed to ldd. Both static archives
remain selected; unknown non-runtime ELF refuses without a generic skip.

The fixed host ABI program is code only in this evidence. Its authenticated
Python3.14 command uses literal-I/-S/-B, the existing empty stdin/scrubbed env,
the helper imports, sysconfig and both fixed public module names; verifies flags,
version and absent sitecustomize; and resolves libc mount without calling it.
Output is a closed enum/bool/numeric patch-version receipt, stdout≤16KiB,
stderr≤4KiB, unchanged30s deadline. Input identities are rechecked after it.
Neither fixture command assertions nor AST inspection proves real host/scratch ABI.

The one new fixed operation `recovery-a-py314-v1` exclusively creates/fsyncs its
root and immutable operation receipt, then its inspect phase. It authenticates
the old ordinary-owned exact two-file pre-daemon predecessor, source8c, helper
hash, full labels and fresh object absence, settled=true/success=false/null IDs,
Q5GB unreleased and recorded H736MB. Predecessor bytes are never rewritten or
used as a successful inventory. New operation source/policy/helper/scene/root,
predecessor hashes/metadata and admission bind to private host provenance beside
unchanged raw helper receipts. Later commands/transitions reauthenticate this
binding. Restore can consume only this operation's successful inspect.

Fresh accounting includes every old/new readable project artifact, all charges
and images, plus the full new H at each material/import/create/start transition.
The material calculation is repeated after creating initial operation/state/
provenance records. No existing operation is reset/adopted; no alternate root,
third helper mode, new mount/profile, automatic Q release or new boot is added.
Existing pending import/create/start refusal is byte/AST unchanged.

## Finite native validation

All tests used process umask0077, `PYTHONPATH=scripts`, and Python `-B`. Temporary
ordinary-UID files/FDs supplied all package, operation and ownership fixtures.
Public-root ownership is fixture-patched only; it is not a host UID0 attestation.
Docker, runtime ABI/ldd, mounts and object boundaries were mocked. Existing bounded
command tests execute only harmless fixed print/sleep fixture subprocesses.

1. Before production edits:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.MaterialPolicyTests test_firecracker_recovery.OperationBindingTests
   ```

   [Real RED](history-boundary-red.log):2 tests,3 expected behavioral failures,
   exit1. The previous implementation accepted both forbidden archive names and
   reused an existing operation root. These were not missing-method failures.

2. Focused implementation runs used:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.MaterialPolicyTests test_firecracker_recovery.OperationBindingTests test_firecracker_recovery.WorkflowTests.test_lost_create_response_keeps_durable_labels_envelope_and_charge
   ```

   [First output](history-focused-first.log):13 tests,2 implementation errors.
   Shared dup-FD offsets exhausted the second alias archive copy; the fixed ABI
   source used invalid import syntax for hyphenated sysconfig module names.
   Corrections seek each copied FD before tar streaming and use the two literal
   `__import__` calls. [Next output](history-focused-green.log):13PASS/0.040s.
   Added exact link metadata and post-ABI input-drift coverage plus corresponding
   identity rechecks: [focused output](history-final-focused-green.log),15PASS/
   0.048s. A final source self-check tightened private snapshot pre-open/held-FD/
   pathname equality; its inode-swap regression and affected operation fixtures
   passed with `PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery.OperationBindingTests`:
   [6PASS/0.023s](history-snapshot-green.log).

3. Exactly one committed-source host covering run at05505be:

   ```sh
   PYTHONPATH=scripts python3 -B -m unittest -v test_firecracker_recovery
   ```

   [34PASS, exit0,0.111s](python-tests.log), comprising the previous19 tests and
   15 new tests. No unchanged helper, Go, Task3, SQL/runc or broad historical suite
   was rerun. This is the only full affected-module covering run in this scope.

New cases cover exact copies/omissions and byte accounting, guarded omitted-target
access, object20-byte-only reads, metadata/type/mode/size/link/xattr/owner/header
refusal, no ldd on the omitted object, unknown ELF refusal, stable input/alias/
FD identities, fixed sanitized ABI output, predecessor shape/state/object refusal,
exclusive operation creation, immutable provenance/drift, and fresh real fixture
R with image/other-charge growth plus full H at four transitions. Previous pending
cleanup and lost-create-response preservation remain covered.

## Narrow integrity and remaining actual gates

Run `python3 -B docs/evidence/task-4/recovery-material/05505bebb316a180c39e6e75f4a101e3c57224f1/verify-command.py`.
The [manifest](source-verification.json) and [output](source-verification.log)
confirm exactly3 authorized source paths;5 changed old host functions plus13 new
functions/one material class;33 unchanged old functions, including cleanup policy,
profiles, caps, account/admitted, bounded-command and ordinary postflight; and14
unchanged helper/runtime/Gate/shared/guard bindings. Two current historical indexes
and their15 referenced artifacts retain their indexed and parent-commit bytes.
No176-file crawl was repeated. Source and authored evidence are0644. Raw log
whitespace is retained and excluded from authored-evidence whitespace checks.

The [first verifier output](history-verification-initial.log) stopped on its
unsupported assumption that historical controller README filesystem mode was0644.
The final verifier records observed historical modes without normalizing them,
while checking their indexed lengths/hashes and parent bytes. This was an evidence
checker assumption, not a recovery-code test failure; no old file was changed.

No actual package/version/import/ABI probe, omitted-target access, Docker query or
mutation, private live or predecessor read, recovery operation, remount/chown,
Go/B/VM/cloud/GPU or host/budget change ran. Original Q remains5GB; ordinary full
guard still refuses the root-owned scene. This work claims no new admission.
Original owner retirement remains cleanup_pending, creation unknown and old node
never-reopen; original output tail/WaitStatus remain irrecoverable. Task4 remains
5/5/unaccepted and Task3 cap unchanged; no sixth causal loop or extra boot is earned.

The [runbook](../../../../firecracker-recovery.md) gives strict inspect-once,
conditional restore, and ordinary whole-tree-plus-Q postflight order. A scoped
material/predecessor/ABI-plan source review must precede any controller execution.
Actual public ABI/closure/package metadata, predecessor shape, scratch imports,
scene schema, mount/chown and ordinary postflight remain unverified. Every unknown
premise stops with applicable H/Q retained. Partial setup has no generic reset;
pending daemon operations cannot settle from empty lists. Separate physical-only
Q release, B and any final diagnostic boot remain controller decisions under the
existing rulings, never consequences of these fixture results.
