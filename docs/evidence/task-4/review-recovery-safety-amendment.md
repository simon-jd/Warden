- **I8 — unresolved-operation envelope settlement: ADDRESSED at source.** `scripts/firecracker_recovery.py:651` validates state before cleanup; `:653` unconditionally rejects `import-pending`, `create-pending` and `start-pending` before helper discovery, deletion, unlink or state writes. Known IDs and current empty/stopped-object listings cannot bypass refusal. The original pending record, staging, H and Q remain unchanged.

- **Check — inconsistent state and bindings:** the closed policy at `scripts/firecracker_recovery.py:597` rejects contradictory settled/success flags and missing or mixed identities. `state_read` retains exact source, mode and helper-hash binding (`:613`). Cleanup no longer discovers and fills missing IDs. The create/start extension correctly addresses the same source boundary; the earlier reviewer’s executed reproduction covered import only.

- **Check — legitimate cleanup preserved:** `material-pending` requires absent IDs and empty exact-label listings (`scripts/firecracker_recovery.py:598`, `:663`). `result-validated` requires both IDs and retains existing exact-object cleanup checks (`:602`, `:668`). Coherent `objects-settled` and `complete` states perform absence rechecks without rewriting or deleting (`:658`). The runbook’s closed table and indefinite pending-retention semantics agree with the code (`docs/firecracker-recovery.md:153`).

- **Check — recorded tests support the correction:** `scripts/test_firecracker_recovery.py:268` covers ten pending combinations and asserts unchanged memory/disk state, retained staging and no Docker/state-write calls. Eighteen inconsistent cases cover both state reads and cleanup (`:283`); five positive cases and unexpected pre-daemon objects cover preserved behavior (`:304`, `:329`). Archived output records the prior-code RED with ten failures, focused four PASS/34 cases, and committed-source affected-host19 PASS. No tests were rerun during this review.

- **Check — bounded scope/provenance:** read the complete four-commit `078329d..96b2016` package, appended report, seven indexed artifacts and narrow verification commands/results. Product changes are confined to the three authorized paths and the stated state/cleanup functions. The controller’s35 unchanged-function/14-binding and prior-A27-artifact checks are consistent with the supplied delta; no historical integrity crawl was repeated.

- **New Critical: None. New Important: None. New Minor: None. Out-of-Scope Observations: None.**

- **Spec verdict: PASS** for this conservative safety amendment. It preserves unresolved H/Q without adding cancellation, polling, retry, proof inputs or authority.

- **Quality verdict: PASS** for the scoped delta. The explicit state table and behavioral regression cases close the demonstrated defect while preserving legitimate cleanup.

- **Execution readiness: PASS at the A source/plan gate.** The previous source blocker is closed. Controller-only staged A execution remains subject to the existing fresh identity, admission, inventory and postflight checks. This verdict provides no B or boot authorization.

- **Cannot Verify / actual limitations:** actual packaging/ELF closure, Docker configuration, mount/chown ABI, live scene shape and ordinary postflight remain unverified. This review performed no tests, Git commands, writes, subagents or actual operations. A and B remain unperformed; Q=5GB remains unreleased. I7, Task4 acceptance and original-owner/Gate/VM/API retirement remain OPEN.

- **Amendment verdict: All scoped findings addressed; no new Critical/Important breakage.**
