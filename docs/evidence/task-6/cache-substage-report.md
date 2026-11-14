# Task6 resource substage report — code/fixture layer only

Delegated identity implementer; resource-substage BASE `0a18e1aa54619097cfc90fa0488ddb3e2269ac25`; overall Task6 BASE `84018e512d78156283ae64aab62ccb76d5d20801`.

The fixed retired-cache entrypoint and private filesystem fixtures are frozen for controller's independent source/execution-plan review. Source commits are `0ed796d0591b0d57fb66746616596b2427f4ee60` and `7be15fa29aafc7cf84dcd488dbf8aadc22ae2655`. Only `scripts/identity_cache.py` and `scripts/test_identity_cache.py` were changed. The shared trusted_directory, canonical resource charge schema, old recovery modules, legacy scripts and current Go profile were not modified.

The implementation first validates a fixed Go-cache layout without reading file bodies, saves durable original/target permission metadata, narrows only owned recognized entries through held FDs, rescans with strict permissions, and deletes only known derived files/empty executable-cache directories. It preserves buckets/metadata and receipts, and refuses retries after an intent or partial failure. This follows the controller's supplementary permission ruling prompted by the observed0775/0664 old-cache permissions. It does not loosen shared path trust.

## Real fixture execution record

Every listed run saved pre/post manifests of139source files (tracked Go/Python/shell/SQL/Terraform/TOML/YAML plus root build manifests and both new source files), exact command, output, duration/exit and source equality. No earlier RED was reconstructed. Evidence directories are immutable records of the source at each run; final source differs from earlier records as expected.

| Evidence | Actual command/result | Interpretation |
|---|---|---|
| `cache-red-01/` | `python3 -B scripts/test_identity_cache.py`, exit1 |Real setup/import RED: identity_cache module absent; no claim of behavioral assertions executed |
| `cache-fixture-02/` |same command,17tests,exit0 |Strict FD scanner/deletion private fixtures |
| `cache-red-03/` |same command,24tests,exit1/errors9 |New tightening API absent; API-shape errors, not proof of a security behavior failing |
| `cache-fixture-04/` |same command,24tests,exit0 |Durable-intent fixed permission-tightening fixtures |
| `cache-cover-05/` |same command at source0ed796d,26tests,exit1/error1 |New whole-entrypoint fixture hit unchanged trust check: sandbox `/tmp` is presented as owner65534 |
| `cache-cover-06/` |same command at source7be15fa,26tests,exit0 |Final finite covering after fixture-parent correction; no source changed during run |

Final26fixtures cover recognized deletion with metadata preservation and no cache body reads; malformed names/layout/types/index size; symlink root/bucket/file, hardlinks, wrong owner and group-write rejection; parent/file substitution; updates between scan and deletion; lock contention/unsafe lock; rejected CLI arguments; permission-intent ordering; refusal to unlink before completed tightening; original-mode whitelist; persistent intent and partial narrowing on failure; fsync failure before chmod; and a complete main-flow run against private generated directories with sibling caches preserved.

Fixture boundary: production main's UID/EUID/GID1000 gate takes its positive path on this UID1000 test process; rejecting other process identities was not separately simulated. Existing lock and all real filesystem scanner/chmod/unlink/receipt behavior run in the private fixture. For the whole-main fixture only, `trusted_directory` is injected to return FDs for exactly two generated fixture parents (`.cache`, `.cache/warden-lab`) after exact path/UID assertions. This avoids accepting the sandbox's UID65534 `/tmp` ancestry. It **does not test the actual host project's ancestor trust/admission**, nor relax production checks. Generic cache validation still rejects group-write. The final passing run is private filesystem evidence, not an actual cache execution receipt. Shared helper was not edited or revalidated as a separate old suite.

There were no Go tests, container starts/creation, actual cache chmod/unlink, package downloads/install, token reads/acquisition, identity mutation, Terraform execution, cloud resources, newVM/runtime rounds, Q release or publication. The initial local source commit attempt hit read-only `.git`; the authorized Git-only escalation succeeded. No automatic-approval rejection occurred.

## Pending controller action and preserved gates

Review [cache-execution-plan.md](cache-execution-plan.md) and frozen source independently. Only controller may admit a writer-free actual cleanup using fresh guard and exact source hashes, then recompute full R+Q5GB+new3GB+other outstanding/image charges. Existing intents or unknown results block automatic continuation. No actual disk space recovery or new test admission is claimed here.

Authn/JWKS/TenantAdapter, migration003, persistent SCIM, real API composition, operator credentials/binding, Terraform source, fixed material/PG/SQL harness, original four Task6 named tests and actual Entra assignment/unassignment are **not implemented or executed in this substage**. Those are the next authorized implementation scope after this resource source-review handoff, with separate execution gates. Resource fixture success is not Task6 acceptance or Goal completion. Task3/4 original five-round/runtime acceptance and retained Q/journals/unknown cleanup states, Task5 actual42cells and all budget/publication restrictions remain unchanged.

## 2026-10-25 — fix round 1/5, documentation only

Read the complete [first independent review](review-cache-substage.md) and [controller maintenance scope ruling](cache-maintenance-scope-ruling-20261025.md). Appended a dated clarification to the execution plan resolving the review's sole Important finding: this fixed, offline-rebuildable old-cache cleanup is development maintenance; Task14 response dry-run and second-identity approval requirements remain in force. No source reviewer or fixture is represented as actual deletion authorization or a second operational identity. All real admission/postcheck gates remain, with the ruling's96MB maintenance headroom replacing the earlier64MB planning allowance and the standard new3GB test reservation still separate.

This round starts from HEAD `a607af6` and edits only the execution plan, this public report, and the append-only working `task-6-report.md`. No production/test source changed;26fixtures and old suites were not rerun. There was no actual cache/Go/Docker/PG/cloud/identity operation. Historical findings, failed runs and manifests were preserved. Minor additional fsync-failure fixtures remain explicitly deferred, not verified. Only the two public documents are submitted in this fix commit; targeted independent rereview and all actual operations remain pending. Business/SQL/real IdP and overall Task6/Goal remain incomplete.
