# Task6 resource substage: fixed retired Go-cache entrypoint

Status: source/fixture evidence prepared; independent scoped safety review and controller admission are required before the real command. This document authorizes nothing by itself. Resource-substage BASE is `0a18e1aa54619097cfc90fa0488ddb3e2269ac25`; Task6 overall BASE remains `84018e512d78156283ae64aab62ccb76d5d20801`.

Source commits: `0ed796d0591b0d57fb66746616596b2427f4ee60` (fixed cache engine/fixtures) and `7be15fa29aafc7cf84dcd488dbf8aadc22ae2655` (private fixture parent injection). Source scope is only `scripts/identity_cache.py` and `scripts/test_identity_cache.py`. Shared trust/path/accounting/recovery modules are unchanged. There is no PG/Go harness or identity business implementation in this substage.

## Controller gates before any real execution

1. Independent reviewer checks both source files, this plan, original controller rulings and the permission supplement. The reviewer must specifically assess the unlink race assumptions, original-mode whitelist, immutable authority of fixed paths, durable intent before chmod, partial failure handling, and fixture limitations.
2. Controller confirms ordinary UID/EUID/GID1000, the exact Warden checkout/source hashes, trusted ancestor ownership/permissions, and existing project lock identity. No root invocation. The script opens the existing `.cache/warden-lab/docker.lock` without creating or replacing it and obtains nonblocking exclusive flock.
3. Controller establishes a writer-free maintenance window: no legacy Go invocation or other actor writes `.cache/go-build`. The retired `scripts/go.sh` does not participate in the project lock; holding the lock alone is insufficient proof. No process-wide/other-project inventory is authorized here. If this cannot be established from existing project operation receipts, do not run cleanup.
4. Fresh ordinary guard evaluates current complete project R, all outstanding charges including original retained Q5GB, actual owned-image accounting and metadata/log headroom. This maintenance script creates no container/image and does not create or release a canonical test charge. Allow up to32MB for its intent and a conservative64MB maintenance headroom; do not claim the old1.973GB planning observation as current free space. The existing standard3GB test reservation is evaluated again **after** actual cleanup; it is not reduced or replaced by this maintenance allowance.
5. Confirm no preexisting `.cache/identity-cache-permission-intent.json` or `.cache/identity-cache-permission-result.json`. Either name, including a symlink or partial file, means prior/unknown operation state and requires controller review. The script never deletes or overwrites these receipts. Do not reset them to force a retry.
6. Save actual pre-source hashes and command/admission evidence. No Go, Docker, identity, cloud or service command is part of cleanup. The controller may impose a180sec wall deadline, terminate then wait5sec before killing if necessary; a timeout is incomplete/unknown, not success, and no automatic rerun is allowed.

## Sole mutation command and scope

From `/home/postedism/Desktop/Warden`, the sole script command is:

```text
python3 -B scripts/identity_cache.py
```

There are no path/mode/regex/selectors. Arguments are rejected before filesystem access. This command has **not** been run against the real cache. Existing source/fixtures were tested only with private generated directories.

The production entrypoint resolves the project from its own script location, traverses `.cache/warden-lab` and `.cache` through the unchanged shared `trusted_directory`, then only opens the literal `go-build` child by FD. It does not call Docker, Go, a service, shell commands, or network code; does not read cached file bodies; does not alter ownership; and never recursively removes a tree.

Read-only preflight recognizes precisely256 lowercase hexadecimal bucket directories. Root metadata names README/trim.txt/testexpire.txt may exist and are preserved. Every bucket entry is the matching bucket prefix plus62hex characters and `-a` or `-d`. An action index is a regular175byte file. Data is a regular file or a `-d` directory with exactly one regular executable and a bounded ASCII basename; nested/empty/multi-file directories are rejected. Fuzz directories and any unknown root/child entry are rejected, not silently skipped. Original mode whitelist is directories0755/0775, normal files0644/0664, executable files0755. All owners/groups must match1000, device must match the trusted parent, regular nlink must equal1, directory nlink must match the complete scanned structure, and no repeated inode is accepted. Group-writable layouts remain rejected by the generic CachePlan and shared trusted_directory; only this explicit fixed-child tightening plan recognizes the old modes.

The implementation caps a bucket at4096entries, total derived files at100000, aggregate logical and allocated bytes each at3e9B, and serialized receipt at32MB. It retains directory FDs; each ordinary file is opened nofollow/nonblocking, fstat-checked, and closed during scanning, then reopened and held during its operation. Unexpected FD/memory/IO exhaustion fails closed before mutation if encountered during preflight. Extremely many executable directories could exhaust the descriptor limit; that is rejection, not a reason to enlarge limits or retry with a weaker scan.

After complete preflight, `.cache/identity-cache-permission-intent.json` is created exclusively0600, records original metadata and target mode for every item, and is fsynced together with the parent directory before the first fchmod. The complete layout is checked again after writing intent. Held FD/stat identity is checked around each operation, permissions only narrow to directory0700, normal0600, executable0700, and metadata is fsynced. No owner changes or permission rollback occur.

After all permissions narrow, a new strict CachePlan rescans the complete tree. Before the deletion phase, the complete plan is again checked; before each unlink, its held ancestors and file FD/path fingerprints are checked. The engine unlinks only accepted ordinary derived entries, then rmdirs only proven empty single-executable `-d` directories. It retains go-build root, all256 buckets, and metadata files. Final structure/metadata checks and directory fsync precede the exclusive durable completion result.

Important limit: Linux unlinkat has no compare-and-unlink-by-inode operation. A malicious/uncooperative same-UID writer could change a name between its final stat and unlink despite held FDs. This implementation therefore **requires** the controller's writer-free window and does not claim protection against arbitrary concurrent same-UID attacks. Nofollow still prevents traversal through a substituted symlink. If review requires stronger same-UID concurrency protection, this plan is not admitted as written; do not pretend the lock supplies it.

## Failures and postchecks

- Any exception, signal, timeout, missing result or ambiguous outcome preserves the intent and all already-narrowed permissions. No automatic rollback, path replacement, broad rm, inode/owner repair, receipt deletion, or restart. Controller investigates only the fixed cache/receipts with read-only metadata.
- Success requires exit0, durable result state `completed`, unchanged source hashes, expected retained metadata/256 empty buckets, and unchanged sibling caches/original lab state according to controller postchecks. The result counts block allocations of unlinked files; it is not proof of actual whole-project disk reduction or storage reclamation.
- Save actual post-source hashes and metadata/command output. Recompute full project size and ordinary guard with Q5GB and **new standard3GB** reservation plus all other existing charges/images. If it does not fit12e9B, do not proceed to material/PG. This script neither admits that later phase nor releases any retained charge.
- Intents/results stay as evidence. Successful cache cleanup is resource maintenance only. Cached Go1.26.10 toolchain/modules, current firecracker-code cache, original warden-lab/journals/root/Q, repository source, and external identity authorities remain untouched.

## Layout basis and actual observation limits

The exact cached Go1.26.10 toolchain source was read, not executed:

| File under `.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/src/cmd/go/internal/` | SHA-256 | Relevant behavior |
|---|---|---|
| `cache/cache.go` | `22da4896758772a443d90dd148719866d20e811bfefd3668597eae083b6f39b2` |256buckets; full hash-a/hash-d names;175byte index; one-file executable directory |
| `cache/default.go` | `3b4697e22509682f6339813ab7fdd9ed0f5628bdcbed261ee2eff3003b7f5d54` |README creation |
| `clean/clean.go` | `52db63640ae65ee1ba34c67b92eea3e6634f5876b8de2e92c09c5e0a6ae0153b` |testexpire.txt |

The original Go source's broader RemoveAll behavior is deliberately not copied. The observed fixed old-cache metadata had22420derived entries:22417regular files and3executable directories (two govulncheck, one task1-listen-probe);4214normal files0664,18203normal files0644,3directories0755, root0775, all observed entry owners1000. These were bounded planning metadata observations, not a full admitted scan or a mutation receipt. File bodies were not read. The script independently checks every owner/group/mode/link/device/layout before action and may reject the actual cache even if these planning counts looked plausible.

## 2026-10-25 — fix round 1/5: maintenance scope clarification

The [first independent review](review-cache-substage.md) identified a plan-mandated conflict between global response `--dry-run`/second-identity approval requirements and this fixed no-argument entrypoint. That original finding and all failed execution records remain intact. The controller's [written maintenance scope ruling](cache-maintenance-scope-ruling-20261025.md) resolves the classification for this exact operation: reclaiming confirmed, offline-rebuildable artifacts in the retired `.cache/go-build` is a separate development maintenance workflow. Its authority does not extend to evidence, original runtime state, identity records, other caches/resources, tenants, or running workloads.

The ruling retains the fixed no-argument interface. The private read-only constructor is not a public `--dry-run`, and this plan does not claim such an interface exists. Task14 response execution (`Executor.Handle(alert Alert, dryRun bool)`, including lease revocation, Pod isolation, node cordon and tenant suspension) and applicable tenant/cloud response deletions retain the original dry-run and second-identity approval requirements. This narrowly scoped maintenance classification cannot be reused as permission for broader deletion tools or response actions.

Independent source review, fixture PASS and this clarification are neither authorization for actual chmod/unlink nor approval by a second operating identity. The reviewer is a delegated AI agent, not a human or second operational identity; no second-identity approval is asserted. Actual maintenance remains unexecuted and requires a separate controller admission after the targeted rereview.

All original real-operation gates above remain: frozen source/hash; actual trusted ancestry and lock identity; confirmed old-cache provenance; controller-established absence of concurrent writers; ordinary UID/EUID/GID1000; complete read-only whitelist checks; durable intent before any permission tightening; complete strict revalidation before unlink; and preservation of unknown/partial outcomes without retry or permission rollback. For the next admission, the scope ruling's **96MB conservative maintenance headroom supersedes the earlier64MB planning allowance** while retaining the32MB intent bound. Fresh complete project R plus all outstanding Q/charges and owned-image accounting plus96MB must fit12e9B; resident memory including1GB host allowance must fit16e9B. These are future admission checks, not current measurements or approval.

After any separately admitted actual operation, durable completed result, exit status, source hashes, original-state/sibling-cache integrity and the ordinary complete guard still require verification. A new standard3GB test reservation is evaluated separately; no original Q/charge is released or reduced by this clarification. The review's Minor fsync-failure fixture gaps remain deferred and visible to final branch review; no unexecuted fixture is claimed as passed. This fix changes documentation only and does not establish Task6 or Goal completion.
