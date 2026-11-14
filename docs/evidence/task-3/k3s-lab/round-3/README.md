# Task3 bootstrap fix round3 — code and read-only diagnosis

Status: implemented and ready for independent scoped review. Task3 remains open. No real Docker create, start, import, recovery, or new bootstrap occurred in this round. The original failed scene and its 6,000,000,000-byte charge remain retained.

Source: `e91e9addbf85c4314630d32dd8f62bb607fe84e3`; actual source parent: `6d610e80ff81930eb341039c1151156d7ad40521`. Re-review FIX_BASE is `df6e891`, including interleaved controller documentation; original dispatch BASE `0be4325` is provenance, not the source parent. Earlier SHA-bound evidence is unchanged.

## Diagnosis and its limits

The retained second bootstrap is CID `37b95dd4bbd84a5aa9b33a1f5d8d40402d26f0e1b765c4779ea47294eaa2f2b5`, image `sha256:a2bd74a7126bbb0c858d2e904a0eb4feef8849b83527193a89ebde08bf96f7fc`, session `5c8b4330bd7a1a3a6d0e237a604370d0`. Exact labels, stopped state, outer dev/inode 66307/55586536 and private child dev/inode 66307/55619975 were checked before authorized read-only diagnostics. The original inner child remains root-owned0700. No permissions were changed.

Only fixed archive streams were read into bounded process memory, with a 32MB combined content limit plus bounded tar overhead and strict regular-member/name/size checks. No private log copy or cache was created. The startup snapshot contained30,471 bytes/173 lines, SHA256 `515adf74e4f403ac96a5432ed2b3c962164bf3d8287f9bd94523f64d3eb935e0`. Public records contain fixed classifications/counts/hashes only. Authorized HEAD metadata found root/state/io absent and exactly the known containerd.toml124B, containerd.log0B and startup-private.log30,471B. The exact old systemd Docker scope was absent; no cgroup tree traversal or write occurred.

Actual safe classifications and pinned source agree on two startup incompatibilities: enabled containerd NRI attempts a socket beneath read-only `/var/run`, and k3s attempts its default kubeconfig symlink beneath read-only `/etc/rancher/k3s` despite a separate explicit output. The original cleanup exception phase cannot be proven from its generic RuntimeError. Metadata supports completed bulk private cleanup; an immediate nonblocking adopted-child wait can fail before a killed child becomes waitable. This is a covered lifecycle defect, not a claimed reconstruction of the exact old exception. The outer PermissionError reflects the deliberately unreadable retained child. Neither stopped state nor scope absence proves original Popen reaping or GoGate retirement.

`source-references.json` records URL, length and SHA256 for the selected k3s v1.36.5+k3s1, its actual containerd v2.3.4-k3s1.36 fork, and pinned dynamiclistener sources. The earlier crictl hypothesis was rejected; no workaround for that unproven cause was introduced.

## Changes

Unused NRI is disabled in the fixed v3 extension and verified after rendering. The image constructs only `/etc/rancher/k3s -> /run/k3s-client`; PID1 exclusively creates the0700 target in existing bounded `/run`. Actual private admin.yaml location/0600 permissions stay unchanged. Adopted-child reaping now has a bounded five-second wait. Fixed diagnostic stage/errno codes cover startup, owned cleanup, adopted reap and kernel postflight without arbitrary exception text.

The warning gate recognizes four exact source-backed startup templates: missing initial certificate cache, core-not-ready503, automatic v3 migration, and the exact owned content-store fsverity probe returning EOPNOTSUPP. The five historical matching observations are classification evidence only, not readiness evidence. Future acceptance requires the proper log, bounded counts, timestamps after launch and strictly before the first Ready second, and a subsequent API+Node Ready check after a one-second interval. Wrong path/error/source, extra fields/prefixes/suffixes, unknown text, no Ready window and post-Ready/persistent observations fail. One-shot templates allow one occurrence; initialization503 allows at most240. Old safe module/sysctl denials retain actual lines; new internal-address/path templates retain actual matched safe fragments and one SHA256 record per occurrence. Public output uses `startup_observations`.

Whole-main archive cleanup now requires successful completion, the held output-directory identity and the original archive inode, and unlinks through the held FD. A failed or drifted run preserves the archive and does not delete a replacement directory's same-name file.

## Fixed recovery contract — implemented, not executed

The new one-shot recovery script accepts no path, object ID, code or shell passthrough. It pins the original scene and reuses its retained immutable image. Under Docker.lock it verifies the held outer FD, original stopped CID, exact old scope absence, charge and labels. Trusted helper code is copied into immutable Docker Config argv, hashed, journaled and checked before start.

The helper has one RO/rprivate original-session bind, private namespaces, read-only root, NNP, only SYS_ADMIN+DAC_OVERRIDE,256MB memory+swap,32 tasks,1CPU, two1MB log files and a20-second inner deadline. Before remount it verifies the old reviewed mount handshake, exact child identity and precisely three known root-owned0600 single-link regular files with exact sizes and combined allocated blocks<=33MB. It reads no private file contents or public session files. Only then may it remount the same private bind and delete via held child/outer FDs. It never starts k3s.

Dedicated preflight excludes only this exact already-reserved private child from the otherwise normal allocated-file walk. The shared guard is unchanged; unrelated unreadability, alias or drift fails. It charges all outstanding reservations, every owned image at2×Size+64MB, and an additional64MB helper allowance. A durable exclusive journal before create retains helper labels/hash/reservation across lost responses or failures; the original6GB remains held. An existing journal is not blindly retried.

Only helper exit0, the exact success marker and absent child permit removal, in order: helper CID, original CID, original image. Each removal has exact ownership and full-label --all plus exact inspect-absence checks. Anchor/scope checks continue across deletion. The ordinary fresh guard runs before original charge release through the held FD. Unknown results preserve remaining objects/journal/charge. This is narrowly scoped stopped-scene reconciliation, not a general privileged cleanup API.

After independent review, only the controller may execute the documented fixed recovery command. Recovery must succeed before any fresh bootstrap import; a later bootstrap requires its own authorized run and new manifest. The old retained image intentionally supplies the existing Python/handshake closure; reviewed recovery code is in fixed Config argv. No new image/ABI smoke or new674-input manifest is claimed for this source.

## Resource accounting

The read-only estimate was project allocation3,024,191,488B excluding only the exact reserved child, outstanding6,000,000,000B, all owned-image charges1,434,733,588B (2×685,366,794+64,000,000), plus64,000,000B helper reserve: total10,522,925,076B, below12,000,000,000B. Other declared services were0; helper plus host allowance was320,000,000B, below16,000,000,000B. No helper reservation was actually journaled and no helper allocation occurred. This is not an ordinary complete postflight or measured recovery peak.

The original six-GB reserve remains intact: downloads160MB, source40MB, extraction900MB, tar900MB, image1,800MB and node headroom2,200MB. Existing project materials and the actual retained image charge remain explicit. Normal bootstrap private namespaces,4GB memory+swap,512 tasks,2CPU, no SYS_MODULE and read-only global sysctls are unchanged. This round made no host service, kernel, cloud or GPU change.

## TDD and verification

Meaningful RED records cover whole-main replacement archive deletion, NRI, delayed adopted-child reap, fixed recovery boundaries/lifecycle, safe stage diagnostics, exact startup templates and final readiness. Some initial REDs intentionally expose missing new APIs/modules. Original raw outputs are preserved.

Two misleadingly named historical files need explicit interpretation: `green-recovery-host.txt` contains an early sandbox-projection ancestry error, not a passing verification; `recovery-focused.txt` contains seven early errors because newly created task files inherited0664 from host umask0002 and trusted source reads correctly rejected them. Only those new source files were made0644; no directory permissions or trusted-directory guard was weakened. These records are historical RED, superseded by final results.

`verification-tests.txt`: ordinary-UID, umask0077, selected k3s host/init/material/recovery tests —53 PASS, zero skips. `final-recovery-focused.txt`: seven recovery tests PASS after final recovery hardening. Tests include lost create response, command mismatch, helper failure, unknown absence, image-removal failure, exact deletion order/charge retention, path drift, metadata shape and block bounds; they use fake Docker and real temporary filesystem objects. The adopted-reap test also uses an unprivileged process-local subreaper and delayed child. No real Docker objects are created by these tests. Source `git diff --cached --check` passed. SHA-bound input verification confirms committed bytes match the tested working files; no broad suite was repeated after these results.

Remaining concerns are actual recovery execution, fresh bootstrap readiness/identity/CNI/cgroup behavior, actual warning formats and peak usage. No Ready, tenant conformance, per-RunID revocation,100-launch or Task3 completion claim is made.

## Automatic review refusal and safe alternative

Automatic approval review rejected an attempted command that would have exported complete matched historical warning lines, because those lines contained private internal addresses, paths and timing metadata. The rejected command did not execute and was not retried. The authorized replacement performed bounded matching only in memory and exported fixed enums/counts/hashes, with no raw private lines persisted. Future successful harness output distinguishes original safe denial lines from redacted exact-template fragments; this change is explicitly part of scoped review.
