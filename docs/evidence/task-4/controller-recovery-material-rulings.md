# Exact necessary recovery material proposal and controller ruling

Historical proposal followed by binding amendments. No new operation is authorized before implementation, finite fixture verification and scoped source review.

# Exact Python3.14 material compatibility and new recovery operation — proposal only

**NEEDS_CONTEXT: controller ruling required.** This proposal is the only write.
No implementation/tests, new Python/ELF/ABI execution probe, packaging, Docker,
private-live entry access, recovery, Go/B/VM or Git/index operation ran. Read the
named eight public artifacts at controller commit
`cd7a1e99709fd2a48a061957af26334e7405196e`, the existing host/helper source, bounded
public Python source/metadata and primary documentation. No `/etc` or user
configuration target was read or copied.

## 1. Established stop and limited compatibility conclusion

At23:31:25Z the reviewed source8c8e9edf4a269effb155ae027b703cd9dc770836 entered
material inspection and refused `stdlib_file_alias`. The version check and
bounded stdlib walk ran; complete ELF closure, tar, image, container and helper
did not. The reviewed pre-daemon cleanup at23:34:12Z succeeded: old helper H is
settled with retained growth0; original Q=5GB remains, live is still root-owned
dev66307/inode56377608, and original owner/creation ambiguity is unchanged.
This was not a VMM/guest attempt and supplied no ordinary guard pass.

The proposed compatibility rule is **one exact public alias materialization and
two exact metadata-only omissions**, limited to the observed Python3.14 layout.
No generic alias following or exclusion pattern is proposed. All other existing
source, ownership, file/link/xattr, ABI, count/size and archive protections remain.
An unexpected Python version/layout, alias or changed expected entry refuses.

| Exact included-walk entry | Required observed link text | Proposed action |
| --- | --- | --- |
| `/usr/lib/python3.14/_sysconfigdata__x86_64-linux-gnu.py` | `_sysconfigdata__linux_x86_64-linux-gnu.py` | Authenticate the exact link and its fixed sibling regular target independently; copy target bytes under the alias's archive name as a regular0444 file. Retain the existing canonical regular module too. |
| `/usr/lib/python3.14/sitecustomize.py` | `/etc/python3.14/sitecustomize.py` | Authenticate only the link's own metadata/text, then omit this exact archive entry. Never resolve/open/stat/hash the target. |
| `/usr/lib/python3.14/config-3.14-x86_64-linux-gnu/libpython3.14.so` | `../../x86_64-linux-gnu/libpython3.14.so.1` | Authenticate only this exact link's own metadata/text, then omit this exact development-config entry. Do not omit the containing directory or real runtime ELF dependencies. |

For all three, require the recorded root UID/GID0 symlink type, single link,
exact text, safe root-owned nofollow parent chain and unchanged before/after
lstat/readlink identity. Symlink0777 is the expected link metadata, not permission
to relax target-file guards. Unknown link text, unexpected regular replacement,
extra included-walk alias, missing expected entry or changed identity refuses.
Do not inspect the `/etc/python3.14/sitecustomize.py` target to justify omission.

For the copied sysconfig alias, open only the fixed sibling target by a held
directory FD with O_NOFOLLOW; require regular UID/GID0, nlink1, existing safe
mode/no set-ID/group-other write, no xattrs/filecaps, bounded size and unchanged
inode/metadata during hashing/copy. Do not follow a second link. The already
included canonical target and alias archive name must hash to identical bytes;
count both copied names against128MB file and160MB tar/image limits. Produce
regular archive entries only, never a symlink/hardlink or PAX link escape. The
manifest records exact alias source, target, action and copied-byte hash.

The public regular sysconfig target is55,868B by this read-only metadata view.
The two omission rules retain only their reason enums and authenticated link
metadata, never target contents. The final archive input set must contain neither
omitted name nor any `/etc`/home/user configuration path. If later ELF dependency
discovery would reintroduce either omitted entry, refuse the conflict rather
than silently override the rule. Missing or unknown dependencies still refuse.

My sandbox metadata view reports UID/GID65534 for public system files, whereas
the controller's archived ordinary-host metadata reports0. I did not reinterpret
that mapped view as a fresh host ownership attestation, nor relax UID checks.
Actual packaging must freshly authenticate UID/GID0 in the controller's already
approved ordinary-host environment. No escalation/probe was run for this proposal.

## 2. Why these selections fit the fixed helper

The unchanged helper imports `hashlib`, `ctypes`, `json`, `os`, `re`, `stat`, `sys`.
The installed public `/usr/lib/python3.14/ctypes/__init__.py:3–19` additionally
imports `sysconfig`, `_ctypes`, `types` and `struct`; these must not be removed
under an assumption that ctypes is self-contained. Installed
`sysconfig/__init__.py:394–411` chooses the default name using ABI/platform/multiarch
and imports the corresponding public build-time data. The default Linux spelling
includes `linux`; preserving both authenticated sysconfig names avoids deleting
this public compatibility alias while adding only one bounded regular copy.
No host environment override is imported into the helper's fixed environment.

The interpreter remains `/usr/bin/python3 -I -S -B /recovery.py MODE`. `-I`
excludes script/user site paths and ignores Python environment settings; `-S`
prevents automatic site initialization; `-B` prevents import bytecode writes.
These flags do not eliminate normal standard-library or ELF dependencies.
[CPython3.14 command-line contract](https://docs.python.org/3.14/using/cmdline.html#cmdoption-I).
The current online documentation identifies itself as3.14.9; it is a contract
reference, not an assertion of the installed patch version or binary ABI.

Omitting sitecustomize is intentional isolation: it is a site-specific hook,
not required initialization for this fixed helper. `site` initialization is
suppressed by `-S`; even a later ordinary import of `site` does not call its
initialization under that flag. The unchanged helper never calls `site.main()`.
[CPython site contract](https://docs.python.org/3.14/library/site.html).
The installed public `site.py:709–741` independently shows sitecustomize invoked
inside `main`, gated at module end by `sys.flags.no_site`. No host-config body
needs to be inspected, copied or executed to establish this.

Omitting the config-directory linker alias does **not** mean omitting libpython
or other runtime libraries. Installed ctypes on Linux uses `PyDLL(None)`
(`ctypes/__init__.py:560–567`); its Android/Cygwin branch uses LDLIBRARY instead.
The public generated build data identifies INSTSONAME `libpython3.14.so.1.0`,
LIBDIR `/usr/lib/x86_64-linux-gnu` and Py_ENABLE_SHARED1. These are source data,
not an executed dependency proof. Readlink metadata shows the development alias
ultimately names that runtime library, but the proposal does not copy through it.
Actual runtime closure must come from the unchanged authenticated bounded ELF
dependency process for the interpreter and included extension objects, including
`_ctypes`; every dependency is copied as authenticated regular bytes at its
needed public archive pathname and hashed. The dynamic loader loads dependencies
identified by ELF and its search rules, rather than requiring every development
linker alias to be installed. [Linux loader contract](https://man7.org/linux/man-pages/man8/ld.so.8.html).
If actual closure contradicts this selection, stop and report that specific
incompatibility; do not infer ABI success from these names or add a fallback.

## 3. New immutable operation and fresh admission

Use a single new **hard-coded** operation root:

`/home/postedism/Desktop/Warden/.cache/warden-lab/docker-firecracker-89c9296e79ce14c5dd30e0d5e4772f1d/recovery-a-py314-v1`

Its fixed phase children remain `inspect` and `restore-traversal`; the helper
still accepts exactly those two modes. No CLI workdir, operation number, retry,
reset, skip or alternate material argument. The first inspect exclusively creates
the operation root and its inspect child; an existing root on that initial
invocation refuses. Restore later authenticates the same immutable operation
root and exclusively creates its distinct restore child. No existing phase is
replaced, reset or rerun. Existing
cleanup/postflight selectors operate only on this newly fixed operation in the
new source. Retain `recovery-a/inspect` and all its bytes as historical failed,
settled, **unsuccessful** evidence. Never relabel it successful or run it again.

Before creating the new root, under the existing project lock:

1. Verify the independently reviewed new source/module hashes and the unchanged
   source95 runtime premise; reauthenticate original parent/live held identities,
   identity/binding/receipt/CG-absence/charge records and fresh original object
   absence. Q must remain5GB/released=false. No live entry traversal occurs here.
2. Read only the old ordinary-owned recovery metadata through held nofollow
   parent/phase FDs. Require fixed source8c8e9edf4a269effb155ae027b703cd9dc770836,
   helper SHA72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2,
   modeinspect, complete valid original helper labels, stepobjects-settled,
   settled=true, success=false, image=null, cid=null, Q5GB/released=false and
   recorded envelope736MB. Retained helper growth is0 because this was the
   validated pre-daemon cleanup; do not rewrite its envelope field to zero.
   Authenticate private metadata owner/mode/nlink/bounds and recheck FD/path
   identity. The old source path implies only `state.json` and
   `admission-material.json` in its phase; require that bounded shape, no tar,
   result, outcome or old restore phase. If actual ordinary metadata disagrees,
   stop for an exact ruling rather than repairing it.
3. Freshly require no old full-label container/image and no other project
   container. The null IDs are accepted **only with this proved pre-daemon
   predecessor state**, never as proof that a pending daemon operation completed.
   The archived material-cleanup record supports this premise; fresh bounded
   predecessor metadata must supply the exact labels/digest before use. Those
   private ordinary-record values were not read or invented in this proposal.
4. Freshly compute R across every readable project path except the one original
   authenticated live subtree covered once by Q. Include old failed-phase files,
   controller/evidence/Git/cache bytes and all new material as it appears; add
   all current image charges, other reservations and the full **new H736MB**.
   The historical9,752,091,136B figure is not current admission. Require unchanged
   12GB disk/16GB aggregate resident ceilings, helper256MB plus1GB host allowance
   and honest other-service memory. Another unreadable path or unknown object
   refuses. This is special recovery admission, never ordinary Go/boot admission.

Then exclusively create/fsync the new fixed root and a private immutable
`operation.json` binding the new source/helper/material-policy version, original
scene, predecessor source/validated state hash/labels, measured admission and
Q/H semantics. Preserve that operation receipt; bind subsequent phase receipts
to it. Fresh random full helper labels and known immutable image/CID remain in
the existing phase state. No new Docker label/cap/profile or generic input is
needed. Under each existing lock reacquisition recheck original and predecessor
bindings; repeat fresh R/E plus full newH before material, import, create and
start. The second phase consumes only this operation's successful inspect receipt,
not the old failed one. Its expected inventory remains embedded at the fixed
immutable image path with the sole original RO session bind.

Keep the closed pending-state refusal exactly: unresolved import/create/start
never deletes/unlinks/writes settled or discovers a missing ID, even when lists
are empty. Known material-only cleanup and positively validated terminal cleanup
retain their current rules. Any changed predecessor, running/unknown helper,
partial restoration or missing original proof retains Q and applicable newH.
No automatic operation2, daemon cancellation, authority adoption or Q release.

## 4. Required finite validation and remaining runtime uncertainty

After a ruling, implement/test only the exact material selection and fixed
operation/predecessor binding. A finite host fixture RED/GREEN should cover all
three exact links, the regular sysconfig copy/hash/duplicate byte accounting,
the two omitted names, and rejection of wrong text/owner/type/extra link/target
link/replacement/xattrs/size overflow. A guarded open fixture must prove the
`/etc` target is never opened. Archive fixtures must show regular-only entries,
exact omissions and no dependency reintroduction. State fixtures must prove old
unsuccessful-settled records stay byte-identical, only the fixed new root can be
created once, predecessor drift/old objects/pending states refuse, and every
transition counts old/new artifacts plus full H. One committed-source covering
run of affected host tests suffices; unchanged helper/Go/Task3 suites need no
repeat. Freeze source/evidence for a scoped safety/source review before actual
material work. No tests or package/probe were performed now.

Before any new helper launch, actual reviewed material validation must freshly
authenticate all public inputs, verify the exact alias selection, complete the
existing bounded ELF closure, hash the streamed archive and enforce every cap.
I recommend augmenting the existing fixed isolated version query with **one
fixed, bounded public-runtime import/ABI self-check**, within the same ordinary-UID
material step and its host allowance: import exactly the unchanged helper's
modules plus sysconfig and both approved public sysconfig names; verify Python3.14,
the isolated/no_site/dont_write_bytecode flags and absence of loaded sitecustomize;
construct `ctypes.CDLL(None)` and resolve the `mount` symbol **without calling it**.
Use the existing bounded-command deadline, a ≤16KB fixed enum/boolean receipt,
empty stdin and the fixed scrubbed environment. No arbitrary `-c`, path or probe
argument may be supplied by CLI, and no raw environment/config/exception output
is published. This would be new execution validation requiring the ruling;
it has not run. Authenticate the known public alias targets before that check.

This host check is distinct from fixture correctness and catches a missing
Python extension/libc symbol before daemon operations. It does **not** prove the
final scratch-image ABI. Package input/hash/layout/ELF-closure verification plus
the subsequent existing capless RO `inspect` remain the proposed acceptance
sequence: helper imports execute before its mount/anchor/entry inspection. A
loader/import failure must stop, retain its pending envelope under current rules,
and create no further attempt. No third helper mode, extra image, alternative
interpreter, entrypoint override or new mount is proposed. If the controller
requires successful execution **inside the sealed image before any scene-bound
helper launch**, that cannot honestly be supplied by a host probe; it requires a
separately reviewed fixed no-scene validation design. Do not silently add one.

## 5. Requested ruling

Approve/reject this exact one-alias/two-omission rule, the exclusive
`recovery-a-py314-v1` operation with predecessor authentication, and the single
fixed host public-runtime self-check before any new helper launch. If approved,
implementation/finite fixtures and source review come first; controller alone
later performs actual admitted work. Unknown ABI/metadata/shape or incomplete
predecessor evidence remains a blocking prerequisite, not permission to weaken
guards. Q remains charged through A; ordinary full guard still requires actual
readable entire tree plus Q after recovery. Original tail/WaitStatus remain
irrecoverable and no guessed VMM cause is offered. Task4 remains5/5/unaccepted,
Task3's cap unchanged, B/Go/VM work unopened, and no extra boot opportunity is
earned by this necessary material adjudication.

## Controller ruling: exact public materials and one fresh physical operation

Ruling: approve the proposal's one exact alias materialization and two exact
omissions for implementation/native fixtures and scoped review only — actual
inspection established a legitimate Python3.14 layout incompatibility before any
daemon request, while no file in the original scene has changed — if an input,
startup premise or layout differs, refuse and preserve applicable H/Q; the cost
is another recorded unmet prerequisite, never a generic alias/config fallback.

The three source paths and link texts in the table are exhaustive. Require all
three to exist as root UID/GID0 single-link symlinks with exact recorded0777
metadata, trusted root-owned nofollow parents, and stable before/after identity.
Only the fixed sibling sysconfig target may supply bytes: held nofollow regular
FD, root ownership, nlink1, safe modes, no xattrs/caps, bounded size, hash and
metadata stability. Alias and canonical module archive names are separate regular
copies and both count. Neither omitted target may be resolved, opened, statted or
hashed for omission; no parent-directory blanket exclusion. Unknown aliases,
regular replacements, missing expected entries or dependency reintroduction of
an omitted archive name refuse. Existing128M/160M/160M/64M ceilings and H736M stay.

Ruling: approve one new fixed operation root recovery-a-py314-v1 after the exact
known pre-daemon predecessor is reauthenticated — failed recovery-a/inspect is
retained, settled and unsuccessful and may never be reset/reused — wrong or
missing predecessor binding blocks the new operation; no third operation or
automatic retry is authorized.

Authenticate the ordinary-owned old phase's exact two-file shape, source8c8e9ed,
module hash, full labels, coherent objects-settled/success=false/IDsnull state,
Q5GB unreleased and736M recorded envelope through held nofollow FD chains. No
Live traversal is permitted for this check. Recheck old label object absence and
original source95/scene/receipt/charge/CG absence. Count all old metadata/evidence
and current artifacts in freshR, all images/other charges, and full newH. Exclusive
creation/fsync of the new root and a private never-rewritten operation.json must
bind the validated predecessor state digest, new source/material-policy version,
helper hash, scene and admission. Later phases reauthenticate that binding; raw
helper schema stays unchanged. Carry operation provenance in the host records
beside raw helper receipts, not as an extra helper JSON key or input channel.

Ruling: approve the single fixed isolated public-runtime self-check as a later
controller material step, after code review — source/import and symbol checks can
catch a missing local dependency before a daemon operation — it is only host ABI
evidence and must never be reported as successful scratch-image execution.

Use only authenticated existing /usr/bin Python3.14 with literal -I -S -B and
scrubbed environment/empty stdin, the fixed import set and exact public sysconfig
names, fixed flag/version assertions, absence of loaded sitecustomize, and lookup
of libc mount through CDLL(None) without calling it. Authenticate the copied alias
target before the check and recheck material identity afterwards. Record measured
patch version as numeric metadata. Fixed bounded enum/boolean output<=16KiB,
stderr<=4KiB/deadline unchanged; no raw config/environment/exception/path output,
arbitrary -c/input/path or additional helper mode/image/mount. Unknown ABI stops.

Current authorization is only host coordinator/material/predecessor code, its
meaningful finite native fixtures and runbook. Keep helper/init,22-entry shape,
profiles/caps/limits, pending-state refusal, all original Gate/RunID/Q semantics,
ordinary guard, Task3, Go/B and VMM unchanged. No packaging/ABI execution probe,
Docker mutation, private inventory/remount/chown or actual new operation by the
implementer. Focused RED/GREEN then one committed-source affected-host covering;
no unchanged helper/Go/Task3 or historical176-file crawl. Freeze source/evidence
separately with same appended report; one scoped material/predecessor/ABI-plan
review uses prior reviewed boundaries and checks the new delta.

Controller alone may run the new inspect once after that gate and fresh admission.
Any material/ABI/profile/shape failure stops without reset, fallback or another
operation. Restore is conditional on its successful bounded inventory. Original
Q remains through A and the ordinary full guard; its physical-only release stays
a separate decision. This necessary physical-recovery material ruling does not
add a VMM causal round, sixth core edit/retry, B authorization, or boot opportunity.
Task4 remains5/5/unaccepted, Task3 cap and original I7/owner/API ambiguity remain.

## Pre-freeze exact public development-object supplement

This supplements the material ruling before its first implementation handoff,
without authorizing another operation, helper or test scope beyond affected host
fixtures. It will be appended to the tracked ruling once controller Git ownership
resumes. Controller public-header evidence is preserved at
`/tmp/warden-fc-python314-development-metadata.json` (ordinary-host UTC23:48:15Z).

Ruling: additionally omit exactly
`/usr/lib/python3.14/config-3.14-x86_64-linux-gnu/python.o` from archive inputs and
ELF dependency invocation, only after authenticating its fixed public development
object metadata/header — the current unconditional ELF discovery would otherwise
attempt ldd on an unneeded relocatable build object; neither the fixed helper
imports nor its CDLL(None) runtime path compiles/links this object — if that premise
or metadata differs, fail closed; no generic ET_REL filter or config-directory
exclusion is authorized.

Require a trusted root-owned nofollow parent chain, regular UID/GID0, nlink1,
mode0644, size11504B, no xattrs/filecaps and stable held-FD identity/mtime/ctime.
Read only the first20 bytes for this omission; require exact header hex
`7f454c4602010100000000000000000001003e00` (ELF64 little-endian, ET_REL1,
machine62), SHA256 f43453b3fe51a3fba833a8277427ab17f9bd218590b0c87a13151612e1b7fe3e.
Never invoke ldd on it or copy it. Record the omission reason and authenticated
metadata/header, not a whole-body read/hash. A missing/linked/replaced/changed
object refuses. Unknown non-runtime ELF still follows the original fail-closed
boundary; no blanket skip by ELF type, suffix, directory or executable bit.

There are now exactly3 expected symlink rules (one sysconfig regular copy and
two link omissions) plus this one exact regular-object omission. No other omission
or target rule changes. Both regular static archives remain ordinary bounded
inputs; no need to drop them. A read-only public metadata/header walk observed628
regular files totaling41,578,611B before interpreter/dependencies, including those
archives, so there is no basis to waive the existing file/archive/image ceilings.
These observations are not a closure/ABI execution result or source signature.

Add finite native fixtures for exact omission, wrong header/type/mode/size/owner/
link/xattr/missing/replacement refusal, and proof that neither ldd nor archive
receives this object while a different unknown object is not silently excluded.
Integrate into the already authorized single affected-host covering run, not a
second broad suite. No actual ABI probe/packaging/operation is authorized to the
implementer. Old source/evidence/operation bytes and pending H/Q rules remain.


## Cap adjudication: enumeration must not follow omitted targets (I9)

Ruling: the material reviewer source-confirmed a real load-bearing violation:
os.walk(followlinks=False) still classifies entries with following is_dir calls
before applying omission rules. Do not run source05505be. Permit one minimal
necessary recovery safety amendment of enumeration and its regression only;
this is not another VMM causal round or operation/boot retry. The cost of a wrong
ruling is an unmet recovery prerequisite and retained Q/H, never configuration
access or weaker admission. I7/Task4 actual acceptance remains open at5/5.

Replace implicit target-following classification with explicit held-directory
metadata enumeration using nofollow operations. Apply the same exact link/object
rules; authenticate link metadata and text without target stat/open/resolve.
Unknown links/types still refuse. Keep the existing directory exclusions, fixed
root, all material/size/hash rules, predecessor/operation, host ABI, helper,
profiles, caps, pending-state cleanup, guard and Go/B/Task3/VMM unchanged.
No public/private actual scan or ABI/package/Docker operation by implementer.

Regression must detect DirEntry's implicit following classification, not merely
patch Python os.stat/os.open. Use isolated ordinary-UID fixtures and guarded
scandir entries that fail/record default or follow_symlinks=True classification;
prove the old enumerator RED and the corrected nofollow traversal GREEN. Include
explicit omitted-target access guards and refusal of unknown directory/file
links without widening scope. Only finite focused TDD then one committed-source
covering of the affected MaterialPolicyTests class; no unchanged operation/
helper/Go/Task3/whole-host suite or historical integrity crawl. Separate source/
evidence, same appended report, freeze and return for one scoped I9+newdelta
re-review by the same reviewer. Controller alone can later admit inspect once
after PASS/fresh original/predecessor/accounting. No operation has been created
from05505be, so no retry/reset or additional root is needed or authorized.


## Public dependency investigation, distinct from a scene retry

Ruling: permit one fixed bounded read-only diagnostic of the unchanged reviewed
public runtime_inputs path at sourceba8, solely to persist its first exact
strict-dependency refusal and validated host ABI metadata. The previous stop
prohibited guessing a compatibility fix or starting a third physical operation;
applying it as a permanent ban on public prerequisite investigation leaves every
Go task stuck without new evidence. This narrow investigation does not reuse or
create any recovery phase, tar, image, container or live traversal. Original
strict validators execute unchanged. No parser relaxation, omitted-target access,
new interpreter, arbitrary probe or continued scan after first refusal.

Controller read-only support may trace only dependencies/host_abi frames in the
hash-bound existing source, capture their public-only bounded arguments/return,
redact ASLR addresses in the public copy, and keep raw hashes. Use existing
scrubbed environment/empty stdin/per-command bounds plus45s overall signal
deadline and original child finally-cleanup. Under the project lock, authenticate
original scene/Q/CG/object absence and fresh R+Q+fullH736M admission before/after;
this is special necessary investigation admission, not ordinaryguard. No other
resident project service is present;256MB helper-equivalent+1GB host allowance
remain charged conservatively. Write only new controller diagnostic evidence;
all old phase/evidence bytes stay untouched.

Cost if wrong: a failed public diagnostic remains an unmet prerequisite with
Q retained. It cannot authorize a third operation, Go/guest test, B, VM or sixth
causal Task4 round. Any subsequent source or recovery design still needs its own
specific ruling and independent review. Previous goal turn classified progress:
it changed source/tests, obtained actual failure evidence and froze Task5 design.


## Exact no-dependency output correction, before any scene decision

The single public diagnostic at00:20:52.632781Z–00:20:56.015052Z reached its third
dependency call, `_testsinglephase.cpython-314-x86_64-linux-gnu.so`, and observed
exit0/stdout `\tstatically linked\n`/empty stderr. It retained original validators
and stopped there. Fixed host receipt independently reports3.14.4 and all
required isolation/import/symbol checks true. No phase/archive/daemon mutation
or live descendants were involved; fresh R+Q+H was9,754,376,704B.

Ruling: allow a minimal parser-only amendment accepting the exact normalized
stdout literal `statically linked` with code0 and entirely empty stderr as an
empty dependency set. This is the same authenticated public executable/shared
ELF input path, not an unknown output fallback or evidence of scratch ABI. Keep
all other outputs/errors/limits and existing nonzero cases unchanged. No new
link/object omission or package size relief. If wrong, public closure still
refuses; no physical action follows automatically.

Only dependencies and its focused fixtures/runbook sentence may change. Genuine
RED then GREEN and one committed-source affected parser-class covering; no
other material/operation/helper/Go/Task3 suites or old integrity crawl. Independent
scoped review follows. After PASS, controller may run one fixed public-only
closure validation of amended source with fresh same admission and deadline,
without creating an operation or tar. Completion is a material prerequisite,
not permission for a third recovery operation. Its concrete immutable history
and execution design must be ruled/reviewed separately if necessary. Task4
causal cap5, unknown retirement, Q5GB and all existing phases stay unchanged.


## Public sealed archive preflight

Ruling: before consuming any newly reviewed physical operation, allow one fixed
public-only sealed archive preflight using the unchanged independently reviewed
build_archive/check_archive functions at d8 source, now that all50 dependency
checks pass. It writes only a fresh private `.cache/warden-lab/public-recovery-package-v1`
with exclusive creation; never an old scene phase. No daemon mutation, image,
container, helper mode, bind, remount, ownership change, or live entry access.
The same fixed inputs/128Mfiles/160Mtar/source/helper hashes and strict parser
remain. Before/after hold project lock, originalScene proof and full R+Q+H736M
admission;45s overall alarm and original cleanup apply. Archive and full package
metadata remain private, public evidence only hashes/counts/bounds/admission.
No reuse/reset/automatic retry if this preflight fails; readable retained bytes
stay in freshR. Cost if wrong: the known public artifact cannot pass sealing,
so no third physical action is consumed and no ordinaryguard is bypassed.
This extends only material verification, not the parser review's scene gate.


Public preflight instrumentation correction: v1 stopped before mkdir because
controller applied private_directory to shared BASE (actual trusted UID1000/0755).
No runtime_inputs/build_archive, stage directory, daemon or scene action occurred.
Independent ordinary parent metadata/Path.exists check showed the missing stage;
v2's exclusive mkdir later proved no existing entry was adopted. Preserve v1 script/
receipt. Ruling: one corrected v2 public preflight uses the existing reviewed
trusted_directory(BASE,1000) parent validator, as project_lock already does; newly
created staging remains exclusively0700/private. Output has a new O_EXCL name,
no failed record/root is reset. Same functions/bounds/45s/admission; no other fix,
material fallback or physical operation. Cost if wrong: public preflight refuses
again and retains readable actual bytes, not access to another path.
