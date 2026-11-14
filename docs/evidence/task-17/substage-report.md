# Task17 implementation handoff

Result: **DONE_WITH_CONCERNS — independent documentation/checker substage only.**
Task17 final evidence-index integration remains OPEN, as do the overall Goal and
all tasks other than the previously accepted Tasks1/2. No plan checkbox changed.

Author: subagent `/root/task17_docs`, 2026-10-25. This is subagent-produced analysis
and local checker testing, never human annotation, real-cloud evidence or an audit
opinion. No reviewer child or other subagent was spawned. Root independent review
is still required; this handoff makes no claim to supply it.

## Scope and immutable base

Dispatch BASE and first observed HEAD were exactly
`f127289b159a69b89045b16a3fcee0cd7562ac8d`. Initial `git status --short` was empty.
Root later created an unrelated untracked file,
`docs/evidence/azure-budget/reaper-material-actual-followup-20261025.json`; it was
left untouched/untracked/uncommitted. The brief was the sole task requirements
source; no whole plan was read. A bounded STATUS tail provided current truth,
along with the existing evidence index and original Task6 actual blocker. The
initial180-line tail included more history than the requested last18 paragraphs;
no additional old-history or old canonical source-body campaign followed.

Product source frozen before behavior validation in local commit
`dc0db033fb4e546849269a1b0f8ea921bbeacaaf`, exact required subject:
`docs: threat model, SOC 2 mapping and evidence index`.
It contains only these five authorized paths:

- `docs/threat-model.md`:48rows, six STRIDE classes for each of API, scheduler,
  runc, gVisor, Firecracker, identity, log pipeline and CI;14linked controls;
  two Mermaid attack trees (tenant escape to node and credential theft).
- `docs/soc2-mapping.md`: indicative CC6.1–CC6.8 and CC7.1–CC7.5 appendix, with
  explicit physical-access/disposal gaps and no criterion-satisfaction claims.
- `docs/evidence/README.md`: preserves all existing entries verbatim and appends
  genuine isolation links and explicit missing measurement destinations.
- `scripts/check_threat_model_links.py`: Python stdlib, repo-local deterministic
  CLI; three default source files, optional explicit repo-relative sources.
- `scripts/test_check_threat_model_links.py`: five finite behavior tests using
  only tiny disposable owned `/tmp/warden-task17-*` fixture directories.

Research/raw results/report are confined to `docs/evidence/task-17/`; this exact
report is mirrored there as `substage-report.md`. STATUS receives one precise
scope entry. No canonical150 body, Task6 caller/controller/candidate/proposed diff,
private cache/history/scene/Q/guard/recovery/main/Terraform or plan checkbox was
changed. No push or publication occurred.

## Implementation and checker contract

Implementation writes used `tools.apply_patch` for the five product paths and
the authorized evidence/report/status paths. Successful patch tool returns were
ordinary `{}`. No formatter, Go invocation, shell service wrapper, cloud query,
credential query/download, Docker/GPU/service, sandbox/VM or project security
controller import was used.

The checker reads only explicit source bodies and Markdown targets requiring
heading checks; other local link targets receive metadata existence checks. It
does not crawl the repository, recurse through links, execute targets, fetch URLs
or traverse private/hidden components. It rejects lexical/percent-encoded parent
escape, absolute paths, local URI authorities/unsupported schemes, symlink files
and symlink ancestors, missing/nonregular targets and missing Markdown fragments.
Diagnostics identify source:line and target. Supported syntax is intentionally
small: inline links, reference definitions and ATX headings with duplicate suffixes;
fenced examples are ignored. It is not a general Markdown engine: reference-use
resolution, HTML anchors, setext headings and complex nested-link markup are not
implemented. The authored/default documents use the supported subset.

File bodies are bounded to2MiB; normal links do not read target bodies. Both
Python entrypoints set their own SIGALRM45s, RLIMIT_CPU20s, RLIMIT_AS256MiB and
RLIMIT_FSIZE2MiB, preserving tighter inherited limits. Those limits begin after
interpreter startup/imports; this is not an external startup-inclusive hard-bound
proof. Test fixtures total far below5MiB (only short Markdown/text files and owned
symlinks) and are deleted by TemporaryDirectory cleanup. No proc/private traversal
or real attack occurs. This is a cooperative local link check, not a security
reference monitor against concurrent hostile filesystem mutation.

## Exact validation commands and actual results

After the product commit, once each, from `/home/postedism/Desktop/Warden`:

```bash
python3 -I -B scripts/test_check_threat_model_links.py
python3 -I -B scripts/check_threat_model_links.py
```

The commands were independent and issued together with Promise.allSettled; both
results were inspected. Full raw tool return objects, command strings and source
commit bindings are retained without alteration in:

- `docs/evidence/task-17/checker-tests-tool-result.json`: chunk`3bb53e`, exit0,
  five tests PASS in0.003s, no skips. Cases: valid local/heading/duplicate/Unicode
  links and reference definitions; fenced code and external URL skip; missing file
  and missing fragment diagnostics; six finite escaping/private/URI targets;
  symlink file and directory escape; missing source, directory target and a
  non-Markdown fragment.
- `docs/evidence/task-17/links-tool-result.json`: chunk`18d037`, exit0,
  `Checked 208 local links; 0 error(s).`

There was no failing behavior run and no historical RED manufactured. No prior
Task1–16 tests, old150/hash/mock campaigns or actual acceptance suites were run.
There was no test rerun after success; the source was unchanged after the freeze.
Post-cover exact source comparison:

```bash
git diff --exit-code dc0db033fb4e546849269a1b0f8ea921bbeacaaf -- docs/threat-model.md docs/soc2-mapping.md docs/evidence/README.md scripts/check_threat_model_links.py scripts/test_check_threat_model_links.py && git status --short
```

Chunk`01e2d7`, exit0; no source diff; only the unrelated root Azure file and the
new Task17 evidence directory were untracked at that point. `git diff --check`
and `git diff --cached --check` also passed (initial check before new paths were
staged applied only to the existing index diff; the staged check covered all five).
Final evidence/status/report commits and Git status are reported separately in
the handoff rather than embedding a self-referential evidence commit SHA here.

## Preserved command/tool failure history

1. Initial bounded discovery command was:
   `ls -la && ls internal && ls docs && cat docs/ACCEPTANCE.md && cat docs/evidence/task-1/README.md docs/evidence/task-2/README.md docs/evidence/isolation-matrix.md`.
   Chunk`ff8ea3`, exit2 at `ls: cannot access 'internal': No such file or directory`.
   The subsequent dependent reads did not execute in that command; the correct
   `controlplane/internal` layout was then used and requested public docs read.
2. Public source-name discovery command was:
   `rg --files controlplane runtimes policies .github scripts -g '!*.sum' -g '!task6*' -g '!task4*' -g '!test_task6*' -g '!test_task4*'`.
   Chunk`9b037b`, exit2 with `rg: .github: No such file or directory (os error 2)`;
   results from the other named public directories were still returned. No CI
   workflow was invented from that absence.
3. Two primary PDF web-service operations returned HTTP500 internal errors; exact
   requests/error text and the successful direct-URL fallback are recorded in
   `docs/evidence/task-17/research.md`. These were research-tool failures, not
   evidence of a Warden control failure.
4. First local source commit attempt, chunk`50ee77`, exit128, exact command:

   ```bash
   git add docs/threat-model.md docs/soc2-mapping.md docs/evidence/README.md scripts/check_threat_model_links.py scripts/test_check_threat_model_links.py && git diff --cached --check && git commit -m "docs: threat model, SOC 2 mapping and evidence index" && git rev-parse HEAD
   ```

   Exact output: `fatal: Unable to create '/home/postedism/Desktop/Warden/.git/index.lock': Read-only file system`.
   This was the default filesystem sandbox refusal, not an automatic-review
   rejection. No index/source mutation succeeded in that attempt. The same
   narrow command used `sandbox_permissions=require_escalated` under the existing
   explicit local-commit authorization and succeeded, chunk`275fee`, exit0:

   ```text
   [implementation/warden dc0db03] docs: threat model, SOC 2 mapping and evidence index
    5 files changed, 557 insertions(+)
    create mode 100644 docs/soc2-mapping.md
    create mode 100644 docs/threat-model.md
    create mode 100644 scripts/check_threat_model_links.py
    create mode 100644 scripts/test_check_threat_model_links.py
   dc0db033fb4e546849269a1b0f8ea921bbeacaaf
   ```

No failure output was rewritten, and no inaccessible measurement was replaced
with fabricated evidence. Read-only exploration output was sometimes truncated
by the tool; those reads were used only for current scope, not claimed as new
complete audits. Raw new behavior-test results above were not truncated.

## Evidence truth and remaining integrations

Only Tasks1/2 are accepted. The model explicitly separates their local/real-lab
scope from gVisor/Firecracker partial work, Task6 cryptographic unit-only review
and unimplemented identity lifecycle, federation, Vault, network, log, detection,
response, supply-chain and vulnerability operations.

The original Task6 final5/5 actual chain remains CLOSED at the real0664 trusted-
record refusal. No retry, repair, rename, authority, terminal, capture, approval,
pin change, cache operation, PG allocation or Q release occurred in this task.
Scene22/Q5000000000 releasedfalse and all original task/runtime limits persist.

All42 Task5 matrix cells remain unevaluated; old runc conformance and subagent
classifier fixtures do not populate them. The four missing artifacts remain
missing and their exact expected destinations are plain text, not dead links:

- `docs/evidence/attack-coverage.md` — future Task12 real rule/query coverage.
- `docs/evidence/detection-coverage.md` — future Task13 real simulations, latency
  and seven-day false positives.
- `docs/evidence/time-to-contain.md` — future Task14 actual authorized response
  replay/timestamps and outcome.
- `docs/evidence/vuln-sla.md` — future Task16 sourced remediation history/metrics.

Future producers must create genuine version/configuration/command/raw-data
artifacts and update the index. Current link-check success does not close these
integrations, prove test names execute, verify all control semantics, establish
cloud/runtime deployment, certify SOC2, or complete Task17/Goal.

Primary-source terminology checking and source/version limitations are in
`docs/evidence/task-17/research.md`. The CC6/CC7 associations are explicitly this
subagent's inference. AICPA's accessible March2020 criterion text was checked;
the2022 points-of-focus download was gated and is not claimed reviewed.

Root should independently review the correct dispatch BASE..handoff HEAD and
this new scoped checker/docs only; no additional actual resource operation or
old Task6 review/retry is requested by this report.
