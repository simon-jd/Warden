Verbatim independent subagent review archive; not human or SOC2 audit. BASE f127289b159a69b89045b16a3fcee0cd7562ac8d → HEAD c9d5a0e1c3e8570b2100e58e7517969fcc8e8a9a. Body bytes=6750 SHA256=93a80a69126f333363a25491414e85a3a5cbc5d5e5d86c9839d5d21c9b04ad50.

### Spec Compliance

- ✅ Spec compliant for the explicitly authorized Task17 documentation/link-checker substage. BASE `f127289b159a69b89045b16a3fcee0cd7562ac8d` → HEAD `c9d5a0e1c3e8570b2100e58e7517969fcc8e8a9a`; frozen product source `dc0db033fb4e546849269a1b0f8ea921bbeacaaf`. The supplied package contains both commits and all ten changed paths; review covered the complete package in four bounded passes, without deduplication, cut hunks or rereading changed source files.
- ✅ Required outputs are present: the eight-component, six-category STRIDE register and two Mermaid attack trees in `docs/threat-model.md:1`; indicative CC6.1–CC6.8/CC7.1–CC7.5 mapping in `docs/soc2-mapping.md:16`; preserved existing index entries plus current isolation evidence and explicit pending destinations in `docs/evidence/README.md:18`; deterministic stdlib checker and focused behavior tests in `scripts/check_threat_model_links.py:1` and `scripts/test_check_threat_model_links.py:1`.
- ✅ Scope and claim boundaries are accurate within the reviewed change: accepted/partial/pending meanings are explicit at `docs/threat-model.md:36`; no criterion is declared satisfied at `docs/soc2-mapping.md:32`; `docs/evidence/README.md:41` leaves missing measurements pending instead of manufacturing linked placeholders. The original Task6 actual refusal, exhausted final5/5 chain and no-retry boundary are preserved in `docs/threat-model.md:6` and `docs/evidence/task-17/substage-report.md:164`. Task17 final index integration and the overall Goal remain OPEN; this approval does not close either.
- ⚠️ Cannot verify from diff: unchanged Task1/2 acceptance, all historical runtime/control assertions, the 42-cell matrix's underlying contents, and every cited existing test's behavior. These remain bounded by their pre-existing evidence and root's accepted state; this review does not reopen those tasks or claim actual deployment. The one targeted scheduler check described below supports its named claims only.
- ⚠️ Cannot verify from diff: original tool execution provenance, absence of every prohibited operation, or complete historical Git/index state. The committed test outputs are complete and consistent with the source and report, but are not independent reruns. Research at `docs/evidence/task-17/research.md:1` identifies primary sources, versions, tool references and failures; this review did not independently fetch the external publications or treat the record as an audit opinion.

### Strengths

- `docs/threat-model.md:36` consistently separates scoped accepted implementation, unit/partial evidence and unimplemented controls. Pending rows link real gap records and explain that those links are not passing tests. This avoids turning link existence into a control-effectiveness claim.
- `docs/evidence/README.md:29` adds genuine isolation references while retaining prior entries; `docs/evidence/README.md:41` names the four exact missing destinations and future producers, explicitly keeping final integration open.
- `docs/soc2-mapping.md:16` maps the requested criterion families while acknowledging physical-access/disposal gaps and distinguishing local runtime cleanup from media sanitization. Its version and inference limitations are explicit at `docs/soc2-mapping.md:10`.
- `scripts/check_threat_model_links.py:19` keeps default inputs narrow. `scripts/check_threat_model_links.py:39` rejects repository escape, hidden paths, symlink components and nonregular targets; body reads are bounded and links never execute targets or fetch URLs. Resource bounds are applied by the entrypoint at `scripts/check_threat_model_links.py:25`.
- `scripts/test_check_threat_model_links.py:14` uses tiny owned temporary fixtures with cleanup. Its five finite cases exercise real link/fragment, diagnostic, escape, symlink and nonfile behavior without importing project controllers. `docs/evidence/task-17/checker-tests-tool-result.json:8` records exit0, five passing tests, no skips or warning noise; `docs/evidence/task-17/links-tool-result.json:8` records exit0 and 208 local links with zero errors against the frozen source.
- `docs/evidence/task-17/substage-report.md:119` preserves discovery, research-service and default Git-sandbox failures instead of recasting them as success or hiding their limits.

### Issues

#### Critical (Must Fix)

- None. Count: 0.

#### Important (Should Fix)

- None. Count: 0.

#### Minor (Nice to Have)

- None. Count: 0. The documented limited Markdown subset is sufficient for the authored/default documents; broader parser coverage is not required by this substage.

### Checks and review boundaries

- Read the binding task brief first, then the complete public implementation report and reviewer prompt. Reviewed the full 64,283-byte raw package in nonoverlapping ranges 1–260, 261–520, 521–780 and 781–1040; the final range reached EOF. No hunk was cut off, so no changed file needed a separate read.
- One named outside-diff risk: the new scheduler control register could cite invented test names or overstate the tested assertions (`docs/threat-model.md:61`). One focused read-only `rg -n -A 38` over the nine named test declarations in `controlplane/internal/scheduler/scheduler_test.go` found all nine. The displayed assertions support single-start behavior (`:119`), policy failure (`:153`), worker bounds (`:297`), node-bound recovery (`:343`), terminal rollback (`:365`), lost-session fencing (`:419`), lost-log handling (`:597`), stored-spec dispatch (`:647`) and ambiguous recovery (`:681`). No tests were executed, and this did not establish fleet recovery or actual runtime acceptance.
- No test rerun was warranted: reading raised no specific unresolved behavior doubt requiring a new fixture. No broad crawl, old Task6 proof review, actual resource operation, Go/Docker invocation, private/proc access, Git command, source/index/HEAD mutation or agent dispatch occurred. The only write is this requested ignored review report.
- This is an independent subagent task review, never human review, human annotation, actual cloud/runtime validation or SOC2 assurance. Original actual0664 refusal, final5/5, Q5000000000/releasedfalse, scene22, no host k3s/iptables authority, budgets and no-push/publication boundaries remain in force.

### Assessment

**Task quality:** Approved for this documentation/checker substage; 0 Critical / 0 Important / 0 Minor.

**Reasoning:** The implementation is small, bounded and consistent with the task's evidence-honesty requirements. It supplies the requested current analysis and link validation without upgrading partial or absent controls into accepted deployments; final Task17 measured-index integration and the overall Goal remain OPEN.
