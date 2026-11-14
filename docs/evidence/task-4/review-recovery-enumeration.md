- **I9 — implicit following during enumeration: ADDRESSED at source `ba8cfaf6bffd7996f54bd50db9ccf453ff121022`.** `scripts/firecracker_recovery.py:661` enumerates names through held directory FDs; `:665` classifies entries using explicit FD-relative `stat(..., follow_symlinks=False)`. No `DirEntry` classification or `os.walk` remains in this path. The exact omitted links therefore receive only their own metadata checks.

- **Check — safe descent and preserved selection:** child directories open with `NOFOLLOW_DIR` and must match observed metadata and trusted ownership/modes before descent (`scripts/firecracker_recovery.py:671`). Parent metadata is rechecked afterward (`:690`). Exact link/object entries must match their authenticated metadata (`:680`); unknown links and nonregular types refuse (`:687`). Existing directory exclusions apply only to actual directories. Required entries, count limits and final material rechecks remain (`:689`, `:694`).

- **Check — regression closes the demonstrated test gap:** the guard at `scripts/test_firecracker_recovery.py:340` intercepts default/explicit-following `DirEntry.is_dir`, `is_file` and `stat` before target lookup, alongside explicit open/stat/resolve guards. Archived RED records the old enumerator failing specifically on `following DirEntry.is_dir for sitecustomize.py`. Tests at `:401` and `:421` additionally cover unknown links/types, preserved directory exclusions and replacement before descent. Recorded results are focused3PASS/0.011s and committed-source `MaterialPolicyTests`12PASS/0.034s. No tests were rerun during review.

- **Check — bounded delta:** read the complete four-commit `36c5856..9aa87b2` package, exact ruling/brief, appended report and verification records. Production changes are confined to `select_stdlib`; the supplied verification records50 other host functions and14 bindings unchanged. Previously reviewed ABI, operation, admission, cleanup, helper and retirement boundaries were not reopened.

- **New Critical: None. New Important: None. New Minor: None. Out-of-Scope Observations: None.**

- **Spec verdict: PASS** for the I9 amendment.

- **Quality verdict: PASS** for the scoped delta. Explicit nofollow classification and the behavioral regression address both the defect and its previous validation gap.

- **Source/plan execution gate: PASS.** I9 no longer blocks the previously approved controller-only, inspect-once plan. Fresh original/predecessor authentication and admission remain mandatory; this verdict adds no operation, retry, reset or boot authorization.

- **Cannot Verify / actual limitations:** actual system traversal, host/scratch ABI, closure/package, predecessor shape, inventory, remount/chown and ordinary postflight remain unverified. This review performed no tests, Git commands, writes, historical crawl, subagents or actual operations. Q5GB remains unreleased; I7, Task4 acceptance and original-owner/Gate/API retirement remain OPEN at Task4round5. B and a new boot remain outside this approval.
