- **I1 — batch suppression by question names: ADDRESSED.** `detect/dns_exfil/score.go:90–97` excludes rejected names while preserving valid observations; `:64–68` exposes rejection diagnostics. `detect/dns_exfil/exfil_test.go:249` covers both original reproductions, and `:267` checks malformed-name diagnostics and surviving alerts.
- **M1 — expiration-only coverage: ADDRESSED.** `detect/dns_exfil/exfil_test.go:345` checks the earliest expiration crossing at `t=60s`; its count-30 control first qualifies at `t=61s`.

### New Breakage in the Fix Diff

- **Important — unbounded allocation before enforcing DNS wire length.** `detect/dns_exfil/score.go:163–199` accumulates every decoded label, and `:202` allocates another slice for all labels before `:209` checks the 255-byte limit. A malformed name containing millions of short labels can amplify a relatively small input into large allocations and terminate the scorer. The previous implementation rejected oversized input before splitting. Enforce the decoded wire-length budget during parsing, before growing label storage; add a many-short-label regression.

### Out-of-Scope Observations

- None. Full Task 10 network/collector acceptance remains open as already recorded.

### Review Checks

- Read the required template, original brief, complete updated report, and fix diff once. Report/diff sizes and hashes matched.
- Confirmed the report includes named covering tests and complete output showing six top-level/19 total passes without FAIL/SKIP.
- Static review only; no tests, builds, Git operations, network access, or mutations. The allocation finding follows directly from allocation order; no stress test was run.

### Verdict

**Fix round: Findings remain open** — both original findings are addressed, but the fix introduces an Important parser allocation risk.