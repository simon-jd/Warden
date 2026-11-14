### Spec Compliance

- ❌ Full Task 10 remains incomplete: Cilium policies, scheduler allowlist delivery, Host/SNI proxy enforcement, and original network acceptance tests are absent ([task-10-brief.md:4](.superpowers/sdd/2-warden-security-plan/task-10-brief.md:4), [task-10-brief.md:10](.superpowers/sdd/2-warden-security-plan/task-10-brief.md:10)). The report accurately identifies this as a partial scoring milestone.
- ❌ The scoring component can suppress qualifying exfiltration because one unrelated DNS question fails its hostname validation.
- ⚠️ Real DNS transport, collector identity binding, tenant isolation, network attachment, bypass resistance, and lifecycle cleanup cannot be verified from this diff.

### Strengths

- `detect/dns_exfil/score.go:70` copies observations before sorting; `:105` includes complete timestamp groups before evaluating thresholds.
- `detect/dns_exfil/exfil_test.go:102` constructs and reconstructs an actual 4,096-byte encoded fixture, with meaningful assertions for identity, count, window, and entropy.
- `detect/dns_exfil/exfil_test.go:141` and `:151` exercise strict count/entropy thresholds, repetitions, query types, and per-query averaging.

### Issues

#### Critical (Must Fix)

- None found.

#### Important (Should Fix)

- **`detect/dns_exfil/score.go:64–66`, `:128–146`: attacker-controlled question names can disable detection for the entire batch.** The validator restricts DNS questions to LDH hostname syntax and requires a registrable domain. Legitimate DNS questions such as `_dmarc.example.com` and `com` therefore invalidate every observation in the run, including an earlier qualifying exfiltration window. `detect/dns_exfil/exfil_test.go:235–237` explicitly enshrines this suppression. Trusted identity/time metadata does not make question names trusted. Handle DNS question syntax appropriately and prevent one rejected question from erasing valid detection evidence; surface rejected telemetry distinctly. Add a regression containing qualifying traffic followed by these questions.

#### Minor (Nice to Have)

- **`detect/dns_exfil/score.go:91–104`; `detect/dns_exfil/exfil_test.go:169`: the expiration-only crossing path lacks a direct test.** Add 31 zero-entropy questions at `t=0`, 31 entropy-5 questions at `t=30s`, and a final question at `t=61s`; the documented earliest result should be the expiration event at `t=60s`. Include a count-30 negative control.

### Checks Run

- Read the complete reviewer template, original brief, final author report, and supplied diff once; diff size/hash matched the supplied values.
- Static review only. No tests, builds, Git operations, network access, or mutations.
- Reported GREEN evidence contains nine top-level/34 total passing cases and no FAIL/SKIP; it demonstrates scoring behavior, not live transport.
- The proposed expiration regression remains unexecuted.

### Assessment

**Task quality:** Needs fixes.

**Reasoning:** The implementation has clear windowing logic and useful component tests, but batch-wide rejection creates a practical detection bypass. Full Task 10 acceptance must remain open independently of the component repair.
