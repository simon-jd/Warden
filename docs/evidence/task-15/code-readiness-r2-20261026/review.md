**Scoped CODE readiness — Needs fixes.** The proposed patch remains unapplied. Fix1 findings I1/I2/I3 retain their accepted status; this review covers only the new requirements and proposed changes.

### Requirement Verdicts

| New requirement | Verdict | Evidence |
|---|---|---|
| Dispatch-only workflow | **ADDRESSED** | Push trigger removed; explicit `clean`, `unsigned`, and `kev` choices added (`.github/workflows/build.yml:3`). |
| Build bounded to 20 minutes | **ADDRESSED** | `timeout-minutes: 20` is executable configuration (`.github/workflows/build.yml:26`). |
| Provenance bounded to 10 minutes | **OPEN — Important** | No timeout mechanism exists; the claimed execution closure is only a comment (`.github/workflows/build.yml:208`). |
| Bounded concurrency | **ADDRESSED** | Workflow/ref concurrency serializes runs; it correctly does not claim to limit total dispatches (`.github/workflows/build.yml:17`). |
| Bounded retention | **PARTIAL / OPEN** | The report specifies one-day repository retention and future readback, but supplies no executable prerequisite establishing that setting before publication. |
| Lowercase OCI owner comparison with exact GitHub identity | **PARTIAL — Important** | Registry comparison lowercases only the owner correctly, but CI still lowercases the repository passed to the renderer (`.github/workflows/build.yml:56`, `:120`). |
| Exact genuine unsigned/clean/signed-KEV acquisition and fixture path | **PARTIAL — Important** | Conditional signing preserves real scan checks, but the KEV input and complete verification/fixture path remain unspecified (`.github/workflows/build.yml:101`, `:175`). |
| Immutable provenance mechanism or explicit documented exception | **ADDRESSED AS DOCUMENTED EXCEPTION ONLY** | The report explicitly retains the unresolved tag exception for decision. It establishes neither an approved waiver nor a compatible bounded replacement (`.github/workflows/build.yml:216`). |
| Exact verifier credential/cache isolation closure | **OPEN — Important** | The packet’s “Future verifier filesystem boundary” section provides a design outline and explicitly states that transitive paths are not fully closed. |
| Minimal upload allowlist and SHA manifest | **NOT VERIFIED FROM THIS PACKET** | The report claims a separate 33-path manifest; its entries and hashes are not included in the authorized review material. This is an evidence limit, not a finding that the manifest is absent. |
| Concrete remaining human scope | **PARTIAL** | Account/quota, private publication, public metadata, settings, execution and deletion are identified. The finite execution count still needs alignment with three independently selected proof cases and verification. |

### Important Findings

1. **CI bypasses the new repository-case preservation.**  
   **Location:** `.github/workflows/build.yml:120`; `scripts/test_supplychain.py:120`.  
   The production workflow still constructs the binding with `os.environ["GITHUB_REPOSITORY"].lower()`. Allowing uppercase characters in `scripts/supplychain.py:17` and testing a directly supplied mixed-case binding does not repair this caller. CI therefore cannot produce the exact raw identity claimed by the report and regression test.  
   **Minimal fix:** Pass the raw repository value into the renderer; keep lowercasing confined to OCI owner comparison. Check the production binding construction as well as the renderer regression. Actual certificate casing remains an unrun compatibility check.

2. **The unresolved provenance execution limit is not enforced.**  
   **Location:** `.github/workflows/build.yml:208`.  
   The condition permits every successful `clean` or `kev` build to invoke the reusable workflow. The following comment says execution is closed, but provides no guard. Once the ordinary binding variables are configured, a dispatch can build, publish, sign, and enter provenance without the required ten-minute bound. The report’s truthful compatibility explanation does not implement that bound.  
   **Minimal fix:** Supply a compatible bounded provenance mechanism, or enforce the unresolved readiness stop before build/publication until a concrete exception or replacement is reviewed. Do not add an unsupported caller keyword. Apply the same fail-closed readiness prerequisite to the outstanding retention readback.

3. **The signed-KEV subject acquisition requirement remains incomplete.**  
   **Location:** `.github/workflows/build.yml:101`, `:175`.  
   The `kev` path builds the same application and dependencies with a different OCI label. That distinguishes the digest but does not supply a known vulnerable input. The report expressly acknowledges that a future reviewed vulnerable fixture is still necessary. Thus the patch safely rejects an unsuitable result, but does not yet provide the requested concrete acquisition path. It also supplies no completed real-digest test-manifest/verification procedure, and skipping signing does not establish that an unsigned digest has no pre-existing signatures.  
   **Minimal fix:** Prepare the exact reviewed, pinned this-repository fixture input and subject-to-manifest procedure, preserving the real complete-scan/CISA checks. Specify signature-absence verification for the unsigned subject and a finite execution allowance sufficient for all three cases. No invented CVE, digest, or synthetic scan substitution is needed or acceptable.

4. **The requested exact verifier isolation boundary is still a proposal rather than closed preparation.**  
   **Location:** `root-review-packet.txt`, author report section “Future verifier filesystem boundary, not an admitted command.”  
   The report calls for a future verifier image, trust material, scratch layout, egress restrictions, and transitive path investigation. It explicitly leaves Kyverno SDK/go-containerregistry/Cosign/Sigstore paths unresolved. This does not meet the new requirement to prepare the exact boundary; ephemeral-runner wording alone does not establish credential isolation.  
   **Minimal fix:** Provide a concrete reviewed verifier-image specification and inert caller/layout, identifying fixed tool/trust inputs, effective home/default paths inside disposable storage, credential-helper behavior, mounts, environment, egress enforcement, cleanup and output limits. Preserve the current execution prohibition until those details close.

### New Breakage and Out-of-Scope Observations

- **Critical:** None established.
- **Important:** Findings 1–4 above are scoped requirement gaps; no additional independent regression established.
- **Minor:** None established.
- The KEV branch still requires an assessed complete scan, genuine nonempty KEV results, and no fixable criticals before image signing. It does not fabricate a passing fixture (`.github/workflows/build.yml:188`).
- Unchanged SLSA URI, OCI format, cryptographic and live-admission uncertainties were not re-reviewed or converted into new defects.

### Checks and Limits

- Read only the supplied packet. The first successful read suffered **transport truncation**, not approval rejection. Root then authorized one same-route read of the clipped patch/workflow sections; that recovery was complete. No further file reads occurred.
- No patch application, tests, imports, Git operations, network access, Docker/CLI execution, mutations or child agents occurred. The author’s static AST claim is not treated as a test PASS.
- No genuine OCI, signature, provenance or admission result is inferred. The three original cryptographic cases and full Task15 remain **OPEN/UNRUN**.

**Continuous fix round 2/5: Needs fixes — raw-identity propagation, enforced provenance/readiness limits, concrete genuine-fixture acquisition, and exact verifier isolation remain open.**