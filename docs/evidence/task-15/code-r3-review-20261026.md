**I1 — Production repository-case preservation: ADDRESSED.** `.github/workflows/build.yml:138` now passes raw `GITHUB_REPOSITORY` into the binding. `scripts/test_supplychain.py:316` executes the embedded production caller and passes its captured binding to the renderer. Actual certificate casing remains UNKNOWN; the pure test does not establish it.

**I2 — Enforced readiness stop before publication: ADDRESSED.** `.github/workflows/build.yml:44` adds an unconditional, machine-readable `ready:false` result and exit 78 before checkout. It blocks all proof modes while immutable provenance, the ten-minute limit, retention readback and verifier readiness remain unresolved. `scripts/test_supplychain.py:295` checks the actual embedded guard, ordering, exit code and blocker set. This satisfies the previously offered fail-closed alternative; it does not resolve the underlying execution prerequisites.

**I3 — Genuine KEV acquisition and three-subject verification path: PARTIAL / NOT FULLY ADDRESSED — Important.**

- The candidate acquisition is now concrete: `controlplane/fixtures/kev/Dockerfile:16` fetches a fixed Maven version from an exact URL and checks a recorded SHA-1. Its inclusion in the this-repository image is explicit at line 25. The report identifies the advisory and expected CISA CVE, preserves the production scan gates, and honestly leaves actual detection UNKNOWN. SHA-1 is explicitly disclosed as a limited integrity check; no stronger authentication is inferred.
- The three subject slots, expected evidence, unsigned signature-absence requirement and finite execution maxima are now specified. Null digests correctly denote unrun subjects.
- **The requested subject-to-test and verification procedure remains incomplete.** `proof-subjects.json:5` describes expected outcomes, but supplies no Kyverno `Test` manifest/template or mechanism for binding the three acquired digests to their policies and expected rule results. The inert caller runs `kyverno test /input/cases` at `scripts/verify_oci.sh:50`, while its declared inputs contain only case JSON files (`scripts/verify_oci.sh:13`). No supplied source constructs the required test mapping or implements the authenticated signature-absence checks.

**Minimal remaining fix:** Provide concrete inert templates/caller steps that consume the recorded subjects, render the matching policies and Kyverno tests, establish unsigned signature absence with errors distinguished from absence, and account for each required rule’s pass/fail/skip/error result. Future execution and actual digests must remain separately gated.

**I4 — Exact verifier isolation preparation: PARTIAL / NOT FULLY ADDRESSED — Important.**

`scripts/verify_oci.sh:4` safely stops execution, and the proposed read-only root, unprivileged UID, limited mounts and private tmpfs materially improve the boundary specification. The required preparation nevertheless remains incomplete:

- Trust inputs are still “TO BE PINNED” (`scripts/verify_oci.sh:11`). ELF validation, input checks and transitive default-path checks are requirements in comments, not implemented preparation (`:16`).
- Trust material is copied to `/trust/tuf-root/`, but `TUF_ROOT` points to `/scratch/tuf`; no initialization connects them (`:22`, `:28`).
- Required scratch directories and effective-home configuration are not initialized. Credential ownership/readability for UID 65532 is unspecified (`:12`, `:25`, `:49`).
- Enforced online egress remains absent; `--network=none` deliberately prevents the required registry verification (`:35`, `:44`).
- The caller requires digest pinning in its comment but actually runs `warden-kyverno:local` (`:33`, `:50`).
- Output caps and owned-container cleanup are deferred to an unspecified outer wrapper (`:52`). Timing out the Docker client is not an implementation of that cleanup.

**Minimal remaining fix:** Complete the concrete trust/input specification, scratch initialization and default-path mapping, immutable verifier-image reference, enforceable disposable egress boundary, and bounded caller with owned-container cleanup and output capture. Unknown prerequisites must continue to stop execution. The current hard stop makes this safe to retain as unfinished source; it does not make the requested isolation preparation complete.

### New Breakage in the R3 Packet

- **Critical:** None established.
- **Important:** No independent new finding beyond the remaining I3/I4 gaps above.
- **Minor — Contradictory upload-manifest totals.** In the packet’s complete `source-manifest.json`, `file_count` is 35 and `total_source_bytes` is 149499, but the retained `source_files` and `source_bytes` fields still say 33 and 143408. The schema also retains its R2 name. These conflicting snapshot totals make downstream interpretation ambiguous. Update or explicitly rename the historical fields so the current manifest has one unambiguous count and byte total. The complete 35-entry list itself was supplied for this review.

### Checks and Evidence Limits

- Read the authorized packet completely in one successful same-route call, without truncation. No additional reads, network access, tests, imports, Git commands, mutations or child agents.
- The supplied root receipt records **two affected pure tests passing**, empty stderr, known owned-child-group cleanup and unchanged source pins. Their scope covers I1 and I2; it does not validate the fixture, verifier image, registry access or cryptography.
- The full allowlist is present and identifies f5/R2/R3 origins. Root’s per-entry verification is reported evidence; this review did not independently recalculate hashes.
- Fix1 acceptance remains unchanged. Previously unresolved SLSA/OCI compatibility was not broadened into a fresh review.
- The author’s 4096-byte phase overrun remains explicitly recorded with root’s internal budget reallocation; no deletion credit or counter reset is inferred.

**Continuous fix round 3/5: Needs fixes — I1 and I2 addressed; I3 and I4 remain partially open.** Actual Docker/Grype/Kyverno execution, all three cryptographic cases and full Task15 acceptance remain **UNRUN/OPEN**.