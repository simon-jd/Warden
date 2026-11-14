**I3 — Three-subject acquisition and verification procedure: PARTIAL / OPEN — Important.** `scripts/oci_cases.py:62` now renders digest-bound policies, Pods and Kyverno Test manifests with explicit expected rules. `scripts/oci_cases.py:103` rejects Skip/Error/Excluded rows and duplicate or missing rules. The unsigned probe distinguishes non-200 referrer responses from absence (`scripts/oci_cases.py:170`). These address substantial parts of the finding, but the candidate inconsistency and unreadable mounted cases below prevent approval.

**I4 — Exact verifier isolation and bounded execution: PARTIAL / OPEN — Important.** The new caller provides immutable local image-ID selection, scratch mounts, credential-helper restrictions and bounded subprocess capture. It nevertheless retains unresolved TUF pins and an unconditional `_network` failure (`scripts/verify_oci.py:23`, `:148`). The caller also has concrete access, deadline and cleanup defects listed below. Its unconditional main stop remains effective (`scripts/verify_oci.py:203`); no present execution or isolation success is inferred.

**M1 — Contradictory manifest totals: ADDRESSED.** `upload-manifest.json` now has a single `file_count: 36`, `total_source_bytes: 166236`, and v4 schema. The obsolete competing counts are removed. The complete entries were supplied; their byte/hash verification remains root’s recorded check.

### Remaining and New Important Findings

1. **Generated cases cannot be read by the verifier UID.**  
   **Location:** `scripts/oci_cases.py:90`, `:99`; `scripts/verify_oci.py:184`, `:192`.  
   Rendering creates case directories with mode 0700 and files with mode 0600 under the caller’s UID. Docker then mounts them read-only into a process running as UID 65532. Unlike the credential file, their ownership or accessibility is never adjusted. A normal hosted-runner owner therefore produces permission failures before Kyverno can read the test and policies.

   **Minimal fix:** Establish and validate a private owned root, then explicitly prepare the mounted case tree for UID 65532—through suitable ownership or read/traverse permissions within that private boundary. Preserve read-only container mounts. Add a focused permissions-contract check; no container execution is necessary merely to inspect the intended ownership/modes.

2. **The whole-call deadline excludes registry work, and cleanup failure can be reported as success.**  
   **Location:** `scripts/verify_oci.py:161`, `:177`, `:143`; `scripts/oci_cases.py:147`, `:166`.  
   The 90-second deadline is passed to Docker subprocesses but not to `unsigned_absence`. That function can perform sixteen referrer requests and a legacy-tag request, each with its own timeout, after the build has already consumed time. A per-socket timeout is not a whole-operation deadline.

   Container cleanup also discards output and ignores `docker rm` failure (`scripts/verify_oci.py:143`). No final absence check is made. Consequently, the future caller can return `{"status":"verified"}` without confirmed cleanup.

   **Minimal fix:** Propagate the same absolute deadline through registry requests, reads and pagination, reserving cleanup time. Capture cleanup status, identify the created container positively, and establish final absence. Failure or unknown cleanup must prevent a verified result. Include creation/ownership validation for the private caller root rather than relying on its comment.

3. **The reported KEV candidate contradicts the frozen fixture.**  
   **Location:** R4 `report.md:7`; retained `controlplane/fixtures/kev/Dockerfile:18`.  
   The report now names **Spring 5.3.0 / CVE-2022-22965**, while the manifest retains the unchanged R3 Dockerfile, which fetches **spring-cloud-config-server 2.2.2.RELEASE / CVE-2020-5410**. No fixture change appears in the R3→R4 diff. The v2 proof manifest also drops the explicit expected candidate CVE. These are materially different artifact/advisory identities.

   **Minimal fix:** Restore consistent identification of the unchanged R3 candidate in the report and proof contract, or submit an explicit fixture change for review. Carry the expected candidate CVE through the evidence-accounting procedure; retain the independent complete-scan and fixable-critical gates.

4. **Verifier readiness remains deliberately but incompletely specified.**  
   **Location:** `scripts/verify_oci.py:23`, `:87`, `:148`.  
   TUF bytes/hash, transitive trust/cache behavior and enforceable disposable online egress remain unresolved. `_network` always raises, including after a hypothetical policy hash is supplied. Furthermore, the unsigned registry probe runs in the Python caller (`:177`), outside the Docker network selected for Kyverno; a future container-only network implementation would not constrain that probe.

   **Minimal fix:** Complete the pinned trust/input specification and transitive path mapping, and define enforceable egress for **both** registry acquisition and container verification. Preserve the current stops until those mechanisms are reviewed. Their safe failure does not satisfy the requested complete preparation.

### Additional Scope Limits

- **Critical:** None established.
- **Minor:** No additional finding beyond the corrected manifest totals.
- R3 I1/I2 and accepted fix1 findings remain unchanged and were not re-reviewed.
- The new Basic-only registry client has no challenge/token-exchange path (`scripts/oci_cases.py:137`). Real GHCR authentication compatibility remains unverified; an authentication challenge must not be mistaken for evidence that the absence procedure works.
- Null subject slots correctly remain non-evidence. No real registry, certificate, Rekor, provenance, Grype, Kyverno or live-admission outcome was established.

### Checks

- Read exactly the five authorized packet sections in one successful call; decompressed only the supplied diff in memory. No truncation, additional reads, network access, tests, Git operations or mutations.
- The supplied receipt records **two new accounting-contract tests passing**, empty stderr, known owned-child-group cleanup and unchanged source pins. It explicitly does **not** cover rendered-file accessibility, registry authentication, Docker cleanup, whole-call networking bounds or cryptography.
- No artifact hashes were independently recalculated during this review.

**Continuous fix round 4/5: Needs fixes.** I3/I4 remain open; M1 is addressed. The unconditional guards must remain in place, and all three cryptographic cases and full Task15 acceptance remain **UNRUN/OPEN**.