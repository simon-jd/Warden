Spec Compliance — **Needs fixes; final continuous round 5/5.** Source remains unapproved. No Critical finding identified. Whole Task15 remains OPEN.

Prior finding dispositions:

1. **R4 permissions finding — ADDRESSED in source.** `scripts/oci_cases.py:74,106,115` now requires a private, owned 0700 parent and creates container-readable case directories/files with checked 0755/0644 modes. `scripts/verify_oci.py:80` checks the input root. Actual rendering and container readability remain UNRUN.

2. **R4 candidate consistency finding — ADDRESSED in source.** `scripts/oci_cases.py:36,241` restores the frozen CVE-2020-5410 artifact identity and invokes the production assessor, requiring the intended KEV, matching image digest, complete scan and no fixable-critical blocker. This fixes candidate drift; it does not authenticate the local scan evidence.

3. **R4 deadline/cleanup finding — PARTIAL.** `scripts/oci_cases.py:185` adds an absolute registry-probe alarm with cleanup reserve. `scripts/verify_oci.py:130` requires a valid CID, matching ownership label, successful removal and confirmed absence before recording cleanup success. These are substantive improvements. The remaining deadline issue is listed below.

4. **R4 verifier-readiness finding / original I4 — OPEN, Important.** `scripts/verify_oci.py:23,189` still lacks the concrete trusted bootstrap and enforced network implementation; `_network` and the entry point stop unconditionally. TUF/bootstrap and transitive trust paths, host-probe plus container egress enforcement, and compatible authenticated GHCR access remain incomplete. Minimal completion is a concrete supported implementation of those boundaries with immutable inputs and owned cleanup. The safe STOP must remain until then; it is not complete prospective preparation.

5. **Original I3 — PARTIAL, Important.** The concrete case mapping, strict row accounting and corrected candidate are present, but the authenticated reason for the KEV denial remains unresolved below.

6. **M1 — ADDRESSED.** The complete manifest contains 36 paths with the corrected total of 171,572 bytes.

Remaining scoped Important findings:

7. **Local KEV evidence is not bound to the authenticated attestation.** `scripts/oci_cases.py:241` and `scripts/verify_oci.py:243,248` assess local Grype/CISA files after accepting the expected failing Kyverno rule. Matching their claimed image digest does not prove these are the bytes underlying the trusted signed scan attestation. The rule can fail for a missing or invalid scan attestation while an unrelated local report supplies the expected CVE. Minimal fix: authenticate the same-digest scan attestation and compare its report/catalog hashes and relevant predicate fields with the assessed inputs before attributing denial to KEV.

8. **The absolute deadline still does not cover final local processing.** `scripts/verify_oci.py:244–250` reads/parses the bounded reports and runs the assessor outside an enforced whole-operation deadline, then returns success without checking expiry. Earlier input/render/accounting work also lacks a whole-operation timer. Minimal fix: enforce the deadline around the complete prepared operation, retaining the cleanup reserve and rejecting any expired completion.

Coverage: I inspected the supplied packet once and ran no tests. Root reports two pure checks passing for composed-source integrity/compilation and frozen-candidate acceptance versus wrong-CVE rejection. They do not verify permissions, registry authentication, deadline enforcement, cleanup, Docker/Kyverno execution or cryptography. All three real OCI cases remain UNRUN.

**Final verdict: Needs fixes. Round 5/5 is exhausted; no further round, source acceptance or Task15 completion is implied.**