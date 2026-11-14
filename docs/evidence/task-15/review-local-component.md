### Spec Compliance

- ❌ **Source/local component: Needs fixes.** All ten authorized source paths are present, but the Docker build omits required local packages, scan completeness is not established by the implemented Grype profile, and malformed findings can bypass the critical gate. See findings 1–3.
- ✅ **Evidence scope is accurately limited.** The preserved first RED records eight tests with four intended assertion failures and zero errors; the final local cover records fifteen passes with zero failures, errors, or skips. These are local semantic results, not cryptographic acceptance (`docs/evidence/task-15/semantic-red-first-20261025/status.txt:2`; `docs/evidence/task-15/local-cover-first-20261025/status.txt:2`).
- ⚠️ **Full Task15 remains OPEN.** Docker/CI/tool execution, genuine registry artifacts, exact certificate identities, attestation subject/digest verification, the original three Kyverno cases, credential/cache closure, and live admission remain UNRUN (`docs/evidence/task-15/report.md:17`, `:21`). Documenting these gaps does not establish source correctness.
- ✅ **Scope inventory:** Dockerfile and context filter; full workflow; production renderer/assessor and tests; both default-deny policies; Kyverno manifest/resources; and README all have corresponding hunks. The metadata correction does not alter source or original test output (`docs/evidence/task-15/inventory.md:7`; `docs/evidence/task-15/inventory-handoff-correction-20261025.json:28`).

### Strengths

- The unbound policies contain unconditional denial with enforcement and fail-closed webhook settings; they do not rely on an “UNBOUND” signer string (`policies/kyverno/verify-images.yaml:7`; `policies/kyverno/block-kev.yaml:7`).
- Bound rules cover every image in the selected namespace, use exact issuer/workflow identities, and distinguish the build signer from the SLSA generator (`scripts/supplychain.py:40`, `:49`, `:89`).
- The assessor checks direct and related CVEs against an independent CISA catalog, retains the complete supplied report, and records fixable critical findings separately (`scripts/supplychain.py:227`, `:247`).
- CI preserves vulnerability attestations before enforcing the release gate; failed gates prevent image signing and the dependent provenance job (`.github/workflows/build.yml:119`, `:131`, `:140`, `:153`).
- The report explicitly distinguishes release-asset hashes from publisher-signature verification and synthetic tests from genuine admissions (`docs/evidence/task-15/report.md:11`, `:17`).

### Issues

#### Critical

None established by this read-only review.

#### Important

1. **The image build excludes required production packages.**  
   **Location:** `controlplane/Dockerfile:6`; `.dockerignore:1`.  
   Only `controlplane/`, `go.mod`, and `go.sum` reach the build stage. The actual control-plane dependency graph imports `warden/runtimes`, `warden/runtimes/gate`, and `warden/runtimes/runc` (`controlplane/internal/scheduler/scheduler.go:15`; `controlplane/internal/scheduler/config.go:12`; `controlplane/internal/runs/execution.go:12`). These are local module packages, so `go mod download` cannot supply them. The build at Dockerfile line 7 cannot compile, preventing the entire supply-chain pipeline from reaching scanning or signing.  
   **Minimal fix:** Allow and copy the required runtime source subtree and any necessary transitive local dependencies into the build stage. Recommend one admitted build of this exact Docker context after correction; no build was run during review.

2. **The “complete, unfiltered” scan claim is not supported by the actual Grype configuration.**  
   **Location:** `scripts/supplychain.py:205`; `.github/workflows/build.yml:116`; `scripts/test_supplychain.py:40`.  
   The assessor checks `onlyFixed`, `onlyNotFixed`, and `vexDocuments`, but pinned Grype serializes `only-fixed`, `only-notfixed`, and `vex-documents`. It also accepts an empty configuration mapping and never rejects `exclude`, which removes packages before matching. The synthetic fixture repeats the incorrect field names. Pinned upstream source establishes both the serialization and the exclusion path. ([Grype options](https://raw.githubusercontent.com/anchore/grype/v0.121.0/cmd/grype/cli/options/grype.go), [Grype scan implementation](https://raw.githubusercontent.com/anchore/grype/v0.121.0/cmd/grype/cli/commands/root.go))

   Independently, Grype defaults `include-matcher-suppressions` to false, and the workflow does not enable it. Internally suppressed matches can therefore be absent from `ignoredMatches`; checking that array is empty does not establish the required unfiltered result. ([Pinned Grype defaults](https://raw.githubusercontent.com/anchore/grype/v0.121.0/cmd/grype/cli/options/grype.go))

   **Impact:** An incomplete scan can receive `scanComplete: true`, allowing omitted critical or KEV findings to escape subsequent assessment. Some filtering flags also populate `ignore`, which the assessor rejects; that incidental protection does not cover exclusions or undisclosed matcher suppressions.  
   **Minimal fix:** Define and enforce the actual pinned configuration profile, reject missing completeness fields and package exclusions, and expose matcher suppressions so the existing fail-closed handling can account for them. Replace the invented configuration fixture fields with upstream-shaped data. Recommend affected tests for an empty configuration, real serialized filter fields, exclusions, and matcher suppressions.

3. **Malformed severity values are accepted as noncritical.**  
   **Location:** `scripts/supplychain.py:217`, `:223`.  
   Finding validation requires an ID, fix mapping, and recognized fix state, but never validates `severity`. A finding with a missing/null severity, `state: "fixed"`, and a non-KEV ID reaches an assessed, release-allowed result. That contradicts the requirement and report claim that malformed findings are rejected.  
   **Minimal fix:** Validate required vulnerability fields and their pinned-schema types before applying business decisions, including a recognized severity value. Preserve legitimate upstream `Unknown` severity as an explicit case. Recommend focused missing/null/invalid-severity tests and a valid unknown-severity case; none were executed here.

#### Minor

None additional.

### Focused Checks and Remaining Acceptance

- **Build-context risk:** Read `go.mod` and the actual entry point, then inspected control-plane local imports and embedded-file declarations. This established finding 1; no build or dependency operation ran.
- **Grype contract risk:** Read pinned upstream option serialization, scan configuration flow, and DB provenance structures. This established finding 2. No scanner, DB download, or fixture-generation campaign ran.
- **SLSA predicate risk:** The pinned README contains conflicting examples with and without the `.git` suffix. The renderer’s exact URI condition therefore remains unresolved against the actual generated predicate; this review does not assert an unproven URI bug (`scripts/supplychain.py:99`). Verify the genuine predicate and certificate against the exact conditions. ([Pinned SLSA documentation](https://raw.githubusercontent.com/slsa-framework/slsa-github-generator/v2.1.0/internal/builders/container/README.md))
- **OCI verification risk:** Kyverno documents `SigstoreBundle`, but documentation alone does not prove compatibility between this Cosign signature/attestation output, legacy SLSA provenance, and the pinned controller. Requested pinned-source URLs were unavailable through read-only web access. Genuine verification must establish issuer, subject, predicate type, registry lookup, and same-digest binding for every rule (`scripts/supplychain.py:91`, `:94`, `:102`, `:107`). ([Kyverno Sigstore documentation](https://kyverno.io/docs/policy-types/cluster-policy/verify-images/sigstore/))
- **Review execution:** Read the complete supplied diff once in bounded chunks. No changed file was separately reread; no tests, Git commands, mutations, builds, CLI executions, services, or publication actions were performed.

### Assessment

**Task quality: Needs fixes.**

The source includes the intended major components and honest evidence boundaries, but the build is presently nonfunctional and the scan gate overstates completeness. Correct these source defects before treating local component implementation as approved; full Task15 acceptance remains separately OPEN.
