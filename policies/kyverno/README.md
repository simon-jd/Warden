# Warden image admission (Task 15: source only)

The checked-in `verify-images.yaml` and `block-kev.yaml` are **unbound,
unconditional deny** policies for Pods. Do not install them into a shared
cluster: with no authenticated repository, protected ref, namespace, OCI
repository, image digest, and SLSA signer, no Pod can pass them. This repository
currently has no Git remote or published Warden OCI image. The rendered
(bound) policies are verified offline with the real Kyverno CLI; see
"Offline `kyverno test`" below.

`.github/workflows/build.yml` is the future production path. It requires a
protected `supplychain-publish` GitHub environment and the environment
variables `WARDEN_TRUSTED_REPOSITORY`, `WARDEN_TRUSTED_REF`,
`WARDEN_IMAGE_REPOSITORY`, `WARDEN_NAMESPACE`,
`WARDEN_ALLOW_PUBLIC_REKOR=true`. Missing values or a context mismatch stop
before checkout/build/push. Cosign v3.1.4 Linux amd64 is pinned to the
[official GitHub release API asset digest](https://api.github.com/repos/sigstore/cosign/releases/tags/v3.1.4)
`sha256:424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa`
(145,688,404 bytes). This establishes expected asset bytes via GitHub TLS/API
metadata, not independent publisher signature verification. The flag to post to public Rekor is explicit because the
SLSA generator exposes private repository names there.

After pushing a control-plane image, CI takes the registry's immutable
`image@sha256:...`, uses it for Syft CycloneDX, a **direct and unfiltered**
Grype v0.121.0 JSON scan, and keyless attestation/signing. The Python
`assess_scan` gate rejects missing or invalid DB status, DBs older than five
days (Grype v0.121.0's default), missing provider metadata, missing/mismatched image digests,
`ignoredMatches`, malformed findings, and missing or stale CISA KEV feed.
Its required pinned Grype JSON profile rejects filtering through `only-fixed`,
`only-notfixed`, `ignore-wontfix`, `ignore`, `exclude`, `vex-documents`, and
`vex-add`; CI enables `include-matcher-suppressions` so internally suppressed
matches are visible to the existing `ignoredMatches` rejection. It also
enables `match-upstream-kernel-headers` so that built-in header suppression
does not hide findings. A missing profile field cannot establish completeness.
The CISA catalog is fetched over HTTPS from the official URL and compared
against both direct and related CVE IDs. Grype's own `knownExploited` flags
cannot manufacture a clean result. CI signs the complete report and catalog
hash as an attestation even when the separate fixable-critical/KEV gate blocks;
the image signature and SLSA job only follow a clean gate. Local synthetic
tests validate parsing and rendering, not HTTPS origin or cryptography.

The CI renderer produces JSON syntax that is also YAML. All verification
entries use `imageReferences: ["*"]` inside the bound namespace, with
`required`, digest verification, Enforce and fail-closed webhook behavior.
The four separate checks are exact build-workflow keyless image signature,
CycloneDX attestation, SLSA container-generator provenance with its own
identity, and the complete-scan/no-KEV attestation. The latter binds
`imageRepository` and `imageDigest` to one published artifact. The SLSA
generator [requires the full `@v2.1.0` tag, not a commit SHA](https://github.com/slsa-framework/slsa-github-generator/blob/v2.1.0/internal/builders/container/README.md#referencing-the-slsa-generator);
its documented container predicate uses
`https://slsa.dev/provenance/v0.2`, `builder.id`, `buildType`, and
`invocation.configSource`. The renderer verifies these exact fields. A
different observed signed predicate must be reviewed, not silently accepted.
All four checks use Kyverno's default Cosign verifier (legacy `.sig`/`.att`
tags, no `type: SigstoreBundle`): slsa-github-generator v2.1.0 only writes
that format, so CI signs with `cosign --new-bundle-format=false
--use-signing-config=false` too. Those cosign v3.1.4 flags have not run in
GitHub Actions yet (no repository).

## Offline `kyverno test` (part of `make test`)

`supplychain/kyvernolab` (`TestKyvernoAdmission`, also `make test-kyverno`)
runs the pinned Kyverno CLI v1.19.2 (`make tools`, sha256-checked) against
four images in an in-process loopback registry:

| case | contents | expected |
|---|---|---|
| `tests/unsigned` | no signature or attestation | all 4 rules fail |
| `tests/signed-clean` | build-workflow signature, SLSA provenance from the generator identity, CycloneDX SBOM, complete scan with `kevCves: []` | all 4 pass |
| `tests/signed-kev` | same, scan lists `CVE-2021-44228` | signature/SLSA/SBOM pass, `complete-scan-no-kev` fails |
| `tests/wrong-identity` | everything signed by `attacker/warden`'s workflow | all 4 fail (`subject mismatch`) |

The policies are produced by `scripts/supplychain.py render` for each
image's own digest. The test changes exactly one thing per keyless attestor:
the trust root becomes a throwaway CA that issues Fulcio-style certificates
(URI SAN plus the issuer extensions 1.3.6.1.4.1.57264.1.1/.8), and the
Rekor/CT checks are off (`ignoreTlog`, `ignoreSCT`). Subjects, issuer,
predicate conditions and digest binding are exactly as rendered. Keys exist
only in the test process. HOME, DOCKER_CONFIG and TUF_ROOT are isolated, and
the test asserts that no TUF cache was created.

What this does **not** show: real Fulcio certificates, Rekor inclusion, the
real cosign v3.1.4 output, or a live admission controller. Those still need
a GitHub repository and a cluster. The root `tests/kyverno-test.yaml` still
covers the unbound default-deny placeholders.

Primary formats: [Grype v0.121.0 Document](https://github.com/anchore/grype/blob/v0.121.0/grype/presenter/models/document.go),
[DB status/provenance JSON](https://github.com/anchore/grype/blob/v0.121.0/grype/vulnerability/provider.go),
[CLI dbInfo](https://github.com/anchore/grype/blob/v0.121.0/cmd/grype/cli/commands/root.go),
[KEV metadata](https://github.com/anchore/grype/blob/v0.121.0/grype/presenter/models/vulnerability_metadata.go),
[Kyverno Sigstore verification](https://kyverno.io/docs/policy-types/cluster-policy/verify-images/sigstore/),
and the [official CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
