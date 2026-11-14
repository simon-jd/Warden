# Task 15 fixed Kyverno CLI isolation check — inert, 2026-10-25

**Decision: no executable caller is justified.** The fixed `kyverno test`
path has no source-proven setting here that prevents every host credential and
cache lookup without changing `HOME`; its transitive TUF/Cosign write closure
is unresolved. More decisively for the original acceptance, this checkout has
no authenticated this-repository GitHub workflow signature, immutable
published image digest, SBOM/scan/SLSA attestations, or three genuine OCI
subjects. A synthetic fixture, context variable, `--registry`, `--version`,
or exit 0 cannot replace those cryptographic cases. The single prerequisite
for a real acceptance caller is an **admitted, isolated this-repository OCI
verification fixture**: real protected workflow identity and same-digest
artifacts, with host credential/cache access denied by a reviewed filesystem
boundary. Until that exists, Task 15 and the parent goal stay OPEN; no new
preparation loop or local substitute test is proposed.

## Fixed entry and actual knobs

The pinned Kyverno v1.19.2 `go.mod` locks `github.com/kyverno/sdk` at
`5a61cbc9e077`, go-containerregistry v0.21.8, Cosign/v3 v3.1.2, Sigstore
v1.10.9, and client-go v0.36.3
([primary go.mod](https://github.com/kyverno/kyverno/blob/v1.19.2/go.mod)).
The [Kyverno test reference](https://kyverno.io/docs/kyverno-cli/reference/kyverno_test/)
accepts a local test folder, `--registry`, `--require-tests`,
`--test-case-selector`, `--output-format`, and inherited `--kubeconfig` and
log flags. It explicitly describes `--registry` as accessing the image
registry **using local Docker credentials**; the [CLI guide](https://kyverno.io/docs/subprojects/kyverno-cli/#testing-policies-with-image-registry-access)
only promises live registry context variables, not successful signature or
attestation verification. The test reference exposes no explicit keychain,
registry-config, TUF root, or Sigstore cache option. `--require-tests` only
rejects an empty test suite. Prior pinned-source notes at
`task-15-source-preparation.md` locate the test command in
`cmd/cli/kubectl-kyverno/commands/test/{command.go,test.go}` and the
`VerifyAndPatchImages` call in `processor/policy_processor.go`; they also
record that Skip can be counted with passes. The exact pinned Kyverno source
URLs were unavailable in this lookup, so this note does not elevate those
earlier observations into proof of a complete positive verifier path.

[go-containerregistry v0.21.8's default keychain](https://github.com/google/go-containerregistry/blob/v0.21.8/pkg/authn/keychain.go)
checks `os.UserHomeDir()/.docker/config.json` **before** `DOCKER_CONFIG`, then
`REGISTRY_AUTH_FILE` and XDG Podman auth locations; Docker config can also
invoke credential helpers. Therefore explicit `DOCKER_CONFIG`,
`REGISTRY_AUTH_FILE`, and XDG paths do not by themselves prove zero host-home
probes. Go's [`os.UserHomeDir`](https://pkg.go.dev/os#UserHomeDir) returns an
error on Unix when `HOME` is absent, but this does not prove that Docker CLI,
`os/user.Current`, or another transitive consumer cannot recover the passwd
home. In particular [`os/user`'s Unix implementation](https://github.com/golang/go/blob/go1.26.9/src/os/user/lookup_unix.go)
can read `/etc/passwd`; no fixed-call-chain proof excludes such fallback.
Setting `HOME=N` was explicitly rejected and is not an option here.

[client-go v0.36.3's loader](https://github.com/kubernetes/client-go/blob/v0.36.3/tools/clientcmd/loader.go)
supports `KUBECONFIG` and explicit loading, but initializes a recommended
home config path and migration rules. A private `KUBECONFIG` is a useful
candidate, not proof that the Kyverno test path avoids all host config
probes. The previous source-preparation note names `TUF_ROOT` and
`SIGSTORE_NO_CACHE` as Sigstore candidates and reports a possible read of
`remote.json`; fixed Sigstore v1.10.9 and Cosign v3.1.2 transitive write paths
were not fully available/closed in this lookup. Consequently `TUF_ROOT`,
`XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR`, `TMPDIR`, and `env -i`
cannot currently be asserted sufficient, and no credential-bearing or
anonymous actual verifier invocation is admitted.

## Boundary for a later real run

The previously prepared v1.19.2 CLI remains 265,805,986 bytes,
SHA-256 `dd492a230e3f7c68235efbf925932cdb34cefbabbd4436d932c3287d9450eea8`,
mode 0600, never executed or modified. It was not downloaded or rehashed in
this check. A future copy/execution needs separate root full-read/fresh
admission and a demonstrable filesystem denial of host home credentials and
caches, rather than reliance on environment variables. If such a caller
becomes justified, the established upper bounds remain whole 89 s TERM +
1 s KILL including owned-child cleanup, new disk <=1 GiB plus four retained
Task 15 `/tmp` trees conservatively 128 KiB and untouched Q=5 GB, with
fresh R + Q + new + retained <=12 GB; new resident <=2 GiB plus old UNKNOWN
9 GB <=16 GB. These are **limits**, not an admitted command or a fresh guard.
No HOME/home/CODEX_HOME/umask change, old PID/RSS/scene scan, host k3s,
iptables, sudo, GPU, service, cloud, or publication action is authorized.

For the actual three-case acceptance, every bound policy and image rule must
be evaluated on genuine immutable subjects with zero Skip/Error/unmatched
cases; issuer, certificate subject, Rekor inclusion, SLSA builder, predicate
type, attestation subject, same digest, and admission decision must be
examined. The fixed CLI's positive behavior and live Kyverno controller
behavior remain unverified. No SOURCE, Git/index, binary, test, or product
file was changed for this preparation.
