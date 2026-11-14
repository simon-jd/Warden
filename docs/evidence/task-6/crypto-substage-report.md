# Task6 cryptographic verifier/JWKS substage — 2026-10-25

Status: source and bounded local unit evidence ready for independent source/security review; Task6 and Goal remain OPEN. Overall BASE is `84018e512d78156283ae64aab62ccb76d5d20801`; crypto substage BASE is `c43c74f63062e5c1bae7f30893ab37dc5d9d6f06`. Existing Task6 review fix count remains 1/5. This report does not reset original Task3/4 five-round limits, retained现场/Q, or Task5's 42 actual execution cells.

Frozen source commit: `6d02de4062c0ee1e5d62825df0ea670d54672b5e`. It contains exactly `controlplane/internal/authn/{verifier.go,jwks.go,verifier_test.go}` and the fixed `identity-unit` extension in `scripts/firecracker_code.py`. The evidence is committed separately. Controller-owned plan-review/STATUS/ledger/ruling edits are excluded from both implementation commits.

## Implemented boundary

`authn.New(Config)` accepts one fixed public-cloud Entra v2 tenant UUID authority, its exact tenant JWKS URL, and the configured custom API audience UUID. `Verify(raw)` retains the original context-free API; `VerifyContext(ctx, raw)` is separately named. Verified claims expose issuer/subject/audience/time/scope, never a Warden tenant grant. No SQL TenantAdapter, SCIM, migration, CLI, main wiring, Terraform, or API fallback changed; absent-verifier401 remains. Config is trusted operator input: application registration and correct audience selection are later operational obligations.

JWT validation limits total input to16KiB, decoded header to2KiB, and kid to1..128bytes; canonical unpadded base64url and exact three segments are required. It rejects duplicate JSON at every nesting level, excess depth, raw invalidUTF8, algorithm/critical/token-directed key headers, invalid claims and altered signatures. RS256 verifies the original encoded header/payload with stdlib RSA/SHA256. Issuer/version/delegated `warden.access`, subject, configured audience membership, integer exp and optional nbf are checked before I/O and again after signature/fetch for time expiry. Claims allow the configured audience in a unique bounded audience array; no token-supplied endpoint, tid/oid/email-to-tenant authority, ID-token-without-scope or roles-only app token is accepted.

Public construction provides ordinary TLS verification (minimumTLS1.2), a dedicated no-proxy transport, no redirects, fixed HTTPS JWKS, connect/TLS2s, fetch3s and Verify5s bounds. Responses require200, at most1MiB/64keys, unambiguous kids, RSA2048..4096, odd nonzero modulus, sane odd exponent3..65537, compatible alg/use/key_ops when present, and no private key members. Invalid or incomplete keysets never replace a successful snapshot.

Successful complete snapshots expire at exactly10minutes. Fresh known keys remain usable through unrelated refresh failures only until their original expiry; refresh failure does not extend stale trust. One independent bounded shared fetch serves at most32waiters. Fresh unknown-key new fetches have2/sec refill and burst2; joins spend no additional fetch budget. Expired/empty-snapshot fetch failure has1second backoff. A canceled caller cannot cancel another caller's refresh. Final acceptance also checks the snapshot remains current; simultaneous snapshot replacement can conservatively deny an otherwise valid request. Unknown-kid overload may temporarily deny a legitimate rotated key, by the accepted fail-closed availability tradeoff.

## Actual TDD and frozen covering evidence

All three Go invocations used only `python3 -B scripts/firecracker_code.py identity-unit`, whose fixed inner command is `go test -p 1 -count=1 -v ./controlplane/internal/authn`. No selectors, race mode, broad old suite, cache fixture rerun, hostGo or alternate profile ran.

| Evidence | Actual source state and result | Wrapper duration | Source manifests |
|---|---|---:|---|
| [crypto-red-01](crypto-red-01/receipt.json) | Genuine compile/API RED: missing Verifier/newVerifier/Config/Claims before implementation. HEAD was BASE; test/alias working tree captured prospectively. |2.092599s, exit1|141files; pre=post|
| [crypto-unit-02](crypto-unit-02/receipt.json) | Implementation GREEN on uncommitted working tree, still HEAD BASE; Go package6.185s. |8.078446s, exit0|143files; pre=post|
| [crypto-cover-03](crypto-cover-03/receipt.json) | Single final covering on committed6d02de4 after manual style edits;15top-level tests and32subtests PASS, Go package6.252s. |9.040243s, exit0|143files; pre=post and every hash matches frozen commit|

Each stage retains `run.py`, prospective `pre-source.json`, `post-source.json`, pre/post protected sysctls, intent, exact output, receipt and postguard. The RED stage's `red-source/` and GREEN/cover `source-snapshot/` were written before their respective commands; none were reconstructed after results. Manifests cover all tracked Go/Python/shell/SQL/Terraform/TOML/YAML/build files plus new authn source/test and the fixed profile harness; caches, secrets and evidence/working-report directories are excluded. Recording wrappers live separately alongside each run. [Commit comparison](crypto-cover-03/commit-comparison.json) is explicitly a subsequent read-only comparison, additional to the prospective manifests.

The GREEN working tree was then manually edited for normal multi-line Go readability. A lightweight token comparison assisted edit review; it is not test evidence and does not establish the frozen result. The complete143file frozen pre/post hashes and actual final Go run establish that result. The RED and earlier GREEN snapshots remain byte-for-byte preserved.

Tests use ephemeral in-memory RSA keys and tokens and a private in-container TLS loopback fixture with a private test-only transport adapter. No key/token bytes are logged or checked into Git. These are implementer-authored cryptographic unit fixtures, not human IdP/SCIM/real-user evidence. The named audience and rotation tests prove real-signature rejection, A→B unknown-kid immediate refresh and removed-key rejection at exact10minute expiry. Other cases cover altered payload/signature, claims, malformed/canonical/duplicate JSON, key material/response bounds, failures/redirects/no stale extension, shared refresh/cancellation, unknown-kid budget and concurrent waiter admission. Concurrency tests observe acceptance, fetch counts and prompt return; this run is not a race-detector claim.

## Resource and execution facts

The unchanged profile pins image `sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d` and cached Go1.26.10. Actual execution used ordinaryUID1000, source/read-only root, cap-dropALL, no-new-privileges, networknone, private IPC/cgroup namespaces,2GB memory=swap,CPU2,PID256,tmpfs256MiB,GOMAXPROCS2,GOMEMLIMIT1500MiB,umask0077,GOPROXYoff/GOTOOLCHAINlocal. Actual inspected host configuration and task/session labels are in each output; no external listener or network allowance was added. Writable build cache is the existing separate `.cache/firecracker-code` only.

All three fresh preguards and postguards passed under the existing512,000,000byte prospective code charge plus retained5,000,000,000byte Q; own image charge was0, additional total5,512,000,000bytes, download0 and service-memory guard3,000,000,000bytes. Final cover preguard observed project allocated4,206,465,024bytes, postguard4,207,628,288bytes; final R+additional was9,719,628,288bytes. Postguard owned containers/images were empty. No new standard3GB admission or oldQ release is claimed.

Exact per-run containers were removed:

- RED: `f35c2d0362ef265e38150aaeb237b045a1fbae13971220f6740493ed973bd590`.
- GREEN: `9cd0899c10bfb535737ce78f69aab550d1052b70af77c0e9dcb953cc13c5d4a3`.
- Cover: `cced259dace90152e75759a8ee2fe98f5d33587a60618a0d7580021c2ff48412`.

Every run's six protected sysctls stayed at baseline: vm.overcommit_memory1, vm.panic_on_oom0, kernel.panic10, kernel.panic_on_oops1, kernel.keys.root_maxkeys1000000, kernel.keys.root_maxbytes25000000. Nothing modified host sysctls, k3s, iptables or global configuration.

## Formatter refusal and remaining work

The one proposed native formatting opportunity failed its additional unchanged `trusted_directory` ancestor check before reading/checking the binary or editing source: a go-mod ancestor was group/other writable. [Factual preflight note](crypto-format-01/preflight-failure.json) and its unexecuted-beyond-preflight recorder are retained. No binary SHA was collected, no gofmt process ran, and source was unchanged by that attempt. This was a metadata guard refusal, not automatic approval rejection or a gofmt program failure. The controller's [formatter ruling and closure](crypto-formatter-ruling-20261025.md) canceled the opportunity; no weaker retry, permission relaxation or new alias was made.

The earlier actual old-cache maintenance timeout remains exactly as [cache-operation-20261025.md](cache-operation-20261025.md):180seconds, files not deleted, partial permission tightening/private intent retained. This crypto substage did not inspect/recover/retry that state. No actual cache mutation, PG/material acquisition, cloud resource, identity assignment, account/token acquisition, TF apply, VM, push or publication occurred here.

Independent source/security review is pending. Public Entra cloud/single tenant configuration is intentionally narrow; sovereign clouds and multiple authorities are unsupported. Real Entra access tokens, tenant issuer/subject→stored-active mapping, revocation-after-SCIM, administrator auth/bootstrap, durable SQL/reopen tests, and original SCIM tests are not yet implemented/executed in this substage. Existing Task3/4 retained state and Task5 actual42cells remain open as before. No Task6/Goal completion claim is made.
