# Local Sigma rules and OCSF conversion

This component provides 32 action/indicator rules, synthetic fixture pairs and
real pySigma-to-Lucene conversion. `test_rules.py` (`make test-opensearch`)
indexes every fixture into a throwaway OpenSearch 2.19.1 container with
`opensearch-mapping.json` and asserts each rule's query hits exactly the
expected documents; 32/32 passed on 2026-10-27
([evidence](../../docs/evidence/task-12/opensearch-live-20261027.json)).
Fixtures are synthetic: this proves query semantics, not live detection.

The sections below predate that run; where they say the mapping and
normalizer are unverified, the live run has now exercised them.

The rules are JSON documents, which are a YAML subset, saved as `.yml` with
explicit string quoting. UUID directories under `tests/` contain `pos.json`,
`neg.json` and declared edge cases. `tests/manifest.json` marks every fixture as
synthetic. Its `expected_match` labels describe future indexed-query assertions;
the local tests do not evaluate those labels with a matcher. Document IDs are
opaque UUIDs independent of filenames and event `metadata.uid` values.

`convert.py` invokes the released `OpensearchLuceneBackend` with an explicit
`ProcessingPipeline` and `CaseTransformation(method="lower")`. It supports this
catalogue's ASCII scalar/list selections, `startswith`, `endswith` and `exists`.
Regex, `cased`, field-reference/expansion and other modifiers are rejected.
There is no ECS renaming or event-matching implementation.

The candidate mapping uses lowercase keyword normalization for queried string
fields. Original `_source` values remain unchanged. This deliberately follows
Sigma's case-insensitive string policy, including actor allowlist comparisons;
it is not an identity-authorization policy. Linux binary paths remain full
paths: suffix `/bash` includes `/usr/bin/bash`, while `/usr/bin/bash-helper` is a
declared near miss. Normalizer/wildcard behavior still needs real OpenSearch
2.19.1 verification. Plain keyword fields without normalization are
case-sensitive, so the mapping must not be replaced with that default silently.

Class/product guards are explicit detection clauses. IPs and ports have `ip`
and integer mapping types. Required allowlist fields have existence guards.
Unknown bounded `unmapped` values are preserved in `_source` but not dynamically
indexed. This mapping is a proposed test/deployment interface; it has not been
installed into an OpenSearch cluster.

The field contract comes from the existing [normalizers](../README.md):

| Source | Available signal and limit |
| --- | --- |
| Azure Activity REST | Operation, actor, source IP and status. ARM `/write` is Other99; rotation is not new credential creation. |
| AKS/k3s audit | `objectRef` is conditional bounded passthrough, absent from the earlier goldens. Request/verb alone is not successful execution or added privilege. |
| Tetragon | Full executable and parent paths, IDs and node, exec only. No args, connect/file event, Pod or sandbox attribution. |
| VNet v4 | IP/port/direction tuples, not application, domain/SNI, authentication or Pod identity. Allowlist addresses are illustrative documentation IPs. |

Trusted Warden self-approval/cross-tenant denial context, Request-level
privileged-Pod projection, and runtime connect/Pod attribution remain upstream
gaps. Those future detectors are outside the 32 implemented candidates. No
normalizer, collector, failed backpressure source or Task13 metric file is changed.

ATT&CK tags identify related investigation scenarios, not confirmed techniques.
Shared-key listing is not Private Keys; rotation is not Additional Credentials;
ordinary token/CSR creation is not theft or forgery. Unsupported associations
remain unassigned. The coverage generator reports total/tagged/unassigned rules
and unique related techniques separately, with indexed query and live detection
explicitly `UNRUN`. No detection rate is computed.

`requirements.lock` pins the 18 resolved wheels. `provenance.json` links the
immutable resolver report, exact verified wheel sizes/hashes and the sole local
material installation. The target is the project-owned Python 3.14.4 site; no
old interpreter, host environment or cache configuration is changed. Installation
is a separate bounded material operation, not part of the tests.

After the relevant local-run admission, the focused suite is:

```sh
PYTHONPATH=.cache/task12-material-20261025-a/site python3 -B -m unittest \
  detect.sigma.test_contract detect.report.test_coverage
```

On an environment with the locked dependencies already installed, the report
can be generated with `python3 -B -m detect.report.coverage`. It compiles the
catalogue using the actual backend before rendering
[`attack-coverage.md`](../../docs/evidence/attack-coverage.md). The admitted native
callers additionally enforce whole deadlines and resource limits; `.github`
contains only an unexecuted local-component CI definition.

The original testcontainers/OpenSearch `test_rules.py` acceptance remains
pending. No empty, skipped or mocked test represents it. Query hit/miss,
collector/exporter provenance, live alerting and technique success still need
their own actual evidence. Local material/RED/cover outcomes belong in
[`Task12 report`](../../docs/evidence/task-12/report.md).
