# Original Task12: local Sigma component handoff

Original Task12 and the overall Goal remain OPEN. This package implements the independently useful local rule/conversion/coverage component. Real OpenSearch indexing, positive/negative query results, live detection and the missing upstream projections are not accepted or claimed. CI is a file only. One independent spec/quality review of this package is pending; no review-fix allowance is reset.

## Exact package

BASE: `9691c9d7b9bb03e503964e4c6a0d97b5982b8373`.
SOURCE: `6791f7b6c004e5fff2a0af415ad41ca7a933dc0d` (139 added paths, 346441 UTF-8/file bytes total).
EVIDENCE is the separate direct child commit containing this report; its full hash is returned in the final handoff, avoiding a self-referential report hash.

The source inventory is the 138 paths in `local-callers-20261025/source-freeze.json`, with only the test delta recorded in `source-freeze-affected.json`, plus `docs/evidence/attack-coverage.md`. `source-paths.txt` is the exact139 path list. The frozen initial138 files totaled340609B; the four test serialization changes add84B; the actual derived matrix adds5748B. No broad directory was staged.

Evidence uses35 exact paths: material5, semantic-RED7, initial-FAILED7, affected6, seven inert caller/freeze/path copies, the artifact inventory, and the two identical reports. `component-evidence-inventory.json` records exact bytes/SHA256 for32 raw/caller artifacts (387214B). Root coordination records, STATUS, registry-* and reaper artifacts are excluded from this author's commits. The report and inventory are intentionally not self-hashed. The final handoff states their actual sizes/hash and empty index after commit.

## Implemented behavior and interface

There are32 JSON-as-YAML Sigma action/indicator rules,64 synthetic positive/negative OCSF fixture documents in per-rule UUID directories,197 declared edge-case documents and a manifest. Assertions validate exact identities, source/class guards, typed fixture structure, field inventory, distinct opaque document IDs, proposed mapping, and deterministic tag coverage. Edge labels are future query expectations, not evaluated hit/miss results. No custom event matcher exists.

`detect/sigma/convert.py` invokes the released `OpensearchLuceneBackend` with `ProcessingPipeline(items=[ProcessingItem(transformation=CaseTransformation(method="lower"))])`, using real Sigma parsing/conversion. It supports the catalogue's ASCII scalar/list selections, startswith/endswith/exists and rejects unsupported query fields/modifiers. No ECS renaming is applied. `detect/report/coverage.py` derives unique IDs and tags and renders distinct local-conversion/indexed-query/live columns.

Current VRL field semantics govern the fixtures: Azure operation casing is preserved; the proposed lowercase keyword normalizer and real detection-value CaseTransformation deliberately address case-insensitive Sigma values. Raw `_source` casing stays unchanged. OpenSearch keyword/query_string/wildcard behavior is still UNRUN, including literal/suffix cases. Tetragon executable names are full paths, so shell/tool indicators use suffixes. API statuses/activities follow the existing normalizers, including Azure /write Other99. K8s objectRef is conditional bounded passthrough, absent from old goldens. VNet IP/port/direction has no application, Pod or login proof. No Task11 file was changed.

The mapping is a candidate, never deployed. Queried string fields are lowercase-normalized keyword fields; IPs and ports have IP/integer types; allowlists require field existence. `unmapped` unknowns are not dynamically indexed. Trusted Warden denial/self-approval/cross-tenant context, Request-level privileged-Pod projection and runtime connect/Pod attribution remain upstream gaps, outside these32 candidates. No live fields are invented.

The actual tag derivation has32 rules,20 tagged,12 unassigned and15 distinct related techniques. MITRE primary technique URLs and scenario limits are in each assigned rule; original primary-source rationale is in the committed material-closure document. Shared-key listing is not Private Keys, rotation is not Additional Credentials, and token/CSR issuance is not theft/forgery. Actions, process names and ports are investigation indicators, not proof of technique execution, compromise or attack success. No detection rate is reported.

## Material admission and provenance

Host facts are Python3.14.4, pip25.1.1, nativeUID1000. The successful resolver report already in BASE is182088B SHA256 `3354cabf92878600843183de31fcb7fec3f989d570864bf4783e1a4cdb519739`; root resolver5f81da/session63124→79b4c1 known0. Two earlier static metadata helpers failed their strict raw version-string assertion before ABI filtering; they were preserved/stopped and not reused. The successful material path compares PEP440 versions and actual supported tags.

`requirements.lock` is1934B SHA256 `af3de7ebdd63284a206235aaf1cc2a9cf0076d0ea3d395874cc5f5a070c8b752`, pinning18 official, non-yanked wheels including pySigma1.5.1, OpenSearch backend2.0.3, Elasticsearch backend2.1.1 and jq1.13.0 cp314. Exact URLs/hash/bytes/dependencies are in provenance and material selected.json. The provenance state is a preimplementation material snapshot, not a replacement for validation outcomes below.

Root's sole material execution4f177a/session96700→6f9eac known0 used official JSON and wheel URLs, fixed hash/ABI/version checks, safe ZIP bounds and offline --require-hashes --no-deps --no-compile target installation. No host installation/configuration change. Total18 wheels2996767B, metadata615133B, logical expansion10423506B, allocated estimate11706368B, conservative peak52190460B. Postflight15609856B; root tree15613952B/544entries, work0/head0/cleanup1/tmp absent. The directory total is postflight, not a hard quota. No installation was repeated. Public five original files are under material-first-20261025; root's original material command/events remain separate coordination evidence.

## Genuine RED

Initial adapter and coverage stubs were importable, nonempty semantic stubs. The exact2605B inert caller selected exactly the two original tests. It compared adapter[] with the actual released backend's nonempty lowercased query, and zero coverage structure with exact tagged/unassigned rows. This was not an import/configuration failure.

Fresh gate9d249c known0: R4467036160B; gate35a76d known0: UID1000, MemAvailable86663315456B, namespace absent. Sole RED dff954 known1:2tests/2assertion failures/0errors/0skips. Postread c5bf17 read full2260B output SHA256 `09d5baa739831fa0e772215160a6412f8806e0f7194a035c8d257337a2bc3474`; cleanup1/tmp absent. Exact request/results11397B and initial source snapshot plus inert stubs are preserved in semantic-red-first-20261025. Root accepted the semantic RED before implementation.

## Initial local cover: overall FAILED, retained

After implementation, the initial frozen3310B caller was admitted once. Freeze check9cb161 known0 verified138 files/340609B; fresh budget5129b7 known0 R4467228672B; gate1c2df2 known0 UID1000/MemAvailable86476226560B/namespace absent. Sole execution2c251b known1. Full read525891:10tests/0assertion failures/6errors/0skips; cleanup1, tmp absent, run postflight20480B. Full9942B output SHA256 `5f22f844a191c8f38d98695af525781d771977a7a16f911e97d016e9e9daf15c`; five native events17035B retained.

The original adapter-reference and coverage tests and all five catalogue tests passed in that FAILED batch. Thus32 actual backend conversions,64 fixture contracts, declared edges, guards/mapping and exact deterministic coverage assertions were executed successfully there. This is historical per-test evidence inside an overall FAILED batch, not a rewritten all-GREEN result. No compiled query artifact or matrix was emitted by that failed caller; no queries.json has been reconstructed.

All6 errors came from the three AdapterEdgeTest methods: yaml.safe_load parsed the unquoted reference date into datetime.date; four json.dumps calls failed before their intended adapter assertion (one method has four subtests). The preserved FAILED snapshot/caller/freeze/output/status/postflight/native trace are the seven local-cover-failed-first-20261025 originals. No failure evidence was overwritten.

Root's attempted postread/archive was blocked before execution by automatic approval review: “Automatic approval review failed: You’ve hit your usage limit.” The full service refusal and recovery history remain in root's `automatic-approval-review-unavailable-20261025.md`, excluded from this author's stage. No tool/profile/agent workaround was used. After the user explicitly said “有额度,你继续”, root resubmitted the same original read via the same approval route:08abaf known0 full output,985c6a full events,94f330 focused source. Reaper00a9fb/session45675→d381f5 known0 at2026-10-26T00:15:53Z confirmed RG absent. This restored the original authorized work, not old Task6 allowances or a new test budget.

## Minimal fix and affected verification: PASS

Root authorized only the four serializations in the three AdapterEdgeTest methods to use yaml.safe_dump(..., sort_keys=False). The exact +84B delta preserves legal YAML date semantics and reaches the real adapter; REFERENCE_RULE and all production/catalogue/fixture/mapping/CI bytes remained fixed. test_contract.py is14287B SHA256 `d5ddb93e755bed28ca863ae8690c70d41a4d91737777ccae8d895f31acab13de`. This was an ordinary scoped harness correction before independent review, not a reset of Task6 or a review round.

The frozen3999B affected caller SHA256 `62fe70c31d1df4f26e64aefaece173842c3604f410d616861804d45cc0a54ef8` selects only those three existing methods, including the four subtests. No loadTestsFromModule, catalogue compilation, old seven tests or Task11 rerun. File check990f46 known0; budget1ef489 known0 R4467396608B; gate5dec8b known0 UID1000/MemAvailable85614993408B/namespace absent. Sole executionffb9ce known0:3tests/0failures/0errors/0skips; cleanup1/tmp absent; run postflight32768B. Whole60s/work45s/cleanup10s/kill5s, CPU45s/AS1GiB/output1MiB/tmp16MiB/run16MiB unchanged. All actual gates used Q5GB plus conservative134217728B future reserve: additional5134217728B, service memory10000000000B, downloads0; preflight CPU20/AS256MiB/40+5s. No cap or namespace retry search occurred.

Full postread71e750 read output6047B SHA256 `cf3b0124a130212001ebd19581f7e972d84401cc3b7a0ee1fbc2215eba88b096`, status37B exit0/test0/head0/cleanup1, postflight42B, summary7305B and actual matrix5748B. Five exact native request/results26848B SHA256 `6014a2889507ab97c110f433101e81b8bd4828a117f6fa316cbaf806cadf50d2`. Six originals are under local-cover-affected-first-20261025. Root FULLREAD714c0c/662244/89cfaa and accepted the affected result.

The matrix uses existing summarize_rules/render_markdown APIs for tag/text generation only. Its converted IDs explicitly cite the frozen32 successful catalogue tests within the initial overall FAILED batch. It does not rerun conversion or reconstruct queries. Its provenance preface is preserved. Root authorized the byte-identical copy to docs/evidence/attack-coverage.md:5748B SHA256 `4afc44dc25af7db91293fce7c8bdb47598a0b040c86c4c475db1479eb12f9f75`. Indexed and live columns remain UNRUN.

## Open original acceptance and preserved state

Actual testcontainers/OpenSearch test_rules.py, indexed32 positive/negative results, candidate mapping case/wildcard/IP semantics, real upstream Warden/privileged/runtime projections, live capture/collector/exporter correlation and alert reporting remain OPEN. No empty/skipped/mock backend acceptance or custom matcher is substituted. No Docker/backend/cloud/GPU/network/remote CI was run by this component validation.

Root's separate sole registry metadata attempt9f2649/session91889→621fd6 known1 failed on config GET redirect refusal; no layer GET/retry. Candidate OpenSearch2.19.1 index SHA25672fe2fc84be8295906b8efca020b46c58ed45c8da60cd9b8b49e1991e38e89a4; linux/amd64 manifest7ad3c515e43fb1642ddf2181dfd03402e42e85a16030e098ed1f3fc1404d7e89;7 compressed layers1028720640B. Expected config6445B/SHA731779f1c50424e38335b0af191058642a4964a2b2c62175ebcc8d5734fee13a was not retrieved. Expanded/daemon/writable overlap remains UNKNOWN; metadata does not establish fit or permanent physical impossibility. Registry originals stay root coordination artifacts.

Task11 source/goldens/old FAILED BP and approved validations were not changed or rerun. Task13 detection_metrics.py, Task16 dirty scripts/firecracker_code.py and vuln/, three failed BP drafts under detect/tests, private/scene/cache/Q, old UNKNOWN9GB resident reserve, Q5GB, original caps/pins and actual CLOSED remain preserved. No push/publication or full Task12 checkbox/Goal completion. SOURCE/index ownership returns to root with an empty index after EVIDENCE commit; root's dirty coordination files remain outside these commits. Stop for one independent review of BASE through EVIDENCE.
