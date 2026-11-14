# Task12 material closure

Proposal unchanged. Static only,no SOURCE/Git/native/acquisition/services/children. Root owns BASE/SOURCE/actual. Task12 OPEN.

## 1. All32 rule mappings corrected

Proposal numbers retained. R=related hypothesis,U=untagged. Action/name/port is not technique proof. Count total/tagged rules/unique techniques and fixture/conversion/backend/live status separately.

|# action|R/U; MITRE primary basis and missing context|
|---|---|
|01 listkeys|U; [Private Keys](https://attack.mitre.org/techniques/T1552/004/) is not shared-key listing.|
|02 regeneratekey|U; [T1098.001](https://attack.mitre.org/techniques/T1098/001/) adds adversary credentials; rotation is not addition.|
|03 roleAssignments/write|R T1098.003;delta absent.|
|04 roleDefinitions/write|R [T1098.003](https://attack.mitre.org/techniques/T1098/003/); delta absent.|
|05 diagnosticSettings/delete|R T1685.002;target/success needed.|
|06 diagnosticSettings/write|R [T1685.002](https://attack.mitre.org/techniques/T1685/002/); write may improve logging;replaces T1562.008.|
|07 locks/delete|U; lock is not [defense impairment](https://attack.mitre.org/techniques/T1685/).|
|08 policyAssignments/delete|U;security purpose unknown,T1685 insufficient.|
|09 pods/exec|R T1609; request not execution.|
|10 pods/attach|R [T1609](https://attack.mitre.org/techniques/T1609/); no command/success.|
|11 portforward|R [T1572](https://attack.mitre.org/techniques/T1572/); no inner traffic/C2.|
|12 ephemeralcontainers|R [T1610](https://attack.mitre.org/techniques/T1610/); patch not deployment.|
|13 RoleBinding|R T1098.006; delta absent.|
|14 ClusterRoleBinding|R [T1098.006](https://attack.mitre.org/techniques/T1098/006/); same gap.|
|15 SA secret read|R [T1552.007](https://attack.mitre.org/techniques/T1552/007/); may be authorized/noncredential.|
|16 TokenRequest|U; [T1528](https://attack.mitre.org/techniques/T1528/) theft != issuance.|
|17 SA CSR|U; drop T1550; [T1649](https://attack.mitre.org/techniques/T1649/) certificate theft/forgery != CSR.|
|18 shell|R [T1059.004](https://attack.mitre.org/techniques/T1059/004/); execution indicator,not malicious script.|
|19 Python|R [T1059.006](https://attack.mitre.org/techniques/T1059/006/); no script/args.|
|20 curl|R T1105; no actual transfer/direction.|
|21 wget|R [T1105](https://attack.mitre.org/techniques/T1105/); same gap.|
|22 nc/ncat|U; [T1095](https://attack.mitre.org/techniques/T1095/) needs nonapplication C2,not utility name.|
|23 socat|U; [T1090](https://attack.mitre.org/techniques/T1090/) needs proxy behavior.|
|24 xmrig/minerd|R [T1496](https://attack.mitre.org/techniques/T1496/); no resource-hijacking proof.|
|25 kubectl|Weak R T1609 only; current args absent,may just read.|
|26 nsenter|R [T1611](https://attack.mitre.org/techniques/T1611/); no target/escape proof.|
|27 module loader|U by default; [T1547.006](https://attack.mitre.org/techniques/T1547/006/) needs autostart/persistence beyond exec.|
|28 metadata IP|R [T1552.005](https://attack.mitre.org/techniques/T1552/005/); flow is not token retrieval/Pod attribution.|
|29 port53|U by default; [T1071.004](https://attack.mitre.org/techniques/T1071/004/) needs DNS C2,not port alone.|
|30 port22|R [T1021.004](https://attack.mitre.org/techniques/T1021/004/); no SSH login proof.|
|31 port3389|R [T1021.001](https://attack.mitre.org/techniques/T1021/001/); no RDP login proof.|
|32 nonallowlisted IP|U; T1095 is not generic egress-policy violation.|

32 action candidates retained. Future33/34 Warden unassigned;35 privileged-Pod related T1611 needs safe Request projection. All3 outside32. K09-17 conditional objectRef,not current golden/live evidence.

## 2. Version metadata and callable API

[Core1.5.1 JSON](https://pypi.org/pypi/pysigma/1.5.1/json): Python>=3.10,<4; complete direct Requires-Dist: diskcache>=5.6.3,<6.0.0; diskcache-stubs>=5.6.3; jinja2>=3.1.6,<4.0.0; jq>=1.12,<2.0; packaging>=26.3,<27.0; pyparsing>=3.2.5,<4.0.0; pyyaml>=6.0.3,<7.0.0; requests>=2.32.5,<3.0.0; types-pyyaml>=6.0.12.20260815,<7.0.0.0; typing-extensions>=4.16.0,<5.0.0. Wheel171485B.

[ES2.1.1 JSON](https://pypi.org/pypi/pysigma-backend-elasticsearch/2.1.1/json): Python>=3.10,<4; sole Requires-Dist pysigma>=1.4.0,<2.0.0. Wheel42529B.

[OpenSearch2.0.3 release](https://pypi.org/project/pySigma-backend-opensearch/2.0.3/) exists,Python>=3.10,<4,wheel SHA bcb90e21207385fadb56ac5358242c86d32736a897289f2e0cb5d6949670e927,publisher42c52c8d6f3a717485091f9860a795844194c0a8. Versioned JSON/pinned code/PEP658 unavailable: RELEASE Requires-Dist/bytes UNKNOWN. [Mutable main](https://raw.githubusercontent.com/SigmaHQ/pySigma-backend-opensearch/main/pyproject.toml) declares core>=1.4,<2;ES>=2.1. Not wheel METADATA; pins provisional.

[TC4.14.2 JSON](https://pypi.org/pypi/testcontainers/4.14.2/json): Python>=3.10. Complete always-active direct list: docker,python-dotenv,typing-extensions,urllib3,wrapt. Wheel125712B. No extras. Full optional Requires-Dist at linked JSON; opensearch-py>=3[Python<4,extra=opensearch] is not base.

Minimal roots: three Sigma pins,base+transitive dependencies; unittest/stdlib HTTP,no sigma-cli/pytest/TC extras. TC base is later integration root.
[Core collection](https://raw.githubusercontent.com/SigmaHQ/pySigma/c9f748389fc5dd888fa1ab2bc10c30416c7a0c6f/sigma/collection.py): from_yaml(yaml_str,collect_errors=False,...). [Conversion](https://raw.githubusercontent.com/SigmaHQ/pySigma/c9f748389fc5dd888fa1ab2bc10c30416c7a0c6f/sigma/conversion/base.py): convert(collection,output_format=None,...).
[Backend main](https://raw.githubusercontent.com/SigmaHQ/pySigma-backend-opensearch/main/sigma/backends/opensearch/opensearch.py) requires_pipeline=True. Candidate OpensearchLuceneBackend(ProcessingPipeline(),collect_errors=False).convert(SigmaCollection.from_yaml(text)); imports sigma.backends.opensearch/sigma.processing.pipeline/sigma.collection. Explicit identity OCSF pipeline,no ECS; release wheel verification still required.
[TC pinned](https://raw.githubusercontent.com/testcontainers/testcontainers-python/5c67efb8e51885021e6d41cd8bc60300978a8377/core/testcontainers/core/container.py): DockerContainer(image,docker_client_kw=None,**kwargs),with_env/with_bind_ports/with_kwargs/start/stop; with_kwargs replaces dict. All caps/labels in one call; TESTCONTAINERS_RYUK_DISABLED=true before import. start may acquire image; no TC in local cover.
Root cfeb0b: UID1000,Python3.14.4,pip25.1.1,R4449996800,MemAvailable86735925248. Use3.14,no3.12 install;Requires-Python fits,ABI/jq wheels UNKNOWN.

## 3. Future caller drafts, not executed

Root FULLREAD exact caller,UID1000,new owned namespace,fresh R+Q5GB+peak<=12GB,oldUNKNOWN9GB+new<=16GB,fresh MemAvailable.
Metadata-only: GET four versioned JSON URLs above+only advertised PEP658 .metadata,no wheel/archive. <=24requests,2MiB/body,16MiB total,8s/socket,no redirects/retries;whole60s(work45/cleanup10/kill5),CPU20,AS512MB,FSIZE2MiB,output512KiB,tmp16MiB. Raw+fields/hash;partial on error;not solver.
Future resolver argv:
python3 -I -m pip --isolated install --dry-run --ignore-installed --no-cache-dir --disable-pip-version-check --only-binary=:all: --retries 0 --timeout 8 --index-url https://pypi.org/simple --report <owned>/report.json pysigma==1.5.1 pysigma-backend-opensearch==2.0.3 pysigma-backend-elasticsearch==2.1.1
Actual3.14.4/pip25.1.1,TC later. dry-run may fetch wheels without PEP658: NOT strict metadata-only. Later material ruling must allow bounded fallback or stop before .whl. No sdist/build/install. Whole120s(work90/cleanup20/kill10),CPU60,AS1GB,output1MiB,tmp64MiB,report2MiB,NEW128MiB. Live Popen/pidfd,absolute bounded I/O,no unbounded communicate/join;cleanup inside deadline,unknown/resource/timeout stops.
Chosen URL/hash+metadata,then bounded matching versioned PyPI JSON supplies exact file size (report lacks size). Check all constraints/yanked/ABI wheels,sum wheel+venv+unpack overlap; offline hash lock,no upgrade. Backend: ONE later approved known-SHA wheel GET<=32768B+zip METADATA read,exact advertised length first,no extraction/import/install.

## 4. Read-only registry draft; no image pull

2.19.1 linux/amd64 digest/config/compressed sizes UNKNOWN; web inaccessible. Future read-only sequence per [Registry](https://distribution.github.io/distribution/spec/api/)/[auth](https://docs.docker.com/reference/api/registry/auth/):
1 GET https://registry-1.docker.io/v2/opensearchproject/opensearch/manifests/2.19.1
Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json
2 On401 require exact challenge realm/service/scope matching URL; GET https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Aopensearchproject%2Fopensearch%3Apull,anonymous,no refresh token.
3 Repeat1 with memory-only Bearer token; hash raw manifest,compare Docker-Content-Digest.
4 If list/index,select exactly one linux/amd64 descriptor,GET same manifest endpoint/<selected sha256>,verify descriptor digest. Record index/child separately.
5 GET https://registry-1.docker.io/v2/opensearchproject/opensearch/blobs/<config sha256> ONLY; verify digest/size,os/arch. Record layers[].digest/size/mediaType and sum compressed sizes. NO layer GET.

<=6requests,2MiB/body,8MiB total,8s/socket,whole60s incl cleanup,CPU20/AS512MiB/output512KiB;redirects fail closed,token not saved. Same fresh/owned/root review. Config does NOT reveal expanded/daemon/unpack/writable/data/log peak. R~4.45+Q5 leaves~2.55GB;3GB/rejected PG2GB not admitted,not permanent impossibility.

## 5. Query contract, SOURCE and genuine RED

Azure operation case is preserved; Tetragon process.name/actor.process.name are full paths,not basename/args/connect/Pod. [Sigma](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) defaults strings case-insensitive; [keyword](https://docs.opensearch.org/2.19/field-types/supported-field-types/keyword/) is case-sensitive. Plain-keyword proposal is inadequate. Candidate: lowercase normalizer+lowercase ASCII query values in OCSF pipeline,raw _source unchanged. [Pinned pipeline docs](https://sigmahq-pysigma.readthedocs.io/en/v1.5.1/guides/processing_pipelines.html): CaseTransformation/field_name_mapping. Batch ASCII plain/endswith/startswith,number/bool/IP;actor case policy explicit.

[query_string](https://docs.opensearch.org/2.19/query-dsl/full-text/query-string/) wildcard/normalizer behavior needs REAL2.19.1 proof,not term-query inference. Mixed Microsoft.Storage/.../listKeys/action and uppercase must hit. endswith /bash matches /usr/bin/bash,not /usr/bin/bash-helper or /tmp/notbash. Cover parent path,literal-star/slash/colon/backslash,missing fields/NOT; existence guards protect actor/IP allowlists. Class/product guard are detection clauses,not logsource magic; typed scalars,not analyzed text.

K objectRef conditional<=2048B passthrough,absent goldens. Privileged Request projection,runtime connect/Pod,real Warden context remain OPEN; no reliance on synthetic extras override,no Task11 edits.
SOURCE after dispatch: detect/sigma/{convert.py,test_contract.py,requirements.lock,provenance.json,rules/,tests/,README.md},detect/report/{coverage.py,test_coverage.py},.github/workflows/detect.yml,attack-coverage.md. Preserve Task13.32rules/64fixtures,3future pending. CI file/local conversion only;backend fails closed pending image admission,no remote run.

RED after material: real parse+backend conversion gives reference query; adapter stub[] fails exact nonempty output assertion. Coverage stub[] fails exact sorted IDs/tags/unassigned count. Semantic failure,not import/empty suite. Implement,freeze hashes,ONE local cover32UUIDs/64fixtures,actual conversion per rule,field/class/product/case config+deterministic coverage; no matcher/hit claims.
Backend RED separately: real indexed pair+valid wrong predicate misses expected pos. Frozen cover actual pySigma query POST _search requires exact pos/no neg and case/path near-misses. Unrun=PARTIAL;Task12/live telemetry OPEN.
Single FIRST blocker: root-admitted caller closing dependencies/hash/bytes/3.14-wheel budget for local conversion. Image expansion/backend/telemetry remain later obligations.
