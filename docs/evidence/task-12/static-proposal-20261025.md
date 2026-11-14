# Task12 static proposal; Task12/Goal OPEN

Full brief/budget/plan/Task11 source+report read. Static only; root FULLREAD+BASE/SOURCE dispatch before implementation. Preserve Task13/Task16/failed detect/tests, immutable Task11 SOURCE337faf6/EVIDENCE0beb321 and review (27goldens/two validates PASS,soleBP FAILED,no retry),Task6 caps/pins/actual CLOSED,Q/private/scene/caches. No acquisition/native/Git/children/cloud/GPU.

## Rules/fixtures

UUID rules/<name>.yml,tests/<UUID>/{pos.json,neg.json}; synthetic full OCSF,distinct IDs,manifest labeling. cases.json: missing/near-miss/wrong-product. All guard class/product; experimental,FP notes,technique+tactic tags. ARM write=Other99.
Sigma logsource/class/product: A=azure/activity,6003/Azure Activity Log; K=kubernetes/audit,6003/Kubernetes Audit; P=linux/process_creation,1007/Tetragon; N=azure/vnet,4001/Azure VNet Flow Logs; W=warden/audit,6003/Warden Audit. op=api.operation,U=unmapped,actor=actor.user.uid,exe=process.name,parent=actor.process.name. A=Microsoft.<provider>. K* conditional,not in goldens.

|#|Source; positive / negative|attack tag|
|---|---|---|
|01|A op Storage/storageAccounts/listkeys/action / read|t1552.004|
|02|A op Storage/storageAccounts/regeneratekey/action / read; rotation only|t1098.001|
|03|A op Authorization/roleAssignments/write / read|t1098.003|
|04|A op Authorization/roleDefinitions/write / read|t1098.003|
|05|A op Insights/diagnosticSettings/delete / read|t1562.008|
|06|A op Insights/diagnosticSettings/write / read; change only|t1562.008|
|07|A op Authorization/locks/delete / read|t1562.001|
|08|A op Authorization/policyAssignments/delete / read|t1562.001|
|09|K* create,U.objectRef.resource=pods,subresource=exec / pods create|t1609|
|10|K* create,pods subresource=attach / get|t1609|
|11|K* create,pods subresource=portforward / get|t1572|
|12|K* patch,pods subresource=ephemeralcontainers / status patch|t1610|
|13|K* create/patch/update,resource=rolebindings / get|t1098.006|
|14|K* same verbs,resource=clusterrolebindings / list|t1098.006|
|15|K* get/list,resource=secrets,actor SA prefix NOT exact reader allowlist / allowed SA|t1552.007|
|16|K* create,resource=serviceaccounts,subresource=token / get|t1528|
|17|K* create,resource=certificatesigningrequests,actor SA prefix / approved human|t1550|
|18|P exe /sh,/bash,/dash / /bin/true|t1059.004|
|19|P exe /python3 AND shell parent / approved worker parent|t1059.006|
|20|P exe /curl AND shell parent / approved downloader parent|t1105|
|21|P exe /wget AND shell parent / approved downloader parent|t1105|
|22|P exe /nc,/ncat AND shell parent / /bin/true|t1095|
|23|P exe /socat / /usr/bin/socket|t1090|
|24|P exe /xmrig,/minerd / /usr/bin/miner-monitor|t1496|
|25|P exe /kubectl AND shell parent / approved agent parent|t1609|
|26|P exe /nsenter / /usr/bin/enter|t1611|
|27|P exe /insmod,/modprobe / /usr/bin/lsmod|t1547.006|
|28|N dst_endpoint.ip=169.254.169.254,U.direction=O / different dst|t1552.005|
|29|N dst_endpoint.port=53,direction O,NOT resolver IP set / allowed resolver|t1071.004|
|30|N dst port22,direction O,NOT approved IP set / jump host|t1021.004|
|31|N dst port3389,direction O,NOT approved IP set / admin host|t1021.001|
|32|N direction O,NOT explicit lab destination IP set / allowed IP|t1095|
|33|W FUTURE U.decision.reason=self_approval_denied / approved_by_other|t1098|
|34|W FUTURE U.decision.reason=cross_tenant_denied / same_tenant|t1530|
|35|K FUTURE U.k8s.privileged=true,op=create / false|t1611|

Binary signals/flows are not attack or Pod proof. Report version-sensitive tags.
Gaps (no Task11 edits): K preserves objectRef/requestURI/requestObject only when supplied and extras<=2048B; goldens lack them. K09-17 need authorized Metadata audit/objectRef+contract fixtures. K35 needs Request audit+bounded typed containers/init/ephemeral securityContext.privileged projection; large bodies reject. Tetragon exec-only drops nested args/Pod; connect/file/Pod metadata need new policies+normalizer. W raw Event lacks time/actor/src; synthetic VRL drops payload. W33-34 need trusted original time/actor/src/event_uid+denial reason/requester/approver/target-versus-authorized tenant then safe projection; never rely on extras overriding tenant/run. Three FUTURE rules excluded from32 candidates/live claims.

## API/material/backend

Candidate pins: Python3.12,pysigma1.5.1,pysigma-backend-opensearch2.0.3,pysigma-backend-elasticsearch2.1.1,testcontainers4.14.2. SigmaCollection.from_yaml(text); OpensearchLuceneBackend().convert(collection), default Lucene; unchanged result in query.query_string.query POST /<owned-index>/_search. No ECS pipeline. Strict keyword/boolean/integer/IP mappings,objects not nested;class indices,one shard/zero replicas.

Pinned wheel SHA256 backend=bcb90e21207385fadb56ac5358242c86d32736a897289f2e0cb5d6949670e927,publisher42c52c8d6f3a717485091f9860a795844194c0a8. PyPI rounded sizes171.5/16.9/42.5/125.7kB NOT exact bytes. Transitive wheel versions/hashes/bytes/Requires-Dist+pinned API closure still required; no ready lock.
Real design: DockerContainer.with_env/with_kwargs (single kwargs call),Ryuk disabled,no automatic wait. Candidate opensearchproject/opensearch:2.19.1 linux/amd64,single-node,fixture-only security disabled,JVM512MiB,mmap disabled,loopback random port. Index pos/neg fixed IDs,refresh,real query must yield exact pos ID/no neg ID; check HTTP/malformed/timeouts/escaping/product negatives.

Unresolved admission: registry metadata inaccessible through research tool; digest/layers/expanded size and transitive bytes unverified. No runnable image pin yet; not physical impossibility/permanent block. R~4.45GB+Q5GB leaves~2.55GB for ALL new;3GB totals12.45>12GB. No replacement2GB allocation. Metadata+safe expansion/daemon accounting needed.

## Bounds/RED/handoff

Local NEW128MB overlapping cap:source4,metadata4,wheels16,venv64,extraction/tmp16,output/evidence24MB; no external cache. Fresh R+Q5000000000+128000000<=12000000000; oldUNKNOWN9GB+new1GB=10<=16GB; fresh MemAvailable>=2GB. Backend peak must ADD compressed+expanded/duplicate layers,writable,data,tmp,logs,daemon/pull overhead: UNKNOWN,no admission. Proposed backend resident4GB includes JVM/client/daemon increment:9+4=13<=16GB; fresh MemAvailable>=5GB. CLI AS cannot constrain daemon children.
Actuals require root FULL command/source review,UID1000,fresh budget/memory/absent namespace. Local whole60s(work45/cleanup10/kill5),CPU45,AS1GB,FSIZE16MB,output1MB,tmp16MB. Backend separately admitted whole240s(work180/cleanup50/kill10),CPU180,container3GB/pids128/CPU2,clientAS1GB; exact backend AS/birth profile still prerequisite. Labels project=warden,owner=codex-warden,task=12,run,ttl. Live-owned Popen/pidfd+known terminal,Docker handles,bounded I/O/polls on absolute clock; no unbounded communicate/join/readiness counts. Unknown/resource/timeout stops with originals. Cleanup INSIDE deadline,exact new objects only,no old PID scans/signals/global prune.
After dispatch/admission: nonempty semantic conversion/coverage stubs; genuine RED once,not missing/empty. Implement32 rules/64fixtures,freeze affected hashes,one local cover parse/convert/contracts/deterministic coverage; no matcher. Backend RED later uses valid wrong predicate in REAL index,then one frozen cover. No duplicate GREEN/old tests; <=5 review-fix rounds separate from Task6.
Paths: detect/sigma/{rules/,tests/,test_rules.py,test_contract.py,convert.py,opensearch-mapping.json,requirements.lock,provenance.json,README.md}; detect/report/{coverage.py,test_coverage.py}; .github/workflows/detect.yml. Coverage derives sorted technique->rule/class/status from tags to docs/evidence/attack-coverage.md; fixture/backend/live distinct. CI FILE only:path filters,read-only,bounded,no cloud; backend fails closed pending digest/lock,no remote run. task-12-report.md+exact public docs/evidence/task-12/report.md,raw evidence,immutable correct BASE..HEAD to ONE reviewer. STOP for root adjudication.

Sources: https://pypi.org/project/pySigma-backend-opensearch/2.0.3/ ; https://docs.opensearch.org/2.19/query-dsl/full-text/query-string/ ; https://docs.opensearch.org/2.19/install-and-configure/install-opensearch/docker/ .
