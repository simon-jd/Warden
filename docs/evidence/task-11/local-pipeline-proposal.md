# Task11 PHASEA proposal only — 2026-10-25

Required brief/ruling/budget/plan/notes/audit structs/tests read. Root owns SOURCE/Git/index at83dd391. Await FULL read/ruling/exact BASE. Task11/Goal OPEN.

## Deliverable

Create detect/vector/{agent,aggregator}.toml; detect/ocsf/{azure_activity,k8s_audit,vnet_flow,tetragon,warden_audit}.vrl; detect/ocsf/tests/{00-topology,azure_activity,aks_audit,k3s_audit,vnet_flow,tetragon,warden_audit,negative,routing}.toml; detect/tests/{backpressure_test.sh,backpressure_test.py,backpressure.toml}; detect/vector/buffer-alerts.yml; detect/README.md; docs/evidence/task-11/local-pipeline.md. Python stdlib; ignored .cache/task11/. No Go/schema/package/build/controller/recorder/registry/proof-campaign work.

Agent: six synthetic NDJSON spools, bytes decoding, fixed labels azure/aks/k3s/vnet/tetragon/warden, disk sink agent_forward. Aggregator: norm_azure/norm_aks/norm_k3s/norm_vnet/norm_tetragon/norm_warden; sinks os_api/os_process/os_network/reject; literal indices warden-ocsf-6003/1007/4001. Five disk sinks; test adds one. No event-selected index/path. Templates unstarted; test Vector+HTTP peer, not OpenSearch.

OPEN: scoped federated Activity REST polling/checkpoints/dedup; AKS/VNet storage collection; k3s audit export; Tetragon exec/connect/sensitive-file policies/telemetry; Warden exporter/context; local OpenSearch acceptance. No Event Hubs. Fixtures/HTTP prove no cloud/cluster integration, detection coverage or seven-day metrics.

## Audit/OCSF contract

audit.Event=tenant_id,type,run_id,payload; audit_entries=seq,canonical_event,prev_hash,hash, no occurrence time. Tenant is not actor; observation is not occurrence/source endpoint. Raw Warden events visibly reject missing context. SYNTHETIC envelope supplies original_event_time/actor/endpoint only for mapping; collector_observed_at never becomes OCSF time. No Task1 change, invented identity/IP, live export or chain-verification claim.

OCSF1.3.0/no profiles/extensions; [pin](https://github.com/ocsf/ocsf-schema/commit/c8bde8c4cc7e93bb4a36e873623bbe099da22fb5). Read version/categories/dictionary at official raw tag v1.3.0: application6/system1/network4; type_uid=class_uid*100+activity_id. events/ inheritance: application/api.json->application/application.json; system/process.json->system/system.json; network/network_activity.json->network/network.json; parents->base_event.json->includes/{classification,occurrence}.json.

Mandatory: integer activity_id/category_uid/class_uid/severity_id; long type_uid; epoch-ms time; metadata.version1.3.0/product.vendor_name+name/uid. API: api.operation, actor identity, src_endpoint identifier. Process: pid/uid plus inherited actor/device per [browser](https://schema.ocsf.io/1.3.0/classes/process_activity). Network: dst_endpoint; require both flow IPs. Freeze recursive objects/{metadata,product,_entity,actor,api,process,network_endpoint,endpoint,device,user,object}.json/types/constraints. Raw system parent unavailable; browser includes profiles: full profile-free closure UNVERIFIED, blocks admission/conformance.

API CRUD1/2/3/4=>600301/2/3/4; unknown0, known-unmapped99+original activity_name. Tetragon exec Launch1=>100701; VNet Traffic6=>400106 per includes/network/network_activities.json. Unknown severity/status0; unknown optional fields bounded under unmapped. Malformed JSON/type/time/IP/tuple/version, missing mandatory context or unsupported class=>visible reject, no normal output. drop_on_error/drop_on_abort/reroute_dropped=true; wire every .dropped to reject sink, source/reason/UID diagnostics without raw payload; reject failure blocks/fails visibly.

Primary: [REST2015-04-01](https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list?view=rest-monitor-2015-04-01), [AKS](https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference), [audit/v1](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/), [VNet](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview), [Tetragon](https://tetragon.io/docs/use-cases/process-lifecycle/). Distinguish REST/export, AKS-wrapper/k3s, VNet/NSG; bound records/expansion, test versions/tuples.

## Material gates

Vector0.45.0 musl, no install/build: https://github.com/vectordotdev/vector/releases/download/v0.45.0/vector-0.45.0-x86_64-unknown-linux-musl.tar.gz ; sums same directory/vector-0.45.0-SHA256SUMS. [Assets](https://github.com/vectordotdev/vector/releases/expanded_assets/v0.45.0):44.3MB/1.92KB; commit063cabbbf4bc6f75794fa0ccd3b0bd5c074f0e35. SHA256 text unavailable: expected digest UNRESOLVED. Root freezes publisher line/digest before fetch authority. Same-publisher integrity is not reproducible-build proof. No PATH/latest/self-hash substitution. Caps archive50,000,000B/sums4096B/unpacked200,000,000B; reject traversal/links/devices/duplicates, retain licenses. No download.

Pinned0.45 buffer/CLI reads failed. [Moving docs](https://vector.dev/docs/reference/configuration/sinks/http/): minimum268435488B/block/drop_newest/500ms sync/buffer_discarded_events_total, NOT0.45 proof. Root resolves pinned CLI/tests/remap/buffer/metric labels before dispatch or STOP. Alert increase(buffer_discarded_events_total{component_id="bp_http"}[1m])>0; production five fixed IDs. component_discarded_events_total distinct. Old vector_buffer_discarded_events_total untrusted; fsync is not crash-zero-loss proof.

## Finite tests

cwd repo root; V=absolute .cache/task11/vector/bin/vector. RED once `"$V" test detect/ocsf/tests/*.toml`: semantic failure. Implement; frozen cover runs same command once+`bash detect/tests/backpressure_test.sh`, no duplicate GREEN. Only00-topology defines topology; unique cases/six fixed insert_at/extract_from IDs/shared VRL, no deployment-config merge. Six full assert_eq!(.,expected) goldens; malformed/missing/type/time/version/unknown/multi-tuple/routing/reject negatives; deterministic. [Tests](https://vector.dev/docs/reference/configuration/unit-tests/) inject fixtures.

Shell execs `/usr/bin/python3 -I -B detect/tests/backpressure_test.py --vector .cache/task11/vector/bin/vector`. Driver Popen fixed absolute vector --config detect/tests/backpressure.toml; owns HTTP thread/socket127.0.0.1:0. stdin->bp_http disk; internal_metrics->bounded file. Baseline32/s10s, burst320/s100s:32320 IDs <=16KiB; peer stalls60s then drains. Disk268435488B/block/concurrency1/batch64KiB. Require occupancy+producer stall, timed rates, all IDs accepted/received, missing0/discard delta0; retries reported, no exactly-once/crash claim. No fill/stall=>FAIL; alert fixtures do not prove real firing.

## Admission/deadlines

Fresh measurement: ordinaryR includes all retained project/tool/evidence except Q=5,000,000,000B released=false. New maxima: archive50MB+unpack/tool200MB+sums4096+schema2MB+source262144+tmp64MiB+evidence16MiB+spool600MiB+6 buffers*(268435488+64MiB overhead)=2,978,564,032B. Require R+Q+new<=12,000,000,000B and fresh free space; else STOP. Resident reserve old UNKNOWN9GB+Vector3GB+driver/peer1GB=13GB<=16GB; fresh MemAvailable>=new4GB+1GB margin. No daemon/OpenSearch starts.

Whole-process monotonic deadlines: material90s/cleanup10; golden60s/cleanup10; backpressure180s=setup20+baseline10+burst100+drain30+cleanup20. CPU60/45/140s; Vector AS3GB/driver1GB; FSIZE Vector320MiB/driver64MiB/archive50MB, NOFILE128/core0/Vector threads2; output1MiB/process. Setup/readiness/I/O inside deadline; yield is not deadline. No unbounded communicate. Keep owned Popen/pidfd/socket/thread handles, bounded nonblocking I/O. Cleanup INSIDE deadline: owned child TERM/wait/KILL via retained authority/reap-known-return; close/join peer. UNKNOWN=>STOP, retain handles/originals/failure; no old PID/PG signals, scanning/retry/limit search. Delete exact owned tmp only after known terminals.

Preserve Task16 dirty scripts/firecracker_code.py/vuln/ unimported/unverified/unstaged; native UNKNOWN/Q/scene22/private8/HISTORY/pins/Task6 caps unchanged. No clean/source150 claim. Capture/maintenance/approval/continue CLOSED. No cloud/paid API/GPU/host/sudo/push/publication; protected RG untouched. No tests/native execution.
