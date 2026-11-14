# Local OCSF pipeline

Run commands from the repository root. These files target Vector **0.45.0**
(`063cabbbf4bc6f75794fa0ccd3b0bd5c074f0e35`) and OCSF **1.3.0**
(`c8bde8c4cc7e93bb4a36e873623bbe099da22fb5`), without profiles. Local test
results and exact native command returns belong in
[`local-pipeline-substage-report.md`](../docs/evidence/task-11/local-pipeline-substage-report.md).
This is a local pipeline substage; the deployment and actual collection work
below remains open. The committed component covers the mapping and static
configuration checks. The backpressure draft failed and is not a published
runnable test in this checkout.

The agent reads six authorized collectors' NDJSON spool files, adds a fixed
source label, and forwards to the aggregator over loopback Vector transport.
The aggregator loads the same VRL files as the golden tests, rejects malformed
records, and routes normalized classes to literal OpenSearch indices:

| Input contract | VRL | OCSF class / index |
| --- | --- | --- |
| One Azure Activity REST EventData record | `azure_activity.vrl` | API Activity 6003 / `warden-ocsf-6003` |
| AKS storage record, `properties.log`, optionally `records[]` | `k8s_audit.vrl` | API Activity 6003 |
| One k3s `audit.k8s.io/v1` Event | `k8s_audit.vrl` | API Activity 6003 |
| Azure VNet flowLogVersion 4, optionally `records[]` | `vnet_flow.vrl` | Network Activity 4001 / `warden-ocsf-4001` |
| Tetragon `process_exec`, including parent and node | `tetragon.vrl` | Process Activity 1007 / `warden-ocsf-1007` |
| Explicit synthetic Warden mapping envelope | `warden_audit.vrl` | API Activity 6003 |

All input JSON records must fit 16KiB. AKS batches are limited to 128 records;
VNet batches to 32 records, 32 flows/groups per level and 128 total tuples.
An invalid tuple or record rejects the entire input rather than emitting a
partially normalized batch. VNet supports the documented ten digit seconds
and thirteen digit milliseconds and requires 13 comma separated tuple fields.
The log GUID and local tuple index remain in `unmapped`: they are not a unique
event ID. OpenSearch generates document IDs; no deduplication claim follows.

Occurrence times come from source timestamps. API actors and source IPs must
be present and typed correctly. Tetragon needs the parent process as actor and
a node identity; device `type_id=0` means unknown. Unknown severity/status use
the OCSF enum value 0. Unknown activities use 99 with the original operation.
Azure ARM `/write` cannot distinguish create from update and therefore uses
Other, while `/read` and `/delete` map to Read and Delete. No collector clock,
anonymous actor, placeholder IP, or flow GUID is substituted for missing
original context.

The current Warden `audit.Event` has tenant/type/run/payload and its stored row
adds sequence/canonical/hash linkage; it has no occurrence time, actor or source
IP. Raw events are visibly rejected. The fixture envelope requires
`synthetic_context=true`, explicit `event_uid`, `original_event_time`,
`actor_uid`, `source_ip`, and `event`. It tests mapping only. A
`collector_observed_at` field cannot satisfy occurrence time. This adds no
exporter, identity provenance or hash-chain verification and changes no audit
schema. Envelope-level `tenant_id` and `run_id` are reserved collisions and
are rejected for every value type; identifiers belong only in `event.tenant_id`
and `event.run_id`, so unknown extras cannot replace validated context.
Actual Warden audit integration remains uncovered.

Top level fields outside the mapped/known containers are preserved in bounded
`unmapped` (2KiB maximum); VNet also preserves its tuple count strings and
record extras (1KiB). Known containers are selectively mapped rather than
copied wholesale: claims, HTTP/user/process details and Warden payload may
contain sensitive bodies. Unknown nested fields are not a complete raw-event
archive. Overflow is rejected, not silently truncated. Operators must apply
source access controls and retention policy before collecting real records.

Normalization errors/aborts, unknown labels and class/version route misses go
to `reject_redact`, then a disk buffered stderr JSON sink. The diagnostic is
only a fixed reason and one of six source labels (or `unrecognized`), never
the original message, secret or parser error text. File input oversized-line
handling happens before VRL and is observable through Vector component errors;
it cannot produce the same per-record rejection object. Spool retention and
collector-side size/error handling must be configured before deployment.

Required selected-object inheritance was checked against the pinned OCSF
classes, base/system/network/application categories and emitted
metadata/product/actor/user/process/device/API/endpoint objects. Every object
includes the selected class's required context, epoch-millisecond time,
class/category/activity/type identifiers and metadata version/product. Full
object goldens establish the asserted mapping, not full OCSF certification or
coverage of every source schema variation.

`vector/agent.toml` and `vector/aggregator.toml` are separate deployment
configurations: do not merge them for tests. Their five disk buffers are
`agent_forward`, `os_api`, `os_process`, `os_network`, and `reject`, each
268435488 bytes with `when_full="block"`. The local experiment adds one
separate buffer of that size. Blocking propagates backpressure; it does not
guarantee collector retention or physical crash zero loss. Vector's periodic
disk synchronization is not a power-loss durability proof.

`vector/buffer-alerts.yml` supplies a discard alert and a normalization-error
alert. Internal metrics use namespace `vector`; the internal metric name
`buffer_discarded_events_total` exports as
`vector_buffer_discarded_events_total` in Prometheus. An absent counter series
is not a numeric zero. The rules still need installation and live evaluation
(no Prometheus here), so the discard alert has never fired for real.

`make test-vector-live` (`tests/backpressure_test.py`) sends a 10x burst of
16 KiB events with unique IDs through stdin into the production-sized buffer
while the HTTP peer answers 503, then reconciles every ID. Results on
2026-10-27 (`docs/evidence/task-11/backpressure-live-20261027-run*.json`): 0 of
24,200 lost, 0 discards, but the test fails its backpressure check. On-disk
occupancy stopped at about 131 MiB (one 128 MiB data file, half of `max_size`)
while Vector's RSS grew to about 360 MiB. stdin never blocked. The burst was
held in memory, so a crash during the stall would have lost it. Not yet known:
whether this comes from the stdin source or from the disk buffer. Repeat with a
`vector` or `http_server` source before relying on the buffer.

For an authorized local run, use the pinned Vector path supplied in the
evidence and the exact reviewed command body. The focused mapping fix1 cover is:

```sh
vector test detect/vector/aggregator.toml \
  detect/ocsf/tests/warden_audit.toml detect/ocsf/tests/routing.toml \
  detect/ocsf/tests/warden_collisions.toml detect/ocsf/tests/production_routes.toml
vector validate --no-environment --skip-healthchecks detect/vector/aggregator.toml
```

Tests load the production aggregator's source/class routes, redactor and VRL
definitions directly; `00-topology.toml` contains no copied transforms.
The pinned unit runner clears deployment sources/sinks before constructing
test injection/assertion components, so this test command starts no production
listener or OpenSearch sink. Never merge agent and aggregator for a test.
The focused fix1 cover preserves the earlier five unchanged source-golden and
agent-validation results without rerunning them. Real command bodies enumerate
fixed nonempty TOMLs, use a clean environment without replacing HOME or umask,
impose CPU/AS/file/output/deadline limits,
and require fresh native budget, memory and new-directory checks before each
call. Static validation disables component/environment and health checks; it
does not start the deployment. Do not use these shorthand commands to bypass
the reviewed limits or start production services.

The backpressure fixture is a **FAILED draft**, retained only in the original
workspace as untracked `detect/tests/` files. Its exact three source snapshots
are archived as inert text in
[`failed-backpressure-source`](../docs/evidence/task-11/failed-backpressure-source/).
The sole run failed on a negative occupancy gauge; full ID delivery and the
required high-occupancy stall were not proved. There is no committed
`backpressure_test.sh` to run, and no retry is authorized by these notes.

That draft uses only an owned ephemeral loopback HTTP peer and
the pinned Vector. Its design streams 32320 synthetic events without a payload spool;
each canonical JSON plus LF is exactly 16384 bytes. Baseline is 32/s for 10s;
the 100s burst targets 320/s. During the burst the peer ACKs at no more than
32/s for 20s, stalls for 60s, then releases for 20s. The driver measures actual
writes/receptions separately from offered targets. Passing would require all IDs,
no positive discard counter, and at least one continuous one-second producer
stall aligned with observed buffer occupancy of at least 260000000 bytes.
Partial pipe writes or a lone EAGAIN cannot prove disk backpressure. A failure
retains logs, metrics and the owned data tree; unknown/timeout/resource outcomes
stop the batch rather than changing parameters to search for a pass. Process,
socket and thread cleanup is bounded inside the fixed overall deadline.

Before deploying, implement and authorize the Azure Activity REST polling,
AKS audit export/storage polling, VNet storage polling, spool checkpointing,
source replay/retention, k3s audit setup, Tetragon exec/connect/sensitive-file
policies and real Warden exporter context. Configure the spool/data paths,
OpenSearch credentials (the literal password is a replacement marker), TLS
trust, index templates/mappings/access control, retention and alert scraping.
The production listeners and OpenSearch endpoint are loopback defaults; remote
deployment requires an explicitly reviewed transport/authentication design.
No real collector, cluster policy, OpenSearch request, cloud service or daemon
is exercised by the synthetic golden/buffer tests.
