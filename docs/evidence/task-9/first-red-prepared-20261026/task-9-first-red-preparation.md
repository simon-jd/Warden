# Task9 first-RED preparation — NOT EXECUTED

BASE handed off by root: a322164866859d424b88aff213d0bc3d789391ae. Only Task9 SOURCE scaffolding/tests and ignored prep changed; no Git/index/formatter/Go/Docker/download/service/cloud execution. Root must FULLREAD the caller/source/freeze, freshly admit the exact normal require_escalated invocation, and execute at most this first RED. No automatic continuation.

## SOURCE and expected semantic RED

jit.go exposes original Request/Approve/Expire plus trusted ports. Request validates input/caller, inserts jit_requests and calls real audit.AppendTx in one PostgreSQL transaction. Approve and Expire return the explicit fail-closed WARDEN_JIT_NOT_IMPLEMENTED sentinel and cannot create access. New 003_jit.sql plus store.go wiring supplies durable state/constraints; existing migrations and audit implementation unchanged. Added TestJITMigrationPreservesVersionTwoRunsAndAudit is frozen but not run in this first RED.

All three original tests call real testutil.Database, migrate a disposable schema, and successfully Request before their business assertions. Expected failures:
- TestSelfApprovalRejected: expected ErrSelfApproval, got explicit unavailable; state remains requested and activation count zero. 
- TestGrantExpiresAndBindingRemoved: approved request has no external grant; before-expiry grant missing; no owned binding removal at equality. Errors are logged, not fatal prerequisites.
- TestAuditRecordedForGrantAndExpiry: real PostgreSQL audit chain lacks granted/expired events. The requested event exists and real audit.Log.Verify(1,head) completes; a success marker proves this positive prerequisite. No mock audit implementation.

First-RED acceptance requires exactly those three failing names, their business messages, unavailable sentinel, and the positive real Verify marker; no Request/DB/build/skip failure. Injected binding/caller fixtures are explicitly synthetic, not real RBAC/identity acceptance. 

## Read-only material findings

Root already performed the sole image inspect: local immutable image/repo digest sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873, Size432729433B. No repeat inspect/pull/list here.

Exact material manifest contains 85 existing files: six pgx-runtime ZIP sets (pgx5.11.0, pgpassfile1.0.0, pgservicefile20240606, puddle2.2.2, x/sync0.24.0, x/text0.43.0) and all go.sum-listed .mod files. Total8,191,123B; ZIP uncompressed content32,373,366B. None missing. No tree/private-cache hashing. Go uses the root's unchanged go.mod/go.sum and verifies its module sums when consuming the private local file proxy. Dependency tests not run. Go may emit exact allowlisted 'go: downloading' messages for reading these local ZIPs; there is no network.

Existing pinned SDK VERSION is Go1.26.10. File/ELF metadata only: go/compile/link/asm are x86-64 regular executables, no PT_INTERP/PT_DYNAMIC. Hashes frozen. This supports CGO_ENABLED=0 use in the Alpine image; no binary probe ran. SDK mounted read-only, no copy. Full SDK execution compatibility and successful build within caps remain unproven. No new material identified. Offline import/graph failure STOPs; no fetch permission.

## Exact caller operation

Files: task-9-first-red-caller.py.txt (inert Python body), task-9-material-manifest.json, task-9-first-red-source-freeze.json. Body pins both manifest digests; source freeze binds 12 precise files and the three test names. Root's outer invocation: `timeout --signal=TERM --kill-after=4s 86s python3 -B -`, body passed via stdin. Parent whole limit90s, work ends65s, cleanup by82s, status85s. No old wrapper scripts or new reusable runner framework.

The new namespace is `.cache/task9-first-red-20261025-a`, must not exist. Exact new PG/Go names are checked absent before creation. Per-run random owner label and creation CID files establish ownership; only these names can be inspected/removed, and cleanup refuses a different owner. No global Docker lists, old PID operations or Task16 profile use. One native Docker CLI at a time; its unreaped group leader is retained through cleanup. Unknown CLI group cleanup blocks subsequent CLI calls and reports UNKNOWN.

Both containers use the existing image by immutable ID with --pull=never, --network none, --read-only, --cap-drop ALL, no-new-privileges, --user postgres, CPU/PID/cgroup caps, log-driver none. No publish/host/bridge/iptables operation. Both override image /var/lib/postgresql VOLUME: PG uses capped tmpfs; Go mounts an empty read-only directory. Cleanup is owner-checked rm -f -v plus exact-name absence proof, so anonymous volumes must not be created or retained.

PG binds only N/socket to /var/run/postgresql and sets listen_addresses='', local trust only inside this private Unix-socket boundary. Host outer N0700 excludes other users; socket child0777 allows the image's nonroot postgres user (no assumed numeric UID). Go mounts that socket read-only and uses pgx's standard Unix socket DSN. No credentials/.env/kubeconfig/host identity access. Readiness checks /proc/1/comm == postgres and pg_isready only inside the newly owned PG container, excluding entrypoint's temporary server. Its data/WAL/tmp/shm are capped; no host database directory.

Go runs in the second nonroot container with SDK/source/local proxy read-only; all build/module/temp/config/telemetry outputs stay in capped /work tmpfs. GOPROXY=file:///proxy, GOSUMDB=off, GOVCS=*:off, GOTOOLCHAIN=local, GOENV/GOWORK=off, CGO=0; no HOME/CODEX_HOME/umask change. Native Docker CLI has minimal explicit environment and a private --config. Exact go test selects only the original three names, -p1/-parallel1/-timeout18s/-count1; no audit-package rerun, catalog/Task11/Task14 operation. Testutil drops its schemas; the entire owned PG tmpfs/container is removed even if the test process times out.

CLI stdout/stderr is saved verbatim per call with combined128KiB cap plus structured argv/results/status. Source/material/freeze are rechecked after work. Any unknown cleanup/deadline/output/source result prevents RED acceptance and stops; no second invocation implied.

## Complete resource envelope; fresh admission still required

Prior R=5,032,108,032B is not admission. Keep Q=5,000,000,000B and Task15 held /tmp131,072B (actual later check). Proposed complete additional1,748,683,264B <=1,750,000,000B:
- Existing daemon image charge1,000,000,000B, conservatively includes compressed+unpacked representation beyond R; no new image download.
- Go /work472MiB=494,927,872B, including extracted modules, compile cache, binaries/temp simultaneously.
- PG data192MiB+tmp8MiB=209,715,200B, including WAL/initdb overlap.
- Two /dev/shm mounts1MiB each=2,097,152B.
- Host source/proxy/raw evidence/socket/CID/directory and two-container daemon metadata reserve40MiB=41,943,040B. Source/proxy copying has finite16MiB logical cap; outputs128KiB. Reserve is accounting, not daemon quota.

At historical R this totals11,780,922,368B including Q/held, below12GB by219,077,632B. Root must freshly validate image-charge adequacy, R, namespace absence and complete overlap; no unconditional fit claim. Future retained artifacts and current new files must count. Cap failure STOPs.

Memory: old Task16 resident9,000,000,000B remains UNKNOWN. New enforced simultaneous maxima: Go1GiB + PG512MiB + one native CLI4GiB AS + parent256MiB AS =6,174,015,488B. Parent uses soft256MiB/hard4GiB solely to let child preexec raise its own AS to4GiB; parent never raises its soft cap. GOMEMLIMIT is supplementary, not accounting enforcement. New6,500,000,000B allowance leaves325,984,512B daemon/overhead reserve; old+new15.5GB<16GB. Fresh admission must cover overlap/memory. Container cache tmpfs is already inside cgroup cap; do not double-count as additional resident beyond it.

No cloud changes: AZURE-BUDGET $6/$5.40 Retail gate, own RG/tags/TTL/protected RG remain. Task16 stopped batch is untouched, no old scans/signals/quiescence claim. True authenticated caller mapping, operational expiry scheduler and real RBAC acceptance remain prerequisites after eventual implementation.
