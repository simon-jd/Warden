# Fixed HTTP → PostgreSQL → scheduler → runc lab

The fixed harness has passed independent code review, capless checks, and its first **actual HTTP/runc and two-stage retirement run**, including exact cleanup and ordinary-user postflight. See [live evidence](evidence/task-2/api-runtime/live/README.md) and historical [code-phase evidence](evidence/task-2/api-runtime/README.md). Production authentication remains fail closed; the fixture's two fixed tokens are test identities, not Entra/OIDC verification.

## Topology and limits

The existing local Docker wrapper pins `/var/run/docker.sock`, checks the rootful daemon hostname and cgroup v2, holds the project flock, packages trusted inputs into a read-only scratch image, and records their SHA-256 manifest. It does not pull a base layer or bind source code. Existing fixed live capabilities, private PID/mount/IPC/cgroup namespaces, 4,000,000,000-byte memory/no additional swap, 512 pids, 2 CPU, and guest isolation remain in force.

API modes add exactly one session-owned PostgreSQL sidecar. It uses the already cached immutable digest `postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873` with `--pull=never`, UID/GID 70, drop ALL, NNP, read-only root, private namespaces, memory/swap 536,870,912 bytes, 128 pids and 1 CPU. Data is a 512MiB tmpfs; socket/tmp tmpfs are bounded separately. There are no host ports or data volumes. The cached image is not deleted.

The sidecar uses `network=none`; the outer container joins only its exact full-label-owned, running, verified private network namespace and reaches PostgreSQL at 127.0.0.1. There is no third-party egress. Guests still receive their own network namespace from the unchanged runc OCI spec. A generated fixture password travels in the Docker client's explicit environment, never an argument or printed URL. The API verifier/database/schema are fixture-only.

API modes reserve 5,000,000,000 bytes before import: the original 3GB allowance, conservatively duplicated cached PG image storage, bounded PG data/tmpfs/logs. They add PG memory to the outer 4GB and all caller-declared other Warden services. Outstanding 3GB and 5GB charges are cumulative. A failed or ambiguous create/import, failed ownership inspection or failed cleanup retains its charge. A test assertion failure can release the charge only when both exact containers and the owned imported image were successfully removed. No global prune, shared service restart or unknown-object deletion is used.

## Commands and phase boundary

Build only, after the ordinary resource preflight:

```bash
scripts/build-runtime-lab.sh
python3 -B -m unittest discover -s scripts -p 'test_runtime_lab*.py'
python3 -B scripts/runtime_lab_docker.py api-code --other-service-memory-bytes 0
python3 -B scripts/runtime_lab_docker.py api-smoke --other-service-memory-bytes 0
```

Use `0` only after confirming there are no other resident Warden services. `api-code` runs the actual runs and scheduler database tests in a capless outer container joined to the private sidecar. Their runtime doubles remain unit/fault models. `api-smoke` checks ABI and reports the live integration fixture as SKIP without the dedicated acknowledgment. Neither mode enables the runc capability profile.

The live step is:

```bash
python3 -B scripts/runtime_lab_docker.py api --other-service-memory-bytes 0
```

The fixed live fixture uses real HTTP requests, the production handler, Store, scheduler registry, gate and runc driver. It checks queued-policy revocation using the stored tenant, success/final logs, natural nonzero exit, timeout/empty-cgroup metadata, cross-tenant 404, and idempotency. Two real running tasks cover acknowledged and lost-ack recovery after the worker is killed and reaped. The lost-ack decorator is test-only: it waits after a real runc Start succeeds but before the gate can persist its acknowledgment. It is not a fake runtime and does not claim to reproduce the containerd server's delayed-creation race. The accepted core's stateful delayed-server tests remain separate evidence.

## Bound retirement and reconciliation

Before releasing its only fixed worker, the supervisor captures the original daemon/worker pidfds, the actual dedicated cgroup2 directory FD, and the original root/state/io directory FDs. Initial membership must consist of exactly that daemon and worker; the supervisor remains outside. The worker enters the subtree atomically with `CLONE_INTO_CGROUP`. Trusted fixture processes and their daemon/shim/guest descendants must stay within that tree. No shared/root cgroup is a permitted target.

1. The gate permanently closes cross-process admission before issuing `cgroup.kill` on the captured subtree. Both original pidfds must report exit and the entire subtree must report `populated 0`. This writes only `kernel_quiescent`; it cannot clear a pending run.
2. A fixed socket message wakes the original Python Popen owner. It waits/reaps its daemon, verifies the tree empty, and uses the existing FD-anchored cleanup to remove owned root/state/io/socket data. Failure produces no success response.
3. The Go finalizer independently requires both pidfds' HUP/reaped state, the captured empty cgroup, original data-directory descriptors with link count zero and their original device/inode identities, and absence of replacement data/socket entries at the anchored session parent. A response string alone is never proof. Only then is `retired` persisted/fsynced.
4. An opaque per-run proof binds the retained node authority, consumed RunID and final record SHA-256. Scheduler recovery uses it in the Store's result/audit transaction. Ambiguous creation cannot be cleared with a zero proof, a cleanup boolean, or a different error label. No marker is deleted or reset. The final interrupted result records `node_retired`, lost logs and no invented exit metadata, with the proof hash in audit.

The final runner cleanup still verifies/removes its cgroups and reaps every owned Popen. Gate authority, launch markers, binding/proof, config and logs are retained and handed back only through validated FDs. This is permanent retirement of one owned lab node. It adds no fleet restart, general privileged command executor, or supervisor-crash resumption workflow; loss of unfinalized proof stays pending. Full live acceptance additionally requires successful inner and outer cleanup, ordinary-user postflight, and audit Verify. Outer container deletion alone never supplies runtime evidence.

At the historical code gate, the complete kernel-backed retirement protocol was intentionally unexecuted. The subsequent reviewed live run passed the composition and positive proof/audit path; see the evidence above. Capless tests cover real pidfd exit versus parent reap, original-directory unlink/replacement/identity checks, partial proof refusal, durable PG rejection and cleanup failure propagation. Each future reviewed live run must validate that composed protocol and positive proof/audit path again.

## Interface references

- `runtimes/gate/retirement.go`: `BindRetirement`, `Retire`, `Finalize`, opaque `Reconciliation`.
- `controlplane/internal/runs/execution.go`: authority-bound completion and sticky ambiguity designation.
- `controlplane/internal/apilab/api_runtime_test.go`: fixed real-driver HTTP fixture and test-only failure barrier.
- `scripts/runtime_lab_api.py`, `runtime_lab_runner.py`: private PG and fixed original-owner cleanup protocol.

The topology follows Docker's [container network namespace mode](https://docs.docker.com/reference/cli/docker/container/run/#network), and retirement uses the kernel's [cgroup v2 subtree/kill semantics](https://docs.kernel.org/admin-guide/cgroup-v2.html) and [pidfd exit/reap events](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).
