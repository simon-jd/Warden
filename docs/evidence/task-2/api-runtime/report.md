# Task 2 API/runtime code-phase implementation report

Status: **DONE_WITH_CONCERNS — code phase complete; independent code review and reviewed capability-bearing live step still required.**
Implementation commit: `09eed7b622bc70081eb751ea42dd0c81bd5c1395`.
Base: `c3f182386186d52bc8589c706843128ebd398e2c`.
Evidence commit: recorded by the final response after this report/evidence is committed.

## Implemented

- A fixed real-HTTP integration fixture under `controlplane/internal/apilab`, built into the immutable scratch lab input. It uses production handler/Store/scheduler config/registry/gate/runc, a clearly named test-only two-identity verifier, real private PostgreSQL/schema and audit Verify. It is SKIP without dedicated acknowledgment. Production main remains fail closed.
- Fixture scenarios: stored-tenant policy revocation before worker release, successful output and GET logs, tenant-B 404, idempotency, natural nonzero exit and timeout metadata; real acknowledged task recovery plus a real task whose acknowledgment is held at a test-only boundary before durable gate acknowledgement. Killing/reaping the actual worker leaves real runtime state for original-daemon Reap, never another Start.
- One private PG topology using the cached pinned digest, network none, nonroot UID70, drop ALL, NNP, read-only root, tmpfs data, memory/swap 512MiB, pids128, CPU1. Only the owned outer container joins the exact verified sidecar namespace; no host port or volume. Outer limits/capability profile and guest OCI security are unchanged. Fixed live `api`, capless real-PG `api-code`, and capless ABI/no-ack `api-smoke` modes are explicit.
- Existing local-socket/rootful/hostname/cgroup-v2 checks, flock, labels/exact cleanup, trusted input copying and FD anchoring remain. API preflight/charge reserve is 5GB and aggregate service memory is 4,536,870,912 bytes plus declared other Warden services. Unknown cleanup retains charge; PG/outer/image cleanup is independent; cached PG image is retained. Secrets are passed by explicit environment, never command arguments/logged URLs.
- Original-node binding captures actual daemon/worker pidfds and the complete cgroup2 FD before the fixed worker is released; worker birth uses CLONE_INTO_CGROUP. Initial tree membership must be exactly those identities. Admission is permanently fenced across gate instances before cgroup.kill. Kernel emptiness/exit writes only an intermediate state.
- Two-stage final proof: the original Python Popen owner reaps its daemon and uses existing FD-anchored root/state/io/socket cleanup. Go independently requires both pidfds HUP/reaped, original empty cgroup, original data directories unlinked with matching device/inodes, and no replacement entries. The runner response is a wakeup, not a disk-clean boolean. Proof/authority/consumed markers are retained; failure stays pending.
- Opaque proof binds original authority, consumed RunID and proof SHA. The Store checks the recovery claim binding, preserves explicit ambiguity against both boolean clearing and error-label laundering, and atomically audits proof metadata with the final interrupted/lost-log/no-invented-exit result.

The implementation is fixed-node permanent retirement, not fleet orchestration or a general root command executor. See `docs/api-runtime-lab.md` for interfaces, trusted-process containment assumptions and exact sequencing.

## Validation

All final commands and raw results are in `docs/evidence/task-2/api-runtime/README.md` and `verification.json`:

- Build exit0: `scripts/build-runtime-lab.sh`.
- Python: `python3 -B -m unittest discover -s scripts -p 'test_runtime_lab*.py'`: 41 PASS.
- Go race: `scripts/go.sh test -race ./runtimes/gate ./runtimes/runc ./controlplane/internal/apilab -count=1 -v`: 38 top-level PASS, 8 expected live SKIPs, no race report.
- Vet: `scripts/go.sh vet ./controlplane/... ./runtimes/...`: exit0.
- Fixed capless `api-code` mode: 26 top-level real-PG runs/scheduler tests PASS, no SKIP. Runtime doubles remain boundary fault models.
- Fixed `api-smoke`: ABI PASS, API/runc fixture SKIP/NOT EXECUTED.
- `api` without review flag: refused before Docker mutation, exit2 expected. No capability-bearing profile was run.
- Exact final sidecar/outer/image removal and ordinary-user postflight verified; charge0, owned container/image lists empty, cached PG digest still present. Postflight budget: no resident test service; no download/cloud resource.
- `git diff --check` and post-commit source-only diff against implementation SHA: clean.

The final source was built/tested before the implementation commit, and the source-only post-commit diff is empty. SHA-bound package manifests and verification data are committed afterward.

## TDD evidence / self-review

Behavioral RED→GREEN: retired-node Start rejection; real-PG forged proof rejection; real-PG ambiguity-label laundering rejection; topology missing before implementation; capless /tmp permissions; gate evidence retained instead of being rejected/deleted; real pidfd live/exit/reap behavior; original directory FD unlink/identity/replacement checks. Unconditional-success mutations of pidfd/disk checks fail the regressions, restored implementations pass. API-first missing-symbol compilation failures are separately archived and are not described as behavioral execution. Real original-owner reap/storage-failure propagation is covered with a harmless process and temporary filesystem; privileged cgroup success is not exercised.

Self-review corrected capless tmpfs permissions, kept the 5GB charge on independent PG cleanup failure, retained gate evidence through validated descriptors, accounted for asynchronous PG lock release after worker death, and added sticky ambiguity labels so a failed run cannot be relabeled and later cleared without proof. The controller's disk-cleanup clarification was incorporated as the two-stage protocol before source commit.

An initial broad guidance discovery mistakenly used `find ..`, emitted other-project pathnames, and was stopped. It did not read other-project file contents or modify them. All later discovery and actions were scoped to Warden. Default sandbox ownership remapping made existing FD trust tests fail on /home and /tmp ancestry; the same capless tests were rerun outside that remapping as the ordinary project UID, without changing the ownership rules or host permissions.

No subagents were spawned. No shared daemon/service, host controller, sudo policy, other project, dependency, Azure/GPU, push or production credential was changed/read. Estimated Azure cost is $0. All temporary containers/imports from executed checks were removed; retained evidence/cache remains project-owned.

## Concerns and explicit remaining gate

- The full two-stage cgroup/daemon/data proof and positive PG/audit reconciliation composition need independent review and the later actual capability-bearing run. The live integration test currently SKIPs; code tests and capless PG are not API→runc acceptance.
- The lost-ack fixture blocks after real runc Start succeeds. It demonstrates a genuinely running resource with an unacknowledged gate marker; it does not claim to force the real containerd delayed-service-publication race. The accepted core stateful delayed-creation test remains distinct.
- The fixed supervisor is trusted not to move worker/daemon/shim/guest processes outside the captured tree or restart the retired authority. There is no general resumption workflow after losing the in-memory unfinalized descriptor binding; such interrupted/failed proof remains pending and preserves evidence.
- Full live success requires the runner's final cleanup and ordinary-user postflight too. Any cleanup failure must be reported nonzero, even if a fixture assertion already passed.

Task 2 and the overall Goal remain open for the controller's review/live decisions.
