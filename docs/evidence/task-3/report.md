# Task 3 report — backend binding prerequisite

Status: **DONE_WITH_CONCERNS for the controller-approved first code substep only.**
Task 3 overall and the Goal remain open. No gVisor driver, scheduler registration,
node deployment, guest conformance, or 100-launch measurement is implemented or
claimed by this substep.

Source commit: `f232b0d5e833e1060afa5df2533b2421ee714e2c`
(`runtimes: bind gVisor gate authority to backend identity`).
Base: `c0ae3a0` (full base SHA recorded in the evidence manifest).
Evidence: `docs/evidence/task-3/`, committed separately after the source.

## Approved scope and implementation

The controller accepted splitting the original architecture/integration task
before implementation: complete the minimal durable backend identity prerequisite,
then review the actual driver, node proof, and lab capabilities separately. No
retroactive runc migration or speculative guest PID schema was authorized here.

- `runtimes/gate/gate.go`: `NewBound` stores a versioned identity digest in the
  same fsynced node record as the random authority. Node initialization uses the
  existing cross-process lock and directory fsync. Reopening a different identity
  fails before a driver is returned. Legacy `New` refuses bound records;
  `NewBound` refuses every legacy record, unknown versions, and missing authority
  beside orphaned state. Existing Start/Reap permanent consumption, ambiguous
  creation, and retirement behavior remain unchanged.
- `runtimes/gvisor/binding.go`: constructs the identity from a credential-free
  HTTPS endpoint, CA bundle SHA-256, observed kube-system namespace UID (the chosen
  cluster-incarnation marker), exact warden-lab namespace UID, dedicated Node
  name/UID, and reviewed node-input manifest SHA-256. Invalid/incomplete identity
  is rejected before writing gate state. It is configuration/identity binding,
  **not attestation, live API validation, or quiescence proof**.
- `runtimes/gvisor/binding_test.go`: real filesystem/gate tests with explicitly
  labeled runtime-boundary doubles and an actual subprocess reopen. Replacement
  of each configurable identity dimension fails; original recovery remains
  possible; consumed IDs and uncertain launch tombstones survive reopen.
- `docs/gvisor-backend-binding.md`: integration and trust contract, fresh gate
  directory requirement, and remaining per-operation live identity checks.

The future driver must check live cluster/namespace/node identity on every API
operation. It cannot rely on a cached fingerprint to detect replacement while a
process is alive. Jobs/Pods must also be bound to original UIDs and RunIDs with
exact ownership and delete preconditions. A not-found response cannot resolve an
ambiguous submission. Existing scheduler stored-tenant authorization must be used
when that backend is registered. Today scheduler configuration still rejects
gVisor; no independent Job generator is presented as an integrated driver.

## TDD and verification

Commands use the existing project-cached Go 1.26.10 toolchain, project GOCACHE and
GOMODCACHE, and `GOPROXY=off GOSUMDB=off`. No dependency was added. Lab/DB credential
environment variables were removed for the ordinary full-suite attempt.

1. RED: `go test ./runtimes/gvisor -count=1` before implementation reported
   `no non-test Go files` and `FAIL [build failed]`. This is the missing-API compile
   red, not a behavioral assertion failure; original output is `red-binding.txt`.
2. Behavioral RED: `go test ./runtimes/gvisor -run
   TestBindingRejectsInvalidIdentityWithoutState -count=1` failed for invalid,
   zero, and empty ports, invalid hostname and malformed node DNS labels:
   `invalid identity accepted`. Those checks were then implemented; see
   `red-validation.txt` and the succeeding complete focused output.
3. GREEN: `go test ./runtimes/gvisor ./runtimes/gate -count=1 -v` passed 17 top-level
   test invocations, including the helper's ordinary no-op invocation, with zero
   skips. Detailed subcase output is in `green-binding.txt`.
4. Mutation verification: temporarily allowing nonempty mismatched binding
   digests made all seven replacement subcases and cross-process replacement
   fail. The original code was restored and the focused suite passed. This was
   a later sensitivity check, not the initial TDD red; see `mutation-binding.txt`.
5. `go test -race ./runtimes/gvisor ./runtimes/gate -count=1`, `go vet ./...`, and
   `go build ./...` passed; exact commands/output are in separate evidence files.
6. `scripts/build-runtime-lab.sh` rebuilt the fixed fixture binaries from the
   changed source. `python3 -B scripts/runtime_lab_docker.py api-code
   --other-service-memory-bytes 0` then passed **26 real PostgreSQL runs/scheduler
   tests**, using runtime doubles. The unchanged reviewed fixture ran capless;
   it explicitly reports `API/runc live NOT EXECUTED`. Its packed input hashes,
   exact object identities, output, and released charge are retained.
7. `git diff --check` passed before the implementation commit.

The attempted `go test ./... -count=1 -json` **did not pass**. Database-dependent
API/audit/store/runs/scheduler tests explicitly required WARDEN_TEST_DATABASE_URL.
The later capless fixture supplies relevant runs/scheduler regression coverage,
not a replacement claim that every failed DB package was rerun. Eight existing
live test events skipped (the API lab and seven runc conformance cases).

Five unchanged runc socket tests failed directory validation. In the sandbox,
read-only stat showed `/tmp` UID 65534/mode 1777 and `/home` UID 65534/mode 755, while
the process UID was 1000, TMPDIR unset. Outside remapping, `/tmp` was UID 0/mode 1777,
`/home` UID 0/mode 755, process UID 1000 and TMPDIR unset; those tests still reported
`socket ancestor writable by untrusted group/other`, including from the freshly
rebuilt standalone binary. The validator accepts root-owned sticky /tmp, and does
not name the failing component. The ephemeral test ancestry was already removed:
the later failure's exact component remains **unlocalized**. No checks or
permissions were weakened and no further repeats were made. Full failing output
and these diagnostic limits are retained in the evidence.

## Resources and cleanup

No cloud resources, GPU, downloads, installation, capability-bearing lab profile,
host-service change, push, or publication occurred. All code/cache work stayed in
the project. Only the pre-existing reviewed capless PG fixture created disposable
Docker objects. Its build step was the existing controller-requested build script.

Initial project allocation was 2,482,786,304 bytes, free disk 376,879,579,136 bytes,
with 200 MB estimated local-test headroom. Rebuilding the fixture/cache increased
allocation by approximately 383 MB (larger than that initial estimate, still far
below the 12 GB ceiling). Immediately before import, the reviewed wrapper recorded
2,865,819,648 project bytes + 5,000,000,000 reserved bytes, zero outstanding prior
charges, no other Warden containers/images, and 4,536,870,912 aggregate service
memory bytes. This fits the 12,000,000,000 disk and 16,000,000,000 memory ceilings.

The exact outer container, PostgreSQL container, and imported image were removed;
postflight independently confirmed their absence. No shared/unknown objects were
deleted. All outstanding import charges are zero. Final ordinary-user postflight
shows UID 1000, CapEff 0, NNP 1, no Warden Docker objects, project allocation
2,865,963,008 bytes, and free disk 374,288,769,024 bytes. Budget commitment remains
$0.00 estimate; this is not an actual-billing statement.

## Follow-on deployment and PID design — proposal, not executable approval

Use one dedicated local Docker outer node with private PID/mount/IPC/cgroup/network
namespaces, no host binds/sockets or host networking, fixed read-only packaged
inputs, bounded writable storage, and original-owner cleanup. Start design from
the reviewed outer budget (4 GB, 512 host tasks, 2 CPU); account for any API/PG
sidecars separately. K3s/containerd/runsc data, generated CA/token files and their
logs live only in this project-owned node/session. Preserve flock, input hashes,
exact full ownership labels/IDs, and outstanding import accounting. If k3s needs
a non-loopback node address, evaluate a fixed dummy interface only inside its
private network namespace. Neither this network design nor its capability set
has been run or approved for live execution.

Before constructing a runnable profile, pin official k3s, its bundled containerd,
runsc and shim releases/digests, and verify the exact CRI merge path. A candidate
is dedicated handlers `gvisor` (soft=hard RLIMIT_NPROC 128) and `gvisor-pids32`
(soft=hard 32), using administrator-only base_runtime_spec inputs. Other PID
values fail closed until a trusted matching handler exists. Kubernetes exposes
no Pod `pids` resource field. K3s containerd v3 template handling and runsc shim
configuration are documented by [K3s](https://docs.k3s.io/advanced#configuring-containerd)
and [gVisor](https://gvisor.dev/docs/user_guide/containerd/configuration/).

Explicit runsc `network=none` is required for the existing loopback-only/
ENETUNREACH guest assertion; CNI egress-deny alone does not establish it. Explicit
`oci-seccomp=true` is required because current flags default it off. Inspect the
actual final OCI spec and guest filters, with readonly rootfs, UID 65534, drop ALL,
NNP, and denial of privilege/namespace escape paths. These are research candidates
from [runsc flags](https://github.com/google/gvisor/blob/master/runsc/config/flags.go),
not a pinned-release or executed proof.

Current Sentry source enforces ProcessCount while creating tasks and checks
root-user-namespace capabilities for the NPROC exemption; raising hard limits
also checks root capability. Child-namespace self-capabilities alone therefore
do not establish those exemptions in this inspected source. See
[task creation](https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/task_start.go),
[NPROC counters](https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/kernel.go),
[credential checks](https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/auth/credentials.go),
and [rlimit changes](https://github.com/google/gvisor/blob/master/pkg/sentry/syscalls/linux/sys_rlimit.go).
Selected-release tests must still prove hard-limit immutability, UID/capability
and namespace behavior, all guest threads/processes counted, fork EAGAIN at 32
and 128, and independence between fresh sandboxes. Host Sentry/Gofer task counts
remain separate outer protection and cannot supply guest PID evidence.

The controller accepted typed guest evidence as a later direction only. Actual
guest task counts/denials and trusted empty-guest proof must be designed and
reviewed; no pids.events/peak values may be fabricated from RLIMIT. Existing runc
host-event/peak assertions remain intact. Job/Pod absence alone, and outer Docker
deletion alone, do not prove guest cleanup. The trusted node proof path, timeout
tree kill, memory OOM evidence, bounded Pod-log snapshot, late Job creation
recovery, stored-tenant reauthorization integration, all seven real conformance
cases, and 100 fresh-sandbox launches remain future work.

## Self-review and concerns

Reviewed the complete changed code and tests, all identity fields, persistent
format/version refusal, fsync/lock reuse, unchanged ambiguity state machine,
source hashes, runtime-double labeling, and exact cleanup evidence. DNS/port
validation was tightened through a behavioral red-green cycle. No source file
was changed after the implementation commit.

The requested full Task 3 architecture was too broad to safely complete as one
review step; the controller explicitly accepted this smaller prerequisite. The
remaining limitations are the absent real gVisor driver/node proof, unexecuted
gVisor acceptance, and the candid full-suite prerequisite/socket failures above.
Independent controller review is still required before acceptance of this code
substep or any capability-bearing execution.
