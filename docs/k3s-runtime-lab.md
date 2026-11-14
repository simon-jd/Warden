# Isolated k3s/runsc bootstrap lab

> 2026-11-10: Task 3's live runs use a different lab,
> `scripts/k3s_gvisor_lab.sh` ([gvisor-lab.md](gvisor-lab.md)): one privileged
> node container on an `--internal` network. This page describes the earlier
> capless harness, `scripts/k3s_lab.py`, which did not get a Ready node (STATUS
> blocker 3, inotify EMFILE). It is kept as the record of that design and its
> reviews.

This is the Task 3 bootstrap **code phase**. The fixed `smoke` mode performs
capless version/ABI checks. `bootstrap` is reserved for a separate controller
step after independent review. Neither mode implements a tenant scheduler
driver, submits tenant Pods/Jobs, proves guest limits, runs conformance, or
measures cold launches. Task 3 remains open.

From the project root, with ordinary operator UID and the real host filesystem
view (the restricted execution view projects root-owned ancestors as UID65534):

```sh
python3 -B scripts/k3s_lab.py materials --other-service-memory-bytes 0
python3 -B scripts/k3s_lab.py smoke --other-service-memory-bytes 0
```

Declare the actual aggregate maxima of other Warden services. The harness uses
the existing project Docker lock and fixed local socket, enumerates all owned
images including used untagged/intermediate images (`image ls --all`), clears inherited
Docker context/TLS/environment, and checks the local rootful cgroup-v2 daemon.
It never changes the shared daemon, installs host software, pulls base images,
publishes ports, or uses global pruning. `bootstrap` is the live mode.

## Fixed topology and isolation

One scratch Docker image and one random-session-labelled node container. The
outer limit remains 4,000,000,000 bytes memory and memory+swap, 512 host tasks,
and 2 CPUs. PID, mount, IPC, network and cgroup namespaces are private; the
root filesystem is read-only. Smoke uses UID65534, zero capabilities, Docker's
default security profiles, and no host bind. Live bootstrap reuses the reviewed
runc lab capability set: CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, SETPCAP,
SYS_CHROOT, MKNOD, KILL, SYS_ADMIN, NET_ADMIN. Its seccomp/AppArmor profiles are
unconfined, as required by that existing nested-runtime boundary; this is an
explicit review surface. There is no SYS_MODULE, host PID/network, Docker
socket, host cgroup bind, arbitrary device, GPU or host-root/home mount.

The sole host bind is a newly created 0700 project session. Docker receives
only its fixed real path under the project BASE, initially read-only with
`rprivate` propagation. The host retains the no-follow directory FD and passes
its device/inode/owner as strict numeric identity fields. Immutable PID1 opens
only the `/session` mountpoint, verifies that identity, directory mode0700,
initial RO flags and private mount namespace/propagation before reading any
session content or entering prepare/cleanup/snapshot paths. Only then may live
bootstrap remount this exact FD target RW in the private namespace, preserving
other mount flags, and revalidate identity/flags. Image code and software are
immutable image copies, never that bind.

This explicitly replaces the original literal `/proc/HOST_PID/fd/N` source:
the first real OCI mount failed before exec. Runc's plain bind path and the
kernel's rejection of foreign mount-namespace paths make the FD magiclink
unsuitable here; appending `/.` does not relocate its mount reference. The
controller approved the initial-RO plus identity-handshake replacement. Actual
mount compatibility still requires the independently reviewed capless test.

The fixed probe command is:

```sh
python3 -B scripts/k3s_lab.py mount-smoke --other-service-memory-bytes 0
```

It uses the same numeric session-owner UID, zero capabilities, default security
profiles, the sole RO/private owned bind and unchanged private namespaces/outer
limits. It checks only identity and RO flags; it does not remount, read session
files or launch k3s. The host compares exact allowed public session file hashes
and metadata before/after, before deleting objects. A mismatch is nonzero and
retains objects and charge. This probe has not yet run in the round2 code phase. `/run` (128MiB), `/tmp` (64MiB),
`/var/log` (32MiB), and `/etc/rancher/node` (1MiB) are bounded tmpfs mounts.
The controller checks held-FD/path identity and ordinary-UID returned evidence
before deleting objects or releasing its persistent allocation charge. A failed
mountpoint handshake never enters session preparation, failure snapshot or
cleanup, so a mismatched target remains RO and untouched.

The inherited cgroup mount is replaced only after the existing private
namespace/root-membership checks. The new cgroup2 view is rooted at the Docker
container's own cgroup; global/host controllers and outer maxima are never
written. PID1 moves to `/bootstrap`. K3s is placed in
`/warden-lab/service` **before exec**; embedded kubelet/containerd and later
shims inherit that owned tree. The private root enables cpu, memory, pids and
cpuset delegation. Kubelet explicitly uses cgroupfs, `/warden-lab` for its
Pod subtree, `/warden-lab/service` for kubelet/runtime processes, and
`podPidsLimit=128`. This last setting limits host tasks; it is not proof of a
gVisor guest-task limit or an RLIMIT_NPROC implementation.

The node uses native snapshots, disabled flannel/kube-proxy/network policy,
disabled default workload add-ons, and an immutable loopback-only CNI config.
A fixed `198.18.0.1/32` address is added to the private `lo` interface. This
requires NET_ADMIN only in the private namespace, no extra device/module,
published port or external route. Whether the full node becomes Ready with
this profile remains a **live-review validation question**. The endpoint is
reachable only inside that namespace; transport for the later host scheduler
driver is not implemented here.

## Kernel protection and selected sources

The selected stable release is **k3s v1.36.5+k3s1**, official wrapper
79,077,538 bytes, SHA256
`d73847bcd3c5fccef0115b372e2f9a91f3032dc84bbf71518a4617565294d313`.
Its [go.mod](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/go.mod)
pins Kubernetes v1.36.5-k3s1 and containerd v2.3.4-k3s1.36.
The kernel-tunable branch in the
[selected kubelet source](https://github.com/k3s-io/kubernetes/blob/v1.36.5-k3s1/pkg/kubelet/cm/container_manager_linux.go)
selects error-only validation when `protectKernelDefaults=true`.
The fixed preflight checks all six expected values: overcommit_memory=1,
panic_on_oom=0, panic=10, panic_on_oops=1, root_maxkeys=1000000,
root_maxbytes=25000000. A mismatch fails; there are no sysctl fixups.

K3s's separate
[agent initialization](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/pkg/agent/run.go)
calls [syssetup](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/pkg/agent/syssetup/setup.go).
With flannel and proxy disabled, it omits bridge-filter sysctls; conntrack
limits/timeouts are explicitly zeroed. Its two forwarding writes may be
refused by read-only `/proc/sys`. That mount is checked read-only before and
after startup and never remounted. Both fixed startup logs (`root/private.log` and
`root/agent/containerd/containerd.log`) pass a combined 32MB bounded, no-follow
regular-file check. Missing logs, rotated containerd history and unexpected
warning/error lines fail closed. Expected EROFS/module-unavailable warnings
are accepted only as complete fixed-format timestamped lines; the actual safe
lines are archived with their source, order and repeated occurrences. Extra
fields or secret prefixes are rejected. Other log text is never public.

The official wrapper embeds payload SHA256
`d5316b544b0ddcf993305e38b2aee41dc79e8c5d963a8336f5d8df84e99fb426`.
Its archive includes `bin/aux/modprobe -> ../busybox`, `insmod` and `rmmod`.
Therefore the wrapper is **not installed in the image**. The material parser
verifies its hash-named zstd frame, validates paths and direct regular-member
aliases, and never extracts archive symlinks. Only inner k3s, runc, the runc
shim, CNI and ip are selected. No BusyBox, module applet or `/lib/modules`
survives. Explicit internal aliases select containerd/kubectl/ctr/crictl and
loopback. The [inner main](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/cmd/server/main.go)
dispatches directly and does not execute the wrapper's extraction logic.

The selected **gVisor release-20261019.0** official x86_64 tar.bz2 is
73,621,897 bytes, SHA256
`1298e8ed9c3fee900f00d2ea96ec2d79d80ed93f2175812f29b7e7da718041a3`.
All eight regular binaries, including the new `gvisor-bin/` sidecars, remain
together. Selected runtime binaries must be static amd64 ELF files. The
manifest records every member/file SHA256 and constructed alias, together with
the official wrapper/archive pins and embedded-payload identity. Python and
its actual dynamic-library closure are copied only from trusted root-owned
host paths; no package manager or mutable base-image tag is used.

The shim's `-v` reports **containerd library 2.1.5+unknown**, not the gVisor
release tag: [its entrypoint delegates to containerdshim.Run](https://github.com/google/gvisor/blob/release-20261019.0/shim/v1/cli/cli.go).
Artifact SHA256 establishes the shim's release identity. The actual node
containerd version is separately checked as **v2.3.4-k3s1.36**.

The v3 template extends the
[selected k3s base template](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/pkg/agent/templates/templates.go)
with `io.containerd.runsc.v1` and immutable `ConfigPath`. The
[selected shim options](https://github.com/google/gvisor/blob/release-20261019.0/pkg/shim/v1/runsc/options.go)
support `binary_name` and `runsc_config`; selected
[flags](https://github.com/google/gvisor/blob/release-20261019.0/runsc/config/flags.go)
support `platform=systrap`, `network=none`, and `oci-seccomp=true`. Capless smoke
parses those real flags. It does not prove runtime enforcement.

## Lifecycle, identity and bounded resources

Live bootstrap creates only its namespace and RuntimeClass after fixed API and
Node readiness checks. The original PID1 Python controller owns the k3s
`Popen`; no arbitrary command/kubectl passthrough exists. Public output selects
Node name/UID, namespace UIDs, Ready, exact versions, endpoint, public CA
fingerprint and immutable-input-manifest fingerprint. Full Node JSON,
annotations, environment, private keys, tokens and kubeconfig are never
exported. Temporary private logs and generated credentials remain 0600 inside
the owned session or bounded tmpfs. Private diagnostics have a 32MB acceptance
bound; node data is checked against 1.8GB and child file size is bounded at
256MB. These polling/file bounds are conservative bootstrap limits, not a
general filesystem quota or tenant storage enforcement.

On exit the original controller attempts subtree kill, original-process reap,
aggregate `populated 0`, recursive empty-cgroup removal, private-data deletion,
adopted-child reap, and protected-sysctl postflight. A successful fixed marker
is required before the host accepts live cleanup. Before each container/image
deletion the host revalidates the still-open session anchor and returned
evidence. Any observed drift permanently blocks further deletion for that
invocation and preserves its allocation charge. Unknown inspect, path drift,
kill/deletion failure or missing cleanup proof is nonzero and retains the
stopped container/image/session and charge for review. On bootstrap failure,
the controller first attempts a failure-only
`startup-private.log` snapshot in the owned session: two fixed paths only,
no-follow regular-file reads, combined file maximum 32MB including headers,
0600, missing/truncation markers as needed. Snapshot read/copy failure cannot
skip independent kill/reap/data cleanup. The session remains root-owned 0700;
there is no evidence ownership handback, raw printing or archival to git.
Snapshot failure can leave a partial private file. The original mutable node
data is still removed when the existing kill/reap/empty-tree checks permit.
The stopped outer objects and charge remain for controller review. Such a
private failure
scene is not public evidence. Outer deletion never substitutes for inner
emptiness proof. Readiness failure currently also retains the stopped outer
objects conservatively even when inner cleanup printed its marker.

Each download and image import repeats fresh accounting: current project
allocation, every owned image at **2×Size +64MB**, all outstanding charges,
download size/free-space threshold, and aggregate service maxima. The six-GB
additional reserve consists of downloads0.16GB, source/metadata0.04GB,
extraction/staging0.9GB, rootfs tar0.9GB, imported image2×0.9GB, and
node/log headroom2.2GB. Existing image/charge accounting is added separately.
The guard accounts **7GB** service peak (outer4GB + conservative host assembly
3GB), plus the caller's declaration. This changes no outer hard limit.

Measured code-phase image files were approximately496MB and tar497MB;
packaging peak RSS was approximately823MB. Source-bound evidence records exact
values, actual image ID/Size, pre/postflight, removals and test output. These
measurements do not establish live-node peak usage. No tenant limits, guest PID
metrics, launch consumption/revocation guarantee, seven-item conformance or
100-launch p50/p95 result is claimed.


## Round 3–4 stopped-scene recovery and startup fixes

The controller recovered the second failure after round3 review. The third
bootstrap then exited before Ready with kubelet's host-visible swap rejection.
Its exact container/image, archive and six-GB charge remain retained. Round4
is code and read-only diagnosis only; see `docs/evidence/task-3/k3s-lab/round-4/`.
Recovery is a separate reconciliation, not proof that the original Popen was
reaped or that a GoGate node retired.

The kubelet drop-in now uses `failSwapOn=false` with explicit `NoSwap` workload
policy. Before creating private data, before publishing success, and at final
postflight, the controller reads `memory.swap.max` through its verified private
cgroup root FD and requires exactly zero. Missing, aliased, nonregular or
nonzero limits fail. No host swap setting or shared bootstrap code changes.

The selected containerd NRI interface defaults on and tries to create its
socket beneath `/var/run`; this scratch image keeps that filesystem read-only.
The fixed v3 extension now disables unused NRI, and generated configuration
verification requires that setting. K3s also writes a default kubeconfig
symlink even when the actual kubeconfig output is explicitly elsewhere. The
image now constructs only `/etc/rancher/k3s -> /run/k3s-client`; PID1 exclusively
creates its 0700 target in the already bounded `/run` tmpfs. The actual
`admin.yaml` remains 0600 in owned private data. Neither change adds a host bind,
capability or writable global filesystem.

Startup observations now distinguish full, actual safe module/sysctl denial
lines from four exact source-backed startup templates. Certificate-cache
preload, runtime-core initialization, automatic v3 config migration and the
owned content store's fsverity EOPNOTSUPP probe must be in their correct log,
after launch and strictly before the first Ready second. The API and Node
must also pass a final Ready check after a one-second interval. Each one-shot
warning is limited to one occurrence; core initialization has a 240-occurrence
bound. Continued/post-Ready errors, wrong paths/errors, extra fields/prefixes,
and unknown text fail. New records preserve the actual matched safe fragment
and a SHA256 per occurrence, without exporting their internal address, path or
timing fields. The public evidence key is `startup_observations`. Fixed stage
codes identify startup, owned cleanup, adopted-child reap, or sysctl postflight
failure without arbitrary exception messages. Adopted-child reaping waits up
to five seconds instead of rejecting the first non-waitable child.

Round4 additionally recognizes only the 32 observed fixed unused API versions,
the empty metrics-manifest template (at most three), the default machine-id
lookup failure (one), and the initial fixed Kubernetes endpoint reset (one).
Klog caller, severity and UTC timestamp are exact; k3s runs with fixed `TZ=UTC`.
Three exact namespace-initialization errors are limited to one each and also
require final internal GETs proving `default` and `kube-system` have their exact
names, nonempty UIDs, Active status and no deletion timestamp. Their JSON is
never exported. These templates retain the same pre-Ready/final-Ready gates and
safe-fragment/hash output. Shutdown and context-cancellation errors still fail.

The one-off `k3s_lab_recover.py` helper for the third failed bootstrap scene
was removed on 2026-10-26 with the rest of the agent-made review process; see
git history before that date. Task3 remains open.
