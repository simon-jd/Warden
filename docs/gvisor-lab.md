# Local k3s + gVisor lab (Task 3)

Status 2026-11-10, home-ubuntu, source `277050d`: `make test-gvisor` passes. `TestGVisorConformance` passed 7/7 in both runs. `TestGVisorColdStarts` ran 100 serial cold starts, all passing, with start→exec p50 547.77 ms (the arithmetic median) and p95 741.11 ms (nearest rank). Memory, CPU and probe match Firecracker's default VM: 512 MiB + 128 MiB overhead, 1 CPU, the `uid` probe. The pids and timeout limits are lower: 32 pids and 30 s, where the default VM has 128 pids and 300 s. In the 100 runs the probe peaked at 5–6 pids, no run hit `pids.max` or timed out, and the longest start→wait was 3.96 s, so neither limit came into play. Method, load and the comparison with Firecracker are in [evidence/runtime-startup.md](evidence/runtime-startup.md). Raw logs are in [evidence/task-3/live-20261110](evidence/task-3/live-20261110/README.md). After the review fixes (source `a505196`), `TestGVisorConformance` passed 7/7 again ([conformance-rerun.log](evidence/task-3/review-fixes-20261110/conformance-rerun.log)). The cold-start series was not repeated, so its numbers are from `277050d`, before those fixes.

The scheduler does not register a `gvisor` backend yet. The tests call the driver directly, through the gate that `gvisor.Bind` opens.

Cilium mode, 2026-11-13, source `5c436a8`, on a fresh lab: `make test-cilium` passes. Task 10 passed 40/40 and Task 7 33/33. Task 14 cut 12/12 established connections within 1 s, but only after the lab's Cilium configuration turned off the identity jitter and grace period. With Cilium's defaults the cuts took 10.1–32.5 s and the run failed. See [Cilium mode](#cilium-mode-tasks-7-10-and-14) below.

## Run it

```sh
make test-gvisor                                   # up, conformance, down (about 40 s)
make test-gvisor GVISOR_COLD_STARTS=100 GVISOR_OUT=<file.jsonl>   # plus 100 cold starts (about 6 min)

scripts/k3s_gvisor_lab.sh up                       # or keep a lab up between runs:
make test-gvisor GVISOR_REUSE=1
make test-identity IDENTITY_REUSE=1                # Task 7: control plane tokens, sandbox accounts
scripts/k3s_gvisor_lab.sh down                     # always do this at the end
scripts/k3s_gvisor_lab.sh purge                    # down, and remove the lab images

make test-gvisor GVISOR_LAB_FLAGS=--without-corpus  # the same, on a lab with no Task 5 corpus (below)
make test-gvisor GVISOR_LAB_FLAGS='--without-corpus --falco'  # and runsc reporting to the opt-in gVisor-engine instance (broken upstream)
scripts/k3s_gvisor_lab.sh up --without-corpus      # or: run --without-corpus <command>

make test-cilium                                   # Cilium mode: up --cilium, Tasks 7, 10, 14, down (about 8 min)
make test-cilium CILIUM_OUT=<dir> CILIUM_RUN=<regexp> WARDEN_CILIUM_REPS=<n>
scripts/k3s_gvisor_lab.sh up --cilium              # or keep a Cilium lab up:
make test-cilium CILIUM_REUSE=1
```

- **Prerequisites.** Docker and the pinned tools in `.tools/`. `scripts/restore-tools.sh k3s` and `scripts/restore-tools.sh gvisor` check sha256 pins. They copy from `.cache/warden-k3s-materials` when it exists and otherwise download the release files. Nothing is pulled from a registry. The node and pause images are built `FROM scratch`, and the probe image is the runc lab's (`scripts/build-probe-oci.py`).
- **The Task 5 corpus.** Since `f64269a`, `up` also builds the attack helper and the corpus image (`scripts/build-corpus-image.py`), imports the image into the node and exports the matrix paths (`WARDEN_MATRIX_*`) in `lab.env`; without a corpus image it stops with `corpus image missing`. That is still the default. `--without-corpus` (on `up` and `run`, with or without `--cilium`) skips all of it: nothing under `attacks/` is built or read, the node gets only the pause and probe images, and `lab.env` has `WARDEN_K3S_CORPUS=without` and no `WARDEN_MATRIX_*` lines. It mirrors the Firecracker lab's `prepare --without-corpus` (`37bcbe9`). The conformance and cold-start tests need nothing else; the matrix hooks at their end skip without `WARDEN_MATRIX_CORPUS`. RED/GREEN: [evidence/task-13/online-detector-20261113/tdd](evidence/task-13/online-detector-20261113/tdd/).
- **`--falco` (Task 13).** Opt-in and off by default, on `up` and `run`; broken upstream (falcosecurity/libs#3074), so the default detector covers gVisor at host level instead. With it the node's runsc gets the online detector's trace configuration (`detect/falco/gvisor-pod-init.json` as `pod-init-config`, also for `runsc-netstack` in Cilium mode), and the node mounts the detector's volume `warden-detect-gvisor` read-only at `/warden-detect`, where Falco's gVisor engine listens. `up` refuses unless the detector's opt-in gVisor-engine container runs (`make detect-up DETECT_GVISOR_ENGINE=1`); the lab never stops or removes the detector. `lab.env` says `WARDEN_K3S_FALCO=1`. Without the option nothing of this is in the node. Falco's gVisor engine currently exits at the first event (see [falco-detector.md](falco-detector.md#gvisor-what-is-blocked-and-the-options)); the sandboxes then run untraced and `TestGVisorConformance` still passes.
- **Skipped by default.** The live tests skip unless `WARDEN_LIVE_GVISOR=1` (`WARDEN_LIVE_IDENTITY=1` for Task 7's `runtimes/conformance/identity_test.go`, `WARDEN_LIVE_CILIUM=1` for `controlplane/internal/ciliumlab`). The make targets set it and export `.cache/k3s-gvisor/lab/lab.env`, which also names the API server's host (`WARDEN_GVISOR_API_HOST`) so `kindlab.ParseKubeconfigFor` accepts that one address. `TestGVisorColdStarts` also needs `WARDEN_GVISOR_COLD_STARTS=<n>`.
- **Firecracker.** The Firecracker lab guard refuses to run while any other `project=warden` container exists. Bring this lab down before a Firecracker run.
- **CPUs.** `WARDEN_LAB_CPUSET=<cpus>` pins every container the lab creates (`docker --cpuset-cpus`). On home-ubuntu the lab ran with `0-7,16-31` and `make` under `taskset -c 0-7,16-31`, because another project times benchmarks on CPUs 8–15.
- **What `run` removes.** Without `GVISOR_REUSE=1` or `IDENTITY_REUSE=1` the make targets go through `scripts/k3s_gvisor_lab.sh run`. It removes only the node container and the network that its own `up` created. If a lab is already up, `run` fails and leaves that lab alone. If the command passed and the teardown failed, `run` fails. `up` refuses, and `down` leaves in place, a `warden-k3s` network that is not Warden's (`up`: internal and labelled `project=warden`; `down`: labelled `project=warden`).

## The node

One container, `warden-k3s-gvisor`, runs the image `warden-k3s-gvisor:lab`, rebuilt on every `up`. It contains:
- k3s v1.36.5+k3s1;
- runsc and containerd-shim-runsc-v1 from gVisor release-20261019.0;
- the files in `runtimes/gvisor/lab/node/`;
- `warden-gvisor-init`, built from this tree and installed at `/opt/warden/gvisor-init` with mode 0555.

The pause image `warden-lab/pause:1` comes from `runtimes/gvisor/lab/pause`. Every node input is hashed into `node-manifest.txt`, and the sha256 of that file is the `NodeConfigSHA256` the gate binds.

**k3s server** (`config.yaml`):
- Off: traefik, servicelb, metrics-server, local-storage, CoreDNS, kube-proxy, the network policy controller and flannel.
- CNI is a plain bridge conflist (`10-warden.conflist`) using k3s's own plugins.
- The snapshotter is `native`.
- kubelet runs with `protect-kernel-defaults=true` and `pod-max-pids=1024`.

**runsc** (`runsc.toml`): `platform=systrap`, `network=none` (loopback only), `in-sandbox-cgroup=v2` (the cgroup2 view that the supervisor sets `pids.max` in) and `oci-seccomp=true` (the pod's `RuntimeDefault` profile is enforced inside the sandbox too). RuntimeClass `gvisor` uses handler `runsc`, and runs go in namespace `warden-lab`.

**Network.**
- The node sits on the `--internal` Docker network `warden-k3s`, with no route out and no published ports.
- k3s picks its node IP from the default route, and an internal network has none. So the node gets the fixed address `.10` in the subnet Docker assigns, plus `--node-ip`.
- The host reaches the API server at `https://<that address>:6443` with the kubeconfig in `.cache/k3s-gvisor/lab/kubeconfig` (mode 0600).

**Images.** The probe archive is imported with `ctr` and tagged `docker.io/warden-lab/probe:conformance` and `docker.io/warden-lab/probe@<digest>`, because CRI resolves only normalised names. Runs refer to the image by digest with `imagePullPolicy: Never`.

In the bridge mode flannel, kube-proxy, CoreDNS and the network policy controller are all off. The Cilium mode replaces the bridge CNI; see [Cilium mode](#cilium-mode-tasks-7-10-and-14).

## Privileged node, and what bounds it

The node container is `--privileged`, as kind's nodes are, because runsc and kubelet need mounts, namespaces and cgroup control. This is a wider boundary than the capless harness in [k3s-runtime-lab.md](k3s-runtime-lab.md) or the runc lab's fixed capability set. That capless harness did not get a Ready node (STATUS blocker 3), and this lab trades its boundary for a working one.

What bounds the node:
- private network, PID and cgroup namespaces (`--cgroupns=private`);
- no host bind mounts;
- `/lib/modules` is not mounted;
- 4 GiB memory (memory+swap), 4 CPUs and 4096 tasks;
- tmpfs on `/run`, `/var/run` and `/tmp`;
- kubelet's `protect-kernel-defaults`, so kubelet checks the global sysctls but never writes them.

A privileged container could still write global sysctls. So `up` and `down` record the protected sysctls and a hash of the loaded module list, and `down` fails if either changed (in the Cilium mode only a sysctl change fails it; see below). This is a check after the fact, not a prevention. In both Task 3 evidence runs nothing changed. The host's `fs.inotify.max_user_instances=512` and `max_user_watches=524288` appear in those snapshots. This task did not change them, and the node did not hit EMFILE.

## How a run works

**The Job** (`runtimes/gvisor/gvisor.go`). `Start` validates the spec, checks the kube-system, namespace and node UIDs against the bound identity, and POSTs one Job, `warden-run-<run id>`, with:
- `backoffLimit: 0`, `activeDeadlineSeconds` TimeoutS+60 and `ttlSecondsAfterFinished: 600`, the last two as backstops;
- `runtimeClassName: gvisor`, a nodeSelector, no service account token, no service links and a 1 s grace period;
- one container, image `Repository@digest`, command `/.warden/init -pids N -timeout-s N -- <cmd>`;
- the supervisor mounted read-only from the node's hostPath;
- requests = limits = CPU, and MemoryMiB+128 MiB memory;
- `readOnlyRootFilesystem`, all capabilities dropped except SETGID, SETPCAP, SETUID and SYS_ADMIN for the supervisor, and `seccompProfile: RuntimeDefault`;
- labels `warden.dev/run` and `warden.dev/network=none`.

`Network: allowlist` is refused.

**The supervisor** (`runtimes/gvisor/supervisor`) runs as PID 1 and root inside the sandbox. It:
1. moves itself to `init/`, enables `pids`, and creates the `workload` cgroup with `pids.max`;
2. starts the payload through a trampoline that joins that cgroup, takes a private mount namespace, remounts cgroupfs read-only, unmounts `/dev/termination-log`, drops all capabilities, switches to UID/GID 65534, sets RLIMIT_NOFILE 1024, closes inherited fds, installs `policies/seccomp/default.json` compiled to BPF, and calls `execve`;
3. enforces the timeout by killing the workload cgroup, and reaps;
4. writes a JSON report of at most 4096 bytes to the termination log: exit code, timed out, `pids.events` max, `pids.peak`, cgroup empty, and the init/exec timestamps.

**Wait** follows the Pod, keeps at most 1 MiB of logs (dropped bytes are counted) and parses the report strictly. The report's code must agree with the container's exit code. If there is no report, because the whole sandbox was killed (OOM), the exit comes from the pod status. At `activeDeadlineSeconds` the Job controller deletes the pod. kubelet then stops the supervisor with SIGTERM, and its report says `supervisor got terminated`; a supervisor that cannot report is just killed. The pod's status does not say why the pod stopped (its `reason` stays empty). The Job's condition does: FailureTarget, and later Failed, with reason `DeadlineExceeded`. So in these two cases Wait reads the Job, and a deadline gives an exit with `TimedOut` set. A pod deleted for any other reason keeps the SIGTERM report as an error. The API server serves the logs only while the pod exists, and on the lab the pod was gone right after it turned Failed, so the logs can be lost before Wait reads them. Wait then reads the Job too: at the deadline it still gives the exit with `TimedOut`, with `LogsTruncated` set and `DroppedLogBytes` 0 (the lost bytes are not counted); otherwise lost logs are an error. [job-deadline](evidence/task-3/review-fixes-20261110/job-deadline/README.md) has the order of events on the lab. Teardown is a foreground delete with a UID precondition. The first Wait starts following the run in the background, where it goes on whatever happens to that Wait, as the runc and Firecracker handles follow theirs. Each Wait returns the run's result or, if its own context ends first, that context's error at once; a context error is never kept as the result, so a later Wait still gets the exit. A caller that gives up on the run calls `Kill`, as the scheduler does; otherwise the run is torn down when it ends. The result is ready only after the teardown, on every path, also when following the run failed; the teardown has its own budget (`TeardownTimeout`, 60 s). Wait returns an exit only after the Job and the Pod objects are confirmed gone. Otherwise it returns an error, which also says if the teardown was not confirmed. Transient API errors (no answer, 429, 5xx) are retried for up to `APIRetry` (10 s) in a row. Wait also ends without an exit, without waiting for the container: after `Kill` it returns `ErrKilled`, but like every result only after the teardown, once Kill's is confirmed (if Kill's fails, after the one the tracking tries next), as runc's and Firecracker's Wait return only after their Kill's cleanup. Kill holds no lock of the handle while it deletes, so meanwhile a Wait's own context still ends that Wait and `Logs` answers ([m4b-wait-kill-20261113](evidence/task-3/m4b-wait-kill-20261113/README.md)). When the Job was deleted otherwise (`Reap`), or the Job controller gave up on it before its pod appeared (an admission rejection or a full quota ends at `activeDeadlineSeconds`), it returns an error that says so. kubelet removes the Pod object only after the pod's cgroup is gone. `TestGVisorConformance` checks that on the node for every run. [pod-cgroup-positive-control.txt](evidence/task-3/live-20261110/pod-cgroup-positive-control.txt) shows the same check finding running pods.

**Limits.**
- Memory is enforced only at the pod level, on the host cgroup. gVisor does not enforce `memory.max` inside the sandbox, so the sentry, gofer, supervisor and payload share MemoryMiB+128 MiB.
- pids are enforced inside the sandbox by gVisor's cgroup2.

## Cilium mode (Tasks 7, 10 and 14)

`scripts/k3s_gvisor_lab.sh up --cilium` builds the node image `warden-k3s-gvisor:cilium` and runs Cilium 1.20.4 as the cluster's CNI. `make test-cilium` runs the checks in `controlplane/internal/ciliumlab` on it. Evidence, with every run and what the lab did to the host: [evidence/task-10/cilium-lab-20261112](evidence/task-10/cilium-lab-20261112/README.md).

**Cilium.**
- The chart (`cilium-1.20.4.tgz`), helm v3.22.1 and every image come by digest from `scripts/restore-tools.sh helm` and `cilium`, into `.tools/`. The images are imported into the node with `ctr`, and pods use them with `pullPolicy: Never`. helm only renders the chart (`helm template`).
- Values: `runtimes/gvisor/lab/cilium/values.yaml`. They set kube-proxy replacement, native routing, BPF masquerade, `devices: [eth0, eth1]` and the L7 proxy, which the DNS rules need. Cilium installs its iptables rules; the 2026-11-10 attempt without them failed ([evidence](evidence/task-10/cilium-k3s-20261110/README.md)).
- From `5c436a8` the values also set `identityChangeGracePeriod: "0s"` and `identity-max-jitter: "0s"`, so a label change reaches policy at once (Task 14, below). The cost, not measurable on one node: every agent allocates identities at the same moment after a namespace label change, and an endpoint can use a new identity before other nodes know it, so their policy can drop its packets briefly.
- CoreDNS (`coredns.yaml`) answers only the lab's names: `allowed.warden.test`, `blocked.warden.test`, `stream.warden.test` and `metadata.google.internal`. It forwards `exfil.warden.test` to the DNS sink. Every other name is NXDOMAIN.

**Node changes.**
- PID 1 is `warden-node-init` (`runtimes/gvisor/lab/nodeinit`). It makes the node's mounts shared, because Cilium mounts bpffs with Bidirectional propagation. It then makes `/proc/sys` read-only except `/proc/sys/net`, and starts k3s.
- That did not cover the chart's own hostPath mounts of `/proc/sys/kernel`, which on 2026-11-12 let the agent change two host sysctls (below). Since `3681bc4` and `082cc71`, `readonly_proc_mounts.py` makes every mount of the node's `/proc` in the rendered chart read-only. `up` also stops if a protected sysctl changed by the time Cilium is ready, or if the agent's `/host/proc/sys/kernel` is not read-only.
- The node's own network namespace gets `net.ipv4.conf.all.src_valid_mark=0` (`e50da44`). It inherits the host's 1, and with 1 the reverse-path check dropped the packets that Cilium's TPROXY rules mark for its DNS proxy as martians.
- A second containerd handler, `runsc-netstack` (`runsc-netstack.toml`, `config-v3.toml.tmpl`), is `runsc.toml` with `network=sandbox`. It runs gVisor's netstack on the pod's veth, so Cilium's datapath sees and enforces the sandbox's traffic. RuntimeClass `gvisor-netstack` uses it, and the sandboxes in these tests carry `warden.dev/sandbox=true`. The Task 3 RuntimeClass `gvisor` (network=none) is unchanged.

**The world.** The node also joins `warden-k3s-world`, an `--internal` network in 198.18.0.0/15 (198.18.18.0/24 on 2026-11-13). The range is not RFC 1918, so Cilium treats it as world. Stand-ins run `world.py` read-only in `python:3.14.4-alpine`, which is pinned by digest and never pulled, with every capability dropped:
- `.20` is the allowed origin and `.21` the blocked origin;
- `.22` is the stream server Task 14 holds connections to;
- `.30` is the metadata stand-in, which puts 169.254.169.254 on its own loopback and keeps NET_ADMIN only for that; only the node routes 169.254.169.254/32 to it;
- `.40` is a DNS sink that logs every query.

Each stand-in's log says what reached it. The egress proxy is Envoy v1.40.2 in `warden-system/warden-egress`. It uses the bootstrap and listeners `controlplane/internal/scheduler` renders, with grants per sandbox source address.

**The checks** (`controlplane/internal/ciliumlab`, all against real gVisor sandboxes, each with a positive control):

| Test | Task | Result, `5c436a8`, fresh lab ([runs/09-all](evidence/task-10/cilium-lab-20261112/runs/09-all/run.log)) |
|---|---|---|
| `TestSandboxReachesOnlyTheEgressProxy` | 10: `default-deny.yaml` + `egress-proxy.yaml` | PASS 40/40. The allowed host is reachable through the proxy and a denied host gets the proxy's 403. Direct egress to the origins, the API server, the node and 169.254.169.254 times out. DNS TXT exfiltration through cluster DNS is REFUSED, and directly to the sink it times out; the sink logs nothing. Before the policies the same direct connections and both exfiltration paths get through (positive control), and under them a pod without the sandbox label still does. |
| `TestSandboxCannotReachMetadata` | 7: `deny-metadata.yaml` | PASS 33/33. Without the policy the sandbox gets the metadata stand-in's answer by address, by name and through the proxy. The proxy grant deliberately includes `metadata.google.internal`. With the policy all three fail and nothing else is blocked. Removing the policy restores all three. |
| `TestQuarantineCutsEstablishedConnections` | 14: `IsolatePod` + `quarantine.yaml` | PASS, 12/12 established connections cut within 1 s: alert → last line p50 318.0 ms and p95 356.0 ms, by nearest rank. The control stream's longest gap was 298.9 ms. With Cilium's default identity settings it was **FAIL**: 0/12 within 1 s, p50 24232.0 ms, p95 32452.4 ms ([runs/08](evidence/task-10/cilium-lab-20261112/runs/08-task14/run.log)). Details: [time-to-contain.md](evidence/time-to-contain.md#isolatepod-在-cilium-上已建立的连接k3s--gvisor-lab2026-11-13). |

**What the Cilium mode does to the host.**
- **Modules.** Cilium makes the host kernel load modules, which the user allowed on 2026-11-11. In this mode `down` reports the modules that appeared instead of failing; it still fails on a sysctl change. `up` lists the modules at each stage (`modules-before.txt`, `modules-at-node-registered.txt`, `modules-at-cilium-ready.txt`, `modules-at-up.txt`, and `modules-after.txt` at `down`). Warden's Cilium labs loaded 10 modules, and they stay loaded until someone unloads them:
  - 2026-11-10: `geneve`, `xt_socket`, `nf_socket_ipv4`, `nf_socket_ipv6`;
  - 2026-11-12: `cls_bpf`, `sch_ingress`, `xt_TPROXY`, `nf_tproxy_ipv4`, `nf_tproxy_ipv6`, `xt_CT`.

  The user can unload them with `sudo modprobe -r xt_TPROXY xt_socket xt_CT cls_bpf sch_ingress geneve`, which also unloads the four `nf_*` dependencies once nothing uses them. How they were told apart from the host's other activity: [modules-attribution.txt](evidence/task-10/cilium-lab-20261112/modules-attribution.txt).
- **Sysctls.** The first run on 2026-11-12, before the read-only mounts above, changed `kernel.timer_migration` 1→0 and `kernel.unprivileged_bpf_disabled` 2→1 on the host. Restoring them needs root: `sudo sysctl -w kernel.timer_migration=1`. `unprivileged_bpf_disabled` cannot go back from 1 without a reboot. Later runs changed no sysctl; the full sysctl dump differed only in counters.

## Files

| Path | What |
|---|---|
| `scripts/k3s_gvisor_lab.sh` | `up`, `down`, `status`, `purge`, `env <cmd>`, `run <cmd>` |
| `runtimes/gvisor/lab/node/` | Dockerfile and every config the node image contains |
| `runtimes/gvisor/lab/pause/` | the pause binary |
| `runtimes/gvisor/lab_test.go` | `TestGVisorConformance`, `TestGVisorColdStarts` |
| `runtimes/gvisor/lab/cilium/` | Cilium mode: Helm values, CoreDNS, the `runsc-netstack` handler, `readonly_proc_mounts.py`, the stand-ins (`world.py`) |
| `runtimes/gvisor/lab/nodeinit/` | `warden-node-init`, PID 1 of the Cilium-mode node |
| `controlplane/internal/ciliumlab/` | Tasks 7, 10, 14 on the Cilium mode (`make test-cilium`) and their offline parsers |
| `policies/cilium/` | the policies those tests apply |
| `.cache/k3s-gvisor/lab/` | kubeconfig, `lab.env`, `node-manifest.txt`, host snapshots, module lists (state, not committed) |
