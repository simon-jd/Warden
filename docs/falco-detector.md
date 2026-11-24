# Online detector (Task 13): Falco on home-ubuntu

Status 2026-11-14 UTC, branch `detect-online`: built and smoke-tested. Results: [evidence/task-13/online-detector-20261113](evidence/task-13/online-detector-20261113/README.md).

Status 2026-11-24 UTC, branch `seven-day-window`: **the seven-day window ran** from 2026-11-16 06:22:36 to 2026-11-23 06:22:36 UTC (CPUs 0-7). 168 of 168 hourly slices healthy, no drops, the benign workload passed 177 of 177 runs on runc and on gVisor; 293,549 alerts kept, reviewed per group: 293,372 false positives (the labs' own infrastructure: gVisor's runsc 276,549, k3s 16,823), 177 true positives (the conformance probe's `ptrace(PTRACE_TRACEME)`), 0 unreviewed; `observation.py`: eligible. Reloads of the user systemd manager by other software kept pushing the stop timer back, and the stop was run by hand 22 h 45 min after the end (outside the window, not counted). [Evidence](evidence/task-13/seven-day-20261116/README.md).

What the user decided on 2026-11-13:
- Falco from images pinned by digest; the host instance with the modern eBPF probe in a privileged container.
- Only alerts of Warden containers may reach a disk; everything else is only counted.
- Stock rules at the pinned version, untuned; the noise they make on Warden's own labs is handled by a bulk review, not by tuning.
- **gVisor is covered at host level only.** The host instance sees runsc's sentry and gofer and the k3s node's processes; the system calls inside a sandbox are not covered, as Firecracker's guests are not. What the smoke shows on gVisor is that the host sees a sandbox start (runsc's normal start-up); that is not a detection of anything a run does, and it is kept apart from the scored alerts ([below](#only-wardens-alerts-reach-a-disk)). The gVisor-engine instance and the lab's runsc trace mode stay as opt-ins, off by default, because Falco's gVisor engine is broken upstream ([below](#the-opt-in-gvisor-engine-broken-upstream)).
- The seven-day window starts only after all other work is done.

Status 2026-11-14 UTC, branch `task13-stratus`: the Kubernetes audit path (the k8saudit instance, the kind audit lab, the audit importer) is built and smoke-tested with one benign execution ([below](#the-kubernetes-audit-path-k8saudit-instance-and-kind-audit-lab), [evidence](evidence/task-13/k8saudit-smoke-20261114/README.md)). Status 2026-11-16 UTC: the Stratus round ran all 40 runs on the third attempt (2026-11-15, the user's wrapper at `2533736`) and is scored: 25 of 35 successful runs detected under the widest k8saudit map, p50 3.242 s / p95 3.729 s ([evidence](evidence/task-13/stratus-20261114/README.md)). Attempt 1 stopped after 2 runs on the separate cleanup's return code ([evidence](evidence/task-13/stratus-20261114/attempt-1/README.md)), attempt 2 after 3 runs on a Terraform provider without a kubeconfig ([evidence](evidence/task-13/stratus-20261114/attempt-2/README.md)); both are kept as their own records ([below](#what-the-wrappers-runs-depend-on-read-only)).

## Run it

```sh
make detect-up            # the host instance and its collector (needs .tools/falco: scripts/restore-tools.sh falco)
make detect-status        # container, collector, last heartbeat and counts, seven-day timers
make detect-down          # stop and remove them; compares the host's modules and sysctls with up's
make detect-purge         # down, then remove the images, the socket volume and the FIFOs (data is kept)

make detect-smoke DETECT_OUT=<dir>   # up, the smoke actions on runc and gVisor, down, report (about 1 minute)

make detect-seven-day-start                    # a dry run: prints what the start would do, changes nothing
make detect-seven-day-start CONFIRM=seven-day  # THE START OF THE SEVEN-DAY WINDOW (see below); run once, 2026-11-16

make detect-up DETECT_GVISOR_ENGINE=1          # opt-in: also the gVisor-engine instance (exits at its first event)
make kind-audit-up                             # the kind audit lab (below); make kind-audit-status, make kind-audit-down
make detect-up DETECT_K8SAUDIT=1               # opt-in: also the k8saudit instance, which reads that lab's API audit log
scripts/k3s_gvisor_lab.sh up --without-corpus --falco   # opt-in: a lab whose runsc reports to that instance
```

Anything but `CONFIRM=seven-day`, or any `DRY_RUN` value, makes `detect-seven-day-start` a dry run.

Everything runs on CPUs 0-7,16-31: the make targets use `taskset`, the Falco containers have `--cpuset-cpus 0-7,16-31`, and the labs get `WARDEN_LAB_CPUSET`. `WARDEN_CPUSET=<cpu list>` (a make variable, or the environment of `detector.py`) moves all of it to other CPUs; the seven-day timers carry it with `--setenv`, and `seven-day.json` records it as `cpuset`. The eBPF probe itself runs in the kernel on whichever CPU makes a system call, so it also adds a little work to every system call on CPUs 8-15 (see [Limits](#limits)).

## The instances

| | host (the detector) | gvisor (opt-in, broken upstream) |
|---|---|---|
| Falco | 0.45.2, `docker.io/falcosecurity/falco:0.45.2@sha256:1562a643…698e`, run as image ID `sha256:27a94a28…e102` | 0.43.1, `docker.io/falcosecurity/falco:0.43.1@sha256:b4166a61…55e3`, run as `sha256:9f3e058c…8a31` |
| Why this version | Falco 0.43.1's modern probe does not load on this kernel (7.0): the verifier rejects `signal_deliver` ([log](evidence/task-13/online-detector-20261113/version/falco-0.43.1-modern-ebpf.log)). 0.45.2 loads. | 0.44.0 dropped the gVisor engine; 0.43.1 is the last release that has it (deprecated there). |
| Engine | `modern_ebpf`, stock buffer settings (8 MiB per 2 CPUs), no kernel module | `gvisor` (exits at the first event: libs#3074): listens on `/warden-detect/gvisor.sock` in the Docker volume `warden-detect-gvisor`; `runsc` (the lab's, `.tools/gvisor`) mounted read-only for the engine's `runsc --version`/`list` |
| Container | `warden-detect-falco-host`: `--privileged`, `--network none`, read-only root, 1 GiB memory = memory+swap, 512 pids; mounts `/proc` (ro), the Docker socket (ro, for the stock container plugin's metadata), `/sys/kernel/tracing` (ro, for the probe's TOCTOU programs) | `warden-detect-falco-gvisor`: not privileged, `--cap-drop ALL`, `no-new-privileges`, `--network none`, read-only root, 512 MiB, 256 pids, `--group-add` the user's group for the FIFO |
| Rules | the image's `/etc/falco/falco_rules.yaml` (sha256 `30a1a602…865b`) | the image's (sha256 `f355cf51…95a6`) |

Both rule files have the same 25 rules; 0.45.2's adds a few exceptions to existing rules. The rules files are not mounted over or added to. Warden's settings are two files under `/etc/falco/config.d/`: [`falco-common.yaml`](../detect/falco/falco-common.yaml) and the engine file ([host](../detect/falco/falco-host.yaml), [gvisor](../detect/falco/falco-gvisor.yaml)).

Every container, volume and image the detector creates carries `owner=warden-lab` and `warden.detect/role=falco`, and the detector stops and removes only objects with those labels. The Falco containers do **not** carry `project=warden`: the runc lab refuses to start next to any `project=warden` container, and the hourly benign workload has to run it while Falco runs. Each container's log is `json-file`, 10 MiB × 3, and holds only Falco's own messages.

## Only Warden's alerts reach a disk

Falco's only enabled output is `file_output` into a FIFO, `.cache/detect/run/<instance>/alerts.fifo` (stdout, syslog, HTTP, program output, the web server and captures are off; [config](../detect/falco/falco-common.yaml)). A FIFO keeps nothing on disk. [`collector.py`](../detect/falco/collector.py) reads it and, for each line:

- Falco's own events (`source: internal`: the minute's metrics snapshot, drop notices) go to `health.jsonl` unchanged;
- an alert whose `container.id` is a **Warden container** goes to `alerts.jsonl` byte for byte as Falco wrote it, and the decision, with the container's class, to `scoping.jsonl`. `alerts.jsonl` is what is scored against runs (`alert_import.py`);
- **runsc's start-up signature** goes to `platform-alerts.jsonl` instead, with class `platform`: "PTRACE attached to process" from `gvisor_sentry` in a Warden pod's sandbox cgroup. Every gVisor sandbox raises it at start (the systrap platform attaches to its stub processes), so it says nothing about the run; it is kept and reviewed, but never scored. Any other alert from a sandbox cgroup (say, a shell a compromised sentry started on the host) stays a run alert;
- everything else is counted and dropped: alerts of host processes (`dropped_host`), of other containers (`dropped_other_container`; of those, `dropped_other_lab_owned` are lab-owned containers that are not Warden workloads, such as the smoke's control, `dropped_other_lab_pod` are lab pods outside `warden-lab`, and `dropped_other_nested` are cgroups nested in a container that is not Warden's, below), of containers no resolver knew within 20 s (`dropped_unresolved`), lines that are not Falco events (`dropped_malformed`), and lines the collector's queue could not take (`dropped_overflow`). No byte of them is written; only the counters, in the heartbeats.

A Warden container, and its class:
- a Docker container labelled `project=warden`: **sandbox** if it carries a run (`warden.dev/run`, or the runc and Firecracker labs' `session`), **node** if it is the k3s node `warden-k3s-gvisor`, **lab** otherwise (the Cilium mode's stand-ins);
- a container of a pod in the k3s lab's namespace `warden-lab` with the label `warden.dev/run`: **sandbox**;
- a cgroup nested inside a running Warden container's. This is how runsc's sentry shows up: it runs in the k3s node's pod-sandbox cgroup, whose ID no API lists, and Falco reports that ID. **The pod decides first**: the cgroup's pod (from the `pod<uid>` component of its path) must be a `warden-lab` pod with `warden.dev/run` (sandbox); any other pod's cgroup is not Warden's, although it runs in the Warden node (the smoke's control pod). A cgroup of the node in no pod is the node's own infrastructure (node).

Not Warden's: a cgroup nested inside a running container that is not Warden's, if no Warden container has it. These are the pods of a kind node: the kind audit lab's `warden-lab-control-plane`, or another project's permanent kind node. Their containerd IDs are known to no API the collector asks, and they used to be dropped as unresolved, which made every slice with one unhealthy. Now they are another container's (`dropped_other_container`, and `dropped_other_nested`): counted, never kept, not a drop. A Warden container's nested cgroup keeps its rules: the pod decides first, then the node; one whose pod is not listed yet is retried, never another's.

A line is never lost silently. If its container's lookup fails (a Docker HTTP error, a socket timeout) or a write fails, the line is kept for the next pass and the error counted (`collector_errors`); past 20 s it is dropped and counted (`dropped_unresolved`, or `dropped_error` after an error), which makes its slice of the ledger unhealthy. Each pass handles every pending line on its own, and writes are idempotent per alert (also after a restart), so a failure never writes an alert twice.

`owner=warden-lab` alone does not make a container Warden's. The collector asks Docker through its socket; for a container that has gone (the runc lab removes its outer container right after the run) it uses the Docker start event it recorded. It polls the lab's pods every second through the API server in `.cache/k3s-gvisor/lab/kubeconfig` (reloaded on every lab `up`) and records each pod's sandbox cgroup while it exists, so an alert processed after a three-second gVisor run has gone is still placed. Alerts of a container already being looked up wait with it, and a container is looked up once per pass.

Every 30 s (and at once on `SIGUSR1`) it writes a heartbeat: the Falco container's state as Docker reports it (running, `StartedAt`, restart count, OOM kill) and its counters. An error in one step is counted (`collector_errors`) and the loop goes on. If its FIFO reader dies it exits non-zero and systemd restarts it (`Restart=on-failure`, 2 s); the new start counts itself in `collector_restarts`, and the recorder marks any record that spans a restart unhealthy. `registry.jsonl` records Warden containers' lifetimes: Docker `start`/`die` events, and the lab's Warden pods with their container and sandbox IDs.

The collector runs as a transient systemd user unit (`warden-detect-collector-host`) under `taskset`. It prints only start/stop lines and totals to the journal. Its files are in `.cache/detect/data/<session>/host/`, mode 0600 in 0700 directories.

## The container ID Falco reports, and bindings

[`bindings.py`](../detect/falco/bindings.py) turns the registry into the trusted bindings `alert_import.py` reads (`{execution_id, run_id, container_id, start, end}`), with the full ID of the container the host instance reports:

- **runc**: the Docker container. Falco's container plugin takes the `docker-<id>.scope` component of the process's cgroup. For a runc lab run the Warden runc driver's sandboxes are cgroups *below* the lab's outer container, so Falco reports the outer container; for a container Docker runs with runc, that container. `start`/`end` are Docker's `start` and `die` events (nanoseconds). A runc lab container runs all of its tests; give each Warden run its own `--start/--end` inside the container's lifetime.
- **gVisor**: the pod **sandbox**'s containerd ID, where runsc's sentry and gofer run. The sandbox lives longer than the pod's container, so the binding runs from the pod's `creationTimestamp` to the later of one second after the container's `finishedAt` (the API has whole seconds) and when the collector saw the pod gone. The ID is unique to the run's pod, so its whole life cannot take in another run's events. (`--gvisor-engine` gives the opt-in engine's binding: the pod container's own ID.)

```sh
python3 -I -B detect/falco/bindings.py --registry .cache/detect/data/<session>/host/registry.jsonl \
  --run-id <run> --execution-id <exec> >> bindings.jsonl
```

## Health records for the seven-day ledger

[`recorder.py`](../detect/falco/recorder.py) writes the records [`observation.py`](../detect/report/observation.py) reads, for the one source `falco-host`. It cuts the window into one-hour slices and each record is one slice exactly: its end is the next one's start, the first starts at the window's start and the last ends at its end, so a complete week leaves no gap. A slice is substantiated by the heartbeats that bracket it (the last at or before its start, the first at or after its end). It is healthy only if both exist and, between them, heartbeats are never more than 90 s apart, all saw the same running Falco container (no restart, no OOM) and come from one collector start, the collector's `collector_errors` and `collector_restarts` did not grow (an error or a restart may have cost an alert even with nothing counted as dropped), every metrics snapshot has the event and drop counters and the same `falco.start_ts`, and snapshots are never more than 150 s apart.

- `event_count`: Falco's event counter increase over the slice (5.7 million in the benign test's two minutes).
- `dropped_events`: Falco's `scap.n_drops`, `falco.outputs_queue_num_drops` and `falco.n_drops_full_threadtable` increases, its "syscall event drop" notices (threshold 0: any drop), and the collector's `dropped_unresolved`, `dropped_error`, `dropped_overflow` and `dropped_malformed` (an alert the collector could not place may have been Warden's).
- `workload_count`: complete benign hours in the slice: the hourly workload must succeed on runc **and** on gVisor, so it is the fewer of the two runtimes' successful runs. `explain.jsonl` has both counts.
- `receipt`: the sha256 of the exact heartbeat, snapshot and workload lines used.

For the window to be coverable from its first nanosecond, it starts at the **first healthy point**: after `up`, the detector waits for Falco's first metrics snapshot that shows it counting events, makes the collector write a heartbeat (`SIGUSR1`), and that heartbeat's time is the window's start. The end is exactly seven days later. The stop comes 15 minutes after that, so later heartbeats bracket the last slice, and it flushes one more heartbeat before Falco stops. A simulated healthy week through `recorder.py` and `observation.py` is eligible, and one real gap, one hour without a workload, or one hour whose gVisor run failed makes it ineligible (`detect/falco/test_recorder.py`).

## Normal alerts and the bulk review

The stock rules fire on Warden's labs themselves, and these alerts are kept (they are Warden containers'). In the benign test's hour (runc and gVisor conformance runs) that was 1,673 alerts in 17 groups:
- "PTRACE attached to process" from `gvisor_sentry`, class platform (in `platform-alerts.jsonl`): 1,575 (runsc's systrap platform attaches to its stub processes with ptrace; seven sandboxes);
- "Drop and execute new binary in container", class node: 97 in 15 groups, one per process (kubectl, ctr, bridge, …): k3s unpacks its binaries into the container's writable layer at start and runs them;
- "PTRACE anti-debug attempt" from `warden-probe`, class sandbox: one (the runc conformance's seccomp probe calls `ptrace(PTRACE_TRACEME)`, which seccomp denies).

That is roughly 280,000 alerts in seven days in about 20 groups (the window of 2026-11-16 kept 293,549 in 17 groups). [`review.py`](../detect/falco/review.py) makes that a review of groups, not of alerts:

```sh
python3 -I -B detect/falco/review.py groups --alerts <data>/host/alerts.jsonl --alerts <data>/host/platform-alerts.jsonl --scoping <data>/host/scoping.jsonl \
  --out groups.jsonl --template map.jsonl          # one line per (rule, process, class), with counts
# a person edits map.jsonl: each line's disposition false_positive, true_positive or unreviewed
python3 -I -B detect/falco/review.py apply --alerts ... --scoping ... --map map.jsonl \
  --start <window start> --end <window end> --out normal-alerts.jsonl --report report.json
python3 -E -s -B -m detect.report.observation --coverage coverage.jsonl --normal-alerts normal-alerts.jsonl \
  --source falco-host --start <window start> --end <window end> --observed-until <cutoff>
```

The metrics reader (`detection_metrics.read_jsonl`, used by `observation.py` and the alert importers) takes up to 256 MiB and 1,000,000 records per file (it was 16 MiB and 100,000, too small for one week). The template's dispositions are all `unreviewed`; the tool never decides one. An alert of a group the map does not name stays `unreviewed` (and `observation.py` then gives no false-positive count). The report gives each group's count and false positives, the totals, and any map line that matched no group.

## The hourly benign workload

[`benign.py`](../detect/falco/benign.py) runs the conformance suite's seven probes (`runtimes/conformance`) through the real drivers, one runtime after the other: the runc lab (`scripts/runtime_lab_docker.py run`, told Falco's 1 GiB in `--other-service-memory-bytes`), then `make test-gvisor GVISOR_LAB_FLAGS=--without-corpus` (the lab is up only for that run). Each run is under `taskset -c 0-7,16-31` with `WARDEN_LAB_CPUSET=0-7,16-31` and appends one record to `workloads.jsonl`; `ok` means exit 0 and the suite's PASS line. A run that reaches its timeout (20 and 30 minutes) gets SIGTERM so its own cleanup runs, SIGKILL a minute later, and then its lab is taken down, but only this worktree's: the k3s lab's `down` only if the node carries this worktree's `warden.lab/root` label (the lab script now sets it), and runc lab containers only if they bind this worktree's `.cache/warden-lab`. Another worktree's lab is left alone. The same happens to the run in progress when the unit's `RuntimeMaxSec` (50 minutes) stops `benign.py`. A run that cannot start (detector down, previous run still going) is recorded as not ok, so its hour has no workload.

## The seven-day start

Run once, 2026-11-16 to 2026-11-23 UTC ([evidence](evidence/task-13/seven-day-20261116/README.md)). `make detect-seven-day-start CONFIRM=seven-day` (`detector.py seven-day-start --confirm seven-day`) will:

1. refuse if the detector is up, any `project=warden` container or any node of the kind audit lab exists (kind's label `io.x-k8s.kind.cluster=warden-lab`, or a name `warden-lab-control-plane*`/`warden-lab-worker*`), or its timers are already active;
2. build the runc lab's inputs (`scripts/build-runtime-lab.sh`) and make the paths the runc lab checks unwritable by group and others (`chmod go-w`, as [runtime-lab.md](runtime-lab.md) says);
3. `up` (the host instance; a new session; the host's modules and sysctls are recorded);
4. start the window at the first healthy point (above) and write `.cache/detect/state/seven-day.json`: window start, end = start + 7 days, source `falco-host`;
5. arm two transient systemd user timers: `warden-detect-benign` (first run 2 minutes after the start, then hourly after each run's start) and `warden-detect-seven-day-stop` (7 days + 15 minutes after the start). If the second cannot be armed, the first is stopped and the detector taken down again.

`detector.py seven-day-stop` (the second timer; or by hand) stops the benign timer, waits for a running workload, flushes a heartbeat, runs `down` and takes down any lab a benign run left. Whatever of that fails, it then writes to `.cache/detect/data/<session>/seven-day/`: `coverage.jsonl` (with `explain.jsonl`: why a record is unhealthy), `review-groups.jsonl` and `review-map-template.jsonl`, every kept alert in the window as `normal-alerts-unreviewed.jsonl`, and `observation.py`'s result on them; the failures are reported at the end. The false-positive count comes after a person fills in the map and runs `review.py apply` and `observation.py`.

Before starting:
- nothing else of Warden may run for seven days (the runc lab refuses next to another Warden lab container, and any lab run is in the window);
- the host must not sleep, reboot or restart Docker: the transient units and the container do not come back, and the gap makes the window ineligible;
- the user's Task 5/13 emulations would land in the window as alerts; keep them out of it;
- a reload of the user's systemd manager (`systemctl --user daemon-reload`, which other software on the host runs) re-bases a waiting timer's `OnActiveSec` on the reload: in the 2026-11-16 window 35 reloads gave 20 early benign runs per runtime and kept moving the stop, which ended almost seven days late, so it was run by hand. Check `make detect-status` near the end; a future window should arm the stop on an absolute calendar time.

## The opt-in gVisor engine (broken upstream)

`make detect-up DETECT_GVISOR_ENGINE=1` adds the gVisor-engine instance, and `scripts/k3s_gvisor_lab.sh up --falco` makes the lab's runsc send it trace events (`detect/falco/gvisor-pod-init.json`, generated by the pinned 0.43.1 with `--gvisor-generate-config=/warden-detect/gvisor.sock`). It is not part of the default detector or the seven-day ledger, because Falco's gVisor engine does not survive the lab's runsc (release-20261019.0), as the committed runs show ([gvisor-engine-crash/](evidence/task-13/online-detector-20261113/version/gvisor-engine-crash/)):
- Falco 0.43.1 with the generated trace configuration: each log names the probe pod's sandbox (the ID `crictl` gives in the log's header) as a container, then Falco stops with `Error: vector` and exit code 1;
- Falco 0.42.1 (fetched by digest for this test, then removed): the same;
- Falco 0.43.1 with the `container/start` trace point removed (the code path libs#3074 names; that configuration is committed): the same.

This is the open upstream bug [falcosecurity/libs#3074](https://github.com/falcosecurity/libs/issues/3074) (filed 2026-08-04 against 0.42.1); 0.44.0 removed the engine. With `ignore_setup_error: true` the sandboxes keep running untraced. The engine also fills no terminal for any event (libs 0.23.2 `parsers.cpp`), so even a working engine would not raise "Terminal shell in container" for `kubectl exec -it`.

## The Kubernetes audit path (k8saudit instance and kind audit lab)

For Task 13's Stratus round on kind. A system call sensor cannot see a Kubernetes API request, so a second Falco instance reads the API server's audit log of a dedicated kind cluster. The seven-day window does not use it: its only source stays `falco-host`.

```sh
scripts/restore-tools.sh falco-k8saudit   # the plugins and rules (make detect-up DETECT_K8SAUDIT=1 does it too)
scripts/restore-tools.sh stratus          # Stratus, its Terraform and providers, the pod image (make kind-audit-up does it too)
make kind-audit-up
make detect-up DETECT_K8SAUDIT=1
make detect-status                         # both instances, their collectors and counts
# ... runs (attacks/stratus/run.sh), each with its own --out ...
# (the round's driver: docs/evidence/task-13/stratus-20261114/drive.py start | runs | end, then collect after detect-down)
make detect-down
make kind-audit-down
python3 -E -s -B -m detect.report.audit_alert_import --falco .cache/detect/data/<session>/k8saudit/alerts.jsonl \
  --receipt <run 1>/receipt.json --receipt <run 2>/receipt.json ... \
  --expected-rules <map>.jsonl --out <new alerts>.jsonl --provenance <new provenance>.jsonl
```

### The lab

`scripts/kind_lab.sh up --audit` (`make kind-audit-up`) creates the kind cluster `warden-lab`: one node, `warden-lab-control-plane`, node image `kindest/node:v1.34.11@sha256:44e222ee…d67d`, on its own Docker network `warden-kind-lab`, beside the live tests' `warden-respond`, which it leaves alone.
- **CPUs.** kind has no cpuset option: the node container gets `docker update --cpuset-cpus 0-7,16-31` (`WARDEN_LAB_CPUSET`) as soon as Docker has it, and `up` fails if `HostConfig.CpusetCpus` is not that afterwards. Its pods are cgroups inside it, so they stay there too.
- **Audit logging.** kube-apiserver gets `--audit-policy-file`, `--audit-log-path /var/log/kubernetes/audit/audit.log`, `--audit-log-format json`, `--audit-log-mode blocking` and `--audit-log-maxsize 1024`. Blocking means each event is written before the request returns: the API server neither batches nor buffers. The log directory is bind-mounted from `.cache/kind-warden-lab/audit/`, and `up` creates `audit.log` there as this user before the cluster starts: the API server (root in the node) appends to an existing file and keeps its owner and mode, so the collector reads it without root. An earlier lab's log is renamed, never overwritten. 1024 MB is more than a session writes, so the log never rotates in one.
- **Policy** ([k8s-audit-policy.yaml](../detect/falco/k8s-audit-policy.yaml)). Every request at ResponseComplete, and long-running ones (exec) also at ResponseStarted, which "Attach/Exec Pod" reads; RequestReceived is left out. Request bodies are logged, because the stock rules read `requestObject`. Metadata only for secrets, config maps, token requests (`serviceaccounts/token`), token reviews and CSRs, so no token, key or secret value reaches the log, and for node and pod status, events and leases. No response bodies: a token request's response is the token.
- **For the wrapper.** `up` exports the JSON kubeconfig `.cache/kind-warden-lab/kubeconfig.json`, mode 0600 (`kubectl config view --raw --minify -o json`: one context, cluster and user, all `kind-warden-lab`, server `https://127.0.0.1:<port>`, embedded CA, client certificate and key). It also creates the namespace `warden-lab`, labelled `project=warden` and `owner=warden-lab`, and waits until it is Active. `attacks/stratus/emulate.py`'s `guard_kubeconfig`, `guard_nodes` and `guard_namespace` pass against it (the smoke ran them). The kubeconfig holds the lab's admin credentials: keep it out of evidence.
- **Pod image.** busybox 1.37.0 from `.tools/stratus/images` (pinned by digest) is loaded and also named by its linux/amd64 manifest digest. Pass `--pod-image docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4` to the wrapper, and pods start without a pull; any other image is pulled from its registry (the node has a route out).
- `status --audit`: the node, its cpuset, the network, the namespace and the log. `down --audit` deletes the cluster, its network, both kubeconfigs and the generated configuration, and keeps only the audit logs.

### The k8saudit instance

| | k8saudit (opt-in) |
|---|---|
| Falco | 0.45.2, the host instance's image (`sha256:27a94a28…e102`) |
| Plugins | k8saudit 0.18.0 (`libk8saudit.so` `4c28b1bd…81acd`) and json 0.7.4 (`libjson.so` `4009cbf7…8c78c5`), from download.falco.org's release archives (byte for byte the linux/amd64 layers of the `ghcr.io/falcosecurity/plugins` artifacts); `detector.py` checks both and the rules before `up` |
| Rules | the stock `k8s_audit_rules.yaml` at tag `plugins/k8saudit/v0.18.0`, commit `43ec9491…`, sha256 `fa53280e…01a1e`, unchanged, given with `-r`; 48 rules |
| Engine | `nodriver`, `--enable-source k8s_audit`: no system call source, no kernel probe |
| Container | `warden-detect-falco-k8saudit`: `--cap-drop ALL`, `no-new-privileges`, `--network none`, read-only root, 512 MiB, 256 pids, CPUs 0-7,16-31, `--group-add` the user's group for the FIFOs; `config.d` is an empty tmpfs that holds only `falco-common.yaml` and [`falco-k8saudit.yaml`](../detect/falco/falco-k8saudit.yaml), so the image's container plugin is not loaded |

- **Feed.** The plugin reads a path, not a URL, and the instance has no network, so there is no audit webhook. [`audit_collector.py`](../detect/falco/audit_collector.py) (unit `warden-detect-collector-k8saudit`) follows `audit.log` from its size at start, polling every 10 ms, and writes each complete line into the FIFO `.cache/detect/run/k8saudit/audit.fifo`, which the plugin reads as a file. A partial line waits for its newline. A line of 64 KiB or more is not forwarded: the plugin's reader stops at the first longer line, which would end the source. It is counted (`audit_oversize`) and listed in `oversize.jsonl`. `feed.jsonl` records each forwarded line (auditID, stage, stageTimestamp, offset, length, `fed_at`). A log that shrinks or is replaced counts `audit_truncations`.
- **Output.** As for the host instance: `file_output` into `alerts.fifo`, read by the same collector. Every alert is kept (the instance reads only the lab's log): `alerts.jsonl` byte for byte, and `arrivals.jsonl` with each alert's canonical SHA256, `read_at` and `written_at` (after the flush). Falco's metrics snapshots go to `health.jsonl`, heartbeats every 30 s (and on SIGUSR1) to `heartbeats.jsonl`, with the feed's position.
- **Appended fields.** `append_output` adds to every k8s_audit alert's `output_fields` the target namespace, the request body's run labels `warden.dev/run` and `warden_run_id`, `ka.auditid` and `ka.useragent`. `extra_fields` leave the rules, their conditions and their output text as they are.
- **`useAsync: false`.** In a probe on a throwaway lab (2026-11-14), with the plugin's default asynchronous extraction, alerts reached the collector 0.32 to 1.16 s after their line was fed (8 alerts); without it, 10 to 31 ms (6 alerts), about the plugin SDK's 30 ms batch timeout. That probe's outputs were not kept. The smoke, run with it off, measured 11 to 31 ms.
- **Health** (`audit_collector.coverage`, records in the ledger's format for source `falco-k8saudit`). A slice is healthy only if:
  - heartbeats bracket it, never more than 90 s apart;
  - they show one running Falco container (no restart, no OOM kill), one collector start, and the feed writing into the open FIFO;
  - `collector_errors`, `collector_restarts` and `feed_reader_gone` do not grow;
  - metrics snapshots are never more than 150 s apart;
  - at every snapshot, Falco's `falco.num_evts` is at most the lines fed by then and at least the lines fed two seconds before.

  `dropped_events` is the growth of `audit_oversize`, `audit_truncations` and the malformed, other-source and overflow counters, plus `falco.outputs_queue_num_drops`. At `down`, Falco stops first and the feed's next write fails: that is the one `feed_reader_gone`, after the cutoff.
- **Latency path.** The API server writes the event; the feed reads it within 10 ms; the plugin delivers it within its 30 ms batch timeout; Falco writes the alert; the collector stamps it. In the smoke, audit event to feed took 2 to 9 ms and feed to `alerts.jsonl` 11 to 31 ms. Falco's `time` for a k8s_audit alert is the audit event's `stageTimestamp` (the plugin sets it), so "audit event time" and "Falco alert time" are one value. The measurable later points are `fed_at` and `written_at`.

### Scoring: the run record and attribution

[`detect/report/audit_alert_import.py`](../detect/report/audit_alert_import.py) writes the format `detection_metrics.py` reads, as `alert_import.py` does. Its run records come from the files the wrapper (`attacks/stratus/emulate.py`, `795c5db`) writes in each run's new `--out` directory:
- `receipt.json`, one JSON object: `run_id` = `execution_id` (`stratus-<correlation_id>`), `started_at` and `finished_at` (RFC3339 UTC with an explicit offset, as `utc_now()` writes them), `namespace` (`warden-lab`), plus `technique`, `returncode`, `cleanup_returncode`, `pod_image`. `--receipt <dir>/receipt.json` makes it `{execution_id, run_id, namespaces: [namespace], start: started_at, end: finished_at}`;
- **`correlation_id`** in `receipt.json`: the UUID the wrapper passes to Stratus as `STRATUS_RED_TEAM_CORRELATION_ID`, in canonical lowercase form (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, as `str(uuid.uuid4())` writes it), one per run, the same for every Stratus command of the run. Stratus then sends `stratus-red-team_<correlation_id>` as the User-Agent of its own API requests, and the importer attributes by it. Terraform's requests do not carry it: in the round they came as `HashiCorp/1.0 Terraform/1.3.10`, so they are attributed only by run label or namespace, and Terraform's cluster-scoped prerequisites by nothing. The wrapper at `795c5db` records it. It is optional in the contract; without it the matching below is left to labels and the namespace;
- `executions.jsonl`, one `execution_record`: `outcome` is `succeeded` if and only if the detonation's return code is 0, and `executed_at` = `started_at`. This file goes to `detection_metrics.py` unchanged.

Another driver can write the same records directly, one JSON object per line (`--runs`), with exactly `execution_id`, `run_id`, `namespaces` (a list, possibly empty), `start` and `end`, and optionally `correlation_id`. `run_id` must be a label value; the namespaces of Kubernetes and kind themselves (`default`, `kube-system`, `kube-public`, `kube-node-lease`, `local-path-storage`) are refused.

An alert belongs to a run if its time is inside `[start, end]` and one of:
- **correlation ID:** the request's User-Agent (`ka.useragent`) has Stratus's token `stratus-red-team_<correlation_id>`, delimited by the start, the end or a character that cannot be part of it (a space, a parenthesis, a semicolon); the UUID alone or inside a longer string is no match. This also attributes cluster-scoped objects, `kube-system` and lists across all namespaces, and it wins over another run's namespace match. An alert whose User-Agent names a run but falls outside that run's window is attributed to no run;
- **label:** a run label of the request body (`warden.dev/run` or `warden_run_id`) equals the run ID; the wrapper puts both on its pods, and Terraform passes them to the pods it creates;
- **namespace:** the request's target namespace is one of the run's. This ignores who made the request: a kubelet or controller request about an earlier run's leftovers in `warden-lab` would count for the later run. So **`warden-lab` must be empty when a run starts**. `make kind-audit-check-empty` (`scripts/kind_lab.sh check-empty --audit`, `scripts/kind_audit_check.py`) exits 0 only if the namespace holds nothing of any namespaced type but what Kubernetes puts in every namespace (the ServiceAccount `default`, the ConfigMap `kube-root-ca.crt`) and events. Call it before each run.

An alert two runs claim fails the import, as does a correlation ID and a run label that name different runs. The rule map is the reviewed one (`expected-rules.jsonl`); its widest form is every stock k8saudit rule (48). **The Stratus round is scored on k8saudit alerts only**: the 25 stock syscall rules are not in its map. Host syscall alerts from the kind lab's pods count as another container's (`dropped_other_nested`) and are never kept. The kind node is not treated as Warden's on purpose. Of the eight techniques only three create pods, and those run `sleep`, `cat /host/etc/passwd` or `cat` on the service account token; `nodes-proxy` is a kubelet GET through the API server, and the other four are API-only. None of the 25 rules describes any of that, so keeping the node's alerts would add only its start-up noise.

What this does not attribute, and why:
- **Runs without `correlation_id`.** Stratus v2.38.0 takes only a UUID as its correlation ID (`resolveCorrelationID`, `v2/pkg/stratus/runner/runner.go`). For any other value it warns and uses a random UUID, which it records nowhere, so the User-Agent names no run. The wrapper at `dd79f39` passed its run ID and recorded no UUID; `795c5db` passes a UUID and records it. For a run without one, requests outside `warden-lab` without a run label are not attributed: cluster-scoped objects (ClusterRoles and bindings, CSRs, nodes), `kube-system`, and lists across all namespaces.
- **Terraform's cluster-scoped prerequisites.** nodes-proxy's Terraform creates and destroys a ClusterRole and a ClusterRoleBinding; their four alerts per run (ClusterRole With Write Privileges Created, K8s ClusterRoleBinding Created and Deleted, K8s ClusterRole Deleted) are inside the run's window but attributed to no run (above).
- **The window** is `started_at`..`finished_at`: `stratus detonate --cleanup` (warm-up, detonation, revert, Terraform destroy) and, since the wrapper's `1058ca0`, a fallback `stratus cleanup` only after a failed or timed-out detonation, skipped since `9adf201` when `stratus status` reads COLD. Alerts of warm-up and clean-up count for the run under the widest map. Time to detect, from `started_at`, includes Stratus's start-up and, for the Terraform techniques, the downloads and `terraform apply`.

### What the wrapper's runs depend on (read only)

- **Downloads.** The wrapper passes a clean environment (PATH, LANG) and a `HOME` inside each run's directory. So on every run Stratus downloads Terraform 1.3.10 into `<out>/home/.stratus-red-team/terraform` (hc-install checks HashiCorp's checksums), and Terraform downloads the providers from registry.terraform.io, both over the network. `.tools/stratus` is not used by the wrapper. Its receipt's hashes are the reference for checking those downloads after the runs: compare `sha256sum <out>/home/.stratus-red-team/terraform` with `terraform/terraform` in `.tools/stratus/receipt.json` (`51274880…4911`), and each `terraform-provider-kubernetes_v<version>_x5` under `<out>/home` with `providers/…` there. The providers land in Stratus's plugin cache, `<out>/home/.stratus-red-team/plugin-cache/registry.terraform.io/…`, which the clean-up keeps; the technique's own directory, `.terraform.lock.hcl` included, is removed at the clean-up. Terraform also calls HashiCorp's checkpoint (version-check) service (`<out>/home/.terraform.d/checkpoint_*`): the clean environment does not set `CHECKPOINT_DISABLE`.
- **The separate cleanup's return code** (observed 2026-11-14, [evidence](evidence/task-13/stratus-20261114/attempt-1/README.md)). Stratus v2.38.0's `CleanUp` returns an error for a technique that is already COLD unless `--force` is given (`v2/pkg/stratus/runner/runner.go`). A successful `detonate --cleanup` leaves the technique COLD, so the wrapper's second command, `stratus cleanup <technique>`, returns 1 (`... is already COLD and should already be clean, use --force to force cleanup`) and the wrapper exits 1 although the lab is clean. At `795c5db`, `cleanup_returncode` is therefore 1 on every run whose first cleanup worked; only `make kind-audit-check-empty` and a by-name inventory after the run show whether anything was left. The user changed the wrapper: `1058ca0` runs the second cleanup only after a failed or timed-out detonation, and `9adf201` first asks `stratus status` and skips it on COLD, recording `cleanup_mode` "skipped already COLD" and `cleanup_returncode` 0. COLD does not prove that nothing is left; the post-run checks still decide. In attempt 3, all 35 successful runs had `cleanup_mode` "detonate --cleanup" and the 5 failed ones "skipped already COLD".
- **The Terraform provider's kubeconfig** ([attempt 2](evidence/task-13/stratus-20261114/attempt-2/README.md)). Stratus v2.38.0's Terraform for steal-serviceaccount-token and nodes-proxy gives the `kubernetes` provider `config_path = ~/.kube/config` only if that file exists; with the run's HOME it does not, and hashicorp/kubernetes 2.13.0 then reads `KUBE_CONFIG_PATH`. At `1058ca0` the wrapper set only `KUBECONFIG`, and steal-serviceaccount-token failed before Terraform made any request (its error text is redacted, so this cause is inferred from the source and the audit log). `2533736` sets `KUBE_CONFIG_PATH` to the same checked snapshot; both techniques then succeeded 5 of 5. privileged-pod and hostpath-volume were never affected (their Terraform only declares a namespace with `count = 0`).
- **`create-admin-clusterrole` leaves its objects when it fails.** It has no Terraform prerequisites, so its failed detonation leaves it COLD and neither cleanup reverts it (`Revert` runs only from DETONATED): the ClusterRole `stratus-red-team-clusterrole`, the ClusterRoleBinding `stratus-red-team-crb` and the ServiceAccount `kube-system/stratus-red-team-serviceaccount` stay; their names carry no per-run part. Delete them by name (or recreate the lab) before the next run. The round's driver deletes exactly these three by name after each of its runs, records each command, and checks that they are gone; the deletions raise three alerts each, outside every run window.
- **kubectl's cache.** The wrapper's own `kubectl get nodes` and `get namespace` run before it sets `HOME`, so kubectl writes `.kube/cache` into the wrapper's working directory: run it from a directory under `.cache`, not the worktree root.
- **Two limits in `attacks/atomic/lab_common.py`.** At `dd79f39`, `digest()` refused files over 256 MiB (the v2.38.0 binary is 362,488,146 bytes) and `command()` limited every file the child writes to 8 MiB (Stratus installs Terraform, which is larger, into the run's `HOME` at the start of every command). `795c5db` gives both a parameter, and the wrapper passes 512 MiB to each (`STRATUS_FILE_LIMIT`).

### Stratus Kubernetes techniques against the stock rules (v2.38.0 source, the rules file above)

- `k8s.privilege-escalation.privileged-pod`: "Create Privileged Pod" describes it.
- `k8s.credential-access.steal-serviceaccount-token`: "Attach/Exec Pod" (the exec into the pod).
- `k8s.persistence.create-admin-clusterrole`: "ClusterRole With Wildcard Created", "Service Account Created in Kube Namespace" and the activity rules describe the objects it creates. **It fails on Kubernetes 1.24 and later** (this lab runs 1.34.11): after creating them, its detonation polls one minute for a token Secret of the new ServiceAccount, which Kubernetes no longer creates, and returns an error.
- `k8s.credential-access.dump-secrets`: **no stock rule**. "K8s Secret Get Successfully" matches `get`, not a `list` across all namespaces.
- `k8s.persistence.create-token`: **no stock rule** names a token request. The `serviceaccount` macro does not exclude subresources, so a token request in `kube-system` matched "Service Account Created in Kube Namespace" (observed on the throwaway lab). With the receipt's `correlation_id` the importer attributes it, and the widest map counts it.

Observed in the round's attempt 3 (2026-11-15, 5 runs each, [evidence](evidence/task-13/stratus-20261114/README.md#what-fired-on-which-request)):
- privileged-pod 5/5 and hostpath-volume 5/5, by "Create Privileged Pod" and "Create Sensitive Mount Pod" on the technique's own pod create.
- steal-serviceaccount-token 5/5: "Attach/Exec Pod" on the exec, but each run's first alert is "K8s Serviceaccount Created" on Terraform's warm-up ServiceAccount.
- nodes-proxy 5/5 only through "K8s Serviceaccount Created"/"Deleted" on its ServiceAccount set-up, Stratus's token request and the clean-up; its GET through `nodes/<node>/proxy` matched no rule.
- create-token 5/5 through "Service Account Created in Kube Namespace" on its token request, as above.
- create-client-certificate 0/5 (no stock rule covers CSRs), dump-secrets 0/5.
- create-admin-clusterrole failed 5/5 as expected; its 3 alerts per run are alerts on failed executions.
- On the idle cluster, "K8s Serviceaccount Created" and "Service Account Created in Kube Namespace" fired on the kubelet's and kube-controller-manager's token requests: 197 alerts in the 22.7 h between the last run and the cutoff.

## Limits

- **Firecracker guests and gVisor sandboxes are not covered.** A host sensor sees the Firecracker VMM and runsc's sentry and gofer, not the system calls of the code inside. The smoke's read of `/etc/shadow` inside a gVisor sandbox raised nothing, as expected.
- **The probe's cost on every CPU.** Pinning moves Falco's userspace; the eBPF programs run on the CPU of each system call, including 8-15 where another project times benchmarks.
- **runc lab runs share one container.** Falco reports the lab's outer container for all of a lab session's runs; per-run attribution needs per-run `--start/--end`.
- **A lab pod that is not Warden's and has no sandbox cgroup when its alert arrives** stays unresolved and is dropped; unresolved alerts count as drops in the ledger, so such an hour is not active. Nothing of the benign workload does this (the last benign test had none); the smoke's control pod is placed by its pod.
- **Scoring is temporal association within a container.** `alert_import.py` scores only `alerts.jsonl`, by the run's container and window and the reviewed expected rules; runsc's start-up signature is kept out of that file, but a reviewer who lists a rule that the platform raises for other reasons can still associate it with a run.
- Container metadata: the host instance has Docker's (stock container plugin through the socket); pods inside the k3s node have none (`container.name` is `<NA>`), which the stock rules' image-based exceptions then do not match.
- Nothing here authenticates the inputs: the ledger is still a supplied record (`coverage_verified` stays false).
- **The kind audit lab beside the host instance.** The kind node is not a Warden container, so the host collector drops its alerts as another container's. Its pods' containerd IDs are now found as cgroups nested in it and counted the same way (`dropped_other_nested`, [above](#only-wardens-alerts-reach-a-disk)). Before, they waited for the 20 s deadline and were dropped as unresolved: 3 per pod round in a probe, 0 after the fix ([before](evidence/task-13/k8saudit-smoke-20261114/host-probe/probe.jsonl), [after](evidence/task-13/k8saudit-smoke-20261114/host-probe-after-fix/pod-rounds/probe.jsonl)). The same holds for another project's permanent kind node, which would otherwise have kept seven-day slices from being active. A process in a pod that is gone before its alert is looked up still has no cgroup to be found in, and is still dropped as unresolved.
