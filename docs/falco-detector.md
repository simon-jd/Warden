# Online detector (Task 13): Falco on home-ubuntu

Status 2026-11-14 UTC, branch `detect-online`: built and smoke-tested; **the seven-day window has not been started**. Results: [evidence/task-13/online-detector-20261113](evidence/task-13/online-detector-20261113/README.md).

What the user decided on 2026-11-13:
- Falco from images pinned by digest; the host instance with the modern eBPF probe in a privileged container.
- Only alerts of Warden containers may reach a disk; everything else is only counted.
- Stock rules at the pinned version, untuned; the noise they make on Warden's own labs is handled by a bulk review, not by tuning.
- **gVisor is covered at host level only.** The host instance sees runsc's sentry and gofer and the k3s node's processes; the system calls inside a sandbox are not covered, as Firecracker's guests are not. What the smoke shows on gVisor is that the host sees a sandbox start (runsc's normal start-up); that is not a detection of anything a run does, and it is kept apart from the scored alerts ([below](#only-wardens-alerts-reach-a-disk)). The gVisor-engine instance and the lab's runsc trace mode stay as opt-ins, off by default, because Falco's gVisor engine is broken upstream ([below](#the-opt-in-gvisor-engine-broken-upstream)).
- The seven-day window starts only after all other work is done.

## Run it

```sh
make detect-up            # the host instance and its collector (needs .tools/falco: scripts/restore-tools.sh falco)
make detect-status        # container, collector, last heartbeat and counts, seven-day timers
make detect-down          # stop and remove them; compares the host's modules and sysctls with up's
make detect-purge         # down, then remove the images, the socket volume and the FIFOs (data is kept)

make detect-smoke DETECT_OUT=<dir>   # up, the smoke actions on runc and gVisor, down, report (about 1 minute)

make detect-seven-day-start                    # a dry run: prints what the start would do, changes nothing
make detect-seven-day-start CONFIRM=seven-day  # THE START OF THE SEVEN-DAY WINDOW (see below); not run yet

make detect-up DETECT_GVISOR_ENGINE=1          # opt-in: also the gVisor-engine instance (exits at its first event)
scripts/k3s_gvisor_lab.sh up --without-corpus --falco   # opt-in: a lab whose runsc reports to that instance
```

Anything but `CONFIRM=seven-day`, or any `DRY_RUN` value, makes `detect-seven-day-start` a dry run.

Everything runs on CPUs 0-7,16-31: the make targets use `taskset`, the Falco containers have `--cpuset-cpus 0-7,16-31`, and the labs get `WARDEN_LAB_CPUSET`. The eBPF probe itself runs in the kernel on whichever CPU makes a system call, so it also adds a little work to every system call on CPUs 8-15 (see [Limits](#limits)).

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
- everything else is counted and dropped: alerts of host processes (`dropped_host`), of other containers (`dropped_other_container`; of those, `dropped_other_lab_owned` are lab-owned containers that are not Warden workloads, such as the smoke's control, and `dropped_other_lab_pod` are lab pods outside `warden-lab`), of containers no resolver knew within 20 s (`dropped_unresolved`), lines that are not Falco events (`dropped_malformed`), and lines the collector's queue could not take (`dropped_overflow`). No byte of them is written; only the counters, in the heartbeats.

A Warden container, and its class:
- a Docker container labelled `project=warden`: **sandbox** if it carries a run (`warden.dev/run`, or the runc and Firecracker labs' `session`), **node** if it is the k3s node `warden-k3s-gvisor`, **lab** otherwise (the Cilium mode's stand-ins);
- a container of a pod in the k3s lab's namespace `warden-lab` with the label `warden.dev/run`: **sandbox**;
- a cgroup nested inside a running Warden container's. This is how runsc's sentry shows up: it runs in the k3s node's pod-sandbox cgroup, whose ID no API lists, and Falco reports that ID. **The pod decides first**: the cgroup's pod (from the `pod<uid>` component of its path) must be a `warden-lab` pod with `warden.dev/run` (sandbox); any other pod's cgroup is not Warden's, although it runs in the Warden node (the smoke's control pod). A cgroup of the node in no pod is the node's own infrastructure (node).

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

That is roughly 280,000 alerts in seven days in about 20 groups. [`review.py`](../detect/falco/review.py) makes that a review of groups, not of alerts:

```sh
python3 -I -B detect/falco/review.py groups --alerts <data>/host/alerts.jsonl --alerts <data>/host/platform-alerts.jsonl --scoping <data>/host/scoping.jsonl \
  --out groups.jsonl --template map.jsonl          # one line per (rule, process, class), with counts
# a person edits map.jsonl: each line's disposition false_positive, true_positive or unreviewed
python3 -I -B detect/falco/review.py apply --alerts ... --scoping ... --map map.jsonl \
  --start <window start> --end <window end> --out normal-alerts.jsonl --report report.json
python3 -E -s -B -m detect.report.observation --coverage coverage.jsonl --normal-alerts normal-alerts.jsonl \
  --source falco-host --start <window start> --end <window end> --observed-until <cutoff>
```

The template's dispositions are all `unreviewed`; the tool never decides one. An alert of a group the map does not name stays `unreviewed` (and `observation.py` then gives no false-positive count). The report gives each group's count and false positives, the totals, and any map line that matched no group.

## The hourly benign workload

[`benign.py`](../detect/falco/benign.py) runs the conformance suite's seven probes (`runtimes/conformance`) through the real drivers, one runtime after the other: the runc lab (`scripts/runtime_lab_docker.py run`, told Falco's 1 GiB in `--other-service-memory-bytes`), then `make test-gvisor GVISOR_LAB_FLAGS=--without-corpus` (the lab is up only for that run). Each run is under `taskset -c 0-7,16-31` with `WARDEN_LAB_CPUSET=0-7,16-31` and appends one record to `workloads.jsonl`; `ok` means exit 0 and the suite's PASS line. A run that reaches its timeout (20 and 30 minutes) gets SIGTERM so its own cleanup runs, SIGKILL a minute later, and then its lab is taken down, but only this worktree's: the k3s lab's `down` only if the node carries this worktree's `warden.lab/root` label (the lab script now sets it), and runc lab containers only if they bind this worktree's `.cache/warden-lab`. Another worktree's lab is left alone. The same happens to the run in progress when the unit's `RuntimeMaxSec` (50 minutes) stops `benign.py`. A run that cannot start (detector down, previous run still going) is recorded as not ok, so its hour has no workload.

## The seven-day start

Not run. `make detect-seven-day-start CONFIRM=seven-day` (`detector.py seven-day-start --confirm seven-day`) will:

1. refuse if the detector is up, any `project=warden` container exists, or its timers are already active;
2. build the runc lab's inputs (`scripts/build-runtime-lab.sh`) and make the paths the runc lab checks unwritable by group and others (`chmod go-w`, as [runtime-lab.md](runtime-lab.md) says);
3. `up` (the host instance; a new session; the host's modules and sysctls are recorded);
4. start the window at the first healthy point (above) and write `.cache/detect/state/seven-day.json`: window start, end = start + 7 days, source `falco-host`;
5. arm two transient systemd user timers: `warden-detect-benign` (first run 2 minutes after the start, then hourly after each run's start) and `warden-detect-seven-day-stop` (7 days + 15 minutes after the start). If the second cannot be armed, the first is stopped and the detector taken down again.

`detector.py seven-day-stop` (the second timer; or by hand) stops the benign timer, waits for a running workload, flushes a heartbeat, runs `down` and takes down any lab a benign run left. Whatever of that fails, it then writes to `.cache/detect/data/<session>/seven-day/`: `coverage.jsonl` (with `explain.jsonl`: why a record is unhealthy), `review-groups.jsonl` and `review-map-template.jsonl`, every kept alert in the window as `normal-alerts-unreviewed.jsonl`, and `observation.py`'s result on them; the failures are reported at the end. The false-positive count comes after a person fills in the map and runs `review.py apply` and `observation.py`.

Before starting:
- nothing else of Warden may run for seven days (the runc lab refuses next to another Warden lab container, and any lab run is in the window);
- the host must not sleep, reboot or restart Docker: the transient units and the container do not come back, and the gap makes the window ineligible;
- the user's Task 5/13 emulations would land in the window as alerts; keep them out of it.

## The opt-in gVisor engine (broken upstream)

`make detect-up DETECT_GVISOR_ENGINE=1` adds the gVisor-engine instance, and `scripts/k3s_gvisor_lab.sh up --falco` makes the lab's runsc send it trace events (`detect/falco/gvisor-pod-init.json`, generated by the pinned 0.43.1 with `--gvisor-generate-config=/warden-detect/gvisor.sock`). It is not part of the default detector or the seven-day ledger, because Falco's gVisor engine does not survive the lab's runsc (release-20261019.0), as the committed runs show ([gvisor-engine-crash/](evidence/task-13/online-detector-20261113/version/gvisor-engine-crash/)):
- Falco 0.43.1 with the generated trace configuration: each log names the probe pod's sandbox (the ID `crictl` gives in the log's header) as a container, then Falco stops with `Error: vector` and exit code 1;
- Falco 0.42.1 (fetched by digest for this test, then removed): the same;
- Falco 0.43.1 with the `container/start` trace point removed (the code path libs#3074 names; that configuration is committed): the same.

This is the open upstream bug [falcosecurity/libs#3074](https://github.com/falcosecurity/libs/issues/3074) (filed 2026-08-04 against 0.42.1); 0.44.0 removed the engine. With `ignore_setup_error: true` the sandboxes keep running untraced. The engine also fills no terminal for any event (libs 0.23.2 `parsers.cpp`), so even a working engine would not raise "Terminal shell in container" for `kubectl exec -it`.

## Limits

- **Firecracker guests and gVisor sandboxes are not covered.** A host sensor sees the Firecracker VMM and runsc's sentry and gofer, not the system calls of the code inside. The smoke's read of `/etc/shadow` inside a gVisor sandbox raised nothing, as expected.
- **The probe's cost on every CPU.** Pinning moves Falco's userspace; the eBPF programs run on the CPU of each system call, including 8-15 where another project times benchmarks.
- **runc lab runs share one container.** Falco reports the lab's outer container for all of a lab session's runs; per-run attribution needs per-run `--start/--end`.
- **A lab pod that is not Warden's and has no sandbox cgroup when its alert arrives** stays unresolved and is dropped; unresolved alerts count as drops in the ledger, so such an hour is not active. Nothing of the benign workload does this (the last benign test had none); the smoke's control pod is placed by its pod.
- **Scoring is temporal association within a container.** `alert_import.py` scores only `alerts.jsonl`, by the run's container and window and the reviewed expected rules; runsc's start-up signature is kept out of that file, but a reviewer who lists a rule that the platform raises for other reasons can still associate it with a run.
- Container metadata: the host instance has Docker's (stock container plugin through the socket); pods inside the k3s node have none (`container.name` is `<NA>`), which the stock rules' image-based exceptions then do not match.
- Nothing here authenticates the inputs: the ledger is still a supplied record (`coverage_verified` stays false).
