# Task 13: the Task 5 corpus under the online detector, 2026-11-14 UTC

Branch `task13-emulation`, from `implementation/warden` at `1894d3b`, in its own worktree on home-ubuntu (kernel 7.0, Docker 29.9.3). Everything ran on CPUs 0-7,16-31. The detector was the host instance from [falco-detector.md](../../../falco-detector.md): Falco 0.45.2 with the modern eBPF probe, the image's stock rules (sha256 `30a1a602…865b`, 25 rules, [stock-rules.txt](stock-rules.txt)), session `20261114T152748Z`, up from 15:27:48 to 15:30:46 UTC. The Task 5 isolation matrix ran once on runc and once on gVisor inside that time. Firecracker was not rerun: a host sensor cannot see a guest's system calls, so Firecracker is **not covered**. The seven-day window was not started.

## What ran

| | runc | gVisor |
|---|---|---|
| Command | `WARDEN_LAB_CPUSET=0-7,16-31 taskset -c 0-7,16-31 python3 -B scripts/runtime_lab_docker.py matrix --other-service-memory-bytes 1073741824` (Falco's 1 GiB) | `WARDEN_LAB_CPUSET=0-7,16-31 taskset -c 0-7,16-31 make test-gvisor` (the lab with the corpus, the default) |
| Time (UTC) | 15:28:03.4 to 15:28:21.8; the 14 runs 15:28:19.0 to 15:28:20.9 | 15:28:41.2 to 15:30:02.2; the 14 runs 15:29:18.9 to 15:30:01.7 |
| Exit | 2: `TestConformance` 7/7 subtests PASS, `IsolationMatrix` FAIL on the five `error` cells, as in Task 5 | 2 (make): `TestGVisorConformance` 7/7 PASS, `IsolationMatrix` FAIL on the five `error` cells |
| Teardown | the runner removed its outer container `8996cd78656f…` and its image | `run` took the lab down; the lab's own check: modules and its sysctls the same before and after ([run/](run/)) |
| Corpus image | `sha256:49e64da91400…c753` | `sha256:f804f1f7a595…52a8` |

Both used the corpus `sha256:541438cdbd805a8b4558cae8a9eaea5fe9d72b0d8a68d1258b93b832cfb9c091` and Task 5's limits: CPU 1, 512 MiB, pids 128, 60 s. Only the corpus digest is Task 5's: both images were rebuilt for this run and differ from Task 5's (runc `51a7ba94…` → `49e64da9…`, gVisor `57c59eee…` → `f804f1f7…`), and from each other as in Task 5, because the k3s lab rebuilds the probe binary with the local toolchain. The runc lab's inputs were built with the steps of `scripts/build-runtime-lab.sh`, through a copy of `scripts/go.sh` with `--cpuset-cpus 0-7,16-31` added (the build container otherwise runs on every CPU); the attack helper was built as the k3s lab's `gobuild` builds it. Afterwards no `project=warden` container, no Warden network, no Falco container and no `warden*`/`falco*` user unit was left.

## The detector during the runs

- `make detect-status` before, between the runtimes, during the gVisor matrix, after it and before `down` ([run/](run/)): the container running, the collector active, `collector_errors` 0, `collector_restarts` 0, and nothing dropped as unresolved, errored, overflowed or malformed.
- The cutoff is 15:30:41.451: the time taken just before the last heartbeat flush before `down` (as `detect/falco/smoke.py` does). The flushed heartbeat is 15:30:41.647, so a heartbeat brackets the cutoff, which the recorder needs for the last record; every run ended (15:30:02.2) and every kept alert is earlier; Falco was stopped at 15:30:46.
- One coverage record from the first healthy point (15:27:56.720) to the cutoff ([coverage.jsonl](coverage.jsonl)): healthy, 2,873,325 events, 0 dropped. [observation.py](observation.json) does not count it as active coverage only because it has no benign workload (`workload_count` 0); it is not a seven-day record.
- Kept: 287 alerts in the scored file and 4,379 platform alerts (runsc's start-up signature); 4 alerts of other projects' containers were only counted.
- `make detect-down` ([host-compare.json](host/host-compare.json)): no module added or removed, no global sysctl changed (only counters such as `fs.file-nr`).

## Scoring

[`score.py`](score.py) feeds the runbook's tools and tabulates them; from the repository root, `python3 -I -B docs/evidence/task-13/emulation-20261114/score.py` rewrites every scoring file here and the coverage page from the committed inputs.

- **Bindings** ([bindings.jsonl](bindings.jsonl)), 28 of 28, by `detect/falco/bindings.py`. runc: the lab's outer container `8996cd78656f…` (session label `e1a3d65f…`), with each run's own window, the matrix's `started_at`..`finished_at`, inside the container's Docker start and die. gVisor: each run's pod sandbox ID (the pod label `warden.dev/run` is the run ID in lower case); each of the 14 sandboxes has platform alerts, so the host saw every one of them start. Those are never scored. A gVisor window is what `bindings.py` derives from the pod: from its `creationTimestamp`, which the API gives in whole seconds (0.57 to 0.88 s before the matrix's `started_at` here), to the later of its container's `finishedAt` + 1 s and when the collector saw the pod gone. For 13 runs that ends 0.04 to 0.43 s after the matrix's `finished_at`; for the last (sys-leak) the collector recorded no `gone`, so it ends at 15:30:00, 1.674 s before that run's `finished_at` (15:30:01.674). This changes no number: no alert in the scored file carries any of the 14 sandbox IDs at any time, so any window gives the same zero gVisor imports (checked over the whole session).
- **Rule map** ([expected-rules.jsonl](expected-rules.jsonl)): every one of the 25 stock rules for every run, so any kept alert on the run's container inside its window counts. No narrower map has been reviewed; the table below names the rule that fired.
- `alert_import`: 3 alerts ([alerts.jsonl](alerts.jsonl), [provenance](alert-provenance.jsonl)), none of them a platform alert.
- `matrix render` with those alerts: [isolation-matrix.md](isolation-matrix.md) and [executions.jsonl](executions.jsonl). `detection_metrics` with the cutoff 15:30:41.451 (above): [metrics.json](metrics.json) (both runtimes), [metrics-runc.json](metrics-runc.json), [metrics-gvisor.json](metrics-gvisor.json). `detection_report`: [detection-coverage.md](../../detection-coverage.md), with a Scope section from `score.py`'s notes (`--note`): n=1, the rule map, the runtimes covered, what the alert time is, what has not run.

| Probe | Runtime | Task 5 (11-13) | This run | Alert on the run | First alert after start (s) |
|---|---|---|---|---|---|
| arp-spoof | runc | blocked | blocked | Packet socket created in container | 0.078 |
| arp-spoof | gVisor | blocked | blocked | none | – |
| disk-fill | runc | error | error | none | – |
| disk-fill | gVisor | error | error | none | – |
| dns-exfil | runc | error | error | none | – |
| dns-exfil | gVisor | error | error | none | – |
| fork-bomb | runc | blocked | blocked | none | – |
| fork-bomb | gVisor | blocked | blocked | none | – |
| kernel-module | runc | blocked | blocked | none | – |
| kernel-module | gVisor | blocked | blocked | none | – |
| memory-exhaustion | runc | blocked | blocked | none | – |
| memory-exhaustion | gVisor | missed | missed | none | – |
| metadata-host | runc | blocked | blocked | none | – |
| metadata-host | gVisor | blocked | blocked | none | – |
| metadata-ip | runc | blocked | blocked | none | – |
| metadata-ip | gVisor | blocked | blocked | none | – |
| mount-unshare | runc | blocked | blocked | none | – |
| mount-unshare | gVisor | blocked | blocked | none | – |
| proc-leak | runc | error | error | none | – |
| proc-leak | gVisor | error | error | none | – |
| ptrace | runc | blocked | blocked | PTRACE attached to process | 0.080 |
| ptrace | gVisor | blocked | blocked | none | – |
| raw-socket | runc | blocked | blocked | Packet socket created in container | 0.085 |
| raw-socket | gVisor | blocked | blocked | none | – |
| reverse-shell | runc | error | error | none | – |
| reverse-shell | gVisor | error | error | none | – |
| sys-leak | runc | error | error | none | – |
| sys-leak | gVisor | error | error | none | – |
| all 14 | Firecracker | (9 blocked, 5 error) | not run | not covered | – |

Every cell has the verdict it had in Task 5. Per cell, with run IDs, windows and alert IDs: [cells.json](cells.json).

## What the numbers show, and what they don't

- `detection_metrics` scores only runs whose probe reached its goal (verdict `missed` or `detected`). One did: gVisor memory-exhaustion (`WARDEN_SUCCESS … 576 MiB touched`, again), and it raised nothing. So the detection rate is **0 of 1** on gVisor and **0 of 0** on runc (no rate), and there is **no time to detect and no p50/p95**: no successful run was detected.
- Three runc runs raised a stock alert **on the attempt, although the sandbox denied it**: arp-spoof and raw-socket "Packet socket created in container" (`fd=-1(EPERM)`), ptrace "PTRACE attached to process" (the alert's parent command line is the shim of `warden-CHSGIOOMRNRTMGNIRWP2XNGJHA`, the run's ID). The matrix keeps them `blocked` and lists the alerts; `detection_metrics` counts them as alerts on failed executions (3), not as detections. Their 0.078 to 0.085 s run from the matrix's run start (before the sandbox exists) to the alerted event's own time (Falco's `time`, the system call). How long Falco and the collector took to deliver the alert is not recorded, so this is not an end-to-end alert latency.
- No other runc run raised an alert. "Linux Kernel Module Injection Detected" requires `sys_module` in the effective capabilities, and the sandbox has none; none of the 25 stock rules describes a fork bomb, memory or disk exhaustion, mount/unshare, or a connection to the metadata address.
- gVisor: nothing scored, as expected at host level: the host does not see a sandbox's own system calls. Of the 287 alerts in the scored file, 283 are the k3s node's own (class `node`) and 4 are runc's.
- A host-visible signal, **unscored**: the fork-bomb run's sandbox raised 1,161 start-up (platform) alerts, runsc's sentry "PTRACE attached to process", against 128 for each of the other 13 matrix sandboxes (the conformance fork test's sandbox 708, the other conformance sandboxes 141). These are runsc's start-up class, kept apart and never scored, so the fork bomb counts as not alerted; the count is only what the host saw ([cells.json](cells.json): `platform_alerts_on_sandbox`).
- The five `error` cells (disk-fill, dns-exfil, proc-leak, reverse-shell, sys-leak; Task 5's open gaps) are `skipped` executions with no alert; they have no verdict and say nothing about detection.
- One run per cell; the alerted runs are unreviewed Falco output, and the rule map is not a reviewed one.

## The plan's Task 13 criteria

- Run the emulations (Stratus, Atomic Linux, the Task 5 corpus): the corpus is done on runc and on gVisor (host level) under the detector; Firecracker is not covered. Stratus and Atomic have not run live, and the plan's Stratus AWS and GCP techniques (for example `aws.persistence.iam-create-admin-user`, `aws.defense-evasion.cloudtrail-stop`) are not wrapped at all: the wrapper runs only `k8s.privilege-escalation.privileged-pod` and rejects AWS, GCP and Azure execution ([attacks/stratus/README.md](../../../../attacks/stratus/README.md)). Task 12's Sigma rules (`detect/sigma/rules`) are not in this scoring path: only Falco's stock rules were scored. **Open.**
- Tests pass, a report from real data: `make test` and `make check` pass in this worktree ([final/](final/)); [detection-coverage.md](../../detection-coverage.md) is rendered from this run. **Met for the corpus runs.**
- Evidence of the detection rate, time to detect p50/p95 and the false positives over seven days of normal operation: the rate is computed (0/1, 0/0 above) but has no detected successful run behind it, so there is no p50/p95; the false-positive count needs the seven-day window, which has not started. **Open.**

## The session's kept alerts, for review

[review-groups.jsonl](review-groups.jsonl) (`review.py groups` over the scored and the platform alerts) has 19 groups; [review-map-template.jsonl](review-map-template.jsonl) has them all `unreviewed`, and no disposition was assigned:
- class `node`, "Drop and execute new binary in container": 15 groups, 283 alerts (bridge, host-local, loopback 74 each; kubectl, ctr 16 each; find 7; exe, modprobe 6 each; k3s-server, containerd, unpigz 2 each; containerd-shim, runc, umount, cat 1 each), from the k3s node's start-up and its CNI plugins;
- class `platform`, "PTRACE attached to process" from `gvisor_sentry`: 4,379 (21 sandboxes: 7 conformance, 14 matrix);
- class `sandbox`: "PTRACE anti-debug attempt" from `warden-probe`, 1 (the runc conformance's seccomp probe, outside every matrix window, not scored); "PTRACE attached to process" from `warden-attack`, 1, and "Packet socket created in container" from `warden-attack`, 2 (the three scored alerts).

## Files

- `runc.json`, `gvisor.json`: the matrix reports (every run ID, time, output, exit and cgroup result); `runc.log`, `gvisor.log`: the runners' output.
- `run/`: `runs.json` (commands, times, exit codes), `window.json`, every `make detect-*` output, the runc lab's `identity.json` and input `manifest.json`, the k3s lab's host checks and node manifest.
- `collector-host/`: what the host collector wrote, unchanged: `alerts.jsonl` (the scored file), `heartbeats.jsonl`, `health.jsonl` (Falco's metrics), `registry.jsonl`, `falco.log`; `platform-alerts.jsonl.gz`, `scoping.jsonl.gz`.
- `host/`: the detector's host snapshots and their comparison.
- Scoring: `bindings.jsonl`, `binding-errors.json` (empty), `expected-rules.jsonl`, `alerts.jsonl`, `alert-provenance.jsonl`, `alert-import.out`, `executions.jsonl`, `isolation-matrix.md`, `metrics*.json`, `cells.json`, `cells.md`, `review-groups.jsonl`, `review-map-template.jsonl`, `coverage.jsonl`, `explain.jsonl`, `observation.json`, `checks.json` (every check true, 0 dropped events).
- `final/`: `make test`, `make check`.

Before the commit every file here (gzip'ed ones unpacked) and the coverage page were searched for the first 12 hex digits of every container, network and image ID on the host that is not Warden's (838): no match.
