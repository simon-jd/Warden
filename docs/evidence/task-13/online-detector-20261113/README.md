# Task 13 online detector: build and smoke test, 2026-11-14 UTC

Branch `detect-online` on home-ubuntu (kernel 7.0.0-42, Docker 29.9.3, 32 CPUs; everything on CPUs 0-7,16-31). How it works and how to run it: [docs/falco-detector.md](../../../falco-detector.md). The seven-day window was **not** started (dry runs only). Falco ran only for the short tests below and was stopped and purged afterwards.

After the first round's review the user decided (2026-11-13): gVisor is covered at host level only, like Firecracker's guests not at all inside the sandbox; the gVisor-engine instance is opt-in, off by default, and broken upstream; the stock rules stay untuned and their noise goes through a bulk review. This directory's `smoke/` and `benign/` are from after the second re-review's fixes (sessions `20261114T050135Z` and `20261114T050242Z`). The first round's runs are in `round-1-smoke/` and `round-1-benign/` (two Falco instances, the gVisor engine crashing); the second round's are in git history (`c796dab`).

## Results (host instance, the detector)

| | runc | gVisor (host level) |
|---|---|---|
| Interactive shell in a Warden container (`docker exec -it`) | **detected**: "Terminal shell in container", kept, bound, imported, `detected` | not part of the host-level smoke |
| Read of a dummy `/etc/shadow` by the container's own shell | **detected**: "Read sensitive file untrusted" | **not detected, as expected**: a sandbox's own system calls are not covered |
| A sandbox starts in a Warden pod | | **seen, not a detection**: runsc's sentry raises "PTRACE attached to process" at every sandbox start; the collector kept 162 such alerts with the sandbox's ID as class `platform` in `platform-alerts.jsonl`, none in the scored `alerts.jsonl` |
| Same actions in a non-Warden container / pod (namespace `default`) | 2 alerts, only counted (`dropped_other_lab_owned` 2) | 102 sentry alerts of the control pod, only counted (`dropped_other_lab_pod` 102), although the pod runs in the Warden node |
| Control IDs in any kept file | none (container ID, pod container and sandbox IDs searched) | none |
| A real Warden run | the runc lab's conformance session: "PTRACE anti-debug attempt" (seccomp probe) carried the lab's outer container ID; its binding from Docker's events matched; `detected` | a gVisor conformance run, bound by its pod sandbox's ID and scored on purpose against "PTRACE attached to process": `not_detected_by_cutoff`, because the start-up signature is not in the scored alerts |
| One benign hour (runc 7/7, gVisor 7/7) | | one record, healthy, 5,013,633 events, 0 drops, `workload_count` 1 (`explain.jsonl`: runc 1, gVisor 1); `observation.py`: `active_continuous_coverage` true, `gap_ns` 0 (not eligible only because it is two minutes) |

`smoke/checks.json` has every check true. Collector counters in both runs: `collector_errors` 0, `dropped_error` 0, `dropped_unresolved` 0, `duplicates` 0. The seven-day eligibility is shown with a simulated week (`detect/falco/test_recorder.py`): a healthy week is eligible; one gap, one hour without a workload, or one hour whose gVisor run failed is not. The error paths (a lookup error, a persistent error, a failing container in a pass, a failed write, a restart) are unit tests (`detect/falco/test_collector.py`).

## Images (by digest; `scripts/restore-tools.sh falco`)

| Instance | Reference | Image ID (manifest) | Stock rules sha256 |
|---|---|---|---|
| host, modern eBPF | `docker.io/falcosecurity/falco:0.45.2@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e` | `sha256:27a94a2841d872ec5ff158f2c86a9d87b0b74503d0445d63cbd57d6d1545e102` | `30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b` |
| gVisor engine (opt-in) | `docker.io/falcosecurity/falco:0.43.1@sha256:b4166a61f41e2fa638c041cac881d8bb32c284e3aaf282fdfed80f15f6eb55e3` | `sha256:9f3e058ce652ecf98aa2b4d8a41e80385b08ecb17d3153bb1d1a03a406378a31` | `f355cf51a7b9ce0c0f8e6e488a195ec4d3c3ba5e3893d81fa7506282cf8695a6` |

Receipts: [version/](version/). Falco 0.43.1's modern probe does not load on this kernel ([log](version/falco-0.43.1-modern-ebpf.log): the verifier rejects `signal_deliver`), so the host instance runs 0.45.2; 0.44.0 dropped the gVisor engine, so that instance would run 0.43.1. Falco 0.42.1 (`sha256:0ad5a831…12a6`, [receipt](version/falco-0.42.1.receipt.json)) was fetched only for the gVisor-engine test and removed. `detect/falco/gvisor-pod-init.json` (sha256 `dda7d6b2…5dcd`) is the output of the pinned 0.43.1's `--gvisor-generate-config=/warden-detect/gvisor.sock`. The smoke image is built from the host's `/usr/bin/busybox` (busybox-static 1:1.37.0-7ubuntu1, sha256 `df12634c…ed5b`); its `/etc/shadow` has no hash.

## The gVisor engine (opt-in, broken upstream)

[`version/gvisor-engine-crash/`](version/gvisor-engine-crash/) has three committed runs of the gVisor-engine instance at debug level against one probe pod in the k3s lab (`--without-corpus --falco`), made with [`run-variant.sh`](version/gvisor-engine-crash/run-variant.sh) and [`90-debug.yaml`](version/gvisor-engine-crash/90-debug.yaml) (alerts to `/dev/null`):

| Log | Falco | Trace configuration | Container Falco names (`adding container [...]`) | Pod sandbox from `crictl` (log header, newest first) | End |
|---|---|---|---|---|---|
| `falco-0.43.1-generated-config.log` | 0.43.1 | `detect/falco/gvisor-pod-init.json` | `0bcc0a6493f6` | `0bcc0a6493f6…` | `Error: vector`, exit 1 |
| `falco-0.42.1-generated-config.log` | 0.42.1 | the same | `eca8088f85d6` | `eca8088f85d6…` | `Error: vector`, exit 1 |
| `falco-0.43.1-without-container-start.log` | 0.43.1 | [`gvisor-pod-init-without-container-start.json`](version/gvisor-engine-crash/gvisor-pod-init-without-container-start.json) (no `container/start` point) | | | `Error: vector`, exit 1 |

`falco-0.43.1-smoke-run1.log` is the first round's smoke. This is [falcosecurity/libs#3074](https://github.com/falcosecurity/libs/issues/3074), open.

## Files

- `smoke/` (session `20261114T050135Z`): `checks.json`; `smoke-runc.json`, `smoke-gvisor.json` (what was run; the container, pod and sandbox IDs, the controls' too); `executions.jsonl`, `expected-rules.jsonl`, `bindings.jsonl`; `falco-warden-alerts.jsonl` (the scored alerts, unchanged: 110) and `falco-platform-alerts.jsonl` (runsc's start-up signature: 162); `alerts.jsonl`, `alert-provenance.jsonl`, `alert-import.out`, `metrics.json`; `review-groups.jsonl` and the all-`unreviewed` `review-map-template.jsonl`; `coverage.jsonl`, `explain.jsonl`, `observation.json` on the smoke's minute (contiguous: one record from the window's first healthy point to its end); `collector-host/` (heartbeats, metrics snapshots, registry, scoping, Falco's own log); `host-compare.json`.
- `benign/` (session `20261114T050242Z`): `workloads.jsonl` and both suites' logs; `coverage.jsonl`, `explain.jsonl` (with each runtime's count), `observation.json`; `review-groups.jsonl` (17 groups, 1,673 alerts: 98 scored, 1,575 platform), `review-map-template.jsonl`, `review-report.json` and `normal-alerts-unreviewed.jsonl.gz`; the two real runs' `bindings.jsonl`, `executions.jsonl`, `expected-rules.jsonl`, `alerts.jsonl`, `alert-provenance.jsonl`, `metrics.json`; `collector-host/` (the kept alerts, platform alerts and scoping gzip'ed); `seven-day-start-dry-run.txt` (`make detect-seven-day-start`, and with `CONFIRM=seven-day DRY_RUN=0`: both dry runs); `host-compare.json`.
- `restart/heartbeats.jsonl`: the collector killed with SIGKILL; systemd restarted it within 2 s (`NRestarts` 1) and the next heartbeat says `collector_restarts` 1, with a new `collector_started_at`.
- `version/`: the receipts and logs above.
- `host/`: the host's modules and global sysctls before anything of this work ran and after the first round's purge, and per session; the final purge's are in `final/`.
- `tdd/`: RED/GREEN logs.
- `final/`: `make test`, `make check`.

## Runs that did not count

- Round 1, smoke runs 1-3: an image mode bug (the read failed), unresolved pod-sandbox IDs, a service-account race; fixed (`tdd/red-smoke-fixes.log`).
- A host-only benign hour (session `20261114T042953Z`) whose runc run failed: the runc lab's build outputs had been removed with the first round's scratch; rebuilt (`scripts/build-runtime-lab.sh`), as the seven-day start does.
- A host-only benign hour (session `20261114T043211Z`) that dropped 282 sentry alerts as unresolved: lookups fell behind three-second gVisor runs. Fixed (`tdd/red-sandbox-resolution.log`); the next hour had none.

## Host

Every `down` compared the host with its `up` (`*/host-compare.json`, `host/sessions.txt`): no module added or removed, no global sysctl changed (only counters such as `fs.file-nr`). The modern eBPF probe loaded no kernel module. `kernel.bpf_stats_enabled` stayed 0.

## No other project's data

The collector wrote nothing of other projects' alerts; the heartbeats hold their counts (`dropped_other_container` beyond the controls: 1,611 in the benign hour, all other projects'). Before each commit every file here was searched for the first 12 hex digits of every container, network and image ID on the host that is not Warden's; there were no matches.
