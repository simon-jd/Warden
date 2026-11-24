# Seven-day normal window, 2026-11-16 to 2026-11-23 (Task 13)

The false-positive count of the online detector in normal operation: Falco 0.45.2's host instance (modern eBPF, the
stock rules, not tuned) on the shared lab host for seven days, with Warden's hourly benign workload, then every kept
alert reviewed per group. Branch `seven-day-window` (from `task13-stratus` at 239dfa6, plus 9c72514: `WARDEN_CPUSET`
kept the detector, its timers and the labs on CPUs 0-7).

## Result

| | |
|---|---|
| Window | 2026-11-16T06:22:36.637725377Z to 2026-11-23T06:22:36.637725377Z (7.00 days, from the first healthy point) |
| Source | `falco-host` only (no k8saudit instance, no kind lab) |
| Hourly slices | 168 of 168 healthy; 0 dropped events in every slice; Falco's own drop monitor: 0 occurrences ([host/falco.log](host/falco.log)) |
| Benign workload in the window | conformance suite on runc 177/177 passed (13–19 s each), on gVisor 177/177 passed (34–37 s); every slice has at least one passed run on both |
| Alerts kept in the window | 293,549 |
| Reviewed | 293,372 false positive, 177 true positive, 0 unreviewed ([review-report.json](review-report.json)) |
| False positives per day | 41,910 (1,746 per hour); 94.3% are gVisor's runsc tracing its stubs |
| `observation.py` | `eligible_seven_day_window: true`, covered 604,800 s, gap 0, rejected intervals 0 ([observation.json](observation.json)) |

The groups, as `review.py` formed them (rule, `proc.name`, container class) and as they were decided ([review-map.jsonl](review-map.jsonl)):

| Rule | Process | Class | In window | Disposition | Why |
|---|---|---|---:|---|---|
| PTRACE attached to process | gvisor_sentry | platform | 276,549 | false positive | runsc's systrap platform attaches to its stub processes with ptrace while it runs a sandbox (about 1,560 per gVisor run) |
| Drop and execute new binary in container | bridge, host-local, loopback, kubectl, ctr, find, exe, modprobe, containerd, k3s-server, unpigz, cat, containerd-shim, runc, umount (15 groups) | node | 16,823 | false positive | the gVisor lab's k3s node unpacks its bundled binaries into the container's writable layer at start and runs them during each gVisor run (CNI plugins for every pod, kubectl, find, …) |
| PTRACE anti-debug attempt | warden-probe | sandbox | 177 | true positive | the runc conformance's seccomp probe calls `ptrace(PTRACE_TRACEME)` (seccomp denies it): the behaviour the rule describes, from an attack fixture |

Per-group counts are in [review-report.json](review-report.json); [review-groups.jsonl](review-groups.jsonl) counts the
whole session, including the hours after the window's end. The dispositions were filled in per group, as the bulk review is
designed; `review.py` itself decides none.

What the count means: the stock rules on this lab raise about 42,000 alerts a day from the labs' own infrastructure, so the
rate measures the untuned stock rules against gVisor and k3s infrastructure on one host, not a production false-positive
rate. "Normal operation" is Warden's own hourly workload; there were no tenants or users.

## How it ran

- Start, 2026-11-16 06:22 UTC: `WARDEN_CPUSET=0-7 make detect-seven-day-start CONFIRM=seven-day` (session
  `20261116T062228Z`; [plan.json](plan.json)). The two transient user timers: the hourly benign run (2 minutes after the
  start, then 1 hour after each run's start) and the stop (1 week 15 minutes after the start).
- The host did not reboot, sleep or restart Docker, and the Falco container never restarted
  ([run/stop-timer-before-manual-stop.txt](run/stop-timer-before-manual-stop.txt)).
- **The stop did not fire on time.** Other software on the host reloaded the user's systemd manager 35 times during the
  session (below). A reload re-based a waiting transient timer's `OnActiveSec` on the reload, so the stop moved at every
  reload, from the first on 2026-11-17 21:25 UTC; the last, at 2026-11-23 00:30:59 UTC (requested from
  `sponsoratlas-airflow-end.service`, another project), put it at 2026-11-30 00:45:59 UTC instead of 2026-11-23 06:37:36 UTC. It was found at 2026-11-24 05:06:59 UTC and the stop was run by hand by starting the same unit
  (`systemctl --user start warden-detect-seven-day-stop.service`, the command the timer would have run) at 05:08:22 UTC,
  22 h 45 min after the window's end ([run/seven-day-stop.journal](run/seven-day-stop.journal)). The leftover timer went
  with the unit. Coverage, review and `observation.py` use the plan's start and end, so the extra hours (23 more benign
  runs on each runtime and their alerts) are outside the window and not counted.
- **Some hours had two runs.** 35 reloads of the user manager happened between the start and the stop (29 from
  `systemctl` with no unit recorded, in ssh sessions to the host; 4 from `sponsoratlas-airflow-end.service`; 2 from
  `snapd.session-agent.service`; [run/user-manager-reloads.journal](run/user-manager-reloads.journal)). The 33 that came
  while the benign timer was waiting re-based its 2-minute trigger as well (the other two came during a run), so 20 runs
  on each runtime came early (4–59 minutes after the previous one), each about 2 minutes after a reload
  ([run/early-runs.jsonl](run/early-runs.jsonl)). In the window that is 177 runs per runtime in
  168 hours: 159 slices with one run per runtime, 9 with two.
- The stop: `down` (container removed, collector stopped, host compared), then the records in
  `.cache/detect/data/20261116T062228Z/seven-day/`. Afterwards no Warden or kind container and no Warden timer remains
  ([run/detect-status-after-stop.log](run/detect-status-after-stop.log), [run/timers-after-stop.txt](run/timers-after-stop.txt)).
  The host comparison ([host/host-compare-20261116T062228Z.json](host/host-compare-20261116T062228Z.json)): nine
  kernel modules were loaded between the session's start and the stop (`act_gact`, `af_packet_diag`, `cls_u32`, `mptcp_diag`, `netlink_diag`,
  `raw_diag`, `sch_ingress`, `unix_diag`, `xsk_diag`), none removed, no sysctl changed apart from volatile counters;
  nothing records what loaded them.
- The collector over the whole session: 0 errors, 0 restarts, 0 overflow, 0 unresolved, 0 malformed; 6,859 host-process
  and 559,249 other-container alerts dropped as not Warden's, by design.

## The review and the observation

```sh
D=.cache/detect/data/20261116T062228Z; R=$D/seven-day
python3 -I -B detect/falco/review.py apply --alerts $D/host/alerts.jsonl --alerts $D/host/platform-alerts.jsonl \
  --scoping $D/host/scoping.jsonl --map $R/review-map.jsonl --start 2026-11-16T06:22:36.637725377Z \
  --end 2026-11-23T06:22:36.637725377Z --out $R/normal-alerts.jsonl --report $R/review-report.json
python3 -E -s -B -m detect.report.observation --coverage $R/coverage.jsonl --normal-alerts $R/normal-alerts.jsonl \
  --source falco-host --start 2026-11-16T06:22:36.637725377Z --end 2026-11-23T06:22:36.637725377Z \
  --observed-until 2026-11-24T05:08:27Z
```

`seven-day-stop`'s own run of `observation.py` on the unreviewed alerts failed with `error: file exceeds byte limit`
([observation-unreviewed.json](observation-unreviewed.json)): the metrics reader accepted at most 16 MiB and 100,000
records per file, and the week's unreviewed file was 293,549 records in 60.4 MB (61.6 MB once reviewed). The bounds were raised to 256 MiB and 1,000,000 records
(`detect/report/detection_metrics.py`, its test updated; no computation changed), and [observation.json](observation.json)
is that run on the reviewed alerts (1.3 s, 335 MB peak memory; [observation-time.txt](observation-time.txt)). [render.py](render.py) re-rendered the
[coverage page](../../detection-coverage.md) with the same normal alerts; it checks that every part of the report other
than the normal window equals the Stratus round's `metrics-all-rounds.json`.

## Files

- [plan.json](plan.json), [coverage.jsonl](coverage.jsonl) and [explain.jsonl](explain.jsonl) (one line per hourly slice), [workloads.jsonl](workloads.jsonl) and [workload-logs.tar.gz](workload-logs.tar.gz) (all 400 runs of the session), [host/heartbeats.jsonl.gz](host/heartbeats.jsonl.gz), [host/falco.log](host/falco.log), the host snapshot before and the comparison after.
- [review-groups.jsonl](review-groups.jsonl), [review-map-template.jsonl](review-map-template.jsonl), [review-map.jsonl](review-map.jsonl), [review-report.json](review-report.json), [normal-alerts.jsonl.gz](normal-alerts.jsonl.gz) (every alert of the window with its disposition), [observation.json](observation.json), [metrics-all-rounds-normal.json](metrics-all-rounds-normal.json).
- Not committed, for size (1.34 GB in all): the raw alerts, platform alerts, scoping and health records; their sha256 and sizes are in [raw-sha256.txt](raw-sha256.txt) and [raw-sizes.txt](raw-sizes.txt), and the coverage receipts hash the exact lines used.
- [final/](final/): `make test` and `make check` after the change (358, 231 and 14 tests, 3 skipped; no failures).

## Limits

- One host, one week, one detector source. gVisor is covered at host level only (a sandbox's own system calls are not
  seen); Firecracker and the Kubernetes audit path are not in this window.
- The normal operation is Warden's own benign workload; the count is the stock rules' noise on this lab, dominated by
  two infrastructure signatures, and says nothing about a tuned rule set.
- The dispositions are a reviewer's, per group, not per alert; `observation.py` notes that the
  ledger and dispositions need external validation (`coverage_verified: false`).
- The stop came 22 h 45 min late and some hours had two runs, both because other software reloaded the shared user
  systemd manager; neither changes the window's coverage, but a future window should arm its stop on an absolute
  calendar time.
