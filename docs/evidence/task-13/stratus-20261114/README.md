# Task 13: Stratus round on the kind audit lab, 2026-11-15 UTC: attempt 3, 40 of 40 runs

**Attempt 3, the scored record.** Branch `task13-stratus` rebased on `implementation/warden` `2533736`, so the user's wrapper (`attacks/stratus/`, not changed here) includes:
- `1058ca0`: no second cleanup after a successful `detonate --cleanup`; a fallback `stratus cleanup` only after a failed or timed-out detonation;
- `9adf201`: before that fallback, `stratus status` with the run's HOME and correlation ID; on COLD the fallback is skipped and recorded (`cleanup_mode` "skipped already COLD");
- `2533736`: `KUBE_CONFIG_PATH` set to the same checked kubeconfig snapshot as `KUBECONFIG`, which the Terraform provider of steal-serviceaccount-token and nodes-proxy reads.

The two earlier attempts stopped early and are kept as their own records, not scored and not on the coverage page: [attempt-1/](attempt-1/README.md) (2 runs; the separate cleanup returned 1 after every clean run) and [attempt-2/](attempt-2/README.md) (3 runs; steal-serviceaccount-token's Terraform found no kubeconfig). This attempt is on the [coverage page](../../detection-coverage.md) with the corpus and Atomic rounds. The seven-day window was not started.

## Result

Eight Kubernetes techniques of Stratus Red Team v2.38.0, five runs each, sequential, scored on k8saudit alerts only against all 48 stock rules of `k8s_audit_rules.yaml` (the widest map: any alert attributed to the run inside its window counts, Stratus's warm-up and clean-up included; [expected-rules.jsonl](expected-rules.jsonl)).

| Technique (ATT&CK) | n | Succeeded | Detected | Rules fired on succeeded runs (alerts) | Start → audit event = Falco time, s (min / p50 / max) | Start → alerts file, s (min / p50 / max) |
|---|---|---|---|---|---|---|
| privileged-pod (T1611) | 5 | 5 | 5 | Create Privileged Pod (5) | 3.497 / 3.662 / 3.795 | 3.514 / 3.695 / 3.804 |
| hostpath-volume (T1611) | 5 | 5 | 5 | Create Sensitive Mount Pod (5) | 3.242 / 3.342 / 3.668 | 3.271 / 3.371 / 3.694 |
| steal-serviceaccount-token (T1528) | 5 | 5 | 5 | Attach/Exec Pod (5), K8s Serviceaccount Created (10), K8s Serviceaccount Deleted (5) | 3.087 / 3.232 / 3.403 | 3.111 / 3.267 / 3.428 |
| nodes-proxy (T1609) | 5 | 5 | 5 | K8s Serviceaccount Created (10), K8s Serviceaccount Deleted (5) | 3.097 / 3.198 / 3.294 | 3.131 / 3.217 / 3.338 |
| create-token (T1098) ¹ | 5 | 5 | 5 | Service Account Created in Kube Namespace (5) | 1.140 / 1.192 / 1.301 | 1.156 / 1.200 / 1.337 |
| create-client-certificate (T1649) | 5 | 5 | 0 | none | – | – |
| dump-secrets (T1552.007) ¹ | 5 | 5 | 0 | none | – | – |
| create-admin-clusterrole (T1098.006) | 5 | 0 (failed, expected) | – | 15 alerts on failed runs, below | – | – |

¹ No stock rule is written for this technique.

- **Successful executions detected: 25 of 35 (71.4%)** under the widest map. By Stratus technique 5 of 7; by ATT&CK ID 4 of 6 (T1611 merges privileged-pod and hostpath-volume) ([report.md](report.md), [metrics.json](metrics.json)).
- **Without the two techniques no stock rule is written for** (dump-secrets, create-token): 20 of 25 (80%) ([metrics-written-rules.json](metrics-written-rules.json)).
- **Time to detect** over the 25 detected runs (nearest rank), from the receipt's `started_at` to the first attributed alert's audit event (= Falco's `time`, the event's `stageTimestamp`): **p50 3.242 s, p95 3.729 s**. To the alert's arrival in the collector's `alerts.jsonl`: p50 3.271 s, p95 3.744 s. Most of it is Stratus starting and, for the four Terraform techniques, `terraform init` and `apply` before the first request; create-token has no Terraform and comes in at about 1.2 s.
- **create-admin-clusterrole** failed in all 5 runs, as it does on Kubernetes 1.24 and later. Its 15 alerts (3 per run) are alerts on failed executions, reported separately and not counted as detections.
- Per run: [runs.md](runs.md); per technique: [techniques.md](techniques.md); every attributed alert with its request, sender, match and times: [alerts-detail.json](alerts-detail.json).

## What fired, on which request

The widest map counts any attributed alert, so what "detected" rests on differs by technique. From [alerts-detail.json](alerts-detail.json) and the audit log ([audit-session.jsonl.gz](audit-session.jsonl.gz)):

| Technique | Alerts and the request behind each | Sent by | Matched by |
|---|---|---|---|
| privileged-pod | Create Privileged Pod: the technique's own pod create in `warden-lab` | Stratus | correlation ID, run label, namespace |
| hostpath-volume | Create Sensitive Mount Pod: the technique's own pod create | Stratus | correlation ID, run label, namespace |
| steal-serviceaccount-token | first, K8s Serviceaccount Created on Terraform's warm-up ServiceAccount (3.09–3.40 s); K8s Serviceaccount Created on the kubelet's token request for the pod (3.37–3.67 s); Attach/Exec Pod on the detonation's exec into the pod (4.16–4.88 s); K8s Serviceaccount Deleted at Terraform's destroy | Terraform; kubelet; Stratus; Terraform | namespace (and label for the warm-up create); correlation ID for the exec |
| nodes-proxy | first, K8s Serviceaccount Created on Terraform's warm-up ServiceAccount (3.10–3.29 s); K8s Serviceaccount Created on Stratus's token request for it (3.26–3.44 s); K8s Serviceaccount Deleted at destroy. The detonation's GET on `nodes/<node>/proxy/runningpods/` (one request per run, logged at two stages, 200) matched no rule | Terraform; Stratus; Terraform | namespace; correlation ID |
| create-token | Service Account Created in Kube Namespace on the technique's own token request (`serviceaccounts/token`) in `kube-system` | Stratus | correlation ID |
| create-client-certificate | none: its CSR create (201), approval update, get and delete (200) match no stock rule | – | – |
| dump-secrets | none: its `list secrets` across all namespaces (200) matches no stock rule ("K8s Secret Get Successfully" is `get`) | – | – |

- Only privileged-pod and hostpath-volume are detected by a rule describing the technique's own request. steal-serviceaccount-token's exec has its rule too, but the first alert of its runs, which sets the latency, is the warm-up. nodes-proxy is counted only through its ServiceAccount set-up, token request and clean-up. create-token is counted through a rule about ServiceAccount creation: the stock `serviceaccount` macro does not exclude subresources, so a token request in `kube-system` matches it.
- Terraform's requests carry the User-Agent `HashiCorp/1.0 Terraform/1.3.10` without Stratus's correlation token, so they are attributed only by namespace or label. Its cluster-scoped prerequisites are attributed to no run (below).

## What ran

1. `make kind-audit-up`: cluster `warden-lab`, Kubernetes 1.34.11, kind v0.33.0, node on CPUs 0-7,16-31 ([run/kind-audit-up.log](run/kind-audit-up.log), [run/kind-audit-status-up.log](run/kind-audit-status-up.log), [run/environment.json](run/environment.json): the node image, the Stratus binary's sha256, the wrapper commit and its files' hashes). `make detect-up DETECT_K8SAUDIT=1`: session `20261115T065213Z` ([run/detect-up.log](run/detect-up.log), [run/detect-status-before.log](run/detect-status-before.log)).
2. `drive.py start`: first healthy points host 06:52:28.639, k8saudit 06:52:29.234; the window starts at the later ([run/window-start.json](run/window-start.json)). By-name inventory of the cluster-scoped objects, the namespaces and `kube-system` ([run/inventory-before.json](run/inventory-before.json)).
3. `drive.py runs`: 40 wrapper invocations, 06:52:31.216 to 07:03:52.027 (11 min 21 s), each with a new `--out` under `.cache/stratus-20261114-attempt3/runs/` (ignored; it holds Stratus's state and downloads), and the wrapper run from `.cache/stratus-20261114-attempt3/`. Five rounds, the order of the eight techniques rotated each round, `make detect-status` after each ([run/detect-status-round-1.log](run/detect-status-round-1.log) … [5](run/detect-status-round-5.log)). Records: [run/runs.jsonl](run/runs.jsonl); the wrapper's `receipt.json` and `executions.jsonl` as written: [runs/](runs/).
   - Before every run: `make kind-audit-check-empty` exit 0, create-admin-clusterrole's three objects absent by name, and the inventory equal to the start's.
   - After every run: `warden-lab` empty at the first check, and the inventory equal to the start's (after the by-name deletions for create-admin-clusterrole).
   - 35 runs: detonate 0, `cleanup_mode` "detonate --cleanup", wrapper exit 0. 5 runs (create-admin-clusterrole): detonate 1, the status check read COLD, `cleanup_mode` "skipped already COLD", `cleanup_returncode` 0, wrapper exit 1. No other result occurred, so the round never stopped ([checks.json](checks.json)).
4. `drive.py end`: cutoff **2026-11-16 05:44:08.120**, then `make detect-down` ([run/detect-status-before-down.log](run/detect-status-before-down.log), [run/detect-down.log](run/detect-down.log), [run/detect-status-after-down.log](run/detect-status-after-down.log)), `drive.py collect`, `make kind-audit-down` ([run/kind-audit-down.log](run/kind-audit-down.log), [run/kind-audit-status-down.log](run/kind-audit-status-down.log)), then `score.py`.

**The cutoff came 22 h 40 min after the last run.** The lab and both detector instances stayed up from the end of the runs until the teardown on 2026-11-16, so the window (06:52:29.234 on 11-15 to 05:44:08.120 on 11-16) includes that idle stretch. No run's result depends on it: an alert counts for a run only inside that run's own window, and time to detect runs from each run's start. The idle stretch adds 197 unattributed alerts and the one host drop notice below, and makes `audit-session.jsonl.gz` and `collector-k8saudit/feed.jsonl.gz` large (16 MB and 12 MB).

## create-admin-clusterrole: the known failure

In each of its 5 runs the detonation created ClusterRole `stratus-red-team-clusterrole`, ClusterRoleBinding `stratus-red-team-crb` and ServiceAccount `kube-system/stratus-red-team-serviceaccount`, then waited a minute for a legacy token Secret that Kubernetes ≥1.24 does not create, and returned 1 (runs took 61.1–61.5 s). The wrapper's status check read COLD and skipped the fallback cleanup. As agreed with the user, the driver deleted exactly those three objects by name after each run; every `kubectl delete` exited 0, after which all three were absent, `warden-lab` was empty and the inventory equalled the start's ([known-deletions.md](known-deletions.md), `known_deleted` in [run/runs.jsonl](run/runs.jsonl)).

The 15 alerts on these failed runs, each attributed by the correlation token alone (cluster-scoped and `kube-system` objects) ([failed-runs.md](failed-runs.md)):

| Alert | Request | Audit event = Falco time after start (s) |
|---|---|---|
| ClusterRole With Wildcard Created | create clusterroles `stratus-red-team-clusterrole` | 1.078–1.425 |
| Service Account Created in Kube Namespace | create serviceaccounts `stratus-red-team-serviceaccount` (kube-system) | 1.103–1.427 |
| K8s ClusterRoleBinding Created | create clusterrolebindings `stratus-red-team-crb` | 1.105–1.430 |

They show the stock rules see this technique's objects being created, but the technique did not succeed, so they are not detections.

## Unattributed alerts

The k8saudit instance kept 297 alerts in the window; the importer attributed 65 (50 to succeeded runs, 15 to failed ones) and none to two runs ([alert-import.out](alert-import.out), [unattributed.json](unattributed.json)). The other 232:
- **20 inside the five nodes-proxy runs**, from Terraform's cluster-scoped prerequisites: ClusterRole With Write Privileges Created, K8s ClusterRoleBinding Created, K8s ClusterRoleBinding Deleted, K8s ClusterRole Deleted, one each per run. Cluster-scoped, no run label, and Terraform's User-Agent has no correlation token, so nothing ties them to the run.
- **15 from the driver's by-name deletions** after the create-admin-clusterrole runs (K8s ClusterRole Deleted, K8s ClusterRoleBinding Deleted, K8s Serviceaccount Deleted; `kubectl`), outside every run window.
- **197 after the last run**, all from the cluster's own components: K8s Serviceaccount Created (kube-controller-manager 56, kubelet 56 in `kube-system` and 28 in `local-path-storage`) and Service Account Created in Kube Namespace (kubelet 56, kube-controller-manager 1). All are their token requests (`serviceaccounts/token`), which the rules' `serviceaccount` macro matches. This is not a false-positive count (no normal-operation window was defined or reviewed), but it is what these two stock rules raise on an idle kind cluster: about 8.7 an hour over the 22.7 idle hours.

## Downloads against `.tools/stratus`

Every run fetched Terraform 1.3.10 into its own HOME (`51274880…`), and the four Terraform techniques their provider: hashicorp/kubernetes 2.7.1 for privileged-pod and hostpath-volume, 2.13.0 for steal-serviceaccount-token and nodes-proxy, with the lock files the driver copied while the runs worked. All 40 runs match the reference hashes in [tools/stratus.receipt.json](tools/stratus.receipt.json), none differ ([downloads.md](downloads.md), [downloads.json](downloads.json)).

## Detector health

Window 2026-11-15 06:52:29.234 to 2026-11-16 05:44:08.120, 23 hourly slices per instance, all healthy ([coverage.jsonl](coverage.jsonl), [explain.jsonl](explain.jsonl), [checks.json](checks.json)).
- **k8saudit:** 270,505 audit lines fed, none oversize, truncated, malformed or dropped; collector without error or restart. The one `feed_reader_gone` is the expected one at `down`, after the cutoff. 6,969 lines had been fed by the end of the runs (heartbeat 07:03:31.679, [run/detect-status-round-5.log](run/detect-status-round-5.log)).
- **Host:** 1.82 billion events. The collector kept no alert (the kind node is not a Warden container), counted the 15 alerts from the lab's pods as another container's (`dropped_other_nested`), and had none unresolved or pending at the cutoff. **One Falco drop notice**, at 2026-11-16 05:08:53 UTC: 13,382 system calls dropped in one second because the ring buffer was full (the notice itemizes 5,459 close exits and 1,793 open exits); `scap.n_drops` went from 0 to 13,382, and the last slice's `dropped_events` is 13,383. It came 22 h after the last run, and the host instance scores nothing in this round. During the runs (the first slice) both instances had 0 dropped events. The recorder's `healthy` flag does not include drops; they are reported in `dropped_events`.
- `make detect-down` added or removed no module and changed no global sysctl ([host/host-compare.json](host/host-compare.json)).

Latency hops over the 65 attributed alerts (min / median / max): API request received to audit event 1.4 / 3.1 / 56.1 ms; audit event to fed into Falco 0.4 / 5.5 / 10.2 ms; fed to the collector's `alerts.jsonl` 3.2 / 19.7 / 40.5 ms (`useAsync: false`).

## Teardown

`make detect-down` stopped and removed both Falco containers and both collectors. `make kind-audit-down` deleted the cluster, its network and kubeconfigs and kept the audit log. Afterwards no Warden container, kind cluster, network, collector process or unit was left. create-token and create-client-certificate did issue a token and a client certificate in every run. The wrapper keeps their outputs only as hashes, Stratus deletes the CSR at clean-up, and the cluster that would accept them is gone.

## What this shows, and what it doesn't

- Real Stratus Kubernetes techniques against a real API server: every attributed alert traces to its audit event, its feed time and its arrival, and the correlation token attributes cluster-scoped and `kube-system` requests that no label or namespace would.
- Of seven techniques that succeeded, the stock k8saudit rules describe the main request of two (privileged-pod, hostpath-volume) and the exec of a third (steal-serviceaccount-token). The widest map's 25 of 35 also counts set-up, clean-up and incidental matches; 0 of 10 for dump-secrets and create-client-certificate are real gaps in the stock rules. A narrower map is the user's to write.
- n = 5 per technique, one kind cluster, one Kubernetes version; not a sample of attacks. Not run: Stratus's cloud techniques, any run on AKS. No false-positive count.

## Files

- `drive.py` (start, runs, restore, end, collect) and `score.py` (import, metrics, report, tables, downloads, health, the coverage page). Attempts 1 and 2 keep their own drivers.
- `run/`: the window, the inventory, `runs.jsonl`, the environment, the audit session's offset and hash (`audit-session.json`), and every `make` output. `detect-status-before-down.log`, `detect-down.log` and `kind-audit-down.log` are the commands' terminal output as captured; the two `*-after-down`/`*-status-down` logs were run afterwards.
- `runs/`: each run's `receipt.json` and `executions.jsonl` as the wrapper wrote them; credential outputs stay hashed.
- `collector-k8saudit/` and `collector-host/`: the collectors' files as written (files over 1 MiB gzip'ed).
- `audit-session.jsonl.gz`: the 270,521 audit log lines from where the feed started.
- `host/`, `tools/`, and the scoring outputs (`expected-rules.jsonl`, `executions.jsonl`, `alerts.jsonl`, `alert-provenance.jsonl`, `alert-import.out`, `metrics*.json`, `report.md`, `alerts-detail.json`, `unattributed.json`, `runs.*`, `techniques.*`, `downloads.*`, `failed-runs.md`, `known-deletions.md`, `coverage.jsonl`, `explain.jsonl`, `checks.json`).
- `final/`: `make test` and `make check` in this worktree under `taskset -c 0-7,16-31`, both passing; the last line of each is its exit status.

Before the commit, every file of this attempt was searched for:
- JSON Web Tokens, private keys, `client-key-data` and token fields: none (`checks.json`);
- the first 12 hex digits of every container, network and image ID on the host (837): the only matches are the detector's Falco image in the heartbeats and the kind node image in `run/environment.json`, both named on purpose.
