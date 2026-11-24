# Task 13: Stratus round on the kind audit lab, 2026-11-14 UTC: stopped after run 2 of 40

**Attempt 1, kept as its own record.** The user changed the wrapper afterwards (`1058ca0`: no second cleanup after a successful `detonate --cleanup`; a fallback `stratus cleanup` only after a failed or timed-out detonation; the receipt records `cleanup_mode`), and the round was rerun from run 1 in a fresh lab and detector session: [../README.md](../README.md). The scripts here were moved one directory down with their files (their paths adjusted); `score.py` reproduces every output byte for byte.

Branch `task13-stratus` at `c7b90c7` (the user's wrapper at `795c5db`), in its own worktree on home-ubuntu. The plan was the eight techniques the wrapper admits, five runs each, sequential, scored on k8saudit alerts under the widest map. **Two runs ran, and the round stopped at run 2 by its own rule ("stop if a cleanup returns nonzero").** With the wrapper as committed, its separate `stratus cleanup` returns 1 after every run whose `detonate --cleanup` already cleaned up, so every run would stop the round. What the wrapper should do about that is the user's call (`attacks/` was not changed). Nothing here is on the coverage page, and the seven-day window was not started.

## What ran

1. `make kind-audit-up` (cluster `warden-lab`, Kubernetes 1.34.11, node on CPUs 0-7,16-31; [run/kind-audit-up.log](run/kind-audit-up.log), [run/environment.json](run/environment.json)). `make detect-up DETECT_K8SAUDIT=1`: session `20261114T195926Z`, both instances ready ([run/detect-up.log](run/detect-up.log)). `drive.py start`: first healthy points host 19:59:45.857, k8saudit 19:59:46.295. The window starts at the later one. It also took a by-name inventory of the cluster-scoped objects, the namespaces and `kube-system` ([run/inventory-before.json](run/inventory-before.json)).
2. Run 1 and run 2, one wrapper invocation each, with `make kind-audit-check-empty` before each (exit 0 both times) and after each (exit 0 at the first attempt). Each run had a new `--out` under `.cache/stratus-20261114/runs/` (ignored; it holds the Stratus state and downloads, and none of it is in this directory). Records: [run/runs.jsonl](run/runs.jsonl); the wrapper's `receipt.json` and `executions.jsonl` as written are in [runs/](runs/).
3. After run 1: restore ([run/resumed-02.json](run/resumed-02.json), below). After run 2: the stop. Then `drive.py end` (cutoff 20:17:27.891), `make detect-down`, `drive.py collect`, `make kind-audit-down`, then `score.py`.

| # | Technique | Wrapper exit | Detonate | Cleanup | Outcome | warden-lab empty after | Left outside warden-lab | k8saudit alerts on the run (widest map) |
|---|---|---|---|---|---|---|---|---|
| 1 | create-admin-clusterrole (T1098.006) | 1 | 1 | 1 | failed (expected on ≥1.24) | yes | ClusterRole `stratus-red-team-clusterrole`, ClusterRoleBinding `stratus-red-team-crb`, ServiceAccount `kube-system/stratus-red-team-serviceaccount` | ClusterRole With Wildcard Created, Service Account Created in Kube Namespace, K8s ClusterRoleBinding Created (alerts on a failed execution) |
| 2 | privileged-pod (T1611) | 1 | 0 | 1 | succeeded, detected | yes | nothing | Create Privileged Pod |

## The stop: the wrapper's cleanup return code

- **Run 2, `k8s.privilege-escalation.privileged-pod`.** `stratus detonate --cleanup` returned 0. Its log, which the wrapper keeps for this technique only, runs from warm-up (Terraform init and apply) through the pod's creation to "Reverting detonation" and "Cleaning up technique prerequisites with terraform destroy". The wrapper's second command, `stratus cleanup k8s.privilege-escalation.privileged-pod`, then returned **1** with `k8s.privilege-escalation.privileged-pod is already COLD and should already be clean, use --force to force cleanup` and a status table showing COLD ([runs/02-privileged-pod/receipt.json](runs/02-privileged-pod/receipt.json), `cleanup_output`). The wrapper exited 1. The lab was clean: `warden-lab` was empty at the first check and nothing was left outside it.
- **Why.** In Stratus v2.38.0 (`v2/pkg/stratus/runner/runner.go`), `CleanUp` returns that error for a COLD technique unless `--force` is given. A successful `detonate --cleanup` leaves the technique COLD and removes its state, and the second command's runner reads no state, which it takes as COLD. So at `795c5db`, `cleanup_returncode` is 1 and the wrapper exits 1 on **every** run whose first cleanup worked. A real cleanup failure cannot be told from this by the return code. The output that would tell them apart is redacted for the other seven techniques, and only the post-run checks (namespace and inventory) can.
- **Run 1, `k8s.persistence.create-admin-clusterrole`.** As expected, the detonation failed (1); the redacted output does not say why. Its cleanup also returned 1, and the ClusterRole, the ClusterRoleBinding and the `kube-system` ServiceAccount it creates stayed. Same code: the technique has no Terraform prerequisites, so warm-up sets no state, and a failed detonation leaves it COLD. Both cleanups then return the COLD error before anything else. `Revert` runs only from DETONATED, so no Stratus cleanup can remove what this technique creates when it fails. The names carry no per-run part, so every failed run of it leaves the same three objects, and the next run of it would meet them.
- **Restored by exact name** between runs, outside any run window: `drive.py restore` deleted the three objects (each `kubectl delete` exit 0). The inventory then equalled the start's, and `warden-lab` was empty ([run/resumed-02.json](run/resumed-02.json)). Those three deletes are the session's only unattributed alerts ([unattributed.json](unattributed.json)).
- Not done here: any change to the wrapper. Possible directions for the user: run the separate cleanup only when `detonate --cleanup` did not return 0 or timed out; or count Stratus's COLD answer as clean. For create-admin-clusterrole, delete the three named objects after each run, or recreate the lab. A rerun should start over from run 1 in a fresh lab and detector session.

## Downloads against `.tools/stratus`

Both runs fetched into their own `HOME` ([downloads.md](downloads.md), [downloads.json](downloads.json); the reference is [tools/stratus.receipt.json](tools/stratus.receipt.json)):
- Terraform 1.3.10 at `home/.stratus-red-team/terraform`: sha256 `51274880…4911` in both runs, the reference's `terraform/terraform`.
- Run 2 only (run 1's technique has no Terraform code): hashicorp/kubernetes 2.7.1 at `home/.stratus-red-team/plugin-cache/registry.terraform.io/hashicorp/kubernetes/2.7.1/linux_amd64/terraform-provider-kubernetes_v2.7.1_x5`, `c49ac4c7…bb50`, the reference's. The technique's `.terraform.lock.hcl` lists `zh:` `c50d6617…0d0a`, the reference's linux_amd64 zip. The provider sits in Stratus's plugin cache, which survives the clean-up. The technique's own directory, lock file included, is removed at the clean-up, and the driver copied the lock file while it ran.
- Terraform also wrote `home/.terraform.d/checkpoint_signature` and `checkpoint_cache`: it called HashiCorp's checkpoint (version-check) service. The wrapper's clean environment does not set `CHECKPOINT_DISABLE`.

## Alerts and latency (runs 1-2 only; not a result)

Rule map: every one of the 48 stock k8saudit rules for both runs ([expected-rules.jsonl](expected-rules.jsonl)); no syscall rule. The importer attributed 4 of the session's 7 k8saudit alerts ([alerts-detail.json](alerts-detail.json)). Times are from the receipt's `started_at`. "Audit event" is the event's `stageTimestamp` (stage ResponseComplete). Falco's `time` for a k8s_audit alert is that same value, so the two are one column.

| Run | Alert | Request | Sent by | Matched by | Request received (s) | Audit event = Falco time (s) | Fed (s) | Alerts file (s) |
|---|---|---|---|---|---|---|---|---|
| 1 | ClusterRole With Wildcard Created | create clusterroles | Stratus client | correlation ID | 1.071 | 1.073 | 1.079 | 1.096 |
| 1 | Service Account Created in Kube Namespace | create serviceaccounts (kube-system) | Stratus client | correlation ID | 1.074 | 1.075 | 1.079 | 1.097 |
| 1 | K8s ClusterRoleBinding Created | create clusterrolebindings | Stratus client | correlation ID | 1.076 | 1.077 | 1.079 | 1.097 |
| 2 | Create Privileged Pod | create pods (warden-lab) | Stratus client | correlation ID, label, namespace | 3.087 | 3.092 | 3.101 | 3.114 |

- Run 1's three alerts come from a failed execution, so they are not detections ([metrics.json](metrics.json): `alerts_on_failed_or_skipped_executions` 3). They are cluster-scoped or in `kube-system`, and only the correlation token attributes them: Stratus's User-Agent `stratus-red-team_<correlation_id>`.
- Run 2 was detected by the rule written for it. Most of its 3.09 s is Stratus starting and Terraform's init and apply (warm-up) before the pod is created. Audit event to fed: 9 ms; fed to the alerts file: 13 ms.
- 1 of 1 successful run detected. With n = 1 there is no rate or p50/p95 to report ([techniques.md](techniques.md), [runs.md](runs.md), [report.md](report.md)).

## Detector health

Window 19:59:46.295 to 20:17:27.891 ([coverage.jsonl](coverage.jsonl), [explain.jsonl](explain.jsonl), [checks.json](checks.json)):
- Both instances' records were healthy with 0 dropped events.
- Host: 24.8 million events. The collector kept no alert, dropped none as unresolved, and had none pending at the cutoff. The 1,626 alerts of other containers were counted and dropped by design.
- k8saudit: 3,727 audit lines fed in the window, with no oversize, truncated or malformed line. The one `feed_reader_gone` is the expected one at `down`, after the cutoff.
- `make detect-down` added or removed no module and changed no global sysctl ([host/host-compare.json](host/host-compare.json)).

## kubectl's cache in the worktree

The wrapper's own kubectl checks (`get nodes`, `get namespace`) run before it sets `HOME`, so kubectl wrote its discovery and HTTP cache to `.kube/cache` in the working directory. That was the worktree root, at 19:59:56.07 UTC in run 1, between the check-empty and the receipt's `started_at`. The cache was removed by exact path. From run 2 on, the driver runs the wrapper with `.cache/stratus-20261114/` as its working directory, and the cache landed in `.cache/stratus-20261114/.kube/`. The wrapper itself was not changed.

## Teardown

`make detect-down` stopped both containers and collectors ([run/detect-down.log](run/detect-down.log), [run/detect-status-after-down.log](run/detect-status-after-down.log)). `make kind-audit-down` deleted the cluster, its network and kubeconfigs, and kept the audit logs ([run/kind-audit-down.log](run/kind-audit-down.log), [run/kind-audit-status-down.log](run/kind-audit-status-down.log)). No Warden container, kind cluster, network or unit was left running. The credentials the techniques could issue (create-token, create-client-certificate) were never created: neither technique ran.

## What this shows, and what it doesn't

- A real Stratus run's API requests reach the scored alerts with the stock rule that fired, attributed by the correlation token alone where no label or namespace applies (cluster-scoped and `kube-system` objects). Every alert can be followed to its audit event, its feed time and its arrival.
- The Terraform and provider downloads of these two runs match the reference hashes.
- No detection rate and no latency distribution. Six techniques did not run, among them the two with no written rule (dump-secrets, create-token). The coverage page is unchanged: it still covers the corpus and Atomic rounds, and its scope note still lists Stratus as not run. `score.py` writes the page only when all 40 runs are there.

## Files

- `drive.py` (the sequence: start, runs, restore, end, collect) and `score.py` (import, metrics, report, tables, downloads, health).
- `run/`: the window, the inventory, `runs.jsonl` (each run's checks, wrapper exit, receipt fields, download hashes, the lock file's text), `resumed-02.json`, the environment, the audit session's offset and hash, and every `make` output.
- `runs/`: each run's `receipt.json` and `executions.jsonl` as the wrapper wrote them. The credential outputs stay redacted, which is the wrapper's choice for every technique but privileged-pod.
- `collector-k8saudit/` and `collector-host/`: the collectors' files as written.
- `audit-session.jsonl.gz`: the 3,801 audit log lines from where the feed started.
- `host/`: the detector's host snapshots and their comparison.
- `tools/`: the receipts of `.tools/stratus` and `.tools/falco-k8saudit`.
- Scoring outputs: `expected-rules.jsonl`, `executions.jsonl`, `alerts.jsonl`, `alert-provenance.jsonl`, `alert-import.out`, `metrics.json`, `metrics-written-rules.json`, `report.md`, `alerts-detail.json`, `unattributed.json`, `runs.*`, `techniques.*`, `downloads.*`, `coverage.jsonl`, `explain.jsonl`, `checks.json`.
- `final/`: `make test` and `make check` in this worktree, both under `taskset -c 0-7,16-31`.

Before the commit, every file here was searched for:
- JSON Web Tokens, private keys, `client-key-data` and token fields: none (`checks.json`);
- the first 12 hex digits of every container, network and image ID on the host (833): the only matches are the detector's Falco image in the heartbeats and the kind node image in `run/environment.json`, both named on purpose.
