# Task 13: Stratus round on the kind audit lab, 2026-11-15 UTC: attempt 2, stopped after run 3 of 40

**Attempt 2, kept as its own record. It is not scored and not on the coverage page.** The user then made two changes to the wrapper: `9adf201` checks Stratus's state before a fallback cleanup, and `2533736` gives Terraform the kubeconfig. The round was then run again from run 1 in a fresh lab and detector session: attempt 3, [../README.md](../README.md). `drive.py` here is the driver as it ran. Its paths are relative to the directory above, so it does not run from here. Attempt 1 is [../attempt-1/](../attempt-1/).

## What ran

- Branch `task13-stratus`, with the user's wrapper at `1058ca0`. `1058ca0` added the fallback `stratus cleanup`, which runs only after a failed or timed-out detonation.
- `make kind-audit-up` brought up Kubernetes 1.34.11 with the node on CPUs 0-7,16-31 ([run/kind-audit-up.log](run/kind-audit-up.log), [run/environment.json](run/environment.json)).
- `make detect-up DETECT_K8SAUDIT=1` started session `20261115T010215Z` ([run/detect-up.log](run/detect-up.log)).
- `drive.py start` set the window start at 01:02:22.725, k8saudit's first healthy point. The host's was 01:02:22.320.
- Records: [run/runs.jsonl](run/runs.jsonl). The wrapper's `receipt.json` and `executions.jsonl` for each run, as written, are in [runs/](runs/).

| # | Technique | Wrapper exit | Detonate | Cleanup (mode) | warden-lab empty after | Left outside warden-lab | Run (s) |
|---|---|---|---|---|---|---|---|
| 1 | create-admin-clusterrole (T1098.006) | 1 | 1 | 1 (fallback cleanup) | yes, first check | its three known objects, deleted by name (below) | 61.2 |
| 2 | privileged-pod (T1611) | 0 | 0 | 0 (detonate --cleanup) | yes, first check | nothing | 3.9 |
| 3 | steal-serviceaccount-token (T1528) | 1 | **1** | 1 (fallback cleanup) | yes, first check | nothing | 3.3 |

## The stop: run 3

- **What stopped the round.** `stratus detonate --cleanup k8s.credential-access.steal-serviceaccount-token` returned 1 after 3.3 s, and the wrapper's fallback `stratus cleanup` returned 1. The round stopped by its own rule: it stops on a nonzero cleanup unless the run is create-admin-clusterrole's known case. `warden-lab` was empty at the first check, nothing was left outside it, and Stratus kept no state for the technique.
- **Not in the record.** The wrapper keeps this technique's output only as a hash (`output_sha256`), so the error text is not here.
- **Diagnosis.** The user diagnosed run 3 from the API audit log before tearing the lab down. The API server saw one request from the run: a SelfSubjectAccessReview for `list pods` (201), Stratus's pre-flight. Nothing came from Terraform.
- **The likely cause.** It is not directly confirmed, because the error text is redacted.
  - Stratus v2.38.0's Terraform for this technique gives the `kubernetes` provider `config_path = ~/.kube/config` only if that file exists, and null otherwise. The run's HOME has no such file.
  - With a null `config_path`, hashicorp/kubernetes 2.13.0 reads `KUBE_CONFIG_PATH`. The wrapper set only `KUBECONFIG`.
  - nodes-proxy would have hit the same failure. Its Terraform creates a ClusterRole, a ServiceAccount and a ClusterRoleBinding.
  - privileged-pod and hostpath-volume were not affected. Their Terraform creates only a namespace, and `count = 0` skips it when the namespace (`warden-lab`) is given. So run 2 succeeded.
- **Why cleanup returned 1 on runs 1 and 3.**
  - Both detonations failed before warm-up set any state, so the technique stayed COLD.
  - The fallback `stratus cleanup` then gets Stratus's "already COLD" error. Run 1's `cleanup_output` names it. Run 3's output is redacted, but the pinned binary returned COLD for run 3's state when the user checked it.
- **The user's fixes before attempt 3:**
  - `9adf201`: after a failed detonation the wrapper runs `stratus status` with the same HOME and correlation ID. On COLD it skips the fallback cleanup, and the receipt records `cleanup_mode` "skipped already COLD", `cleanup_returncode` 0, `cleanup_invoked` false and the status check. COLD does not prove that resources were removed.
  - `2533736`: `KUBE_CONFIG_PATH` points to the same checked kubeconfig snapshot as `KUBECONFIG`.

## Run 1

create-admin-clusterrole failed as it does on Kubernetes 1.24 and later. Like attempt 1, it left ClusterRole `stratus-red-team-clusterrole`, ClusterRoleBinding `stratus-red-team-crb` and ServiceAccount `kube-system/stratus-red-team-serviceaccount`. The driver deleted each by exact name, and each `kubectl delete` exited 0. After that, the inventory equalled the start's and `warden-lab` was empty (`known_deleted` in [run/runs.jsonl](run/runs.jsonl)).

## Downloads

All three runs fetched Terraform 1.3.10 (sha256 `51274880…`). Run 2 fetched hashicorp/kubernetes 2.7.1 (`c49ac4c7…`) and run 3 fetched 2.13.0 (`674f8201…`). Each matches its reference in `.tools/stratus/receipt.json` (`downloads` in [run/runs.jsonl](run/runs.jsonl)).

## Not collected

The detector was brought down after the stop without `drive.py end` or `drive.py collect`, so the collector files and the session's audit lines are not in this directory. They stay in ignored paths:
- `.cache/detect/data/20261115T010215Z/`;
- the audit log, which was rotated at the next lab start to `.cache/kind-warden-lab/audit/audit-20261115T065141Z.log`. That file also holds the requests made during the diagnosis.
