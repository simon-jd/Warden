| # | Round | Technique | Wrapper | Detonate | Cleanup | Outcome | Status | Run (s) | Rules on the run | First alert (s): event / alerts file |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | create-admin-clusterrole | 1 | 1 | 1 | failed | excluded_outcome | 61.2 | ClusterRole With Wildcard Created (1), K8s ClusterRoleBinding Created (1), Service Account Created in Kube Namespace (1) | 1.073 / 1.096 |
| 2 | 1 | privileged-pod | 1 | 0 | 1 | succeeded | detected | 3.7 | Create Privileged Pod (1) | 3.092 / 3.114 |
