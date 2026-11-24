| Technique (ATT&CK) | n | Succeeded | Detected | Rules fired on succeeded runs (alerts) | Alerts on failed runs | Start → audit event = Falco time, s (min / p50 / max) | Start → alerts file, s (min / p50 / max) |
|---|---|---|---|---|---|---|---|
| create-admin-clusterrole (T1098.006) | 1 | 0 | 0 | none | ClusterRole With Wildcard Created (1), K8s ClusterRoleBinding Created (1), Service Account Created in Kube Namespace (1) | – / – / – | – / – / – |
| privileged-pod (T1611) | 1 | 1 | 1 | Create Privileged Pod (1) | none | 3.092 / 3.092 / 3.092 | 3.114 / 3.114 / 3.114 |
