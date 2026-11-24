| Technique (ATT&CK) | n | Succeeded | Detected | Rules fired on succeeded runs (alerts) | Alerts on failed runs | Start → audit event = Falco time, s (min / p50 / max) | Start → alerts file, s (min / p50 / max) |
|---|---|---|---|---|---|---|---|
| dump-secrets (T1552.007) ¹ | 5 | 5 | 0 | none | none | – / – / – | – / – / – |
| steal-serviceaccount-token (T1528) | 5 | 5 | 5 | Attach/Exec Pod (5), K8s Serviceaccount Created (10), K8s Serviceaccount Deleted (5) | none | 3.087 / 3.232 / 3.403 | 3.111 / 3.267 / 3.428 |
| create-admin-clusterrole (T1098.006) | 5 | 0 | 0 | none | ClusterRole With Wildcard Created (5), K8s ClusterRoleBinding Created (5), Service Account Created in Kube Namespace (5) | – / – / – | – / – / – |
| create-client-certificate (T1649) | 5 | 5 | 0 | none | none | – / – / – | – / – / – |
| create-token (T1098) ¹ | 5 | 5 | 5 | Service Account Created in Kube Namespace (5) | none | 1.140 / 1.192 / 1.301 | 1.156 / 1.200 / 1.337 |
| hostpath-volume (T1611) | 5 | 5 | 5 | Create Sensitive Mount Pod (5) | none | 3.242 / 3.342 / 3.668 | 3.271 / 3.371 / 3.694 |
| nodes-proxy (T1609) | 5 | 5 | 5 | K8s Serviceaccount Created (10), K8s Serviceaccount Deleted (5) | none | 3.097 / 3.198 / 3.294 | 3.131 / 3.217 / 3.338 |
| privileged-pod (T1611) | 5 | 5 | 5 | Create Privileged Pod (5) | none | 3.497 / 3.662 / 3.795 | 3.514 / 3.695 / 3.804 |
