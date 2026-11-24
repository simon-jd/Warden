| # | Round | Technique | Wrapper | Detonate | Cleanup (mode) | Outcome | Status | Run (s) | Rules on the run | First alert (s): event / alerts file |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | create-admin-clusterrole | 1 | 1 | 0 (skipped already COLD) | failed | excluded_outcome | 61.5 | ClusterRole With Wildcard Created (1), K8s ClusterRoleBinding Created (1), Service Account Created in Kube Namespace (1) | 1.425 / 1.459 |
| 2 | 1 | privileged-pod | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.3 | Create Privileged Pod (1) | 3.795 / 3.804 |
| 3 | 1 | steal-serviceaccount-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 41.2 | Attach/Exec Pod (1), K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.315 / 3.329 |
| 4 | 1 | hostpath-volume | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 3.8 | Create Sensitive Mount Pod (1) | 3.242 / 3.271 |
| 5 | 1 | nodes-proxy | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.0 | K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.182 / 3.201 |
| 6 | 1 | dump-secrets | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 1.2 | none | – / – |
| 7 | 1 | create-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 1.3 | Service Account Created in Kube Namespace (1) | 1.300 / 1.337 |
| 8 | 1 | create-client-certificate | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 3.2 | none | – / – |
| 9 | 2 | privileged-pod | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.1 | Create Privileged Pod (1) | 3.497 / 3.514 |
| 10 | 2 | steal-serviceaccount-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 41.0 | Attach/Exec Pod (1), K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.228 / 3.267 |
| 11 | 2 | hostpath-volume | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.2 | Create Sensitive Mount Pod (1) | 3.668 / 3.694 |
| 12 | 2 | nodes-proxy | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.1 | K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.206 / 3.235 |
| 13 | 2 | dump-secrets | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 1.1 | none | – / – |
| 14 | 2 | create-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 1.3 | Service Account Created in Kube Namespace (1) | 1.301 / 1.335 |
| 15 | 2 | create-client-certificate | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 3.2 | none | – / – |
| 16 | 2 | create-admin-clusterrole | 1 | 1 | 0 (skipped already COLD) | failed | excluded_outcome | 61.1 | ClusterRole With Wildcard Created (1), K8s ClusterRoleBinding Created (1), Service Account Created in Kube Namespace (1) | 1.078 / 1.116 |
| 17 | 3 | steal-serviceaccount-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 40.4 | Attach/Exec Pod (1), K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.403 / 3.428 |
| 18 | 3 | hostpath-volume | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 3.9 | Create Sensitive Mount Pod (1) | 3.342 / 3.371 |
| 19 | 3 | nodes-proxy | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.1 | K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.198 / 3.217 |
| 20 | 3 | dump-secrets | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 1.1 | none | – / – |
| 21 | 3 | create-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 1.2 | Service Account Created in Kube Namespace (1) | 1.140 / 1.156 |
| 22 | 3 | create-client-certificate | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 3.3 | none | – / – |
| 23 | 3 | create-admin-clusterrole | 1 | 1 | 0 (skipped already COLD) | failed | excluded_outcome | 61.3 | ClusterRole With Wildcard Created (1), K8s ClusterRoleBinding Created (1), Service Account Created in Kube Namespace (1) | 1.240 / 1.267 |
| 24 | 3 | privileged-pod | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.2 | Create Privileged Pod (1) | 3.662 / 3.695 |
| 25 | 4 | hostpath-volume | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.2 | Create Sensitive Mount Pod (1) | 3.576 / 3.613 |
| 26 | 4 | nodes-proxy | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 3.9 | K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.097 / 3.131 |
| 27 | 4 | dump-secrets | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 1.2 | none | – / – |
| 28 | 4 | create-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 1.2 | Service Account Created in Kube Namespace (1) | 1.192 / 1.200 |
| 29 | 4 | create-client-certificate | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 3.2 | none | – / – |
| 30 | 4 | create-admin-clusterrole | 1 | 1 | 0 (skipped already COLD) | failed | excluded_outcome | 61.3 | ClusterRole With Wildcard Created (1), K8s ClusterRoleBinding Created (1), Service Account Created in Kube Namespace (1) | 1.262 / 1.293 |
| 31 | 4 | privileged-pod | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.1 | Create Privileged Pod (1) | 3.559 / 3.593 |
| 32 | 4 | steal-serviceaccount-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 41.1 | Attach/Exec Pod (1), K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.232 / 3.261 |
| 33 | 5 | nodes-proxy | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.2 | K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.294 / 3.338 |
| 34 | 5 | dump-secrets | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 1.4 | none | – / – |
| 35 | 5 | create-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 1.2 | Service Account Created in Kube Namespace (1) | 1.168 / 1.176 |
| 36 | 5 | create-client-certificate | 0 | 0 | 0 (detonate --cleanup) | succeeded | not_detected_by_cutoff | 3.5 | none | – / – |
| 37 | 5 | create-admin-clusterrole | 1 | 1 | 0 (skipped already COLD) | failed | excluded_outcome | 61.2 | ClusterRole With Wildcard Created (1), K8s ClusterRoleBinding Created (1), Service Account Created in Kube Namespace (1) | 1.220 / 1.251 |
| 38 | 5 | privileged-pod | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 4.3 | Create Privileged Pod (1) | 3.729 / 3.744 |
| 39 | 5 | steal-serviceaccount-token | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 40.9 | Attach/Exec Pod (1), K8s Serviceaccount Created (2), K8s Serviceaccount Deleted (1) | 3.087 / 3.111 |
| 40 | 5 | hostpath-volume | 0 | 0 | 0 (detonate --cleanup) | succeeded | detected | 3.8 | Create Sensitive Mount Pod (1) | 3.258 / 3.272 |
