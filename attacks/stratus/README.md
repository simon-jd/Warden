# Official Stratus in a dedicated local kind cluster

`run.sh` executes one explicitly selected Kubernetes Stratus Red Team technique.
The binary must be an absolute path with an operator-supplied SHA256; the
kubeconfig must point to the loopback TLS context `kind-warden-lab`. The wrapper
never creates a cluster or invokes a cloud technique. The local technique IDs
below are Warden's ATT&CK analysis mappings; Stratus documents tactics but does
not assign these exact IDs to the eight entries.

| Stratus technique | Warden ATT&CK mapping |
|---|---|
| `k8s.credential-access.dump-secrets` | T1552.007 |
| `k8s.credential-access.steal-serviceaccount-token` | T1528 |
| `k8s.persistence.create-admin-clusterrole` | T1098.006 |
| `k8s.persistence.create-client-certificate` | T1649 |
| `k8s.persistence.create-token` | T1098 |
| `k8s.privilege-escalation.hostpath-volume` | T1611 |
| `k8s.privilege-escalation.nodes-proxy` | T1609 |
| `k8s.privilege-escalation.privileged-pod` | T1611 |

The [official Kubernetes list](https://stratus-red-team.cloud/attack-techniques/kubernetes/)
describes each operation. In particular, `dump-secrets` lists secrets across
**all namespaces**; `create-admin-clusterrole` creates objects in `kube-system`;
`create-client-certificate` can print a privileged certificate and private key.
Only run these in a disposable, dedicated kind cluster with no other workloads.
The wrapper validates the single context, loopback endpoint, node names and
an active namespace `warden-lab` labelled `project=warden,owner=warden-lab`.
It cannot prove that an operator-controlled cluster name refers to a disposable
cluster. Stratus may create cluster-scoped or `kube-system` objects despite the
fixed namespace. Issued tokens and certificates may remain usable after resource
cleanup; destroy the disposable lab cluster after credential techniques.

Create the owned namespace in the dedicated cluster before running the wrapper.
The wrapper requires it to exist and does not create or relabel it. Its JSON
kubeconfig must contain embedded CA/client certificates and key, with no
credential plugin, proxy, external credential file or insecure TLS. Keep this
credential file private. Example after the cluster and namespace are ready:

```sh
bash attacks/stratus/run.sh --plan \
  --technique k8s.credential-access.steal-serviceaccount-token

bash attacks/stratus/run.sh --ack-dedicated-lab \
  --technique k8s.credential-access.steal-serviceaccount-token \
  --stratus /absolute/path/to/stratus --stratus-sha256 REVIEWED_BINARY_SHA256 \
  --kubectl /absolute/path/to/kubectl --kubeconfig /private/lab/kubeconfig.json \
  --pod-image busybox@sha256:REVIEWED_IMAGE_DIGEST \
  --out /absolute/existing/parent/NEW_RUN_DIRECTORY
```

The wrapper passes its validated private kubeconfig snapshot as both
`KUBECONFIG` (Stratus and kubectl) and `KUBE_CONFIG_PATH` (the Terraform
Kubernetes provider). The command writes a per-run Stratus config with
namespace `warden-lab` and Pod labels `project=warden`, `owner=warden-lab`,
`warden.dev/run=<run ID>`, `warden_lab=warden-lab` and
`warden_run_id=<run ID>`. It also sets
`STRATUS_RED_TEAM_CORRELATION_ID` to a UUIDv4 for detonation and cleanup,
so state for concurrent runs is separate. The Warden run ID and Pod label are
`stratus-<UUID>`, and `receipt.json` records both that run ID and the bare
`correlation_id` to join API audit `userAgent` values to runs even when no Pod
label exists. [Stratus configuration](https://stratus-red-team.cloud/user-guide/getting-started/#configuration-file)
supports namespace and Pod labels; its
[correlation ID](https://stratus-red-team.cloud/user-guide/concurrent-executions/)
isolation is separate from collector attribution. Pod labels do not tag API-only
operations, ClusterRoles, or other resources created directly by a technique.
The current online Falco collector watches the separate k3s lab, not this kind
cluster; a future live Stratus run needs an audit collector for this exact kind
cluster before its execution can count toward detection metrics.

`create-admin-clusterrole` expects an automatically generated legacy
ServiceAccount token Secret; Kubernetes 1.24+ stopped creating those by
default, so this official technique is expected to fail at that step in the
current kind lab. `dump-secrets` and `create-token` have no dedicated Warden
rule today. A successful simulation of either must not be reported as a
detection.

The wrapper hashes an explicitly pinned Stratus binary up to 512 MiB;
Atomic keeps its 256 MiB default. Stratus child processes may write regular
files up to 512 MiB each for Terraform and provider downloads, while captured
stdout/stderr remains limited to 8 MiB. These are local bounds, not proof that
a particular Stratus/Terraform run succeeds. The wrapper captures execution
and cleanup status. A successful `detonate --cleanup` already cleans Stratus
state. After failure or timeout, the wrapper checks `stratus status` for the
same technique, run HOME and correlation ID. It skips the separate cleanup if
Stratus reports COLD; for WARM, DETONATED or an unreadable state it attempts
cleanup. The receipt records the status command result, parsed state, output
hash and byte count, and whether cleanup was invoked. When COLD skips the
second command, `cleanup_returncode` is 0 for the existing driver gate while
`cleanup_invoked` is false and `cleanup_command_returncode` is null. This 0
means only that Stratus reports COLD; it does not prove Kubernetes resources
were removed. For every technique except privileged-pod, command output is omitted
from the receipt; its SHA256 and byte count are kept because it may contain
service-account tokens, secrets or private keys. Keep the private run directory
and Stratus state out of published evidence. Exit 0 requires both detonation
and cleanup to succeed; a nonzero cleanup needs manual review of that dedicated
cluster. A successful command is not evidence that the detector alerted.

Azure/Entra, AWS and GCP techniques remain blocked by the local-only guard.
`--plan` for the Azure example displays a blocked command without invoking a
tool. Cloud execution needs its own scope, budget, cleanup and collector review.

```sh
python3 -E -s -B -m unittest attacks.stratus.test_emulate
```

These tests use synthetic Kubernetes responses and fake commands. They do not
establish a live Stratus run or detector result.
