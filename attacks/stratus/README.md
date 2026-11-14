# Official Stratus, dedicated local kind only

This wrapper invokes an explicitly selected official Stratus executable, pinned
by SHA256. The only executable technique in the current phase is
`k8s.privilege-escalation.privileged-pod`. It creates a privileged pod inside
an existing dedicated `kind-warden-lab` cluster; the wrapper never creates a
cluster. Its T1611 label is Warden's local technique mapping for this probe.

Official references:

- [Getting started and target selection](https://stratus-red-team.cloud/user-guide/getting-started/)
- [Official privileged-pod technique and audit detection guidance](https://stratus-red-team.cloud/attack-techniques/kubernetes/k8s.privilege-escalation.privileged-pod/)
- [Detonation and cleanup CLI](https://stratus-red-team.cloud/user-guide/usage/)

The explicit kubeconfig must be JSON (kubectl supports JSON kubeconfigs), with
exactly one current context and cluster named `kind-warden-lab`, a loopback
HTTPS endpoint, embedded CA/client certificates and key, and no credential
plugins, proxy, external credential files or insecure TLS. All live node names
must match the dedicated `warden-lab-control-plane*` / `warden-lab-worker*`
kind inventory. Do not reuse a cluster holding other workloads. These guards
check supplied configuration and inventory; they do not authenticate the
operator's assertion that the local cluster is disposable.

Prepare a private JSON export from an already authorized dedicated lab:

```sh
/absolute/kubectl --kubeconfig /absolute/warden-lab.kubeconfig \
  --context kind-warden-lab config view --raw --minify -o json \
  > /private/lab/kubeconfig.json
chmod 600 /private/lab/kubeconfig.json
```

This export contains credentials: keep it private, outside published evidence.

```sh
bash attacks/stratus/run.sh --ack-dedicated-lab \
  --stratus /absolute/path/to/stratus --stratus-sha256 REVIEWED_BINARY_SHA256 \
  --kubectl /absolute/path/to/kubectl --kubeconfig /private/lab/kubeconfig.json \
  --pod-image busybox@sha256:REVIEWED_IMAGE_DIGEST \
  --out /absolute/existing/parent/NEW_RUN_DIRECTORY
```

The wrapper uses the real official `detonate ... --cleanup` command and also
attempts explicit cleanup after failure or timeout. Stratus state, Terraform
caches and the pinned pod configuration remain in the private output directory.
Cloud credentials and the caller's default HOME/kubeconfig are not passed
through. The pod carries `warden_lab=warden-lab` and a unique `warden_run_id`
label for collector attribution. `executions.jsonl` uses the existing metrics
contract; `receipt.json` preserves actual exit and cleanup statuses. Exit 0
requires successful detonation and cleanup; 1 indicates a failed execution or
cleanup; 2 indicates invalid configuration. Cleanup failure requires recovery
of this dedicated lab before reuse. No detection is inferred from tool output.

Azure is an explicit **blocked plan**, not a simulated success:

```sh
bash attacks/stratus/run.sh --plan \
  --technique azure.credential-access.app-service-publishing-credentials
```

The plan prints the official command without invoking any tool. Actual Azure,
Entra, AWS and GCP execution is rejected by the local-only guard. Azure/Entra
and AKS provisioning are not authorized in this phase. Future cloud support
needs separately authorized dedicated subscription/tenant guards, a reviewed
technique/tool pin, budget and cleanup receipts, and real Activity/Audit-log
collector evidence. The current local wrapper does not establish cloud
coverage.

```sh
python3 -B -m unittest attacks.stratus.test_emulate
```

The unit tests use synthetic configurations; they do not establish live
Stratus, Kubernetes detector or cloud execution.
