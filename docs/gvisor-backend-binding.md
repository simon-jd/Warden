# gVisor backend identity binding — Task 3 first code substep

This was written before the driver. The driver now exists
(`runtimes/gvisor/gvisor.go`, one Kubernetes Job per run on the `gvisor`
RuntimeClass), and the live tests open it through `gvisor.Bind` against the
k3s + runsc lab; see [gvisor-lab.md](gvisor-lab.md). The scheduler still
rejects `gvisor` operator configuration.

`gvisor.Bind` combines deployment identifiers into a domain-separated SHA-256
digest and opens `gate.NewBound`. The existing random node authority and that
digest are written in one node record, under the existing cross-process lock,
then fsynced with the containing directory. Start/Reap continue to use the
existing permanent launch markers and ambiguity rules.

| Identity field | Required provenance |
| --- | --- |
| `APIServer` | Exact credential-free HTTPS endpoint from trusted deployment configuration |
| `CASHA256` | SHA-256 of the exact CA bundle bytes used to authenticate that endpoint |
| `ClusterUID` | `kube-system` namespace UID observed over that authenticated connection; Kubernetes has no intrinsic cluster UID |
| `Namespace`, `NamespaceUID` | Fixed dedicated `warden-lab` namespace and its observed object UID |
| `NodeName`, `NodeUID` | Dedicated node name and observed Node object UID |
| `NodeConfigSHA256` | SHA-256 of the exact reviewed node input manifest bytes |

Kubernetes assigns object UIDs to distinguish object incarnations; see its
[Object Names and IDs documentation](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids).
Using `kube-system` as a cluster-incarnation marker is this deployment's convention.
An operator must not clone existing authority, CA material, or backend identifiers
into a replacement deployment and treat it as the original node.

The future node input manifest must pin runtime binaries, CRI handlers/base OCI
specs, runsc flags, seccomp, and isolation policy. It must exclude tokens,
kubeconfig credentials, private keys, and other secrets. A config digest describes
inputs; it does not prove that a node applied them. Object UIDs and a CA pin are
deployment identities, not remote attestation or proof of runtime quiescence.

Reopening with any changed field fails before a driver can be returned. Opening
a bound record through legacy `gate.New` also fails. Every existing legacy record
is refused by `NewBound`, including one without consumed runs. A missing/empty
node record beside other state is an orphan and is refused. There is no automatic
migration, identity reset, or copied-authority recovery. A new gVisor deployment
needs a fresh private gate directory and its own node lifecycle; existing runc
configuration is unchanged. The scheduler's requirement that registered drivers
share one authority is unchanged; combining a legacy runc gate with this new gate
is not supported by this substep.

The original requirements for the driver were: validate current
cluster/namespace/node identity before every API read or mutation, not only when
the process starts; durably bind each original Job/Pod UID to its consumed RunID;
verify ownership and UID preconditions on deletion; and preserve ambiguous
submission as pending even after an early not-found response. What the driver
does now: it checks the kube-system, namespace and node UIDs before every
mutation (Job create and delete), not before reads; it deletes only with a UID
precondition and waits until the Job and the Pod objects are gone; it keeps the
Job and Pod UIDs in memory only, so after a restart `Reap` finds the Job by its
RunID-derived name in the bound namespace. Ambiguity is still the gate's
(`gate.NewBound` markers). This helper itself performs none of those API checks.
The scheduler continues to reject `gvisor` operator configuration.

Tests use the real filesystem, locks, gate transitions, and a subprocess reopen.
Their runtime boundary doubles perform no Kubernetes or runsc work. They verify
identity mismatch rejection, no legacy/orphan adoption, durable consumed IDs,
and preservation of uncertain launch state. They are not sandbox conformance or
cold-start measurements.
