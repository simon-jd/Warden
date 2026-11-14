# Local response executor

This Linux-only package runs one playbook step per alert. SuspendTenant is
destructive: it binds one exact tenant and always needs an authenticated second
approver (below). The containment actions RevokeVaultLease, IsolatePod,
CordonNode and DisableAzureServicePrincipalCredential name only a resource type
in the playbook (`vault_lease`, `pod` as `namespace/name`, `node`,
`azure_app_credential` as `appObjectId/keyId`). The concrete target comes from
the alert and is validated per type. They need a second approver only if the
playbook sets `requires_approval`. TerminatePod (`pod`) also takes its target
from the alert but is destructive: it deletes the pod with no grace period, to
close connections a quarantine label leaves open, and its playbook is rejected
unless it sets `requires_approval`. All kinds share the journal deduplication
per alert ID, dry-run and Unknown-outcome rules described below.

Adapters (`adapters.go`): `VaultLeases` (real Vault `sys/leases/revoke`),
`Kubernetes` (merge-patch: quarantine label for policies/cilium/quarantine.yaml,
or `spec.unschedulable`), `AzureCLI` (`az ad app credential delete`), and
`Router` to combine them. Graph answers "No password credential found" for any
keyId that is not a password of the app, so `AzureCLI` then reads the app: a
certificate is removed with `--cert`, a federated credential is refused as
ErrUnsupported, and the key counts as already gone only if the app lists it
nowhere. The Vault adapter has run against a real Vault, the Kubernetes adapter
on a kind cluster and the Azure adapter (client secrets only) against Entra
(docs/evidence/time-to-contain.md); the certificate and federated paths are
tested against a fake `az` only. It is not a running service, and multi-step
playbooks are not implemented.

Use ParsePlaybook for the strict JSON subset in the .yaml example, then New with a
trusted configured private journal path, explicit allowed tenant list, authority
and client. The example is inert data; no file is automatically loaded. Its exact
tenant target must match the alert's authenticated tenant and typed resource.
One executor/playbook binds one exact tenant target. Reopening the same journal
with another authorized configuration keeps tenant/alert keys separate.

New copies configuration slices and performs no filesystem operations. Handle
uses a context of the action budget plus three seconds (five seconds for a
two-second action); HandleContext also respects the caller's cancellation.
Preview validates structure and returns Preview/ApprovalNeeded without calling
either port or opening, locking, creating or appending any journal. It does not
claim the requested operation is authorized. Missing ports are permitted for a
preview; actual execution fails closed.

The authority must authenticate both requester and approval proof, resolve aliases
to globally stable CanonicalID values, verify current revocation and tenant roles,
and authenticate the returned tenant/alert/rule/playbook/step-hash/action/resource
binding and issued/expiry times. Executor requires distinct canonical principals
and distinct issuer/subject pairs, respond:execute and respond:approve roles, exact
binding, and lifetime at most five minutes. An approval boolean or caller-supplied
subject is not accepted. The tests' recording authority proves only this local
contract; it does not implement OIDC, approval storage or revocation.

The authority context is at most one second; the action context is at most the
action's budget and the remaining approval lifetime. The budget is two seconds,
except 30 s for DisableAzureServicePrincipalCredential, whose adapter runs up to
three `az` processes (one took up to 1.71 s in the live Entra drill); killing
`az` after Graph has deleted the credential would only turn a done containment
into Unknown. Parent deadlines also apply. TTL and
cancellation are checked before reservation and immediately before the action.
These contexts require cooperative ports. File I/O, injected clock functions and
noncooperative callbacks cannot be forcibly interrupted. No hard execution SLA or
rollback is claimed. After an action starts, any error, panic, cancellation or
expiry becomes Unknown, with a redacted error and no automatic retry.

The journal requires a trusted local filesystem with reliable fsync/flock
semantics, an owned 0700 directory and a single-link owned 0600 regular file.
Opening each directory component rejects symlinks. The alert never selects paths.
No out-of-band writer or replacement is permitted; an advisory lock cannot defend
against a hostile same-UID process. The exclusive file lock stays until Close.
Close returns ErrBusy during a client operation and keeps its descriptor/lock for
completion. It never unlocks and then writes a completion through an old FD.

The journal stores only hashed tenant/alert keys, binding digests, record kind,
version and outcome. No credential, raw alert, raw resource or principal is stored.
These unkeyed hashes are not secret protection or authentication. Framed records
have a length and checksum for corruption detection. A complete intent is fsynced
before the client is invoked; completion is separately fsynced. Newly created
files are fsynced, and every locked, validated opener must successfully fsync the
parent directory before any intent/client, including an existing pathname whose
creation durability is unconfirmed. Directory-sync failure returns ErrStorage.
Limits are 1024 keys, 1MiB total, 512-byte
payloads, one intent/completion per key, with completion capacity reserved first.
No eviction, expiry, repair or automatic reset exists.

Repeated deliveries require fresh authorization. A changed binding conflicts;
pending repeats return InProgress; terminal repeats return NoOp and the saved
status. Unknown repeats return ErrOutcomeUnknown. Pre-reservation rejection makes
no dedup change. Cancellation/expiry after intent but before the action records
Cancelled without calling the client, and later delivery does not resume it.

On reopen, an intent without valid completion becomes Unknown and suppresses
further attempts. A crash before successful intent fsync cannot have called the
client; a crash afterward may have missed the action or lost its outcome. This
provides durable attempt suppression, not exactly-once external effects. It can
miss containment and needs explicit reconciliation plus adapter idempotency.
Partial I/O, corruption, bad ordering, capacity exhaustion and lock failure never
trigger repair/retry. Uncertain writes poison the executor; the lock remains until
no operation is in flight and Close releases it. If completion sync fails, the
live result is Unknown; reopen may see a valid completion or unresolved intent,
or fail on a torn record. Every case suppresses a new attempt.

Known unimplemented names are RevokeVaultLease,
DisableAzureServicePrincipalCredential, IsolatePod and CordonNode. They return
ErrUnsupported before ports/storage. Obsolete DisableAWSAccessKey and
DisableGCPServiceAccountKey are rejected. The deliberate Azure replacement is
one Vault-issued service-principal credential, not whole-account disablement.
Exact Graph operations/permissions and Vault lease-to-credential semantics are
unverified prerequisites. A pod label is not policy enforcement; cordon is not
eviction. No cloud or host mutation is authorized by this component.

Controlplane internal packages are inaccessible from root respond under Go's
internal rule; tenant.Claims has no actor identity, the API has no suspension
route, and audit.Log.Append starts its own PostgreSQL Background context. No
production wiring or durable response-audit adapter is supplied. Task8 identity,
Task13 alert provenance/live detection, real adapters and genuine replay/action
timestamps/outcome, dry-run, durable idempotency and second-identity approval
evidence remain open. Temporary-file restart/fault tests are local behavior, not
power-loss or live action evidence. Run only the root-admitted affected cover;
go.sh/Docker/downloads, old tasks, services and broad ./... runs are outside scope.
