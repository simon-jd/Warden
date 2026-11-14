# JIT operator access

`New(pool, tenant, config, caller, bindings, clock)` constructs a tenant-bound service.
`Request(user, role, duration, reason)` persists a request; `Approve(id, approver)`
grants it; `Expire()` reconciles pending operations and removes expired access.
Every instance needs trusted dependencies. There is no default allow-all caller,
implicit credential lookup, automatic API route or background controller.

The caller must bind canonical user strings to its authenticated principal and
active tenant membership. `Authorize` checks request/approval actions;
`AuthorizeGrant` checks both requester membership and the approver's permission
to grant the configured alias to that requester. It is repeated immediately
before activation. A separate maintenance principal must authorize `expire`
(with empty user/role arguments). These are integration contracts, not an
implemented identity provider. Do not expose the string APIs directly as an
unauthenticated HTTP endpoint. Tenant and role configuration are trusted wiring;
never derive them from the request. Configure only reviewed, least-privilege
namespaced Roles, excluding permission to escalate, bind arbitrary roles or
mutate this control plane. The configuration map is copied at construction.

Requests require `0 < duration <= 2h`; requester and approver must differ.
Duration begins with the first persisted approval intent, not the request, and
retries never extend it. Timestamps are rounded downward to PostgreSQL's
microsecond precision, so a sub-microsecond window can expire before activation.
Equality with the deadline is expired. A clock used in production must be
trustworthy and UTC; the tests inject a clock. An active successful retry is an
idempotent acknowledgement of durable state, not a fresh grant or external
health check.

Approval commits a `grant_pending` record and real Task1 audit intent first.
It reserves an empty external binding, persists its UID/resourceVersion,
rechecks policy/deadline/session, then activates that exact reserved version.
Only confirmed activation followed by an atomic `active` + `jit.granted`
transaction returns success. A per-request PostgreSQL session lock serializes
calls; state predicates and external UID/version fences protect late work.
The audit head lock is never held across external I/O.

Any incomplete or ambiguous grant is revoked, never resumed on restart.
Failures attempt removal even when PostgreSQL/audit is unavailable. Durable
`grant_pending`, `active` or `revoke_pending` remains for retry; raw provider
errors are not stored. Revocation clears subjects with a fresh version fence,
deletes the owned object conditionally and confirms absence before committing
`expired` + `jit.expired`. Audit failure after deletion leaves retryable state;
confirmed events occur once. `grant_confirmed` distinguishes a committed grant
from cleanup of an uncertain attempt. Tombstones prevent regranting an ID.

`Expire` is a bounded batch of up to 64 rows. A persisted sequence rotates
attempted rows so permanent failures cannot starve later due grants. Deployment must run it with an
authorized maintenance identity at startup before readiness and periodically,
repeating until drained, alerting and retrying errors. This repository change
does not wire that scheduler. A failed scheduler or unavailable Kubernetes API
can leave access beyond its deadline. An expiry annotation is descriptive and
has no Kubernetes enforcement power. Do not claim a hard external TTL guarantee
until supervised reconciliation or an independently expiring binding is deployed
and tested.

`NewKubernetesBindings` provides an HTTP RBAC v1 adapter for namespaced
RoleBindings. Supply an explicit HTTPS cluster endpoint, a trusted RoundTripper
that validates TLS/CA and honors cancellation, and a bounded bearer-token
provider. There is no kubeconfig, environment or host credential discovery.
Direct RoundTrip calls prevent HTTP redirect following. Tokens and transport
error bodies are not returned. Responses have a 64KiB cap, duplicate/case-alias
key checks and exact target/owner/role/subject checks. Reservation is POST with
no subjects. Activation is a single UID/resourceVersion-conditional PUT;
ambiguous results are never retried as activation. Removal GETs and validates
ownership, PUTs empty subjects and a fresh `warden.io/revocation-fence` annotation
with the current version, then verifies the returned fence, unchanged UID, advanced
version and empty subjects before conditional DELETE and confirmed 404. The fence
must differ from its stored value, including on retries: an empty-to-empty PUT
alone can be a no-op that preserves the version. At most three conflicts are
reconciled within a two-second operation context. A foreign UID is never deleted.

This adapter's deployment still requires real-cluster verification of RBAC,
least-privilege credentials, conditional-update/delete behavior (including no
create-on-update after a late activation), restart/recovery and expiry scheduling.
The injected RoundTripper fixture tests HTTP contracts only; it is not evidence
of actual Kubernetes permissions or real authenticated identity.

The original three tests use real PostgreSQL and real Task1 `AppendTx`/`Verify`.
Additional cases cover policy boundaries, retry/expiry fencing, audit rollback,
ambiguous operations, restart and deletion/audit retry. No test skips missing
PostgreSQL. Controlled execution is prepared separately; do not use historical
unbounded mutable-image launcher scripts.
