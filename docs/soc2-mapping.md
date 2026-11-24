# Indicative SOC 2 control mapping

2026-10-25; analysis against BASE
`f127289b159a69b89045b16a3fcee0cd7562ac8d`. This appendix maps Warden's
[control register](threat-model.md#controls-and-evidence-states) to selected
CC6/CC7 criteria. It is not certification, an audit opinion or a determination
of operating effectiveness. Accepted Task1/2 implementation has the limits of
its local/lab evidence; partial and pending controls remain open.

Terminology follows AICPA's [2017 Trust Services Criteria, March 2020 text](https://assets.ctfassets.net/rb9cdnjh59cm/72xv4p67HVXKp6CjWmjkPk/1cdbfa19f6307e2720396b66a6194dc9/trust-services-criteria-updated-copyright.pdf),
printed pages28–37. The official [2022 revised-points-of-focus publication page](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
was checked; its download requires an account. This is a criterion-level indicative
mapping, not a claim to have reviewed the gated revised points of focus.
The short criterion topics below are paraphrases, not reproductions of the standard.

| Criterion | Topic | Related Warden control | Evidence / present gap |
|---|---|---|---|
| CC6.1 | Access architecture | [C1](threat-model.md#c1-tenant-api-boundary), [C4–6 runtime boundaries](threat-model.md#c4-runc-isolation), [C7](threat-model.md#c7-token-verification) | [Task1](evidence/task-1/README.md) and [Task2](evidence/task-2/README.md) scoped acceptance; runtime3/4 and production identity open |
| CC6.2 | User enrollment and removal | [C8](threat-model.md#c8-identity-lifecycle-and-elevation) | Pending actual assignment/SCIM/deactivation; [requirements](ACCEPTANCE.md) |
| CC6.3 | Authorization and separation of duties | [C1](threat-model.md#c1-tenant-api-boundary), [C3](threat-model.md#c3-scheduler-fencing), [C8](threat-model.md#c8-identity-lifecycle-and-elevation), [C12](threat-model.md#c12-detection-and-response) | [Real policy recheck](evidence/task-2/api-runtime/live/README.md); elevation and second-identity response pending |
| CC6.4 | Physical access | Organizational/provider responsibility; no software-control substitute | No physical security evidence collected; [external prerequisites](PREREQUISITES.md) are context, not provider assurance |
| CC6.5 | Asset disposal | Organizational/provider media disposal and data recoverability | No disposal evidence; runtime cleanup is not media sanitization. [Task2 cleanup scope](evidence/task-2/api-runtime/live/README.md) |
| CC6.6 | External boundary access | [C4](threat-model.md#c4-runc-isolation), [C7](threat-model.md#c7-token-verification), [C10](threat-model.md#c10-network-and-metadata-policy) | [Default network-none lab evidence](evidence/task-2/lab-live/README.md); production perimeter/TLS and metadata/egress integration pending |
| CC6.7 | Authorized data movement | [C1](threat-model.md#c1-tenant-api-boundary), [C10](threat-model.md#c10-network-and-metadata-policy), [C11](threat-model.md#c11-log-transport-and-access) | [Tenant-filtered local logs](evidence/task-2/api-runtime/live/README.md); allowlist, transport protection and remote log ACLs pending |
| CC6.8 | Malicious software controls | [C13](threat-model.md#c13-ci-and-artifact-admission), [C14](threat-model.md#c14-vulnerability-operations) | Task15 admission/signing and Task16 operations pending in [acceptance](ACCEPTANCE.md) |
| CC7.1 | Configuration and vulnerability monitoring | [C13](threat-model.md#c13-ci-and-artifact-admission), [C14](threat-model.md#c14-vulnerability-operations) | [Historical scan](evidence/task-1/vuln-after.log); continuous feeds/drift/SLA evidence pending |
| CC7.2 | Anomaly monitoring and analysis | [C11](threat-model.md#c11-log-transport-and-access), [C12](threat-model.md#c12-detection-and-response) | Real collection and rule coverage [pending](evidence/README.md#pending-integrations); seven-day false positives measured on the host detector ([evidence](evidence/task-13/seven-day-20261116/README.md)) |
| CC7.3 | Security event evaluation | [C12](threat-model.md#c12-detection-and-response) | Event triage/incident criteria and real evaluation evidence pending; [requirements](ACCEPTANCE.md) |
| CC7.4 | Incident response | [C12](threat-model.md#c12-detection-and-response), [C8](threat-model.md#c8-identity-lifecycle-and-elevation), [C9](threat-model.md#c9-workload-and-secret-lifetime) | Real dry-run, approval, idempotency, revocation and response timing [pending](evidence/README.md#pending-integrations) |
| CC7.5 | Incident recovery | [C3](threat-model.md#c3-scheduler-fencing), [C12](threat-model.md#c12-detection-and-response) | [Scoped lost-worker/node retirement](evidence/task-2/api-runtime/live/README.md) is available; incident recovery program, exercises and recurrence review remain pending |

No criterion is marked satisfied. Organizational ownership, scope, review periods,
access recertification, physical controls, provider assurance, incident communications
and durable operating records require separate evidence. The [current status](STATUS.md)
and [acceptance ledger](ACCEPTANCE.md) govern completion; a link or a unit test
does not establish an audit-period control conclusion.
