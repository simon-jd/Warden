Conversion PASS cites 32-rule catalogue tests inside initial overall FAILED batch (10 tests/6 harness errors); output SHA256 5f22f844a191c8f38d98695af525781d771977a7a16f911e97d016e9e9daf15c. This run executes only 3 AdapterEdgeTest methods and derives tags; no catalogue conversion/query reconstruction. Indexed/live UNRUN.

# ATT&CK tag coverage and local conversion

Generated from the actual Sigma tags after local pySigma/OpenSearch-backend conversion.
Tags describe related investigation scenarios. They are not technique success or detection-rate evidence.
Fixture events are synthetic. Fixture contract results belong to the local cover evidence.
OpenSearch indexed queries and live telemetry/detection remain UNRUN. Whole Task12 remains OPEN.

Rules: 32; tagged: 20; unassigned: 12; related techniques: 15.

| Rule ID | Action / indicator | Related tags | Local conversion | Indexed query | Live detection |
| --- | --- | --- | --- | --- | --- |
| 01e2eafe-0802-518d-bbac-d17c0c6b50e4 | Cloud role assignment change action | T1098.003 | PASS | UNRUN | UNRUN |
| 04b1c6e8-bc83-5f59-8b27-acf635891f11 | Socat execution indicator | unassigned | PASS | UNRUN | UNRUN |
| 06332649-217d-51ea-be55-6a3e9f0e38d5 | Curl process with shell parent | T1105 | PASS | UNRUN | UNRUN |
| 1753c574-aa24-59ed-827d-a688f2514636 | Unapproved destination port 22 | T1021.004 | PASS | UNRUN | UNRUN |
| 19f0e5bc-cf4d-5173-aee9-4142047fa8ae | Service account token issuance request | unassigned | PASS | UNRUN | UNRUN |
| 1e994d5d-1ab5-5b63-ad54-67a5a17b95a6 | Resource lock deletion action | unassigned | PASS | UNRUN | UNRUN |
| 21c89bd1-10e0-53da-9f47-0d173fa49bb6 | Secret read by nonallowlisted service account | T1552.007 | PASS | UNRUN | UNRUN |
| 3045a181-2881-5ffd-8413-7d35b2bf6c59 | RoleBinding modification request | T1098.006 | PASS | UNRUN | UNRUN |
| 354ba4e7-c8c7-5f4f-9b5a-6c8ae8292aac | Outbound flow outside illustrative IP allowlist | unassigned | PASS | UNRUN | UNRUN |
| 3753e3e6-fbcf-5103-8493-cf9a6f517a9d | Policy assignment deletion action | unassigned | PASS | UNRUN | UNRUN |
| 38b28b75-ff7f-54ec-ad62-7482c9298352 | Namespace-entry tool execution indicator | T1611 | PASS | UNRUN | UNRUN |
| 3bb574eb-18ef-5b54-90b7-ac292b52b11f | Wget process with shell parent | T1105 | PASS | UNRUN | UNRUN |
| 4d088f9b-509f-5ce6-ac7e-a410fdb27f32 | Kernel module loader execution indicator | unassigned | PASS | UNRUN | UNRUN |
| 56cd6626-b755-5bab-a3d5-31b85d03f3e4 | Certificate signing request by service account | unassigned | PASS | UNRUN | UNRUN |
| 58e9df96-53e1-5d33-8a80-3b48baf30196 | Diagnostic setting deletion action | T1685.002 | PASS | UNRUN | UNRUN |
| 5bebc4aa-c4d9-55fd-ab90-cebc911ecdb6 | Python process with shell parent | T1059.006 | PASS | UNRUN | UNRUN |
| 5dcab9b5-554a-5da0-bab2-f29b80cd543a | Pod port-forward request | T1572 | PASS | UNRUN | UNRUN |
| 65a7f1d4-3276-544f-8ca7-01e78c1db2d1 | Mining-named executable indicator | T1496 | PASS | UNRUN | UNRUN |
| 68eccb16-f177-5280-aec8-98e9b1d75ac7 | Kubectl process with shell parent | unassigned | PASS | UNRUN | UNRUN |
| 768e57f3-2e80-52d1-a2c7-106e69830e15 | Outbound cloud metadata IP flow | T1552.005 | PASS | UNRUN | UNRUN |
| 8a8ca06b-b667-5dfb-958e-0256c9d4372f | Cloud role definition change action | T1098.003 | PASS | UNRUN | UNRUN |
| 90c3f14c-fcf7-5b78-a05c-f43813fc28ee | Storage key rotation action | unassigned | PASS | UNRUN | UNRUN |
| 9ea8a65f-02da-57e8-88bc-9955b56384b4 | Pod attach request | T1609 | PASS | UNRUN | UNRUN |
| a44b26f2-1d12-5c80-87a6-ba82dc24db6d | Nonresolver destination port 53 | unassigned | PASS | UNRUN | UNRUN |
| bc213666-ff5e-5223-96f8-3d21affacea4 | Diagnostic setting modification action | T1685.002 | PASS | UNRUN | UNRUN |
| bcaf0c3b-51b0-5485-8a44-b2f6d50d64df | Pod exec request | T1609 | PASS | UNRUN | UNRUN |
| bf4653a2-80c9-58b5-8602-96998c1e82d0 | ClusterRoleBinding modification request | T1098.006 | PASS | UNRUN | UNRUN |
| df4d7f13-64ec-5102-967d-4b25096eb332 | Unix shell execution indicator | T1059.004 | PASS | UNRUN | UNRUN |
| e723ccc6-00ea-5cbd-934d-d803f343fea4 | Netcat process with shell parent | unassigned | PASS | UNRUN | UNRUN |
| ee10f37f-39d6-5746-ad09-186248ab32f6 | Storage shared-key listing action | unassigned | PASS | UNRUN | UNRUN |
| f29f2482-2c13-5fdc-8ef1-c01886f4de0c | Unapproved destination port 3389 | T1021.001 | PASS | UNRUN | UNRUN |
| f8b2e145-130b-548f-87bd-79cae5113265 | Ephemeral container modification request | T1610 | PASS | UNRUN | UNRUN |

| Related technique | Rule IDs |
| --- | --- |
| T1021.001 | f29f2482-2c13-5fdc-8ef1-c01886f4de0c |
| T1021.004 | 1753c574-aa24-59ed-827d-a688f2514636 |
| T1059.004 | df4d7f13-64ec-5102-967d-4b25096eb332 |
| T1059.006 | 5bebc4aa-c4d9-55fd-ab90-cebc911ecdb6 |
| T1098.003 | 01e2eafe-0802-518d-bbac-d17c0c6b50e4, 8a8ca06b-b667-5dfb-958e-0256c9d4372f |
| T1098.006 | 3045a181-2881-5ffd-8413-7d35b2bf6c59, bf4653a2-80c9-58b5-8602-96998c1e82d0 |
| T1105 | 06332649-217d-51ea-be55-6a3e9f0e38d5, 3bb574eb-18ef-5b54-90b7-ac292b52b11f |
| T1496 | 65a7f1d4-3276-544f-8ca7-01e78c1db2d1 |
| T1552.005 | 768e57f3-2e80-52d1-a2c7-106e69830e15 |
| T1552.007 | 21c89bd1-10e0-53da-9f47-0d173fa49bb6 |
| T1572 | 5dcab9b5-554a-5da0-bab2-f29b80cd543a |
| T1609 | 9ea8a65f-02da-57e8-88bc-9955b56384b4, bcaf0c3b-51b0-5485-8a44-b2f6d50d64df |
| T1610 | f8b2e145-130b-548f-87bd-79cae5113265 |
| T1611 | 38b28b75-ff7f-54ec-ad62-7482c9298352 |
| T1685.002 | 58e9df96-53e1-5d33-8a80-3b48baf30196, bc213666-ff5e-5223-96f8-3d21affacea4 |

Pending upstream contracts: trusted Warden denial context; privileged-Pod Request projection; runtime connect/Pod attribution.
Kubernetes objectRef is conditional bounded passthrough, not demonstrated live collection.
