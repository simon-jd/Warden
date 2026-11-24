# Detection coverage

Observed until 2026-11-16T05:44:08.120215Z: 40 executions, 65 alerts.

## Scope

- The Stratus round alone: eight Kubernetes techniques of Stratus Red Team v2.38.0, five runs each, on the kind audit lab; k8saudit alerts only, against all 48 stock k8s_audit_rules.yaml rules (the widest map).
- No stock rule is written for dump-secrets (T1552.007) or create-token (T1098); create-admin-clusterrole (T1098.006) fails on Kubernetes 1.24 and later. T1611 is privileged-pod and hostpath-volume together.

## Detection rate

| Measure | Detected | Of | Rate |
|---|---|---|---|
| Successful executions | 25 | 35 | 71.4% |
| Techniques with a successful execution | 4 | 6 | 66.7% |

Alerts on failed or skipped executions: 15.

## Time to detect

Over the 25 detected successful executions (nearest-rank): p50 3.242 s, p95 3.729 s.

## False positives in normal operation

No normal-operation window was supplied, so there is no false-positive count.

## Per technique

| Technique | Successful | Detected | Failed | Skipped | Fastest detection (s) |
|---|---|---|---|---|---|
| T1098 | 5 | 5 | 0 | 0 | 1.140 |
| T1098.006 | 0 | 0 | 5 | 0 | – |
| T1528 | 5 | 5 | 0 | 0 | 3.087 |
| T1552.007 | 5 | 0 | 0 | 0 | – |
| T1609 | 5 | 5 | 0 | 0 | 3.097 |
| T1611 | 10 | 10 | 0 | 0 | 3.242 |
| T1649 | 5 | 0 | 0 | 0 | – |

## Per execution

| Execution | Run | Technique | Outcome | Status | Executed (UTC) | Time to detect (s) | First alert |
|---|---|---|---|---|---|---|---|
| `stratus-01d23d0b-03dc-4183-9974-bb55074ec075` | stratus-01d23d0b-03dc-4183-9974-bb55074ec075 | T1098.006 | failed | excluded_outcome | 2026-11-15T06:55:59.936368Z | – | falco-8eba6b8800c7ce890f70b6cd7dd094978c8887876518852df01e9bfb016e4a4d |
| `stratus-058c58d6-0210-4517-b75c-74b4ed431512` | stratus-058c58d6-0210-4517-b75c-74b4ed431512 | T1611 | succeeded | detected | 2026-11-15T06:59:20.120643Z | 3.576 | falco-c2b3745ffe43215b955012223159f78230758c620d933e859c0e093b828a9849 |
| `stratus-0ff49478-7bcc-4a6d-b9b4-26eb450a0562` | stratus-0ff49478-7bcc-4a6d-b9b4-26eb450a0562 | T1611 | succeeded | detected | 2026-11-15T06:54:24.639598Z | 3.242 | falco-48f39e12e14513f39df6956c47bee7016f77c1126c3f9c62e3d73162cb1bb5db |
| `stratus-13886bca-d6e8-4a1a-939f-65e60b06815e` | stratus-13886bca-d6e8-4a1a-939f-65e60b06815e | T1552.007 | succeeded | not_detected_by_cutoff | 2026-11-15T06:59:32.409570Z | – | – |
| `stratus-13bf6186-c162-4702-b402-d2fa8fac21cf` | stratus-13bf6186-c162-4702-b402-d2fa8fac21cf | T1098 | succeeded | detected | 2026-11-15T06:59:35.263519Z | 1.192 | falco-67fd5ad1c140ae701538304bf89820f926c0e20ccefdcbea383f0861121480bf |
| `stratus-15e70833-4460-4005-b84f-5df5c9453f75` | stratus-15e70833-4460-4005-b84f-5df5c9453f75 | T1611 | succeeded | detected | 2026-11-15T07:00:47.797582Z | 3.559 | falco-d456086fc7b20eedefeffc44cc4e0e1a91f51835c3ee25953d948a93219cbe77 |
| `stratus-24d137bd-ef99-4d08-ae81-76cfd097ddc5` | stratus-24d137bd-ef99-4d08-ae81-76cfd097ddc5 | T1649 | succeeded | not_detected_by_cutoff | 2026-11-15T06:55:55.045442Z | – | – |
| `stratus-2f19b72c-fc46-4900-b0d8-7da324b9a491` | stratus-2f19b72c-fc46-4900-b0d8-7da324b9a491 | T1649 | succeeded | not_detected_by_cutoff | 2026-11-15T06:58:03.866164Z | – | – |
| `stratus-39d33f46-4f45-4155-9ff2-fc8c1db60773` | stratus-39d33f46-4f45-4155-9ff2-fc8c1db60773 | T1552.007 | succeeded | not_detected_by_cutoff | 2026-11-15T06:55:49.068551Z | – | – |
| `stratus-3beb1cd6-7c09-4e5a-92d6-cbf300dd2f1d` | stratus-3beb1cd6-7c09-4e5a-92d6-cbf300dd2f1d | T1098.006 | failed | excluded_outcome | 2026-11-15T06:59:43.481181Z | – | falco-4d22bbf5ddbcfbeba1f84ec71c0c8b34e80d9c7dc4948b310793fbb3a471391d |
| `stratus-3e1a2513-bf43-4f4c-9f66-e7c872d91c62` | stratus-3e1a2513-bf43-4f4c-9f66-e7c872d91c62 | T1609 | succeeded | detected | 2026-11-15T07:01:36.799559Z | 3.294 | falco-f19b829a0ffd9763e9740c224027a7cd440ae17e034b2fd27e80a4b15cd6ad0c |
| `stratus-43089b8c-7aad-4172-98e4-2d2dba7c54e3` | stratus-43089b8c-7aad-4172-98e4-2d2dba7c54e3 | T1098.006 | failed | excluded_outcome | 2026-11-15T06:58:09.272941Z | – | falco-9b9c29653932055f970fa126753ab6b6112434ad776918afa180e96f17cded58 |
| `stratus-552e41ba-d60b-45f5-8ae3-967c18ba3532` | stratus-552e41ba-d60b-45f5-8ae3-967c18ba3532 | T1552.007 | succeeded | not_detected_by_cutoff | 2026-11-15T07:01:43.166235Z | – | – |
| `stratus-55f75167-3c91-4e02-9961-ab4eec667cc5` | stratus-55f75167-3c91-4e02-9961-ab4eec667cc5 | T1528 | succeeded | detected | 2026-11-15T06:53:41.806028Z | 3.315 | falco-4d6267df6f8ff1a07715f97b345fa3d6cdd77acc2728585748db2454362e251e |
| `stratus-5d7262b5-cadb-44da-81dc-26b4bf55df59` | stratus-5d7262b5-cadb-44da-81dc-26b4bf55df59 | T1552.007 | succeeded | not_detected_by_cutoff | 2026-11-15T06:54:36.285349Z | – | – |
| `stratus-71185abb-fdc6-4d81-9064-907d8f050494` | stratus-71185abb-fdc6-4d81-9064-907d8f050494 | T1609 | succeeded | detected | 2026-11-15T06:54:30.400785Z | 3.182 | falco-fc46d6af7a687225894c914fc16f9a968d8ce5ca5d3de713c7429a3dee6f2bb1 |
| `stratus-73e9c881-fc08-491b-97e9-96b750af02f9` | stratus-73e9c881-fc08-491b-97e9-96b750af02f9 | T1528 | succeeded | detected | 2026-11-15T07:03:05.206719Z | 3.087 | falco-4d8264989601cfd74be555d0932613ea5416f2e108a9a534809db9993ac6b584 |
| `stratus-741670a1-4a63-4b65-bfa1-3b9add559fc9` | stratus-741670a1-4a63-4b65-bfa1-3b9add559fc9 | T1098 | succeeded | detected | 2026-11-15T06:58:01.006165Z | 1.140 | falco-21a769f68ee778a8750390cb2b24895a1069d95dbece6d5e01dfef4d8763e24e |
| `stratus-7a420ae4-51cc-4aaa-af7b-ac630524cd2c` | stratus-7a420ae4-51cc-4aaa-af7b-ac630524cd2c | T1611 | succeeded | detected | 2026-11-15T06:57:46.279394Z | 3.342 | falco-f60d5936c9431cf58ab8fd22a7dcd669d2c7ea4272c6c31a4550defbed70e0be |
| `stratus-89e5d4ce-bc86-4fe0-bbe8-51a2d54646c8` | stratus-89e5d4ce-bc86-4fe0-bbe8-51a2d54646c8 | T1098 | succeeded | detected | 2026-11-15T06:54:39.480417Z | 1.300 | falco-8f47678a80ae657954a019ebca36dea0e40932b5a9bf6a0141bf248595820ae3 |
| `stratus-a2e76b8c-4bab-49fe-9d51-96856923c19c` | stratus-a2e76b8c-4bab-49fe-9d51-96856923c19c | T1649 | succeeded | not_detected_by_cutoff | 2026-11-15T07:01:49.368013Z | – | – |
| `stratus-a5af2b3f-ca51-4713-bed5-a9d0f966fe62` | stratus-a5af2b3f-ca51-4713-bed5-a9d0f966fe62 | T1098.006 | failed | excluded_outcome | 2026-11-15T06:52:31.215904Z | – | falco-3ecfe51d2d476c54415a814d6d19e5d4885fea08032eab583ca235076d06377c |
| `stratus-a6c6226e-83e7-4c5e-ab36-13152df7d250` | stratus-a6c6226e-83e7-4c5e-ab36-13152df7d250 | T1528 | succeeded | detected | 2026-11-15T07:00:53.672167Z | 3.232 | falco-8fe18f97da7a715ddde316551a7c90ccd13d411b4a741b0c2a2cb26b375dbb40 |
| `stratus-a99be7e3-7ccd-40c3-8dff-ee12e1912df7` | stratus-a99be7e3-7ccd-40c3-8dff-ee12e1912df7 | T1528 | succeeded | detected | 2026-11-15T06:54:54.185253Z | 3.228 | falco-e359512682c88e7f76b4466d988ba885208fa8f74e2524d85db7945d2c7e55c0 |
| `stratus-a9bfa6bc-1b67-4de2-b198-194fd1a47f55` | stratus-a9bfa6bc-1b67-4de2-b198-194fd1a47f55 | T1552.007 | succeeded | not_detected_by_cutoff | 2026-11-15T06:57:58.139360Z | – | – |
| `stratus-ae43d06e-c035-4cd7-8023-6e1a75632811` | stratus-ae43d06e-c035-4cd7-8023-6e1a75632811 | T1649 | succeeded | not_detected_by_cutoff | 2026-11-15T06:54:42.837880Z | – | – |
| `stratus-b29ecc5a-828e-4699-a5c3-012ff89479f5` | stratus-b29ecc5a-828e-4699-a5c3-012ff89479f5 | T1098 | succeeded | detected | 2026-11-15T06:55:51.872934Z | 1.301 | falco-b4c578afbc36f3e8d6b294cb3f6c45ed3427066b8b4d8e49767c8b3b0e696fea |
| `stratus-ba617a8d-41b8-41bf-8773-0fecb03d4827` | stratus-ba617a8d-41b8-41bf-8773-0fecb03d4827 | T1098 | succeeded | detected | 2026-11-15T07:01:46.483889Z | 1.168 | falco-8823bc6a7081f87aa4276b5b204602bff2cae16a82baafa03ee7bddf09df53c9 |
| `stratus-bf9486b6-4f98-49ed-a081-14c234b3b4cd` | stratus-bf9486b6-4f98-49ed-a081-14c234b3b4cd | T1611 | succeeded | detected | 2026-11-15T06:54:48.261995Z | 3.497 | falco-687ef8f6eef961ec17426c399dd2ce7499cd1277b7579b314109039a2f274888 |
| `stratus-bf9a3521-f332-428b-b6f9-a76fce8bf411` | stratus-bf9a3521-f332-428b-b6f9-a76fce8bf411 | T1609 | succeeded | detected | 2026-11-15T06:59:26.511104Z | 3.097 | falco-3ef755352b4ccf12bd64f9c8404e00e9a1141503651b9102aa325d2045dbdd96 |
| `stratus-c2aa552b-cd21-4006-8260-7810f34522e0` | stratus-c2aa552b-cd21-4006-8260-7810f34522e0 | T1611 | succeeded | detected | 2026-11-15T06:59:13.547650Z | 3.662 | falco-17b08508d97acd303e5887876983e1c077295e3da79eabc81e72f32049d59c5e |
| `stratus-c43abb01-1756-41ed-9462-15354ac211b3` | stratus-c43abb01-1756-41ed-9462-15354ac211b3 | T1611 | succeeded | detected | 2026-11-15T07:02:58.892082Z | 3.729 | falco-d7b845734d250e5f447d06a094b2cb0f1cb7ddb069ba21bdb20f4d53b1699cb9 |
| `stratus-cde1c56c-5da4-4dbe-8ef0-3afe1de20971` | stratus-cde1c56c-5da4-4dbe-8ef0-3afe1de20971 | T1528 | succeeded | detected | 2026-11-15T06:57:03.771829Z | 3.403 | falco-80c412b3c40886d32800d660ad590b984d64cb6c5052b29384931f6dc47fd010 |
| `stratus-d050e205-dcec-48a5-92e1-fe568964ec0f` | stratus-d050e205-dcec-48a5-92e1-fe568964ec0f | T1611 | succeeded | detected | 2026-11-15T07:03:48.194710Z | 3.258 | falco-7200b3d16104c32c5d586702abfc85247c5b865be0f8d75fd24cdc4d4fd8eb9d |
| `stratus-d2200f64-774e-447b-8453-ce80aab81580` | stratus-d2200f64-774e-447b-8453-ce80aab81580 | T1098.006 | failed | excluded_outcome | 2026-11-15T07:01:54.601792Z | – | falco-3a86988087033be583cc32fea2c44617d9c444411537dad987a388216fc7de8f |
| `stratus-da242337-075d-4b6f-a364-d911a1f693f9` | stratus-da242337-075d-4b6f-a364-d911a1f693f9 | T1649 | succeeded | not_detected_by_cutoff | 2026-11-15T06:59:38.680590Z | – | – |
| `stratus-da67723b-68ae-41b8-87c6-ef9e2072cc59` | stratus-da67723b-68ae-41b8-87c6-ef9e2072cc59 | T1611 | succeeded | detected | 2026-11-15T06:53:35.476661Z | 3.795 | falco-835cdb5a758e73419d760175220e064c339081403d9b3d63e2db56588d88df37 |
| `stratus-e9bac895-f5a2-4b4c-a7d3-f68908343c43` | stratus-e9bac895-f5a2-4b4c-a7d3-f68908343c43 | T1609 | succeeded | detected | 2026-11-15T06:57:52.202768Z | 3.198 | falco-0aa72231f44a203e22ad96efaa6863b5c5c0896cd6427c58acd1710ddacc820d |
| `stratus-ef1f400f-0fa2-486d-afd6-d2da9f38ecdd` | stratus-ef1f400f-0fa2-486d-afd6-d2da9f38ecdd | T1611 | succeeded | detected | 2026-11-15T06:55:36.936873Z | 3.668 | falco-38c14a46b3a64d0ea6624dc2d51fa48ac5e9983665be047dc6c150bf045d5a60 |
| `stratus-fdf9138f-e32f-4a53-832a-f10b388b7a8a` | stratus-fdf9138f-e32f-4a53-832a-f10b388b7a8a | T1609 | succeeded | detected | 2026-11-15T06:55:43.247074Z | 3.206 | falco-f68a3aeb90f6cf72267aee228e3aef5477b14f27aa45ecdccb2afa8d439afdc7 |

## Limits

- Analysis of supplied cohort only; no provider provenance or authentication is asserted.
- Undetected executions are right-censored at the supplied cutoff, not permanent misses.
- Fixture or supplied data does not establish real emulation, integration or deployment coverage.
- Normal-operation data unavailable; no false-positive count inferred.
