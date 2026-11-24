# Detection coverage

Observed until 2026-11-16T05:44:08.120215Z: 98 executions, 88 alerts.

## Scope

- Cohort: three rounds, the corpus and Atomic rounds on 2026-11-14 and the Stratus round on 2026-11-15 (UTC), under the same pinned Falco 0.45.2 image and stock rules (between them the k8saudit instance was added, and the host collector now counts an ID nested in a non-Warden container as another container's rather than unresolved; both are dropped, so no kept alert changes). The Task 5 corpus: 14 probes once on runc and once on gVisor (28 runs; one reached its goal). The Atomic round: six reviewed official Linux Atomic Red Team tests, five runs each, on runc only (30 runs), each in its own container (ubuntu:24.04, no network, read-only root, no capabilities). The Stratus round: the eight Kubernetes techniques of Stratus Red Team v2.38.0 that the user's wrapper admits, five runs each (40 runs), on the dedicated kind audit lab (Kubernetes 1.34.11).
- The Atomic round includes T1082 Hostname Discovery as a control that no stock rule describes; its five successful runs are in the denominator of the rate. T1552.001 Find AWS credentials exited 1 in every run (find meets two directories that root cannot enter without capabilities), so it is a failed execution and not in the rate; counted as executed it would add 5 misses. The two T1552.004 SSH-key searches meet the same two directories and succeed only because their scripts end in `exit 0`.
- Rule maps, both the widest: the corpus and Atomic rounds against the 25 stock syscall rules of the pinned Falco 0.45.2 (any kept alert on the run's container inside its execution counts); the Stratus round against the 48 stock rules of k8s_audit_rules.yaml (k8saudit plugin 0.18.0) only, any alert attributed to the run (by Stratus's User-Agent correlation token, the run label or the run's namespace) inside its window counts, Stratus's warm-up and clean-up included. No narrower map has been reviewed.
- Stratus: no stock rule is written for k8s.credential-access.dump-secrets (T1552.007) or k8s.persistence.create-token (T1098); whatever the widest map counts for them comes from other rules matching the technique's set-up, clean-up or side requests, not from a rule describing the technique (round README). k8s.persistence.create-admin-clusterrole (T1098.006) fails on Kubernetes 1.24 and later (it waits for a legacy token Secret), so its runs are failed executions and their alerts are alerts on failed executions.
- Techniques are ATT&CK IDs, so rows merge across rounds and Stratus techniques: T1611 holds the corpus's two container-escape probes and Stratus's privileged-pod and hostpath-volume. Per-technique rows by Stratus name are in the round README.
- Coverage: runc at host level; gVisor at host level only (a sandbox's own system calls are not seen); Firecracker not covered and not run; the kind lab through its API server audit log only (no syscall rule scores a Stratus run).
- Time to detect runs from the execution's start to the alerted event's own time (Falco's `time`; for k8saudit the audit event's stageTimestamp). The Atomic and Stratus READMEs also give start to arrival in the collector's alerts.jsonl; the corpus round has no arrival times.
- Observed until is the Stratus round's cutoff. The corpus round's detector ran 15:27:48 to 15:30:46 UTC and the Atomic round's until 17:30:10 UTC, so their undetected rows were observed only until then. The Stratus round's cutoff came 22.7 h after its last run, and its alerts count only inside each run's own window.
- Not run: Stratus cloud techniques (AWS, GCP, Azure), the Atomic round on gVisor or Firecracker. Task 12's Sigma rules are not in this scoring path.
- Normal window: the seven-day window of 2026-11-16 06:22:36 to 2026-11-23 06:22:36 UTC on the host instance only (falco-host; no k8saudit, no kind lab), with Warden's hourly benign workload, the conformance suite on runc and on gVisor (177 runs each, all passed); 168 of 168 hourly slices healthy, no drops. The stock rules were not tuned. Dispositions are per group of rule, process and container class (review-map.jsonl, seven-day-20261116 README): the 293,372 false positives are the labs' own infrastructure, gVisor's runsc tracing its stubs with ptrace (276,549) and k3s running the binaries it unpacks (16,823 in 15 groups); the 177 true positives are the conformance probe's ptrace(PTRACE_TRACEME), which the rule describes.

## Detection rate

| Measure | Detected | Of | Rate |
|---|---|---|---|
| Successful executions | 45 | 61 | 73.8% |
| Techniques with a successful execution | 7 | 11 | 63.6% |

Alerts on failed or skipped executions: 18.

## Time to detect

Over the 45 detected successful executions (nearest-rank): p50 1.192 s, p95 3.668 s.

## False positives in normal operation

Window 2026-11-16T06:22:36.637725Z to 2026-11-23T06:22:36.637725Z (7.00 days; at least seven days).

| False positives | True positives | Unreviewed | Alerts |
|---|---|---|---|
| 293372 | 177 | 0 | 293549 |

## Per technique

| Technique | Successful | Detected | Failed | Skipped | Fastest detection (s) |
|---|---|---|---|---|---|
| T1016 | 0 | 0 | 2 | 0 | – |
| T1048.003 | 0 | 0 | 0 | 2 | – |
| T1055 | 0 | 0 | 2 | 0 | – |
| T1059.004 | 0 | 0 | 0 | 2 | – |
| T1070.004 | 5 | 5 | 0 | 0 | 0.039 |
| T1082 | 5 | 0 | 0 | 4 | – |
| T1098 | 5 | 5 | 0 | 0 | 1.140 |
| T1098.006 | 0 | 0 | 5 | 0 | – |
| T1201 | 5 | 5 | 0 | 0 | 0.044 |
| T1499.003 | 1 | 0 | 3 | 2 | – |
| T1528 | 5 | 5 | 0 | 0 | 3.087 |
| T1547.006 | 0 | 0 | 2 | 0 | – |
| T1552.001 | 0 | 0 | 5 | 0 | – |
| T1552.004 | 10 | 10 | 0 | 0 | 0.041 |
| T1552.005 | 0 | 0 | 4 | 0 | – |
| T1552.007 | 5 | 0 | 0 | 0 | – |
| T1557.002 | 0 | 0 | 2 | 0 | – |
| T1609 | 5 | 5 | 0 | 0 | 3.097 |
| T1611 | 10 | 10 | 2 | 0 | 3.242 |
| T1649 | 5 | 0 | 0 | 0 | – |

## Per execution

| Execution | Run | Technique | Outcome | Status | Executed (UTC) | Time to detect (s) | First alert |
|---|---|---|---|---|---|---|---|
| `3ZQCT4F34WAQJZFYSHGBVWRTLQ` | isolation-matrix/gvisor/541438cdbd80 | T1082 | skipped | excluded_outcome | 2026-11-14T15:29:46.643133Z | – | – |
| `43MDPGXN7AQA5KLCMOIBHY262I` | isolation-matrix/runc/541438cdbd80 | T1082 | skipped | excluded_outcome | 2026-11-14T15:28:20.281640Z | – | – |
| `4P5X3Y7NCWRJIJP5QCJLJMK5QA` | isolation-matrix/gvisor/541438cdbd80 | T1552.005 | failed | excluded_outcome | 2026-11-14T15:29:37.643986Z | – | – |
| `642EECGJEQ6SAMOT6THFBOUS3M` | isolation-matrix/gvisor/541438cdbd80 | T1499.003 | skipped | excluded_outcome | 2026-11-14T15:29:21.588800Z | – | – |
| `6STXIEVMGREFHAD3RD3FTV7UYE` | isolation-matrix/runc/541438cdbd80 | T1059.004 | skipped | excluded_outcome | 2026-11-14T15:28:20.637684Z | – | – |
| `7NU4VVDKNMMXOYOYAA63EDRJT4` | isolation-matrix/gvisor/541438cdbd80 | T1499.003 | succeeded | not_detected_by_cutoff | 2026-11-14T15:29:34.603905Z | – | – |
| `7S7T2YCBXNAH72RFM3OMOWHHIU` | isolation-matrix/gvisor/541438cdbd80 | T1499.003 | failed | excluded_outcome | 2026-11-14T15:29:27.609655Z | – | – |
| `BB4ONSI7D36MYN2DI2TKWXS7MI` | isolation-matrix/gvisor/541438cdbd80 | T1059.004 | skipped | excluded_outcome | 2026-11-14T15:29:55.664388Z | – | – |
| `CHSGIOOMRNRTMGNIRWP2XNGJHA` | isolation-matrix/runc/541438cdbd80 | T1055 | failed | excluded_outcome | 2026-11-14T15:28:20.397754Z | – | falco-6a7c337e42b4f7426dd6b0314651ccb4a278f84939f210537270c35b0a10de67 |
| `ELTKG4CNGRSOJVRSCAN4OEM7PY` | isolation-matrix/runc/541438cdbd80 | T1082 | skipped | excluded_outcome | 2026-11-14T15:28:20.754811Z | – | – |
| `KBDMZMB3OZDIIGQTTGX4QK2BV4` | isolation-matrix/gvisor/541438cdbd80 | T1055 | failed | excluded_outcome | 2026-11-14T15:29:49.665303Z | – | – |
| `KJYZMDFA2AG72WVKL6Q7ANRQVI` | isolation-matrix/runc/541438cdbd80 | T1499.003 | skipped | excluded_outcome | 2026-11-14T15:28:19.140797Z | – | – |
| `LVBVS7LGVAXL53CPECZ24SUDGI` | isolation-matrix/gvisor/541438cdbd80 | T1611 | failed | excluded_outcome | 2026-11-14T15:29:43.653496Z | – | – |
| `M36DAMHLGXTOEYBJX35EP5A7M4` | isolation-matrix/runc/541438cdbd80 | T1499.003 | failed | excluded_outcome | 2026-11-14T15:28:19.388308Z | – | – |
| `MBQ5NZYHSQPV6LJSDE7LU3CSZI` | isolation-matrix/runc/541438cdbd80 | T1611 | failed | excluded_outcome | 2026-11-14T15:28:20.177175Z | – | – |
| `MGMOC6E5WEIHETDXDRQGVXN7LE` | isolation-matrix/gvisor/541438cdbd80 | T1048.003 | skipped | excluded_outcome | 2026-11-14T15:29:24.575969Z | – | – |
| `MHGGVKWDXKRME7WNPSCQKOTF5A` | isolation-matrix/runc/541438cdbd80 | T1552.005 | failed | excluded_outcome | 2026-11-14T15:28:20.059771Z | – | – |
| `MKGJOCGGKSGZ5IDHVOOU4Z4FF4` | isolation-matrix/runc/541438cdbd80 | T1552.005 | failed | excluded_outcome | 2026-11-14T15:28:19.947529Z | – | – |
| `MTUNCBNPA3VFZLFSEUJYPMCXDA` | isolation-matrix/runc/541438cdbd80 | T1048.003 | skipped | excluded_outcome | 2026-11-14T15:28:19.274103Z | – | – |
| `N6OXCQZ4PFPO7RIVSRVVTGONBM` | isolation-matrix/gvisor/541438cdbd80 | T1016 | failed | excluded_outcome | 2026-11-14T15:29:52.640761Z | – | – |
| `PYL4PZ7446CFCTAGUC34WZUEUQ` | isolation-matrix/gvisor/541438cdbd80 | T1082 | skipped | excluded_outcome | 2026-11-14T15:29:58.637159Z | – | – |
| `RK7GXSYJPTC25CX6JCP4BJ57NM` | isolation-matrix/runc/541438cdbd80 | T1547.006 | failed | excluded_outcome | 2026-11-14T15:28:19.494170Z | – | – |
| `TRQH2B3QSM4U72NS5YF6R3VFYQ` | isolation-matrix/runc/541438cdbd80 | T1557.002 | failed | excluded_outcome | 2026-11-14T15:28:19.023846Z | – | falco-51478f0330d80afe1853ff073d62568cba65ee437717c4768ac14c4a089e78cf |
| `U7QPI3XHRKISOB7CW56OVBEMOQ` | isolation-matrix/gvisor/541438cdbd80 | T1557.002 | failed | excluded_outcome | 2026-11-14T15:29:18.876199Z | – | – |
| `UCDG4YTO54ZVBFS7K2NXCMTZRM` | isolation-matrix/gvisor/541438cdbd80 | T1552.005 | failed | excluded_outcome | 2026-11-14T15:29:40.626518Z | – | – |
| `WL7VNKJ7WNX3TDG426BCOUGCQU` | isolation-matrix/runc/541438cdbd80 | T1016 | failed | excluded_outcome | 2026-11-14T15:28:20.515673Z | – | falco-10b025e8550af489879624e1d27ba6c9655f9c2a6cf0e0489b69d6fa6249fd46 |
| `XCVPAA7SW3OOEESCZPDICQBMNA` | isolation-matrix/gvisor/541438cdbd80 | T1547.006 | failed | excluded_outcome | 2026-11-14T15:29:31.573659Z | – | – |
| `ZJT2PD4EYJLLICOGQ4IOBJFJFQ` | isolation-matrix/runc/541438cdbd80 | T1499.003 | failed | excluded_outcome | 2026-11-14T15:28:19.612619Z | – | – |
| `atomic-01311715f3e743774fcd4b63-ssh-key-copy` | atomic-01311715f3e743774fcd4b63 | T1552.004 | succeeded | detected | 2026-11-14T17:29:15.916189Z | 0.109 | falco-b333915957252664e0566412093ba9bbfa70c44e6ebddd61484633595aecd589 |
| `atomic-12de27c8b27fb3e306a65578-shred` | atomic-12de27c8b27fb3e306a65578 | T1070.004 | succeeded | detected | 2026-11-14T17:27:34.772965Z | 0.039 | falco-4bcc85f2e5630d85612c928ac17df3507ef568e8af4f96d667d2485c74a15c04 |
| `atomic-1649aed893b8f9ec6184c47e-password-policy` | atomic-1649aed893b8f9ec6184c47e | T1201 | succeeded | detected | 2026-11-14T17:26:18.730072Z | 0.044 | falco-c4c56dd6e27688239725b0d7c29986b723a2d60eddc8b62e448d4c2aba87bf19 |
| `atomic-2d61ff5867bd1eaf02fec384-aws-credentials` | atomic-2d61ff5867bd1eaf02fec384 | T1552.001 | failed | excluded_outcome | 2026-11-14T17:23:58.998939Z | – | – |
| `atomic-3229a46e40ce3ffeb8d7993c-hostname` | atomic-3229a46e40ce3ffeb8d7993c | T1082 | succeeded | not_detected_by_cutoff | 2026-11-14T17:28:50.567708Z | – | – |
| `atomic-3b1d2c28a89025e674337cfa-ssh-key-copy` | atomic-3b1d2c28a89025e674337cfa | T1552.004 | succeeded | detected | 2026-11-14T17:27:08.912035Z | 0.072 | falco-bcd5ad402c44886334aa2ba66907f6b429d9ebff6a2aa13464988f36ac3722bd |
| `atomic-428c99260ab5416847cf9c0b-shred` | atomic-428c99260ab5416847cf9c0b | T1070.004 | succeeded | detected | 2026-11-14T17:24:24.557715Z | 0.058 | falco-da150ff6f2df0e845a3e05f2bf495739fd1140171d0ffe9687e55f959bacf9ac |
| `atomic-4f5ad5ba447d4a616088ad50-aws-credentials` | atomic-4f5ad5ba447d4a616088ad50 | T1552.001 | failed | excluded_outcome | 2026-11-14T17:26:06.127493Z | – | – |
| `atomic-544c09b7276b902014c0646d-ssh-key-copy` | atomic-544c09b7276b902014c0646d | T1552.004 | succeeded | detected | 2026-11-14T17:23:46.325061Z | 0.045 | falco-b30d10d60c17437901f95f3d7d14b5d177e8a6250a21954e9a9dcd919a5857a9 |
| `atomic-5485602b7181edb593d7b0f4-ssh-key-discovery` | atomic-5485602b7181edb593d7b0f4 | T1552.004 | succeeded | detected | 2026-11-14T17:25:53.444539Z | 0.043 | falco-1b728ac0bbc53b022cf7914688fe29396daf9444c4bf8e9e83d17963c7779cc9 |
| `atomic-5e0ab25d66d7be00d17cfb9c-hostname` | atomic-5e0ab25d66d7be00d17cfb9c | T1082 | succeeded | not_detected_by_cutoff | 2026-11-14T17:27:47.204682Z | – | – |
| `atomic-62b68bc0b86769dde1284e87-password-policy` | atomic-62b68bc0b86769dde1284e87 | T1201 | succeeded | detected | 2026-11-14T17:25:15.469438Z | 0.098 | falco-a3c796d80fe1efafa0af4dcf205855d54f10bb5459cfa2b956d6376d32924028 |
| `atomic-67b8a6950c6278aa3ee074cc-hostname` | atomic-67b8a6950c6278aa3ee074cc | T1082 | succeeded | not_detected_by_cutoff | 2026-11-14T17:26:43.852047Z | – | – |
| `atomic-6aa90cbc3960c0a458a6ba4d-hostname` | atomic-6aa90cbc3960c0a458a6ba4d | T1082 | succeeded | not_detected_by_cutoff | 2026-11-14T17:25:40.968834Z | – | – |
| `atomic-6afb735021c0dd27e34c4fcd-aws-credentials` | atomic-6afb735021c0dd27e34c4fcd | T1552.001 | failed | excluded_outcome | 2026-11-14T17:25:02.642714Z | – | – |
| `atomic-7116af4488ce737d812772e2-hostname` | atomic-7116af4488ce737d812772e2 | T1082 | succeeded | not_detected_by_cutoff | 2026-11-14T17:24:37.069614Z | – | – |
| `atomic-778af59f738d5f79a59b361d-password-policy` | atomic-778af59f738d5f79a59b361d | T1201 | succeeded | detected | 2026-11-14T17:29:41.402928Z | 0.044 | falco-1115c12ebc8fcbb1b44e7d1ab0e6c9899617f231625d6e76d4cc25b78eeec9c4 |
| `atomic-7e506a0e160dd858a5a8f3b0-ssh-key-discovery` | atomic-7e506a0e160dd858a5a8f3b0 | T1552.004 | succeeded | detected | 2026-11-14T17:29:03.088084Z | 0.097 | falco-920134e1d62a4dc6916286b7807c2847f2a013753bc64b2ac65d37af05d88ac0 |
| `atomic-84d7b8e7ad5ce2e4474984d5-aws-credentials` | atomic-84d7b8e7ad5ce2e4474984d5 | T1552.001 | failed | excluded_outcome | 2026-11-14T17:28:24.850740Z | – | – |
| `atomic-9752e1ac1c0176a1d053c533-ssh-key-discovery` | atomic-9752e1ac1c0176a1d053c533 | T1552.004 | succeeded | detected | 2026-11-14T17:27:59.664665Z | 0.041 | falco-8bf8be3ff43a167015f35d41b2bcef32d23f22da34060bba536a37d61226cf9c |
| `atomic-a0ca63ea87cbff4278fd04d4-ssh-key-copy` | atomic-a0ca63ea87cbff4278fd04d4 | T1552.004 | succeeded | detected | 2026-11-14T17:24:49.833029Z | 0.060 | falco-6f7edb82bbe441512fc3354d1bd09af99d0d6cae258e0ac3c35f8bf8d6b521f8 |
| `atomic-a851d1c953765f760e5ea1b0-ssh-key-discovery` | atomic-a851d1c953765f760e5ea1b0 | T1552.004 | succeeded | detected | 2026-11-14T17:23:33.684997Z | 0.082 | falco-429dd38f6ef506e287275afe32e181bb8f377bba817e769cbe2c0be8fa6801c0 |
| `atomic-b83698e23fb56002ad873746-shred` | atomic-b83698e23fb56002ad873746 | T1070.004 | succeeded | detected | 2026-11-14T17:26:31.387801Z | 0.044 | falco-b752aa28bb66b5dbfaea388bedf3cde04a744953f3ebaac20da5301ad258a616 |
| `atomic-c80407dbd7311e02833d6d79-ssh-key-copy` | atomic-c80407dbd7311e02833d6d79 | T1552.004 | succeeded | detected | 2026-11-14T17:28:12.242530Z | 0.043 | falco-f48ef90d84a7f4dcdd683fd3f0283b3fc3bdbda996e343c6b5923aeb6b607a55 |
| `atomic-dacd0a7befd939da577f29eb-shred` | atomic-dacd0a7befd939da577f29eb | T1070.004 | succeeded | detected | 2026-11-14T17:28:37.934746Z | 0.063 | falco-980e3b854715a3a9cf2e2aba5563cc6e91cc66a5fc5690024f503bb4bac58d81 |
| `atomic-e231acc2ac91598b30b27c04-shred` | atomic-e231acc2ac91598b30b27c04 | T1070.004 | succeeded | detected | 2026-11-14T17:25:28.318706Z | 0.074 | falco-569814e82fc3cb1604080a1b69497fb09d638b90ca885a7e78f38702f2a921f7 |
| `atomic-ea19aef598891f64fb49c231-password-policy` | atomic-ea19aef598891f64fb49c231 | T1201 | succeeded | detected | 2026-11-14T17:27:21.945947Z | 0.068 | falco-ad636b134e5dc6f830f6fd7a912e97356b38a0b0f9d0f614b429757f2cb5f93d |
| `atomic-ea50be5b6eb6aed38c7fed2f-aws-credentials` | atomic-ea50be5b6eb6aed38c7fed2f | T1552.001 | failed | excluded_outcome | 2026-11-14T17:29:28.613772Z | – | – |
| `atomic-ee8a6a1820ccb6329f28868e-ssh-key-discovery` | atomic-ee8a6a1820ccb6329f28868e | T1552.004 | succeeded | detected | 2026-11-14T17:26:56.304088Z | 0.042 | falco-a690c8d27f66fcfda0e76e23894c02c5e06bd986dc15b9631a9ab6665483b742 |
| `atomic-f505818bcacbf2eed8804fb5-password-policy` | atomic-f505818bcacbf2eed8804fb5 | T1201 | succeeded | detected | 2026-11-14T17:24:11.758995Z | 0.062 | falco-adafcb67c2901dec609076cec5970f4c598d3badd16528807bfbf26680de0df1 |
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
- Supplied endpoints and annotations do not prove continuous source coverage or true ground truth; external validation required.
