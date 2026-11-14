# Detection coverage

Observed until 2026-11-14T15:30:41.450588Z: 28 executions, 3 alerts.

## Scope

- Cohort: the Task 5 corpus (14 probes) once on runc and once on gVisor, 2026-11-14, 28 runs. Only one run reached its goal (gVisor memory-exhaustion), so the detection rate below is over n=1.
- Rule map: every one of the 25 stock rules of the pinned Falco 0.45.2 for every run (any kept alert on the run's container inside its window counts); no narrower map has been reviewed.
- Coverage: runc at host level; gVisor at host level only (a sandbox's own system calls are not seen); Firecracker not covered and not run.
- Alert time is the alerted event's own time (Falco's `time`); the time Falco and the collector took to deliver an alert is not included.
- Not run: the Stratus Red Team and Atomic Red Team live emulations (the plan's Stratus AWS and GCP techniques are not wrapped); Task 12's Sigma rules are not in this scoring path; no seven-day normal window, so no false-positive count.

## Detection rate

| Measure | Detected | Of | Rate |
|---|---|---|---|
| Successful executions | 0 | 1 | 0.0% |
| Techniques with a successful execution | 0 | 1 | 0.0% |

Alerts on failed or skipped executions: 3.

## Time to detect

No successful execution was detected, so there is no time to detect.

## False positives in normal operation

No normal-operation window was supplied, so there is no false-positive count.

## Per technique

| Technique | Successful | Detected | Failed | Skipped | Fastest detection (s) |
|---|---|---|---|---|---|
| T1016 | 0 | 0 | 2 | 0 | – |
| T1048.003 | 0 | 0 | 0 | 2 | – |
| T1055 | 0 | 0 | 2 | 0 | – |
| T1059.004 | 0 | 0 | 0 | 2 | – |
| T1082 | 0 | 0 | 0 | 4 | – |
| T1499.003 | 1 | 0 | 3 | 2 | – |
| T1547.006 | 0 | 0 | 2 | 0 | – |
| T1552.005 | 0 | 0 | 4 | 0 | – |
| T1557.002 | 0 | 0 | 2 | 0 | – |
| T1611 | 0 | 0 | 2 | 0 | – |

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

## Limits

- Analysis of supplied cohort only; no provider provenance or authentication is asserted.
- Undetected executions are right-censored at the supplied cutoff, not permanent misses.
- Fixture or supplied data does not establish real emulation, integration or deployment coverage.
- Normal-operation data unavailable; no false-positive count inferred.
