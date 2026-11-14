# Isolation matrix

Corpus `sha256:541438cdbd805a8b4558cae8a9eaea5fe9d72b0d8a68d1258b93b832cfb9c091`, 14 entries; runtimes: runc, gvisor.

- **blocked**: the probe finished with complete output and never printed its success signal.
- **detected**: the probe printed its success signal and an alert names its run.
- **missed**: the probe printed its success signal and no alert names its run.
- **error**: the run failed (start, wait, logs or cleanup), so the cell has no verdict.

| Attack | Technique | runc | gvisor |
|---|---|---|---|
| arp-spoof | T1557.002 | blocked | blocked |
| disk-fill | T1499.003 | error | error |
| dns-exfil | T1048.003 | error | error |
| fork-bomb | T1499.003 | blocked | blocked |
| kernel-module | T1547.006 | blocked | blocked |
| memory-exhaustion | T1499.003 | blocked | missed |
| metadata-host | T1552.005 | blocked | blocked |
| metadata-ip | T1552.005 | blocked | blocked |
| mount-unshare | T1611 | blocked | blocked |
| proc-leak | T1082 | error | error |
| ptrace | T1055 | blocked | blocked |
| raw-socket | T1016 | blocked | blocked |
| reverse-shell | T1059.004 | error | error |
| sys-leak | T1082 | error | error |

## Totals

| Runtime | blocked | detected | missed | error |
|---|---|---|---|---|
| runc | 9 | 0 | 0 | 5 |
| gvisor | 8 | 0 | 1 | 5 |

## Runs

| Attack | Runtime | Run ID | Verdict | Reason | Exit | Started (UTC) | Seconds | Alerts |
|---|---|---|---|---|---|---|---|---|
| arp-spoof | runc | `TRQH2B3QSM4U72NS5YF6R3VFYQ` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:28:19Z | 0.12 | falco-51478f0330d80afe1853ff073d62568cba65ee437717c4768ac14c4a089e78cf |
| arp-spoof | gvisor | `U7QPI3XHRKISOB7CW56OVBEMOQ` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:29:18Z | 2.71 |  |
| disk-fill | runc | `KJYZMDFA2AG72WVKL6Q7ANRQVI` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:28:19Z | 0.13 |  |
| disk-fill | gvisor | `642EECGJEQ6SAMOT6THFBOUS3M` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:29:21Z | 2.99 |  |
| dns-exfil | runc | `MTUNCBNPA3VFZLFSEUJYPMCXDA` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:28:19Z | 0.11 |  |
| dns-exfil | gvisor | `MGMOC6E5WEIHETDXDRQGVXN7LE` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:29:24Z | 3.03 |  |
| fork-bomb | runc | `M36DAMHLGXTOEYBJX35EP5A7M4` | blocked | no success signal in the complete output | code 0, pids limit hit 6× | 2026-11-14T15:28:19Z | 0.11 |  |
| fork-bomb | gvisor | `7S7T2YCBXNAH72RFM3OMOWHHIU` | blocked | no success signal in the complete output | code 0, pids limit hit 1× | 2026-11-14T15:29:27Z | 3.96 |  |
| kernel-module | runc | `RK7GXSYJPTC25CX6JCP4BJ57NM` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:28:19Z | 0.12 |  |
| kernel-module | gvisor | `XCVPAA7SW3OOEESCZPDICQBMNA` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:29:31Z | 3.03 |  |
| memory-exhaustion | runc | `ZJT2PD4EYJLLICOGQ4IOBJFJFQ` | blocked | no success signal in the complete output | code 137, OOM-killed | 2026-11-14T15:28:19Z | 0.33 |  |
| memory-exhaustion | gvisor | `7NU4VVDKNMMXOYOYAA63EDRJT4` | missed | success signal in the output | code 0 | 2026-11-14T15:29:34Z | 3.04 |  |
| metadata-host | runc | `MKGJOCGGKSGZ5IDHVOOU4Z4FF4` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:28:19Z | 0.11 |  |
| metadata-host | gvisor | `4P5X3Y7NCWRJIJP5QCJLJMK5QA` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:29:37Z | 2.98 |  |
| metadata-ip | runc | `MHGGVKWDXKRME7WNPSCQKOTF5A` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:28:20Z | 0.12 |  |
| metadata-ip | gvisor | `UCDG4YTO54ZVBFS7K2NXCMTZRM` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:29:40Z | 3.03 |  |
| mount-unshare | runc | `MBQ5NZYHSQPV6LJSDE7LU3CSZI` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:28:20Z | 0.10 |  |
| mount-unshare | gvisor | `LVBVS7LGVAXL53CPECZ24SUDGI` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:29:43Z | 2.99 |  |
| proc-leak | runc | `43MDPGXN7AQA5KLCMOIBHY262I` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:28:20Z | 0.12 |  |
| proc-leak | gvisor | `3ZQCT4F34WAQJZFYSHGBVWRTLQ` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:29:46Z | 3.02 |  |
| ptrace | runc | `CHSGIOOMRNRTMGNIRWP2XNGJHA` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:28:20Z | 0.12 | falco-6a7c337e42b4f7426dd6b0314651ccb4a278f84939f210537270c35b0a10de67 |
| ptrace | gvisor | `KBDMZMB3OZDIIGQTTGX4QK2BV4` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:29:49Z | 2.98 |  |
| raw-socket | runc | `WL7VNKJ7WNX3TDG426BCOUGCQU` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:28:20Z | 0.12 | falco-10b025e8550af489879624e1d27ba6c9655f9c2a6cf0e0489b69d6fa6249fd46 |
| raw-socket | gvisor | `N6OXCQZ4PFPO7RIVSRVVTGONBM` | blocked | no success signal in the complete output | code 0 | 2026-11-14T15:29:52Z | 3.02 |  |
| reverse-shell | runc | `6STXIEVMGREFHAD3RD3FTV7UYE` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:28:20Z | 0.12 |  |
| reverse-shell | gvisor | `BB4ONSI7D36MYN2DI2TKWXS7MI` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:29:55Z | 2.97 |  |
| sys-leak | runc | `ELTKG4CNGRSOJVRSCAN4OEM7PY` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:28:20Z | 0.12 |  |
| sys-leak | gvisor | `PYL4PZ7446CFCTAGUC34WZUEUQ` | error | probe objective or denial not recorded | code 3 | 2026-11-14T15:29:58Z | 3.04 |  |
