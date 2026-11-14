# Task 5 live matrix, 2026-11-13 PST / 2026-11-14 UTC

The runc run preceded commit `25c63e4`; the gVisor and Firecracker runs used that commit. The common admitted corpus SHA256: `sha256:541438cdbd805a8b4558cae8a9eaea5fe9d72b0d8a68d1258b93b832cfb9c091`. Each runtime used CPU 1, memory 512 MiB, pids 128, timeout 60 s. JSON files retain every RunID, timestamp, output, exit/cgroup result and image digest. The three OCI image digests differ; use each report rather than assuming image identity.

| Probe | runc | gVisor | Firecracker |
|---|---|---|---|
| arp-spoof | blocked | blocked | blocked |
| disk-fill | error | error | error |
| dns-exfil | error | error | error |
| fork-bomb | blocked | blocked | blocked |
| kernel-module | blocked | blocked | blocked |
| memory-exhaustion | blocked | missed | blocked |
| metadata-host | blocked | blocked | blocked |
| metadata-ip | blocked | blocked | blocked |
| mount-unshare | blocked | blocked | blocked |
| proc-leak | error | error | error |
| ptrace | blocked | blocked | blocked |
| raw-socket | blocked | blocked | blocked |
| reverse-shell | error | error | error |
| sys-leak | error | error | error |

Verdict totals: runc 9 blocked / 5 error; gVisor 8 blocked / 5 error / 1 missed; Firecracker 9 blocked / 5 error. The full matrix tests exit nonzero because error cells are unresolved; the seven preexisting conformance subtests passed for gVisor and Firecracker. runc conformance passed 7/7. A `blocked` verdict refers only to the narrow fixed probe objective and its recorded denial evidence.

The five common `error` probes are disk-fill, dns-exfil, proc-leak, reverse-shell and sys-leak. The disk probe reaches a 64 MiB tmpfs quota on runc/gVisor and has no `/dev/shm` target on Firecracker. The DNS probe has no controlled collector; reverse-shell has no reachable listener; proc/sys have no seeded cross-boundary secret. These are not successful isolation verdicts. `kernel-module` returned EPERM for invalid bytes, so it establishes denial of that syscall invocation, not a valid module load test.

gVisor `memory-exhaustion` returned `WARDEN_SUCCESS` after touching 576 MiB with requested workload memory 512 MiB. It is classified `missed` with detector unavailable. The pod-level limit and sentry/gofer sharing documented for Task 3 require separate memory-accounting diagnosis before claiming a fixed workload limit. This is a local probe success, not host-wide memory exhaustion.

Firecracker prerequisite sequence: prepare, mount-smoke, device-policy and boot passed; conformance failed solely at the unresolved isolation matrix, then its own cleanup reported the VMM/worker reaped and reservation released. gVisor and runc lab runners also returned nonzero due to unresolved matrix cells. Task 13 live detectors were unavailable, so none of these are `detected` claims and no detection latency is available.

Original reports: [runc](runc.json), [gVisor](gvisor.json), [Firecracker](firecracker.json). Original runner logs: [runc](runc.log), [gVisor](gvisor.log), [Firecracker](firecracker.log). Firecracker gate logs: [sequence](firecracker-sequence.log), [prepare](firecracker-prepare.log), [mount](firecracker-mount-smoke.log), [device policy](firecracker-device-policy.log), [boot](firecracker-boot.log).
