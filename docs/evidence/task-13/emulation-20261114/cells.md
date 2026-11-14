| Probe | Runtime | Task 5 (11-13) | This run | Alert on the run | First alert after start (s) |
|---|---|---|---|---|---|
| arp-spoof | runc | blocked | blocked | Packet socket created in container | 0.078 |
| arp-spoof | gVisor | blocked | blocked | none | – |
| disk-fill | runc | error | error | none | – |
| disk-fill | gVisor | error | error | none | – |
| dns-exfil | runc | error | error | none | – |
| dns-exfil | gVisor | error | error | none | – |
| fork-bomb | runc | blocked | blocked | none | – |
| fork-bomb | gVisor | blocked | blocked | none | – |
| kernel-module | runc | blocked | blocked | none | – |
| kernel-module | gVisor | blocked | blocked | none | – |
| memory-exhaustion | runc | blocked | blocked | none | – |
| memory-exhaustion | gVisor | missed | missed | none | – |
| metadata-host | runc | blocked | blocked | none | – |
| metadata-host | gVisor | blocked | blocked | none | – |
| metadata-ip | runc | blocked | blocked | none | – |
| metadata-ip | gVisor | blocked | blocked | none | – |
| mount-unshare | runc | blocked | blocked | none | – |
| mount-unshare | gVisor | blocked | blocked | none | – |
| proc-leak | runc | error | error | none | – |
| proc-leak | gVisor | error | error | none | – |
| ptrace | runc | blocked | blocked | PTRACE attached to process | 0.080 |
| ptrace | gVisor | blocked | blocked | none | – |
| raw-socket | runc | blocked | blocked | Packet socket created in container | 0.085 |
| raw-socket | gVisor | blocked | blocked | none | – |
| reverse-shell | runc | error | error | none | – |
| reverse-shell | gVisor | error | error | none | – |
| sys-leak | runc | error | error | none | – |
| sys-leak | gVisor | error | error | none | – |
