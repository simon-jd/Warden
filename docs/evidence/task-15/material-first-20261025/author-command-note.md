# Task15 material caller note (inert)

The body is `task-15-material-command.py.txt` (8007 B, SHA-256 `c2c908a23ae14338097793aef77a0a1918d22e70b2bb3c1c9aeef0d27ebfd125`). Static syntax parse only; it has never run. Root must review the exact body, fresh disk/memory and new N ownership before authorizing a single material attempt. From `/home/postedism/Desktop/Warden`, the proposed future wrapper is:

```bash
/usr/bin/timeout --signal=TERM --kill-after=1s 89s /usr/bin/python3 -I -B .superpowers/sdd/2-warden-security-plan/task-15-material-command.py.txt
```

The wrapper's 89+1 seconds includes process setup, network, extraction, status and close. The body requires UID/EUID 1000, checks every parent via nofollow directory FDs, creates only a fresh private 0700 N, applies AS 1 GiB/CPU 45s/FSIZE 256 MiB/CORE 0/NOFILE 64, and checks fresh `additional=5419430400` B and `service-memory=10073741824` B without old PID/RSS inspection. It downloads only the fixed GitHub API metadata and three release assets after guards, caps expansion at 256 MiB and N at 400 MiB, retains N on failure and writes a short status when possible. No host umask change, child process, package execution or CLI `--version`. Bundle hash and GitHub TLS/API digest are checked; no cryptographic publisher verification is claimed. Task15/Goal remain OPEN.
