# Official Linux Atomic, in a dedicated local lab

`run.sh` executes **Atomic Red Team T1082, Hostname Discovery**, GUID
`486e88ea-4f56-470f-9b57-3f4d73f39133`. Its official Linux command is
`hostname`. It does not run an arbitrary YAML test or install dependencies.
The source is read from an explicit full Git commit in a checkout whose
`origin` is the official repository, and its whole YAML SHA256 must match the
operator's reviewed pin. The exact selected Linux command and executor are
also checked. A configured remote URL and hash are reproducibility controls,
not a signature or proof of source authenticity; review the official commit
before use. Other official Atomics need a separate review and allowlist change.

Official references:

- [Atomic source and GUID](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.yaml)
- [Repository format](https://github.com/redcanaryco/atomic-red-team/wiki/_About-Atomic-Red-Team)

The target is an existing, running, mount-free Docker container named
`warden-lab-atomic-*`, labeled `warden.lab=warden-lab`, with network `none`,
read-only rootfs, all capabilities dropped, no added capabilities/devices,
private IPC, no host PID/user namespace, and `no-new-privileges`. An explicit
absolute Docker CLI and local Unix socket are mandatory; default contexts and
remote Docker hosts are refused. Inspection resolves the immutable full
container ID before `exec`. The command runs inside that container only.

Prepare an ephemeral target using a reviewed local image pinned by digest;
this example intentionally contains placeholders, and performs no downloads:

```sh
DOCKER=/absolute/path/to/docker
SOCKET=unix:///absolute/path/to/docker.sock
IMAGE=busybox@sha256:REPLACE_WITH_REVIEWED_DIGEST
NAME=warden-lab-atomic-UNIQUE_LOWERCASE_SUFFIX
"$DOCKER" --host "$SOCKET" run --detach --name "$NAME" \
  --label warden.lab=warden-lab --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --ipc private --pids-limit 64 \
  --memory 64m --cpus .25 "$IMAGE" /bin/sh -c 'sleep 300'
```

Then run from the repository, supplying the full reviewed upstream commit and
SHA256 of `git show COMMIT:atomics/T1082/T1082.yaml`:

```sh
bash attacks/atomic/run.sh --ack-dedicated-lab \
  --docker "$DOCKER" --docker-host "$SOCKET" --container "$NAME" \
  --git /usr/bin/git --atomic-root /absolute/path/to/atomic-red-team \
  --atomic-commit FULL_40_HEX_COMMIT --yaml-sha256 FULL_64_HEX_SHA256 \
  --out /absolute/existing/parent/NEW_RUN_DIRECTORY
"$DOCKER" --host "$SOCKET" rm --force "$NAME"
```

`--out` must be a new absolute directory under an existing parent. The wrapper
creates private files: `executions.jsonl` (the exact detection-metrics schema),
`bindings.jsonl` (trusted full container/run binding and execution interval),
and `receipt.json` (source pins, image ID, real timestamps, exit status and
bounded tool output). It exits 0 for command success, 1 for command failure,
or 2 for a rejected target/input. It never writes an alert. A successful
Atomic is an execution result, not evidence that a detector was operating.
Collect real Falco alerts independently and use `detect/report/alert_import.py`.
A detector can alert after the process exits; Falco event timestamps must still
fall within the supplied execution binding. Extend a binding only from actual
collector evidence, retaining the original receipt. Always remove the
dedicated container afterward, including on interruption or timeout.

Tests use synthetic data and a temporary local Git repository; they are not
live Atomic or detector evidence:

```sh
python3 -B -m unittest attacks.atomic.test_emulate
```
