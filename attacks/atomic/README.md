# Official Linux Atomics, in a dedicated local lab

`run.sh` executes one reviewed official **Atomic Red Team** Linux test inside
a dedicated container. It does not run an arbitrary YAML test or install
anything. These are the reviewed tests (`TESTS` in `emulate.py`), each with its
upstream command, argument defaults and dependencies as they are at the
reviewed commit:

| GUID | Technique | Atomic | What runs (defaults substituted) |
|---|---|---|---|
| `486e88ea-4f56-470f-9b57-3f4d73f39133` | T1082 | Hostname Discovery | `hostname` |
| `46959285-906d-40fa-9437-5a439accd878` | T1552.004 | Discover Private SSH Keys | `find / -name "id_rsa" -type f -exec sh -c '…>> /tmp/creds.txt' _ {} \; 2>/dev/null; exit 0` |
| `7c247dc7-5128-4643-907b-73a76d9135c3` | T1552.004 | Copy Private SSH Keys with CP | `mkdir /tmp/art-staging; find / -name id_rsa 2>/dev/null -exec cp --parents {} /tmp/art-staging \;; exit 0` |
| `37807632-d3da-442e-8c2e-00f44928ff8f` | T1552.001 | Find AWS credentials | `find / -path '*/.aws/credentials' -type f 2>/dev/null` |
| `085fe567-ac84-47c7-ac4c-2688ce28265b` | T1201 | Examine password complexity policy - Ubuntu | `cat /etc/pam.d/common-password` (bash) |
| `039b4b10-2900-404b-b67f-4b6d49aa6499` | T1070.004 | Overwrite and delete a file with shred | dependency: `touch /tmp/victim-shred.txt` if absent; then `shred -u /tmp/victim-shred.txt` |

The source is read from an explicit full Git commit in a checkout whose
`origin` is the official repository, without fetching (`GIT_NO_LAZY_FETCH`),
and the whole YAML's SHA256 must match the operator's reviewed pin. The test's
name, Linux platform, executor, exact command, every input argument's default
and every dependency are also checked; a test that needs elevation, or any
change, is refused. A configured remote URL and hash are reproducibility
controls, not a signature or proof of source authenticity; review the official
commit before use. Other official Atomics need a separate review and an entry
in `TESTS`.

Official references:

- [Atomics by technique](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics)
- [Repository format](https://github.com/redcanaryco/atomic-red-team/wiki/_About-Atomic-Red-Team)

## The pinned checkout

Commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6` (2026-11-06): a blobless
depth-1 checkout with no working tree in `.tools/atomic/atomic-red-team`, and
its receipt `.tools/atomic/atomic-red-team.receipt.json` (the commit, how it
was fetched, each reviewed YAML's blob ID and SHA256). The 2026-11-14
checkout was cloned when that commit was master's head. Fetch it by its SHA,
which keeps working after master moves; only the blobs `git show` is asked for
are then downloaded:

```sh
ATOMIC=a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6
REPO=.tools/atomic/atomic-red-team
git init -q "$REPO"
git -C "$REPO" remote add origin https://github.com/redcanaryco/atomic-red-team.git
git -C "$REPO" fetch --filter=blob:none --depth 1 origin "$ATOMIC"
test "$(git -C "$REPO" rev-parse FETCH_HEAD)" = "$ATOMIC"   # FETCH_HEAD must be the pin
git -C "$REPO" show "$ATOMIC":atomics/T1082/T1082.yaml | sha256sum   # one per reviewed YAML; compare with the receipt
```

The wrapper itself never fetches: it reads the YAML with `GIT_NO_LAZY_FETCH`,
so each reviewed YAML's blob must already be local (the `git show` above).

## The target

An existing, running, mount-free Docker container named `warden-lab-atomic-*`
on Docker's **runc** runtime, with Warden's labels: `project=warden`,
`owner=warden-lab` and its own `warden.dev/run=atomic-<24 hex>`. The online
detector's collector keeps alerts of such a container as a sandbox's, with
that run (`detect/falco/collector.py`), and `detect/falco/bindings.py` finds
it by the run. The run label is the run ID of the execution. Network `none`,
read-only rootfs, all capabilities dropped, no added capabilities or devices,
private IPC, no host PID or user namespace, `no-new-privileges`. The only
writable place it may have is `/tmp` as a tmpfs with exactly
`rw,noexec,nosuid,nodev,size=…` (at most 16 MiB). An explicit absolute Docker
CLI and local Unix socket are mandatory; default contexts and remote Docker
hosts are refused. Inspection resolves the immutable full container ID before
`exec`. The command runs inside that container only, with `/bin/sh` or
`/bin/bash` as the Atomic's executor names.

Use one container per run, from a local image pinned by ID; this example
performs no downloads:

```sh
DOCKER=/absolute/path/to/docker
SOCKET=unix:///absolute/path/to/docker.sock
IMAGE=sha256:REPLACE_WITH_REVIEWED_IMAGE_ID
TOKEN=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
NAME=warden-lab-atomic-$TOKEN
"$DOCKER" --host "$SOCKET" run --detach --name "$NAME" --runtime runc \
  --label project=warden --label owner=warden-lab --label warden.dev/run=atomic-$TOKEN \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --ipc private \
  --pids-limit 64 --memory 64m --memory-swap 64m --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1m \
  --entrypoint /bin/sleep "$IMAGE" 300
```

Then run from the repository, supplying the full reviewed upstream commit, the
GUID and the SHA256 of `git show COMMIT:<the GUID's YAML>`:

```sh
bash attacks/atomic/run.sh --ack-dedicated-lab \
  --docker "$DOCKER" --docker-host "$SOCKET" --container "$NAME" \
  --git /usr/bin/git --atomic-root "$PWD/.tools/atomic/atomic-red-team" \
  --atomic-commit FULL_40_HEX_COMMIT --atomic-guid GUID --yaml-sha256 FULL_64_HEX_SHA256 \
  --out /absolute/existing/parent/NEW_RUN_DIRECTORY
"$DOCKER" --host "$SOCKET" rm --force "$NAME"
```

`--out` must be a new absolute directory under an existing parent. A test's
dependencies run first, as Atomic's own runner does (check; set up if the
check fails; check again), outside the execution's interval; if the check
still fails, the test is not run and the wrapper exits 2. The wrapper creates
private files: `executions.jsonl` (the exact detection-metrics schema;
execution ID `<run>-<test>`), `bindings.jsonl` (the full container ID, run and
execution interval), and `receipt.json` (source pins, the script, image ID,
dependency steps, real timestamps, exit status and bounded tool output). It
exits 0 for command success, 1 for command failure, or 2 for a rejected
target/input or an unmet dependency. It never writes an alert and does not
run the Atomic's cleanup command: removing the container is the cleanup. A
successful Atomic is an execution result, not evidence that a detector was
operating. Collect real Falco alerts independently and use
`detect/falco/bindings.py` and `detect/report/alert_import.py`. A detector can
alert after the process exits; Falco event timestamps must still fall within
the supplied execution binding. Always remove the dedicated container
afterward, including on interruption or timeout.

Tests use synthetic data and a temporary local Git repository; they are not
live Atomic or detector evidence (also part of `make test`):

```sh
python3 -E -s -B -m unittest attacks.atomic.test_emulate
```
