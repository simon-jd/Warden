# attacks

The isolation matrix (Task 5): every corpus entry runs once on each runtime,
and each cell says whether the runtime blocked it, detection caught it, or
neither.

- `matrix/`: Go package `warden/attacks/matrix`. It loads the corpus, runs it
  on a `runtimes.Runtime`, classifies each run and renders the matrix.
- `matrix/cmd/matrix`: the command that checks a corpus and renders results.
- `corpus/`: fourteen bounded probe entries, each with its own script and expectation.

## Corpus entries

```
attacks/corpus/<id>/expect.yaml
attacks/corpus/<id>/run.sh
```

`expect.yaml` holds exactly three keys:

```yaml
id: <id, the same as the directory name>
technique: T1611
success_signal: <a line the probe prints only when it reached its goal>
```

`run.sh` runs as `/bin/sh -c <script>` inside the sandbox. The sandbox uses
the platform defaults: no network, read-only rootfs, uid 65534, cpu 1, 512
MiB, pids 128. The timeout is 60 s; `WARDEN_MATRIX_TIMEOUT_S` overrides it.

The script must not contain the success signal literally. Build it at run
time, for example `printf '%s_%s\n' PART1 PART2`, so that a shell error that
echoes a line of the script cannot produce it. `matrix validate` rejects a
script that breaks this rule.

```sh
.tools/go/bin/go run ./attacks/matrix/cmd/matrix validate -corpus attacks/corpus
```

## Verdicts

| Verdict | Meaning |
|---|---|
| blocked | The run finished, its output is complete, its cgroup is empty, and the signal never appeared. |
| missed | The signal appeared in the output. |
| detected | The signal appeared and an alert names the run's ID. |
| error | Start, wait, logs or cleanup failed with no signal in the output, so the cell has no verdict. |

The exit code is recorded but plays no part in the verdict: a probe can exit
non-zero because it was stopped or because it failed on its own. A run that
timed out or was OOM-killed without printing the signal counts as blocked,
and its row in the matrix says so.

## Running it

Each runtime's lab test runs the matrix after its conformance suite when
`WARDEN_MATRIX_CORPUS` is set, through `matrix.RunFromEnv`. The tests are
`TestConformance` (runc), `TestGVisorConformance` and
`TestFirecrackerConformance`. Each writes `<runtime>.json` into
`WARDEN_MATRIX_OUT`.

| Variable | Meaning |
|---|---|
| `WARDEN_MATRIX_CORPUS` | Absolute path of the corpus directory. |
| `WARDEN_MATRIX_OUT` | Absolute path of an existing directory for the results. |
| `WARDEN_MATRIX_IMAGE_DIGEST` | Image the probes run in; it needs `/bin/sh`. Default: the lab's probe image. |
| `WARDEN_MATRIX_IMAGE_NAME` | runc only: that image's name in the lab daemon. |
| `WARDEN_MATRIX_TIMEOUT_S` | Per-probe timeout in seconds, 1–3600. |

The lab probe image is `FROM scratch` and has no shell. `scripts/build-corpus-image.py` packages the pinned Ubuntu dash/libc loader closure and the local `warden-attack` helper into a separate OCI image. The live matrix needs dedicated lab capacity and evidence collection. Integrated lab paths:

- **runc:** `scripts/runtime_lab_docker.py matrix --other-service-memory-bytes 0` packages and imports the corpus image and writes a JSON result in its owned session.
- **gVisor:** `make test-gvisor` imports the corpus image into its internal k3s node and writes `.cache/k3s-gvisor/lab/matrix/gvisor.json`.
- **Firecracker:** `scripts/firecracker_lab.py prepare --other-service-memory-bytes 0`, then `conformance` with the same option packages the shell/helper in the fixed payload and writes a JSON result in the owned live session. The guest accepts only the fourteen exact corpus commands.

## Rendering

```sh
.tools/go/bin/go run ./attacks/matrix/cmd/matrix render \
  -results out/runc.json,out/gvisor.json,out/firecracker.json \
  [-alerts alerts.jsonl] \
  -out docs/evidence/isolation-matrix.md \
  -executions out/executions.jsonl
```

`-alerts` takes the detection alerts as JSON lines
(`{alert_id, execution_id, rule_id, alerted_at}`, with `execution_id` = run
ID) and turns each alerted `missed` cell into `detected`. Alerts about other
runs are ignored. `-executions` writes the runs in the format
`detect/report/detection_metrics.py` reads: a probe that printed its signal
is `succeeded`, a blocked one `failed`, and an error `skipped`. Feeding that
file and the same alerts to `detection_metrics.py`, and its JSON to
`detect/report/detection_report.py`, gives the Task 13 page for the corpus
runs:

```sh
python3 -B detect/report/detection_metrics.py --executions out/executions.jsonl \
  --alerts alerts.jsonl --observed-until <RFC3339> > out/metrics.json
python3 -B detect/report/detection_report.py --metrics out/metrics.json \
  --out docs/evidence/detection-coverage.md
```

`detection_metrics.py` rejects alerts whose `execution_id` is not in the
executions file, so pass it only the alerts for these runs.

## Status

The runner, classifier, renderer and lab hooks are tested with a host-shell
stand-in and two fake probes (`matrix/testdata/corpus`: one always prints its
signal, one never does). The 14-entry corpus and the three lab adapters now have offline tests. The corpus has not yet run on a live runtime, because the user's other Warden Cilium/metadata lab currently owns those resources. No 42-cell result is asserted.
