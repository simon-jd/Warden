# Task 3 first code substep — durable backend binding

Source: `f232b0d5e833e1060afa5df2533b2421ee714e2c`.
This evidence is committed after the source. `manifest.json` binds changed source
bytes and captured evidence hashes. The full report is
`.superpowers/sdd/2-warden-security-plan/task-3-report.md`.

- `red-binding.txt`: missing-API compile failure before implementation.
- `red-validation.txt`: behavioral failures before port/DNS validation.
- `mutation-binding.txt`: later deliberate mismatch-check mutation caught by
  replacement and subprocess tests; mutation was restored.
- `green-binding.txt`, `race.txt`, `vet.txt`, `build.txt`: focused 17 top-level test
  invocations/zero skips, race, full vet/build passed.
- `full-tests.jsonl`, `full-tests.txt`: failed full-suite attempt, including
  unavailable DB prerequisite and existing socket ancestry checks. This is not a
  passing full-suite record. Existing live tests skipped.
- `build-runtime-lab.txt`, `api-code.txt`, `api-code-manifest.json`: rebuilt
  fixture and 26 passing real-PG runs/scheduler tests, with runtime doubles. No
  capability-bearing runtime execution.
- `api-code-identity.json`, `api-code-charge.json`, `postflight.txt`: exact owned
  objects removed, charge released, UID 1000/CapEff 0/NNP 1, resources within budget.
- `runc-socket-regression.txt`, `socket-environment.txt`: unchanged socket checks
  still fail outside remapping; the later failing ancestor is unlocalized.

Reproduce the local Go commands with `GOCACHE` and `GOMODCACHE` set to this
project's `.cache/go-build` and `.cache/go-mod`, `GOPROXY=off GOSUMDB=off`, and the
cached `.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin/go`.
The capless fixture command requires its normal fresh resource/ownership checks.

These artifacts do not supply a gVisor driver, scheduler registration, real
conformance, guest PID evidence, quiescence proof, or 100-launch startup metrics.
Task 3 overall remains open.
