# Task5 independent classifier fixture evidence

Source: `6cedf69d7da82e7fd2cd80c69d5d9bfb5b0024aa`; base: `b765fe109251ed7579386a70d5655c7e4edcccdd`.
This is partial Task5 code evidence, not Task5 acceptance, a runtime test, detector
validation, or an actual attack result. Every fake attack and evidence record was
authored by subagent `/root/matrix_classifier`; source labels such as guest,
runtime and independent collector describe simulated fixture roles only.

## Actual finite runs

1. `python3 -B .cache/task5-classifier/run-fixed.py red`: real working-tree RED;
   the original `TestMatrixClassifiesFixture` failed against a default error/null
   stub (`invalid_fixture`), as captured in [red.log](red.log). Exit1.
2. `python3 -B .cache/task5-classifier/run-fixed.py green`: real working-tree GREEN;
   all then-present tests passed. Exit0. [Saved working source](green-working-source/)
   differs from committed source by final explicit error-reason constants,
   invalid-kill-evidence test, and formatting. No post-hoc test result is invented.
3. Source-only commit above, then exactly ONE
   `python3 -B .cache/task5-classifier/run-fixed.py cover`: exit0.
   [cover.json](cover.json) binds identical pre/post SHA256 manifests to that
   committed HEAD and checks a clean scoped source status before execution.
   [cover.log](cover.log) is the complete covering output.

All three invoke only the literal `matrix-code` selector, whose fixed command is
`umask 0077; exec /workspace/.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin/go test -p 1 -count=1 -v ./attacks/matrix`.
No actual runtime/driver construction, guest/payload build, network, shell command
execution from tests, corpus, or attack was used. Package `matrix` is a library;
original CLI, runtime admission, runner, corpus and actual42-cell execution remain
unimplemented. There is no pretend configured CLI.

[history-command.py](history-command.py) records the earlier RED/GREEN evidence
recorder version; [cover-command.py](cover-command.py) is the exact covering
recorder. These only record the existing fixed profile, not alternative execution
profiles or product entrypoints. Historical recorder HEAD was the base commit;
RED/GREEN source was uncommitted. No pre-run per-file hash was taken for RED or
GREEN; the saved GREEN source was copied immediately after its successful run.
The historical RED implementation was the error/null stub; its source snapshot
was not retained. The frozen covering has exact source hashes before and after.

## Fixed profile, guards and cleanup

The [frozen profile source](source/scripts/firecracker_code.py) preserves the cached
image pin, Go1.26.10 path, project lock and owned-object checks. Its only delta is
the literal matrix-code selector/label. Each log contains the exact inspected
HostConfig: UID1000 command, read-only project/root, cap-drop ALL, NNP, network none,
2GB memory=swap, CPU2, PIDs256, tmpfs256MiB, bounded json logs, GOMAXPROCS2,
GOMEMLIMIT1500MiB, GOTOOLCHAINlocal, GOPROXYoff and umask0077 are fixed by source.
No image pull, download/fallback, hostGo, scripts/go.sh, cloud or GPU was used.

Every run freshly charged whole readable project + Q5,000,000,000B + all own images
(2×size+64MB) +512,000,000B before creation, with service2GB+host1GB. Every receipt
also contains a full ordinary postflight retaining Q and protected-six-sysctl
before/after equality. Logs contain exact own-labelled create/inspect/removal IDs;
all postflight own containers/images are empty. No Q/old evidence/resource was
released or modified. The first sandbox attempt stopped before container creation
at trusted-directory ownership validation; admitted runs used ordinary UID1000
outside that mapping. No rejected guard was bypassed or weakened.

## Self-review

Checked source-only scope, all identity fields and evidence reference bindings,
positive objective outcomes, guest-vs-collector distinctions, enum validation,
unknown exit/cleanup, error/log handling, duplicates/contradictions, absent marker,
nonzero/code137/outer-delete/kill-only ambiguity, no detector verdict, immutable
caller evidence and no execution/import/driver dependencies. Source cannot verify
caller truth: `ClassifyFixture` explicitly handles caller assertions and rejects
live provenance. Runtime authentication/predicate admission remains future work.
Fixtures do not occupy any of the42 real matrix cells. Task3/4 acceptance/caps,
original retirement, Task12 and overall Goal remain OPEN.

[index.json](index.json) hashes every other artifact in this directory. No old
journal/index was rewritten. Later documentation writes are small and follow the
recorded postflight; any subsequent resource operation requires fresh admission.
