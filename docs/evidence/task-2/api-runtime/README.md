# API/runtime code-phase evidence

Implementation: `09eed7b622bc70081eb751ea42dd0c81bd5c1395`.
Base: `c3f182386186d52bc8589c706843128ebd398e2c`.
Date: 2026-10-24 UTC / 2026-10-23 America/Los_Angeles.

Status: **code phase complete, independent review and capability-bearing live acceptance pending**. There is no API→runc live PASS, no positive full kernel-retirement claim, and no Task 2/Goal completion claim. [Design and commands](../../../api-runtime-lab.md).

| Verification | Actual result | Artifact |
|---|---|---|
| `scripts/build-runtime-lab.sh` | Build only, exit 0; fixed probe/test binaries and OCI image | `build.txt`, input manifests |
| `python3 -B -m unittest discover -s scripts -p 'test_runtime_lab*.py'` | 41 tests PASS; external Docker boundary doubles, real ordinary-user filesystem/process tests | `python-tests.txt` |
| `scripts/go.sh test -race ./runtimes/gate ./runtimes/runc ./controlplane/internal/apilab -count=1 -v` | 38 top-level PASS; 8 explicitly unexecuted live SKIPs (7 existing conformance cases + new API fixture), no race report | `go-focused.txt` |
| `scripts/go.sh vet ./controlplane/... ./runtimes/...` | exit 0 | `vet.txt` |
| `python3 -B scripts/runtime_lab_docker.py api-code --other-service-memory-bytes 0` | Real private PG, capless outer: 26 top-level tests PASS, no SKIP; runtime-boundary doubles in scheduler tests | `code-final.txt` |
| `python3 -B scripts/runtime_lab_docker.py api-smoke --other-service-memory-bytes 0` | ABI PASS; live API fixture explicitly SKIP/NOT EXECUTED | `smoke-final.txt` |
| `python3 -B scripts/runtime_lab_docker.py api --other-service-memory-bytes 0` | Expected refusal before Docker activity; no independent-review acknowledgment | `live-refused.txt` |
| `git diff --check`; post-commit code-only diff against implementation SHA | exit 0; no source difference | report/verification metadata |
| Exact resource postflight + zero-resident-service preflight | Own containers/images absent, import charges released, cached PG image retained | `postflight.json`, `postflight-budget.txt` |

Code and smoke manifests contain every packaged input SHA-256, including the trusted Python entry/runner/path code, statically built tests/probe, runtime ELF/ABI closure and OCI archive. Their identity/charge files bind the imported images to full random session labels. Final ordinary-user postflight queried the exact three container IDs from those runs and the Warden ownership scope using the pinned local socket. No other-project object or cached PG image was removed. The 5GB API import charge and 4,536,870,912-byte aggregate service maximum appear in the preflight logs; PostgreSQL uses bounded tmpfs and no persistent volume.

## TDD and fault evidence

Behavioral RED→GREEN evidence includes retired-authority admission, forged PG proof/boolean cleanup, ambiguity-label laundering, missing private PG topology, capless tmpfs writeability, retained gate evidence, pidfd live-versus-exit discrimination, and original-directory cleanup verification. `red-pidfd.txt` and `red-disk-proof.txt` are explicit behavioral mutation checks: replacing the relevant kernel/FD observation with unconditional success made the tests fail; production implementations were restored and their tests passed. Interface-first compilation failures are separately labeled `red-*-interface.txt`, not counted as behavioral failures.

`red-reconciliation.txt` failed with `forged proof accepted` on real PG before validation. `red-ambiguity-label.txt` failed with `ambiguous creation label laundered for a later boolean clear` before the sticky-designation guard. `code-final.txt` verifies both fixes together with the existing durable scheduler suite. Preliminary focused GREEN files are retained for provenance; final results are the files in the table above.

The fixed live fixture's positive composition is intentionally gated. It uses actual HTTP, PG and runc when later enabled, plus a named test-only lost-ack barrier after genuine remote Start. It must still prove parent reap, full controlled cgroup emptiness, final disk cleanup, permanent Start refusal, per-run proof/authority matching, and atomic PG/audit reconciliation on the original node. Negative capless tests and fakes do not establish those live results.

The code commit preceded this evidence package. `verification.json` records its SHA, final commands, code-only diff result, test counts and SHA-256 of evidence files. No dependencies, production authentication, shared host service, cloud/GPU resource, push or deployment changed.
