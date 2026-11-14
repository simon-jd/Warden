- **New Important — omitted targets are still followed during enumeration:** `scripts/firecracker_recovery.py:660` uses `os.walk(..., followlinks=False)`. Before the exact omission checks at `:669`, Python classifies each directory entry using `DirEntry.is_dir()` with its default following behavior. The installed public implementation confirms this at `/usr/lib/python3.14/os.py:377–383`; it yields entries only at `:418`. Thus enumeration attempts target metadata access for the fixed `sitecustomize.py` and development-library links, violating the explicit prohibition on statting their targets for omission. `followlinks=False` prevents recursive descent, not this earlier target lookup. This is a source-confirmed defect; no actual target access was performed during review.

- **Associated validation gap:** `scripts/test_firecracker_recovery.py:375` patches `os.open`, `os.stat` and `os.read`, but does not intercept the internal target lookup performed by `DirEntry.is_dir()`. Its PASS therefore does not establish the claimed no-target-access boundary. Correct enumeration must classify entries without following links and apply the exact rules without querying omitted targets; the regression should detect target-following classification as well as explicit opens/stats.

- **Check — remaining exact material rules:** `scripts/firecracker_recovery.py:573` authenticates the three fixed symlinks through nofollow parents and own metadata/readlink checks. `:591` holds and hashes the fixed regular sysconfig sibling; archive construction at `:182` copies and charges both regular names. `:596` limits the exact development-object omission to authenticated metadata and its first20 bytes. `:637` rejects omitted dependency names before resolution. No additional defect was found in these scoped paths.

- **Check — fixed ABI plan:** `scripts/firecracker_recovery.py:686` contains the literal import/flag/version/symbol-check program; `:705` enforces the closed bounded receipt. `:720` authenticates inputs before the check and rechecks them afterward. It resolves `mount` without invoking it. Host success remains distinct from sealed-image execution.

- **Check — predecessor and operation binding:** `scripts/firecracker_recovery.py:835` requires the exact failed-settled predecessor shape, source/helper, coherent state, labels and fresh object absence. `:881` binds its hashes/metadata to the new operation. Exclusive creation at `:925` prevents reuse; phase provenance at `:914` is rechecked at later transitions. Restore at `:1103` consumes only the new operation’s successful inspect. Fresh accounting at `:1114`, `:1125`, `:1132`, `:1142` and `:1151` retains the full new H and original Q.

- **Check — prior safety boundary:** the scoped delta leaves the reviewed pending-operation cleanup policy unchanged. No new cancellation, settlement-from-empty-list, reset, retry, helper authority or boot opportunity was introduced.

- **Evidence and review performed:** read the requirements, complete supplied seven-commit `96b2016..36c5856` package, final material report, test history and verification records. Recorded committed-source validation is34PASS/0.111s; it was not rerun. For the named enumeration doubt, performed exactly one focused read of the public `os.walk` implementation. No tests, Git commands, writes, historical integrity crawl, subagents or actual operations were performed.

- **New Critical: None. New Important: One, above. New Minor: None. Out-of-Scope Observations: None.**

- **Spec verdict: NOT PASS.** Enumeration violates the explicit omitted-target metadata-access restriction.

- **Quality verdict: NOT PASS.** The implementation and its guarded fixture miss the same implicit target-following path.

- **Source/plan execution gate: NOT PASS.** Do not execute the new fixed inspect from this source. The remaining scoped checks do not override this material boundary failure.

- **Cannot Verify / actual limitations:** new host ABI, ELF closure, archive, predecessor authentication, scratch imports, live inventory, remount/chown and ordinary postflight remain unperformed or unverified. The earlier8c material attempt and pre-daemon cleanup remain failed-settled history, not successful inventory. Q5GB remains unreleased; I7, Task4 acceptance and original-owner/Gate/API retirement remain OPEN. Task4 remains round5; B and a new boot remain unauthorized by this review.
