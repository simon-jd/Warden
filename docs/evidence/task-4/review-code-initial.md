### Spec Compliance

- ❌ **Issues found:** the initial code phase does not fully preserve the binding requirement that every ambiguous gate marker remain `cleanup_pending`. `Driver.Close` overlooks failed starts without registered handles and can publish successful retirement (`runtimes/firecracker/driver.go:237`, `runtimes/firecracker/driver.go:258`). See Important finding I1.
- ✅ The required Firecracker implementation, rootfs construction, snapshot support and gated conformance/measurement entrypoints are present. Local-host documentation correctly replaces the overridden cloud Terraform requirement (`runtimes/firecracker/firecracker.go:16`, `runtimes/firecracker/rootfs.go:39`, `runtimes/firecracker/snapshot_io.go:84`, `runtimes/firecracker/lab_test.go:43`, `docs/firecracker-lab.md:5`).
- ⚠️ **Actual runtime acceptance remains OPEN:** boot, conformance, snapshot performance and capacity were explicitly skipped. Guest enforcement, complete VMM retirement, restored control-channel behavior, TUN denial and host compatibility remain unverified. Production/API retirement integration is expressly unimplemented (`docs/firecracker-lab.md:3`, `runtimes/firecracker/lab_test.go:20`, `runtimes/firecracker/capacity_test.go:14`).

### Strengths

- Default and explicit limits remain distinct: the normal default preserves a 512 MiB workload, while the benchmark fixes the machine at 128 MiB without enlarging smaller payload entitlements (`runtimes/firecracker/firecracker.go:31`, `runtimes/firecracker/firecracker_test.go:57`).
- Host identities are authority-bound and durably advanced before use; corruption, orphan state and duplicate RunIDs fail closed (`runtimes/firecracker/identity.go:105`, `runtimes/firecracker/identity.go:169`, `runtimes/firecracker/identity.go:192`).
- Rootfs normalization implements the exact approved mtab omission, retains ordinary mtab files, and includes omitted metadata in collision checks before extraction. Raw export, normalized input and policy hashes remain separate (`runtimes/firecracker/rootfs.go:78`, `runtimes/firecracker/rootfs.go:113`, `runtimes/firecracker/rootfs.go:124`, `runtimes/firecracker/rootfs_test.go:183`).
- Trusted guest frames are separated from tenant output; replay and malformed session transitions are rejected. API mutations disable connection reuse and are tested against lost responses (`runtimes/firecracker/protocol.go:77`, `runtimes/firecracker/guest/session.go:36`, `runtimes/firecracker/api.go:64`, `runtimes/firecracker/api_test.go:18`).
- Snapshot capture is restricted to an unbound guest, binds immutable inputs and machine shape, and enforces two-baseline retention (`runtimes/firecracker/snapshot_io.go:121`, `runtimes/firecracker/snapshot_io.go:135`, `runtimes/firecracker/snapshot.go:20`).
- Resource wrappers use separate bounded code and live profiles, exact KVM access, eight capabilities and owned-resource accounting (`scripts/firecracker_code.py:35`, `scripts/firecracker_lab.py:58`, `scripts/firecracker_lab.py:77`).

### Issues

#### Critical — Must Fix

- None identified in this review.

#### Important — Should Fix

**I1 — Failed starts without handles can produce a false successful node retirement.**

- **Locations:** `runtimes/firecracker/driver.go:237`, `runtimes/firecracker/driver.go:245`, `runtimes/firecracker/driver.go:258`; originating paths at `runtimes/firecracker/vm.go:70` and `runtimes/firecracker/vm.go:146`.
- **Trigger:** call `Gate.Start` with a valid RunID but an invalid profile or an image digest differing from the manifest. Alternatively, fail allocation or record persistence before `d.handles` is populated at `runtimes/firecracker/vm.go:171`.
- **Behavior:** unchanged `Gate.Start` durably writes `launching` before invoking the driver (`runtimes/gate/gate.go:235`). These failures return without registering a handle. `Driver.Close` enumerates only `d.handles`, so it never calls `Gate.Reap` for that RunID and can write `known-owner-retired`. The supervisor accepts that marker before removing owned assets and releasing metadata (`runtimes/firecracker/supervisor.go:228`).
- **Impact:** the node claims successful retirement despite an unresolved durable gate marker. This contradicts the explicit retirement ruling even when the particular failure occurred before VM creation.
- **Fix:** make shutdown account for every gated start attempt and outstanding durable run/gate state, including attempts that never acquired a handle. Preserve `ErrAmbiguous` and refuse the retirement marker when any such state remains. Coordinate this with shutdown admission; retain the existing Gate proof boundary.
- **Missing regression:** `TestLocalRetirementCannotSwallowAmbiguousGate` installs a handle explicitly (`runtimes/firecracker/driver_test.go:47`), so it cannot catch this path. Add focused cases for a rejected gated start and a reservation failure before handle registration; require `Close` to preserve ambiguity and leave `node/retired` absent. No VM or privileged operation is necessary.

#### Minor — Nice to Have

- None identified.

### Checks and Evidence

- **Frozen-package integrity:** independently reconstructed added-file bytes from `review-ad1ede9..84a132b.diff`; all **43 source-manifest hashes** and **36 evidence-index hashes/lengths** matched. The private report contains the exact public README, with an extra trailing newline (`docs/evidence/task-4/55bd96828669c8e1536da321bcb87bae13afa6ea/source-manifest.json:1`, `evidence-index.json:1`).
- **Recorded validation:** inspected final logs showing **38 Go passes, four declared live skips, five Python passes**, preparation and capless ABI success. No suite, build, preparation or ABI run was repeated (`docs/evidence/task-4/55bd96828669c8e1536da321bcb87bae13afa6ea/code-tests.log:1`, `python-tests.log:1`, `prepare.log:1`, `abi.log:1`).
- **Named unchanged-interface checks:** checked Gate start/reap marker semantics for I1, and the shared conformance limits and probe behaviors against the adapter (`runtimes/gate/gate.go:198`, `runtimes/gate/gate.go:253`, `runtimes/conformance/suite.go:25`, `runtimes/conformance/guest/main.go:16`).
- **Named upstream contract check:** checked whether jailer creates an unremoved nested cgroup. With no `--cgroup` properties, v1.17 moves into the existing parent; this concern did not become a finding. [Pinned jailer implementation](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/jailer/src/env.rs#L213-L225).
- **Review boundary:** finite source, interface and evidence passes; only output-truncated sections were fetched again. No edits, git operations, tests, Docker/device/cloud operations or child agents.

### Assessment

**Task quality: Needs fixes.**

The implementation has clear security boundaries and unusually explicit evidence limitations. I1 breaks the mandatory ambiguous-retirement contract and must be fixed before approving the initial code gate; actual runtime and API integration acceptance remain separately open.
