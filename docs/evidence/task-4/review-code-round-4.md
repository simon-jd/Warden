- **scripts/firecracker_lab.py:315; runtimes/firecracker/supervisor.go:152 — I5: ADDRESSED for the scoped source gate.** The corrected Config requirement removes I6’s obstruction to the previously reviewed denial candidate. The supervisor still requires ACK completion before policy loading and successful device-boundary checks before proceeding (`supervisor.go:155`, `:163`). **Actual TUN enforcement remains OPEN**; this round performed no enforcement attempt.

- **scripts/firecracker_lab.py:315; scripts/test_firecracker_device_receipt.py:127 — I6: ADDRESSED at source.** Inspection now strictly requires `OpenStdin`, `StdinOnce`, and all three Attach fields to be boolean true, with `Tty=false`. The unchanged sender writes exactly one ACK and closes CLI stdin (`scripts/firecracker_device_receipt.py:124`); the unchanged Go receiver retains its bounded ACK+EOF requirement (`runtimes/firecracker/device_gate.go:21`). Pinned v28 sources confirm the existing create flags select this configuration, CLI input completion half-closes attach input, and non-TTY `StdinOnce=true` closes container stdin while retaining output. [CLI configuration](https://github.com/docker/cli/blob/v28.0.0/cli/command/container/opts.go#L673-L676), [CLI input lifetime](https://github.com/docker/cli/blob/v28.0.0/cli/command/container/hijack.go#L133-L163), [Moby stream closure](https://github.com/moby/moby/blob/v28.0.0/container/stream/attach.go#L58-L89).

- **Check — regression coverage:** `scripts/test_firecracker_device_receipt.py:135` verifies valid ACK bytes with a daemon-held writer fail without EOF; `:141` verifies corrected lifetime produces success output after ACK+EOF. Correlation failure sends no ACK; wrong, extra and empty ACK cases fail (`:132`, `:159`). Six-mode Config routing and strict-value rejection are covered at `scripts/test_firecracker_lab.py:155`. Failed completion remains charged despite mocked successful cgroup absence (`:176`).

- **New Critical: None identified. New Important: None identified. New Minor: None identified.**

- **Out-of-scope observations: None.** Earlier I1–I4 and unchanged denial, identity and retirement architecture were not reopened.

- **Check — fixed package:** read the 106,943-byte package in bounded passes; verified four commit-parent links, all 24 changed files and 28 patch hunks against checkout content using read-only object/file inspection, without Git commands.

- **Check — provenance:** verified four source hashes/modes, 18 unchanged interfaces, six unchanged function segments, 88 unchanged Go files, 142 preserved prior evidence files, 91 old indexed entries and 14 new indexed artifacts. The report’s preserved prefix and appended frozen README match. An initial function-hash assertion included a trailing newline; using the manifest’s exact AST source segments confirmed all six hashes.

- **Check — recorded tests:** archived output supports the reported focused RED of one failure/two PASS, GREEN of four PASS, release GREEN of one test/six subcases, and committed-source covering result of **24 Python PASS / exit0**. The six initial release errors are retained and correctly identified as environment errors. No Go rerun is claimed.

- **Check — recorded resources:** both saved postflights match the original six sysctl values and record empty owned image/container lists with zero outstanding charge. The controller snapshot records **3,931,807,744 bytes at 22:13:44Z**. These are archived observations, not fresh admission or peak-memory evidence.

- **Spec verdict: PASS for this narrow Config/stdin-lifetime source fix.** The diff preserves the fixed protocol, closed privileged-mode list and existing authority/release boundaries.

- **Quality verdict: PASS for the scoped fix.** The new live-pipe fixture answers the previously missing daemon-writer lifetime case; its limitation as a Python stand-in is explicit.

- **Cannot verify / actual acceptance: OPEN.** Pinned v28 sources are not a source/binary match for installed Docker29.9.1. Actual attach/EOF behavior, receipt correlation, BPF permissions/composition, TUN denial, basic-device/KVM12 checks and exact outer-cgroup disappearance remain unperformed. Fresh source-bound preparation and admission are required before controller execution. Task3’s existing five-round cap/Ready status, Task4 actual VM/conformance/snapshot/capacity/API retirement and the overall Goal remain OPEN.

- **Check — reviewer execution limits:** no tests, builds, edits, report-file writes, Git commands, child agents, Docker/cloud/device/BPF/KVM/VM actions were performed.

- **Fix round: All scoped source findings addressed; no new Critical/Important breakage. Actual acceptance remains OPEN.**
