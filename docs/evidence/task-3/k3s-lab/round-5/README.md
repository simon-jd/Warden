# Task3 bootstrap fix round5/5 — CRI readiness diagnosis and fixed recovery preparation

Status: **DONE_WITH_CONCERNS** for this code substep. Source `30ac35088034db0d21fc1fc3ea681a973c9bab95`; actual source parent `a853f0155e8c082de71f446d5637f8295a2edb2a` (controller documentation interleaved). Dispatch BASE remains `81a46b0c49e9c8c0ddcc523bdea9d6faa5043015`. Earlier SHA-bound evidence is unchanged. Task3 remains OPEN; this is the final fix round, not a reset of the loop.

No real Docker create/start/import/recovery/deletion, inotify probe, K3s launch, capless image smoke, tenant workload or host mutation occurred. The retained fourth scene and its full 6GB charge remain. This code does not resolve the underlying fsnotify resource shortage or establish Ready. After independent review, only the controller may execute the necessary fixed recovery and inspect its current-helper diagnostic; another bootstrap is not authorized by this result.

## Actual read-only diagnosis

Fixed CID `9a22e3c1817441fa2c4f50616e68a333d2a06c98641d430a05a810ea3f7cac50`, image `sha256:2504a55c791dba7ca00cadae8b11f937aea70ac9149243eb83e590d343bc44a3`, Size685,374,913B. Labels: owner=`codex-warden`, project=`warden`, session=`b5370b6ce57638aee676a14c3c272592`, ttl=`2026-10-24T19:09:18Z`.

Outer `.cache/warden-lab/docker-b5370b6ce57638aee676a14c3c272592` remains DEV66307/INO56143028/UID1000/0700. Child `session-7ca9caee772671b1` remains DEV66307/INO56143043/UID0/0700. Retained `rootfs.tar` remains DEV66307/INO56143030/UID1000/0600/nlink1/496,619,520B. Final diagnosis held the original outer and tar FDs and checked both FD/path identities before and after. The container remained exited/PID0/exit2/restart0, with running/paused/restarting/OOM/dead false; its exact original systemd scope remained absent.

Fixed archive HEADs: root/state/io404, containerd.toml124B/0600, containerd.log0B/0600, startup-private.log154,227B/0600. Both original fixed controller logs below root returned404, with no alternative-path fallback. These metadata reads do not establish absence of extra private entries: the future helper still must verify exact three-file shape, owner/mode/nlink/size/blocks before any remount or deletion.

Only the fixed snapshot archive was read in process memory:154,227B,1,099 lines,SHA256 `805ea89785a0720d6399eb92b3f26b63e2b944aaea3fd42d3ee9932dc36ce68b`. The combined content limit is32,000,000B plus bounded tar overhead; a single exact regular member is required, rejecting links/devices/aliases/extra members/PAX/oversize and metadata drift. Raw log text, keys, tokens, kubeconfig and Node/namespace JSON were not printed, cached, written or committed. `diagnose-fourth.py` reproduces the fixed read-only process; `diagnostic-final.json` contains only safe metadata, enums, counts and hashes. Existing-warning classification explicitly uses synthetic Ready-window/namespace inputs and is not a passing live gate or Ready proof.

All51 previously unknown warning/error observations now match exact source-backed templates. There are no remaining unknown severity observations in this snapshot:

| Fixed diagnostic enum | Count | Primary-source chain |
|---|---:|---|
| cri-cni-watcher-emfile |1| containerd `cni_conf_syncer.go:45–47` → `service.go:267–269` → `plugins/cri/cri.go:165–167` → `server.go:199` |
| cri-service-unimplemented |238 info observations| K3s `pkg/agent/cri/cri.go:47–64`, retrying absent runtime.v1.RuntimeService once per second |
| ca-watcher-emfile |16| Kubernetes `dynamic_cafile_content.go:169–183`, retry every minute |
| cert-watcher-emfile |32| Kubernetes `dynamic_serving_content.go:143–157`, retry every minute |
| flexvolume-missing-default |1| Kubernetes `pkg/volume/flexvolume/probe.go:275` |
| flexvolume-ro-default |1| same `probe.go:278` → `pkg/volume/plugins.go:577` |

The CRI CNI watcher fails with EMFILE while being constructed. Containerd then does not register its CRI gRPC service. K3s waits for this service (`pkg/agent/containerd/containerd.go:118`); `pkg/daemons/agent/agent.go:41` waits for CRIReadyChan before starting kubelet. The238 exact retry observations and absence of kubelet-start/registration/Ready observations agree with that dependency chain. This explains a real readiness blocker, independently of any unobserved client query error. API-serving3, k3s-running1 and kubeconfig-written1 were discovered as safe candidate counts; they are not API/Node Ready proof. The old implementation discarded kubectl stderr and returned only a generic query failure, so the exact old API/TLS/client-query result cannot be reconstructed. The brief's names wait_ready/api_get/load_config were conceptual misnomers; actual code is the nested query plus run_node loop, and no such new interfaces were invented.

The pinned fsnotify v1.9.0 Linux implementation calls `InotifyInit1(IN_CLOEXEC|IN_NONBLOCK)` and returns its errno. EMFILE alone cannot distinguish the original processes' RLIMIT_NOFILE from the shared real-UID inotify instance quota. Original-process FD counts/rlimits and quota usage were not measured. Ancillary read-only configuration reads reported fs.inotify.max_user_instances128, max_user_watches65536 and fs.file-max9223372036854775807; these are limits, not original-time usage or causal proof. No other-process FD enumeration, FD target reads or host changes occurred. NoSwap/outer swap0 remains established by the earlier controller evidence and is not recast as an unproven cause.

`source-references.json` records17 exact pinned primary URLs,338,191 total bytes and all length/SHA256 checks. Cache: `.cache/warden-k3s-materials/round-5-source/`. Versions remain K3s v1.36.5+k3s1, Kubernetes v1.36.5-k3s1, containerd v2.3.4-k3s1.36, gVisor release20261019.0. The earlier round4 source cache supplies the already-verified agent/embedded-executor and dependency pins. Only small primary-source files were fetched; no new runtime material, large download or version change occurred.

## Controller-approved minimal changes

The image tar writer now creates the fixed empty `/usr/libexec/kubernetes/kubelet-plugins/volume/exec` directory and its parents, root-owned0755. The controller-manager's FlexVolume prober can find its default directory without attempting to create `/usr/libexec` on the read-only root. The directory contains no executable plugins. This removes a known default-directory condition; it does not solve subsequent fsnotify failure. The old FlexVolume and EMFILE failure templates remain rejected by the strict startup gate. No new allowlist entry, writable root, capability, bind, device, host namespace or sysctl change was introduced.

The existing240-second readiness loop now publishes one fixed diagnostic on timeout: last_stage enum, attempt count and five failure counters (api-query/api-body/node-query/node-json/node-ready). Counters saturate at240; not-attempted is the initial enum. No stderr, HTTP body, Node JSON or exception message reaches this output. Kubectl invocation, request/process deadlines, API response requirement, Node Ready requirement, subsequent final Ready recheck, UTC warning windows and namespace proof remain unchanged.

The fixed recovery pins only the fourth scene and124/0/154227B files, plus the exact retained tar above. Its approved two-capability profile remains SYS_ADMIN+DAC_OVERRIDE,256MB memory=swap,32 tasks,1CPU, private namespaces, RO root/one original RO rprivate bind, immutable code argv/hash, exclusive durable journal and full original reservation. The old third scene is no longer a recovery target.

After the RO identity/shape/allocation checks, before remount, the helper obtains its own nofile soft/hard limits and counts only entries in `/proc/self/fd` (conservatively refusing upon reaching4096, without reading names/targets or another process). It makes exactly one inotify_init1 call, without adding any watches, and immediately closes a successful FD in finally. The closed call's result is a fixed opened/emfile/enfile/other enum plus bounded errno. RLIM_INFINITY is represented by-1. A supported syscall failure is diagnostic data and does not prevent necessary recovery; unknown reads/schema or close failures preserve the scene.

Host recovery accepts exactly one canonical bounded diagnostic JSON line followed by the original success marker and newline, after exit0. It rejects missing/extra lines or fields, duplicate/noncanonical JSON, bool/noninteger numeric fields, out-of-range values and inconsistent errno enums. The validated record is retained in the final recovery journal/public summary. This future record describes only that helper at that time; one successful probe cannot prove original K3s limits, quota root cause or sufficient capacity for a subsequent K3s launch.

All prior identity/shape/recheck/deletion constraints remain: helper success and child absence; exact helper/original/container-image removal and positive absence checks; fresh ordinary budget guard; recheck original parent, held tar FD and exact tar pathname; dirFD unlink and directory fsync; durable completed journal and charge release. Unknowns retain objects/charge. A failure after tar unlink can leave the tar absent while the charge remains, as already tested. There is no original Popen/GoGate retirement claim.

## Resource accounting and tests

Final read-only diagnosis accounting:3,524,603,904B project allocation (only the exact original reserved private child opaque) +6,000,000,000B outstanding +1,434,749,826B all-owned-image charge (2×Size+64MB) +64,000,000B helper reserve =11,023,353,730B <12,000,000,000B. Helper+host memory allowance320,000,000B <16,000,000,000B with zero other declared service maxima. This is a conservative pre-recovery estimate, not an ordinary complete walk or live peak. Evidence writes can change subsequent allocations; controller recovery must compute fresh accounting. Azure/GPU/cloud commitment0.

`red-tests.txt` records6 new tests with10 failures: the actual synthetic package tar lacks the default directory, actual run_node query-loop behavior lacks the stage diagnostics, the old fixed scene remains selected, and the new bounded helper/protocol APIs are absent. No fixture setup error was counted as behavioral success. `intermediate-tests.txt` records49 PASS before the extra required probe-order/error-cleanup test and final strict newline/cap checks. Final command, actual UID1000 and umask0077:

```sh
umask 0077
PYTHONPATH=scripts python3 -B -m unittest -v test_k3s_lab_round5 test_k3s_lab_recovery test_k3s_lab_init test_k3s_lab_round4
```

`verification-tests.txt`: **50 tests PASS, zero skips**. Docker and inotify syscall boundaries are synthetic; no real probe or scene mutation happened. Coverage includes actual tar output with synthetic inputs, all five query phases without private output, bounded FD enumeration/close behavior, accepted resource-error data, ROshape→probe→remount ordering, strict host proof, malformed proof preserving objects/charge, fixed fourth-scene metadata and prior cleanup/NoSwap/UTC/namespace/alias/lost-response/tar-durability regressions. Existing ordinary unprivileged filesystem/subreaper tests remain real. The obsolete third-scene identity assertion is replaced by the fourth-scene assertion, without dropping archive drift tests. No broad suite, ABI/image smoke or extra reproduction ran. Source `git diff --cached --check` passed. Source was frozen after final verification.

`verification.json` binds source/test hashes, primary-source metadata, safe diagnosis and final test output to the source commit. The report was appended to `.superpowers/sdd/2-warden-security-plan/task-3-k3s-lab-report.md`.

Remaining concerns: persistent fsnotify EMFILE is not solved; actual helper/resource results and future Ready/CNI/cgroup behavior are unverified; no complete cleanup/retirement, driver, guest limits, conformance,100-launch measurement or Task3 completion is claimed. No bootstrap retry follows automatically from this round.
