# Task3 bootstrap fix round4 — code and read-only diagnosis

Status: DONE_WITH_CONCERNS, code ready for independent scoped review. Task3 remains OPEN. No real Docker create, start, import, recovery or deletion occurred. No Ready, complete cleanup, guest/conformance or Task3 completion is claimed.

Source commit: `6f52f54e1a59a8cf7a7b36223f5cd6ab016b270b`. Actual source parent: `43579657d42f835daf8d22c2a8d3f2f6fa4ff35c` (interleaved controller documentation). Dispatch BASE: `93d7c0d951d69ef15354e848e1734f6222052e80`. Earlier SHA-bound evidence is unchanged. `verification.json` binds the committed source/test bytes, final test output and read-only accounting.

## Fixed diagnosis and limits

Only the retained third-bootstrap CID `57a48b46ee5477bf65fdb6ae60bf5b7766c652630c7f2549b3e1e013a696c360` was diagnosed. Image: `sha256:53914c90accfbe8f1e11b530a7ae42edc9d1a79e098a01d50d14f244b5991514`, Size685,369,702B. Labels remain owner=`codex-warden`, project=`warden`, session=`454fc203bfa3b1bb6296520028e6a1cd`, ttl=`2026-10-24T18:35:22Z`.

The outer directory is `.cache/warden-lab/docker-454fc203bfa3b1bb6296520028e6a1cd`, DEV66307/INO56011098/UID1000/mode0700. Child `session-365b23ee00074b56` is DEV66307/INO56011150/UID0/mode0700. Before/after exact inspection confirmed exited/PID0/exit2/restart0, no running/paused/restarting/OOM/dead state, correct image/labels, unchanged directory identities, and absence of the exact original systemd Docker scope. No cgroup tree traversal or write occurred.

Fixed Docker archive HEADs returned root/state/io404, containerd.toml124B/0600, containerd.log0B/0600, startup-private.log55,203B/0600. The two original fixed controller logs beneath root both returned404. There was no fallback to another path. These HEADs do not prove that the child contains no extra entries; the future helper must establish exact directory shape before any remount or deletion.

Only the fixed snapshot archive was read, in bounded process memory. It contains55,203B/386 lines, SHA256 `c0245d4a0c441f9f84b2c39b4b1e81bd88127adb4611c9c1f3cb0fc96839c64b`. Reads enforce a combined32,000,000B content budget plus fixed bounded tar overhead; only the single exact regular member is accepted, with no links, devices, aliases, extra members or oversized content. Raw private logs were never printed, cached, written or committed. `diagnose-third.py` is the fixed read-only reproducer; `diagnostic-final.json` contains only fixed enums/counts/hashes and safe metadata. It explicitly labels its hypothetical Ready/namespace inputs as synthetic classification, not actual readiness proof.

All53 warning/error observations classify:11 previously reviewed observations,40 newly source-matched observations, and2 rejected termination observations. No unknown warning remains in this snapshot. The exact kubelet-exit/shutdown template identifies the swap startup refusal. The later node-password migration cancellation follows shutdown and remains rejected. An early hypothesis that the third namespace error concerned service-account creation was disproved: its exact source is legacy-token-tracking ConfigMap synchronization.

## Pinned source and minimal changes

`source-references.json` records exact primary URLs, lengths and SHA256 values. K3s v1.36.5+k3s1 pins `github.com/k3s-io/kubernetes v1.36.5-k3s1`. That fork's container manager checks `/proc/swaps`; our drop-in had overridden k3s's false default with `failSwapOn=true`. This detects visible host swap even when the enclosing Docker cgroup has zero swap allowance. The fork's NoSwap implementation sets the cgroup-v2 CRI unified swap limit to zero.

The drop-in now uses `failSwapOn=false` and `memorySwap.swapBehavior=NoSwap`. The immutable controller reads only `memory.swap.max` through the already-verified private cgroup root FD, using no-follow/nonblocking bounded reads. It requires the exact zero value before private session creation, before publishing success and at final postflight. Missing/nonregular/alias/nonzero/oversized values fail. Current stopped-container inspect confirms Memory=MemorySwap=4,000,000,000; actual new live cgroup enforcement remains unverified. There is no host swapoff, sysctl modification, shared-bootstrap change, extra capability or new bind. Kernel-default protection and the original six sysctl checks remain.

Controller rulings authorized the following exact additions to the startup gate, with zero occurrences allowed and fixed maxima:

| Template | Pinned source | Maximum |
|---|---|---:|
| Empty API versions | Kubernetes genericapiserver.go:798; exactly the32 observed group/version enums in source |1 per enum|
| Empty metrics manifest | component-base/metrics/options.go:205 |3|
| Missing default machine-id files | vendored cAdvisor machine/info.go:54; exactly the two default paths |1|
| Initial Kubernetes endpoint reset | controlplane/reconcilers/lease.go:265; fixed service and sole configured node address |1|
| Initial lease namespace absence | component-helpers/apimachinery/lease/controller.go:201; only kube-system/not-found/200ms |1|
| Initial service namespace absence | controlplane/controller/kubernetesservice/controller.go:95; only default/not-found |1|
| Legacy tracking ConfigMap namespace absence | legacytokentracking/controller.go:156, util/runtime/runtime.go and k3s logger adapter; exact ConfigMap/error/logger |1|

These require the k3s log, fixed severity/caller/fields, launch-to-before-first-Ready timing and a later successful API+Node Ready recheck. K3s receives fixed `TZ=UTC`; yearless klog dates must resolve uniquely inside the bounded UTC window, including year rollover. Unknown API versions, changed callers/severity, paths, addresses, fields, prefixes/suffixes, duplicate excess, wrong sources and post-Ready errors fail. Prefix-bearing klog warnings are detected and rejected rather than skipped. Output retains only an actually matched safe fragment and per-occurrence hash.

The three namespace templates additionally require fixed GETs after final Ready, checking `default` and `kube-system` for exact name, nonempty string UID, Active status and absent deletion timestamp. Only the resulting verified name set reaches the gate; namespace JSON and annotations never leave memory. Missing evidence or any other namespace/error fails. Swap shutdown and context-cancellation errors remain rejected. This historical failed snapshot cannot pass the live gate.

## New fixed recovery — implemented, not executed

The one-shot recovery source now pins only this third scene; it no longer targets the already-recovered second scene. It accepts no alternate path, ID, image, code or shell argument. Under Docker.lock, it retains the original outer FD, original reservation, exact stopped identity/scope checks, immutable helper argv hash, exclusive durable journal and conservative accounting.

The retained image is reused. The helper keeps the reviewed boundary: SYS_ADMIN+DAC_OVERRIDE only,256MB memory+swap,32 tasks,1CPU, private namespaces, read-only root, NNP, one original RO/rprivate bind, two1MB log files,20-second inner deadline, no k3s invocation. Before any remount it must verify exact outer/child identities, exactly three root-owned0600/nlink1 regular files of124/0/55,203B, and combined allocation<=33MB. Extra bulk directories, links, wrong metadata or drift fail. It reads no private contents. Successful helper exit/marker and absent child are required before removing helper CID, original CID and original image, with exact ownership, --all listing and inspect-absence confirmation.

The retained rootfs.tar is now part of the fixed recovery contract: DEV66307/INO56011120/UID1000/mode0600/nlink1/496,609,280B. It is opened and held from entry; its fixed identity/size are journaled. Only successful object removal and the fresh ordinary budget guard permit rechecking the original directory, held archive FD and exact pathname entry, then unlinking through the held directory FD and fsyncing that directory. Durable charge release follows. There is no pathname-finally deletion. Lost responses, unknown absence, helper/image/ordinary-guard failure, inode replacement or alias preserve the archive and charge before unlink. A failure after unlink, including directory fsync failure, retains the charge although the archive may already be absent. Tests distinguish that partial state.

The final read-only estimate was3,523,018,752B project allocation excluding only the exact fully-reserved child +6,000,000,000B outstanding +1,434,739,404B owned-image charge (2×Size+64MB) +64,000,000B helper allowance =11,021,758,156B, below12,000,000,000B. With zero other declared services, helper+host allowance is320,000,000B, below16,000,000,000B. This is not an ordinary complete walk or measured live peak. The actual controller run must compute a fresh budget. No helper journal/reservation or helper Docker object was created by this round. The original6GB remains held.

## TDD and verification

All test processes used ordinary UID1000 and umask0077. The managed sandbox's UID projection was not used to weaken trusted-directory checks. No private scene permissions changed.

`red-swap-recovery.txt` demonstrates the old swap configuration and missing guards/fixed-scene APIs. Its whole-node RED also reached the absent synthetic /session path before the new guard, rather than launching anything. `red-archive-lifecycle-behavior.txt` runs the new fake-Docker lifecycle cases against the exact BASE host-recovery source, demonstrating missing archive journaling and accepted tar drift/alias instead of safe refusal. The earlier `red-archive-lifecycle.txt` records fixture setup failures before new constants were injectable; it is not behavioral PASS evidence. `red-startup-templates.txt` demonstrates missing exact-template acceptance and the prefixed-klog skip defect. `red-namespace-templates.txt` demonstrates missing namespace-proof gates.

`intermediate-round4-fixture-failure.txt` is an intermediate failed test, not GREEN: a test passed a Path where the trusted path API requires a normalized string. Correcting only that fixture made the full postflight drift test execute; no guard was relaxed.

Final command:

```sh
umask 0077
PYTHONPATH=scripts python3 -B -m unittest -v test_k3s_lab_init test_k3s_lab_recovery test_k3s_lab_round4
```

`verification-tests.txt`:44 tests PASS, zero skips. Coverage includes swap refusal before session/k3s launch, postflight swap drift, fixed UTC environment, exact warning/count/time/source boundaries, namespace recovery evidence, year rollover, tar metadata/alias/replacement, lost create response, unknown absence, deletion order, ordinary-guard failure and post-unlink fsync failure. Docker/query/process boundaries are synthetic where needed; existing unprivileged filesystem/subreaper tests remain real. No image import, capless image smoke, large suite, driver or tenant workload ran. Source `git diff --cached --check` passed. No further source changes followed final verification.

Remaining concerns are independent code review, actual new recovery execution, fresh bootstrap Ready/identity/cgroup/CNI/warning behavior and live resource peaks. No original Popen/GoGate retirement, guest limits, conformance,100-launch measurement or Task3 completion is claimed. The prior automatic refusal to export private historical log lines was respected; this round used only the authorized safe enum/count/hash alternative.
