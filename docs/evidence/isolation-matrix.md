# Warden 隔离矩阵

2026-10-25恢复后快照：**14类×3运行时，共42格全部 unevaluated，实际攻击执行0。** 普通完整资源检查已恢复通过，但没有已准入的语料镜像；Task3/4的真实运行时验收仍开放。下面没有 blocked、detected 或 missed 结果，旧七项 conformance 也不填入这些格。

| 行为 | runc | gVisor | Firecracker |
|---|---|---|---|
| fork bomb | unevaluated | unevaluated | unevaluated |
| 内存耗尽 | unevaluated | unevaluated | unevaluated |
| 磁盘写满 | unevaluated | unevaluated | unevaluated |
| /proc信息 | unevaluated | unevaluated | unevaluated |
| /sys信息 | unevaluated | unevaluated | unevaluated |
| metadata IP | unevaluated | unevaluated | unevaluated |
| metadata名称 | unevaluated | unevaluated | unevaluated |
| raw socket | unevaluated | unevaluated | unevaluated |
| ARP欺骗 | unevaluated | unevaluated | unevaluated |
| ptrace其他进程 | unevaluated | unevaluated | unevaluated |
| mount/unshare | unevaluated | unevaluated | unevaluated |
| 内核模块 | unevaluated | unevaluated | unevaluated |
| DNS TXT外泄 | unevaluated | unevaluated | unevaluated |
| 反弹shell | unevaluated | unevaluated | unevaluated |

| 共同阻塞 | 当前事实 |
|---|---|
| runc | Task2原实机验收保留；新的语料镜像、场景与实际执行票据尚未准入。 |
| gVisor | Task3原入口五轮上限，CRI/Ready、driver及语料执行尚未验收。 |
| Firecracker | Task4原guest启动后Ready前失败，原因未知；原退休cleanup_pending，现场和Q5GB保留，本轮无新boot或语料执行授权。 |
| 场景材料 | 实际ENOSPC、跨边界canary、ARP目标、合法模块材料、DNS collector、完整shell回连尚未闭合。只读shell材料候选不是guest ABI或场景验收。 |
| 检测器 | Task12尚未实现，不输出detected；未来成功目标的missed必须注明detector_state=unavailable，不能宣称在线检测器已验证漏报。 |

分类语义以[控制器裁定](task-5/controller-rulings.md)为准：未运行/前置缺失记 unevaluated；启动/运输/退出/日志/清理不明记 error，不给三种完成结论。只有完整、身份绑定的实际行为及明确保护目标证据才可 evaluated。缺 marker、非零退出、Kill成功或outer删除均不能单独算 blocked。

后续纯分类fixture须另列为代码验证，不进入此真实矩阵。未来真实报告保留每格RunID、镜像/语料摘要、入口/目标/退出/日志/清理证据及检测可用性；按阶段产生新记录，不覆盖历史失败。Task5和整个Goal仍未完成。

## 2026-10-25 independent fixture classification

Code-only evidence: [classifier report](task-5/classifier/6cedf69d7da82e7fd2cd80c69d5d9bfb5b0024aa/README.md), source
`6cedf69d7da82e7fd2cd80c69d5d9bfb5b0024aa`. All in-memory fake attacks were authored by subagent
`/root/matrix_classifier`; positive/denied outcomes are fabricated fixtures, never
real executions. The fake success has complete simulated objective evidence and
classifies missed with unavailable detector; this means defined isolation objective
success, not a validated online detector miss. The fake denial needs positive
policy/limit evidence plus complete simulated entry, exit, logs and cleanup.
Fixture results do not fill or accept any of the42 cells. Task5 remains incomplete.

## 2026-11-13 Task 5 resumed

The user resumed Task 5. Fourteen fixed probes and their expected markers are now in `attacks/corpus/`; `scripts/build-corpus-image.py` built a separate OCI image from a SHA256-pinned Ubuntu dash/libc/loader closure and the bounded Go helper. Three lab adapters are integrated. `TestMatrixClassifiesFixture` and the new proof-required regression pass in the offline Go suite. `make test` and `make check` passed on home-ubuntu after integration.

**Actual live cells: 0/42 evaluated.** The existing Cilium/metadata Warden lab belongs to another active task; the user explicitly asked us to preserve it and wait. No runtime matrix result or detection alert has been captured yet. Some probes (for example, `/proc/1`, CPU topology, invalid module bytes, TEST-NET reverse connection) measure their stated narrow objective and do not establish cross-tenant secret theft, valid module loading, or a working reverse shell. `blocked`, `missed`, detection rate and p50/p95 from real attacks remain unavailable until the lab and detector are run with complete evidence.

Independent review correction: Firecracker guest now forwards and executes the admitted corpus command; gVisor lab builds the corpus image and fails if it is missing; its script executable mode is restored. The Falco importer requires a reviewed execution-to-rule mapping so unrelated same-container alerts do not count. `proc-leak`, `sys-leak`, `disk-fill`, `dns-exfil`, `reverse-shell`, and `kernel-module` (when the valid-module barrier is not established) emit `WARDEN_INCONCLUSIVE` and classify as error until an independent in-lab target/positive control is added. This means the present code cannot close all 42 real cells.

## 2026-11-13 PST live run

Three live columns were executed. See [raw matrix and prerequisite logs](task-5/live-20261113/README.md). Counts: runc 9 blocked / 5 error, gVisor 8 blocked / 5 error / 1 missed, Firecracker 9 blocked / 5 error. This section supersedes the earlier 0/42 pre-run snapshot; it does not erase it. Task 5 remains open because the common five errors need real targets/positive controls, and the gVisor memory miss needs diagnosis. Task 13 detectors were not online.
