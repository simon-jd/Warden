# Recorder 第3轮源码修复裁定（2026-10-25）

[四项 Important 原文](review-controller-operations-substage.md)和[原实现者提案](controller-operations-fix3-proposal.md)完整保留。原 Task6 整体 BASE84018、fix3/5、本轮 scoped FIX_BASE `e9acbe412e699da32a0546de7e98527ba87eae83` 不变；原 continuation 的 I1 已在 round2 关闭，本轮是 controller recorder 的四个新发现。当前仅授权下述源码、生成 fixture 和 scoped 复审，不是实际调用、checkpoint、维护或 PG 准入。

Ruling D1 / I3：用一个新的小型 `scripts/identity_cache_control.py` 作为唯一固定 recorder 入口，替代两份安全 loader — 原三独立入口方案导致同一约50行安全逻辑必须重复，独立审查将其列为 plan-mandated Important；单一维护实现可保留执行前字节验证 — 代价是第五文件及精确 argv/manifest 的源码返工和复审，不是扩充命令框架。旧三文件保留为被验证加载的被动实现，直接执行须明确失败且不做操作。sole entry 只接受 `capture-preprobe`、`capture`、`capture-postflight`、`continue-preprobe`、`continue`、`continue-postflight` 六个 literal，无用户路径、任意函数、插件 registry、shell 或额外 selector。固定 argv 改为 `python3 -B scripts/identity_cache_control.py <MODE>`；cwd/cleanenv 不变；maintenance 产品 child 仍仅 `python3 -B scripts/identity_cache_continue.py`。

sole entry 使用唯一 bounded nofollow/held-FD/fullmetadata/hash/verified-compile loader 钉住 observer；observer 再验证所有 canonical source 后，仅从固定 allowlist 编译 capture/maintenance 实现。不得 unchecked import、接受 pyc、先执行再验 hash 或重造同一 loader。bootstrap 自身的真实性仍须未来独立 caller 验证，不以自 hash 宣称解决。生成 bootstrap fixture 必须到达 owner/mode/link/祖先、FD/path 替换/alter/overflow 和执行前拒绝边界；两操作与四观察以及旧 direct-entry 拒绝都须覆盖。旧共享 trust/engine/continuation/recovery/guard/accounting/crypto 字节不得改变。

canonical 名称改为精确150，更新 name-set hash、source map、policy/command/fixture 及未来 constant-only manifest。保留旧七轮149/146历史，不能补写150或重新构造 RED；原145个旧 canonical 文件保持字节不变。真实 approval 的两常量继续留在 maintenance 模块并为 None。允许 public admission/source 验证早于 None-pin 拒绝；pins 仍必须在 preparation、private read、public launch、Popen 前拒绝。没有真实 admission，故不存在重用旧 authority 的许可。

Ruling D2 / I1：区分有效软限制与仅供 fork 继承的 hard ceiling — 普通 UID 子进程不能提高继承 hard limit，现源码必然在 preexec 失败 — parent CPU soft60/hard540、AS soft256MiB/hard512MiB，FSIZE soft/hard1MiB；固定 SIGXCPU handler directexit124，无 parent 路径提高 soft limit。child 只在已足够的 inherited hard 内设置 CPU540/540、AS512/512MiB、FSIZE1/1MiB，不假定特权。改变任何 limit 前先校验全部 ceiling（正确处理 RLIM_INFINITY）；不足则 launch 前拒绝，不尝试提高 hard 或回滚。有效 parent 上限和原总 native1GB 保持，提案中的 future outer128MiB 仅有效 soft 候选，不可变成限制所有后代的 hard128MiB。

真实 preexec callback 必须在生成 kernel-limit-state 模型中执行，验证 soft<=hard、禁止 hard 提高、parent/child 独立状态、不足 ceiling 时无 Popen，以及固定 CPU 终止行为；不真实 fork/setrlimit/signal。绝对580/585/590/600期限不变。Docker Go CLI 在 observer256MiB 下的实际可行性仍 unknown，不能从该模型宣布通过，不能静默放大 envelope 或运行 CLI。以后 exact caller/material viability 需单独审查。

I2：严格解析 launch 和 proof schema/数值类型，把其 command/stage/source/policy/writer/review/ruling/clock 等 authority 连回当前 admission，验证当前 admission 与 preprobe 的完整 proof 等于 launch 保存值，并保留这些 Record 供前后 recheck。postflight 使用同一已验证 preprobe 字节，不再次接受可替换 baseline；不增加 postflight 的60秒年龄条件。生成用例覆盖 capture/continue 的同字节换 inode、改 authority、改 preprobe facts 恰好匹配已改 sibling、坏 schema/call/policy 及 gate 后替换，要求 private/guard/import 等边界前拒绝。旧 product 数值类型 Minor 不在此修复范围，不宣称关闭。

Ruling D3 / I4：保留旧68PASS和全部原始记录，追加明确 timing scope 更正 — 旧 wrapper 在 imports 后取 clock、setup 后重新给45秒，不证明其宣称的完整 setup envelope — 代价是纠正声明和一次受影响新验证，不擦掉历史行为结果。新 wrapper 在最早可测入口固定 end=entry+45，最小必要 signal/os setup 后只 arm 剩余时间，<=0 directexit124；其他 imports、argument/resource setup、prospective manifest/snapshot、tests、postrecord 与最终 flush 受同一截止约束，禁止重新给45或正数小预算。最终取消 timer 前也检查同一截止。

interpreter startup 和设置 timer 前的最小 essential bootstrap 仍没有独立外部 hard bound，必须在报告、计划和新 receipt 中如实区分“最早可测入口”与整个工具调用，不宣称该门禁通过。该局限对未来真实操作仍阻断，当前不授权 caller 实现或真实 child。使用 exact recorder prefix 的生成 fake-time/signal/os 用例验证8秒 setup 只剩37秒、45秒及以后直接拒绝、final flush 晚于截止不能取消 timer/报成功；记录被测 prefix 与实际 run wrapper 的字节绑定，不写脱离 wrapper 的算术镜像测试，不长 sleep。

源码阶段从裁定提交后的不可变 dispatch BASE 取全150（新文件出现前如实计149）pre/post manifests；相对该 BASE 只存 changed/new body。先 genuine focused RED，有限 GREEN，source commit 后仅一次受影响 fixture 模块的冻结 cover，再单独 evidence commit；不重跑旧 continuation48/cache26/crypto/runtime/SQL 套件，不为历史补跑。旧目录、wrapper、日志、receipt、索引均保持；原报告和计划只追加 dated correction/fix 及明确 supersession，新索引说明原 report/plan prefix 的历史 hash/长度与新增 footprint。

同一原实现者独占 source/Git/index，完整 fix 报告追加到本阶段 report 与 public mirror，列 covering tests/commands/output、全部真实失败、source/evidence commit、到达的生成边界、未验证项与每份 footprint，交还后只对四项 findings 与新 breakage scoped 复审。root STATUS/ledger/review/本裁定文档排除出实现者 commits。原 Q5GB/现场/180秒失败、Task3/4 上限、全部 actual prerequisites、预算与无公开发布/push 保持，Task6/Goal OPEN。
