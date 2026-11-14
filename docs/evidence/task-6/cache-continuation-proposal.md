# Task6 固定旧 cache：一次 checkpoint 续接提案（2026-10-25）

状态：**NEEDS_CONTEXT，仅 proposal，不是源码/测试或实际操作许可。** Crypto source `6d02de4062c0ee1e5d62825df0ea670d54672b5e` / evidence `f4dd9dc75fbabce7b6d7d79eba5d8428f483a1ae` 保持冻结；如独立 crypto review 要求修复，优先回到该 scope。Git/index 归 controller。本次只读公开 evidence 和代码，未读取真实 cache 条目或任何私有文件 body，未运行 Go/Docker/cache/formatter/材料命令。

## 1. 必须保留的事实与缺口

已完整读取 `docs/evidence/task-6/cache-operation-20261025.md`、`controller-cache-timeout-audit-20261025.json`、其公开审计程序、原执行 preflight/intent/result/log/recorder、原 `scripts/identity_cache.py` 与执行计划/权限/维护范围裁定。

原 fixed entry source `7be15fa29aafc7cf84dcd488dbf8aadc22ae2655`，文件 SHA256 `f608dc714b79dcc4f3c4c2071ba6dd561c88eec10c45fc905820ec447d8a1ede`。原进程 PID977390 已由原 recorder 等待至 `-15`，时间窗 UTC10:02:24.874869—10:05:24.909528，180.025779秒。不能再凭这个 PID 发信号：PID 可能复用，已知终态证据来自原 wait/result。原180秒单次机会已结束，不能修改 deadline、重跑原入口、删除/覆盖原 intent 或把无进程/锁释放解释成完成。

唯一允许绑定的旧私有 intent 是 `.cache/identity-cache-permission-intent.json`，4,573,737字节，SHA256 `cbc9e3aad72189cf1a048ee1a30270ea43dce2925823563c283fecd3dcf65e5e`。原 result 不存在。公开超时审计报告260目录、22,422普通文件全部仍在；260目录及18,900文件是目标权限，3,522文件仍原权限，没有删除。

原程序记录的 targets 顺序是 `directories + files + preserved`；只有完成所有 chmod/fsync、整体重查及 strict scan 后才可能 unlink。超时审计逐项检查 identity/type、原权限或目标权限、文件 size/mtime 和名称集合，但它**没有**证明目标权限项是 intent 顺序的连续前缀、没有保存当前逐项 ctime/blocks 快照，也没有用原 strict engine 再做完整 alias/nlink 校验。其汇总不是新的逐项准入清单。

因此不能直接把“全部存在、模式二选一”当作续接授权。原 fingerprint 包含 dev/ino/uid/gid/fullmode/nlink/size/mtime_ns/ctime_ns，**没有 st_blocks**。chmod 会改变 ctime；已到目标模式也不能证明上一次 fsync 返回成功。原文件 body 没有摘要，本方案也不新增 body 读取或内容真实性声明。

## 2. 最小实现边界（裁定后才写）

建议新增两个文件：固定无参数 `scripts/identity_cache_continue.py` 和纯 fixture `scripts/test_identity_cache_continue.py`。保持原 `identity_cache.py` 字节不变，保持 shared `trusted_directory`、原 recovery/accounting/charge schema 不变。新入口不调用旧 main/tighten，不提供 retry/reset/path/mode/selector，不启动 subprocess、Go、Docker、服务或网络。它仅对这个已知 intent/已知终态开放一次新 operation；不能演变为任意 partial recovery。

可复用原 `CachePlan` 的有界 FD 布局扫描、fingerprint、完整 recheck、strict remove 和现有 project_lock。新的私有 checkpoint scanner 只在固定 go-build 子项接受“该已钉住 intent 中该项的 original 或 target mode”，同时构造只读计划；不能更改 generic 的 mode 白名单。若实现为了扫描而先使用原/目标模式的并集，必须在**任何目标 mutation 前**逐项完成 intent 对比、连续前缀验证及精确 checkpoint 对比，不能仅凭并集放行。不得设置旧 `TighteningPlan.tightened=True` 绕过原状态机。

原 Go 布局、UID/GID1000、同设备、无别名、regular nlink1、目录 nlink=2+已知子目录、256bucket、原命名/类型/大小约束、100000文件/3e9逻辑及分配字节上限、nofollow/nonblocking、只持所有目录及单个普通文件 FD 等保持。只允许收紧至目录/执行项0700、普通0600；不 chown、不新增权限、不回退。数据目标仍只有受信 `.cache` 父FD下的 literal `go-build`，不新增其他清理路径。

## 3. controller 需要先取得并冻结的新 checkpoint

这是未来独立授权的只读 metadata 审查，不是本提案已经做过的工作。建议由经过审查的固定 recorder 在完整 writer-free 窗口和**现有同一项目锁**内取得一次私有 snapshot；续接执行时仍重新全部验证，不能仅信任旧快照。

1. 钉住原 source SHA、原 private intent SHA/字节数、原执行 result 和 timeout audit 的公开文件 SHA；验证已知原 wait=-15、timed_out=true、无原完成 result。原 source 与 shared helper 的 hash 必须仍匹配原公开 preflight。续接 source/tests/recorder 另冻结 hash，并保存完整 pre/post 项目 source manifest，不改变旧记录。
2. 普通 UID/EUID/GID1000；重新验证项目/`.cache`/lab 祖先和原 lock 的可信身份。父目录 FD锚定，不跟链；lock 不新建/替换。原 `.cache` 目录 mtime/ctime 可因已经批准的 journal/证据操作变化，不能要求它等于旧 snapshot 的全部 fingerprint；其 dev/ino/type/owner/受信权限和 lock identity 必须成立，并记录新的完整 metadata。
3. 未来若 controller 明确批准，只对这个固定私有 **metadata intent** 做有界读取：nofollow、regular0600、UID/GID1000、nlink1、同设备，固定长度4,573,737且不超32MB，读前/后 fstat/path fingerprint 一致、精确 SHA匹配，严格解析 schema/唯一 relative paths。这是对旧元数据 journal 的读取，不是 cache 数据 body；目前不做。原 intent 永远只读且不得重新序列化后冒充原 hash。
4. 使用原布局规则独立扫描全部 live items，要求 paths/数量与原 entries 完全相等。**任意 missing（包括 derived）、新增、别名、替换、奇异权限/type/owner/device/link/layout 都拒绝。** 由 scanner 独立验证 inode唯一及目录link计数，不能依赖原审计的汇总布尔值。
5. 所有条目的 dev/ino/uid/gid/type/nlink/size/mtime_ns 与原 intent 相同（目录也检查，chmod本身不改目录mtime/size/nlink）。新 scanner 仍检查 logical/allocated bounds；blocks 因旧 intent 未记录，必须从本次实际 snapshot 建立，不能补造旧值。
6. **推荐强制原序列连续前缀方案。** 按原 intent `entries` 原始顺序核对 original/target 和类型派生的目标 mode；要求恰好前19,160项为 target，之后3,522项为 original（260目录+18,900文件已收紧，总22,682项）。suffix 原 full fingerprint（含ctime）应与 intent 完全一致。prefix 除 mode/ctime 外与原 fingerprint 相同；保存当前真实ctime，后续完整匹配。不从当前模式推断 fsync 已完成。
7. prefix 的 ctime 若 controller 能证实 wall clock 未跳变，可进一步要求落在原执行的精确 UTC 窗口内；若时钟事实不能证明，不编造时间容差或拿ctime单独作作者证明。最低仍须连续前缀+全部稳定字段+controller自上次operation起的无writer依据+新完整snapshot。若发现非前缀/数量不符/任何不可解释ctime，**本提案不自动降级到“混合模式均可”**，先停下请求新的具体裁定。
8. 新私有 checkpoint 保存全部 live fingerprint及blocks、每项relative/type/目标、原intent顺序及prefix长度、父/锁identity、source/public-evidence hash、已知终态、审查时间、writer-free依据。controller公布其 SHA/字节数及精确绑定值；不公布普通 cache body，不扫描其他项目或宿主全局进程。

重要限制：没有 body hash，不能以 size/mtime 相同证明文件内容从未改变，不能排除能恢复mtime的恶意同UID writer。这里仅维护可重建派生文件，真正前提仍是 controller 确认 writer-free；checkpoint 不消除 unlinkat 无 compare-and-unlink 的竞态。

## 4. 一次新 operation 的 durable 阶段

建议只新增同一 `.cache` 父目录的四个固定0600 metadata名字，须 controller 明确裁定，不接受任何路径参数：

- `identity-cache-continuation-v1-checkpoint.json`：上节只读审查得到的冻结 metadata，最多16MB，SHA由controller钉住；若实际不能容纳则拒绝，不扩上限。
- `identity-cache-continuation-v1-intent.json`：新一次操作 prepared，绑定原intent、checkpoint、旧/新source、公开终态与本次唯一操作标签、时间盒。最多64KiB。
- `identity-cache-continuation-v1-ready.json`：所有目标收紧且本次fsync完成、完整strict验证后，unlink之前的 durable阶段标记，含最终内存metadata清单摘要及计数；最多64KiB。
- `identity-cache-continuation-v1-result.json`：最终completed，仅代表本次明确绑定续接；最多64KiB。**不创建旧 RESULT_NAME，不把旧超时改成成功。**

名字是维护 journal 的固定增量，不扩大数据目标或canonical charge schema。新operation的后三个名字必须全部不存在（连partial/symlink都禁止）；已有任意一个即拒绝再次启动。checkpoint 必须精确匹配controller批准SHA，不能自行刷新它来跳过不匹配。所有文件exclusive-create/nofollow0600，写入完整后fsync(file)+fsync(parent)；失败留下任何已创建文件，绝不unlink/reset/rename覆盖。公开 recorder 另保存单次 launch intent 和终态，保证即便尚未创建私有prepared时遭中断也不会自动重新启动。

新入口顺序：

A. 检查无CLI参数、UID、源hash与固定原材料；取得同一project lock并保持至退出。读取精确checkpoint/旧intent，按第3节完整只读扫描；live完整fingerprint/blocks必须匹配checkpoint。确认所有新操作journal缺失、旧result缺失；失败不改目标。

B. exclusive durable prepared；再次完整重查live清单、held directoryFD/path对应、旧intent/checkpoint身份及hash、锁身份。在此之前不做任何目标chmod/fsync/unlink。

C. 按原 targets 顺序遍历**全部22,682项**。每项持FD、逐级重查祖先与path/fstat；已target的项不再fchmod，未target的项只做原mode→固定target，验证mode只减少且identity/type/nlink/size/mtime不变，更新自有ctime。**每一个目标（包括已收紧目录、18,900文件、preserved metadata）都重新fsync。** 这样不猜测上一轮在fchmod与fsync之间停在哪里。每项失败即停止，保留状态；不并行、无batch降低durability。最终重查完整计划，重新构造原strict `CachePlan` 并核对同一白名单/identity/targetmode。

D. fsync父目录，并exclusive durable ready；再次完整strict recheck。仅ready持久化及重查成功后，用该strict计划的原 `remove()` 执行精确derived unlink、已知空executabledir rmdir，保留root/256bucket/原metadata。原引擎已保持每项祖先和文件FD检查，删除后父目录info随自身变更更新，不把外部变化当作自身变化。新代码不引入RemoveAll或宽泛递归。

E. 原 strict remove 的末尾完整结构验证、保留项检查、剩余目录/父目录fsync完成后，exclusive durable newresult；包括removed文件/执行目录数、逻辑/分配字节统计、保留项、ready/intent/checkpoint/source hash。原intent/checkpoint仍未被修改。只有exit0、有效durable newresult和独立postcheck共同成立才是新续接成功；空目录或result路径存在不是充分条件。

任何timeout/SIGTERM/SIGKILL/OSError/fsync异常/未知退出/缺result都终止本次机会，保留全部新旧journal和部分权限/删除状态，不自动从ready继续，不把新入口做成第二次恢复工具。即使result看似完整但recorder未等到正常退出，仍先交controller判定，不能默认成功。后续如有需要，必须再独立设计；本方案没有循环机会。

## 5. 时间盒、fsync成本与资源

建议这个**新operation**独立上限600秒（含终止宽限），不改写原180秒。推荐recorder在elapsed590秒向本次新建且拥有的进程组发SIGTERM，最多5秒后SIGKILL，再最多5秒wait；没有已知终态则记unknown，不再等待后重启。信号仅针对本次仍由Popen持有的child/group，不碰原PID或其他进程。若最终wait仍无已知终态，保持authority pending和writer窗口，不凭SIGKILL已发送推断已停止；不启动后续metadata/postguard操作或其他项目命令来与可能仍活跃的child并发，交controller处理。计时覆盖preflight、全部fsync、删除和receipt；新程序不fork/启动后台任务。controller外层阶段日志应有<=60秒的稀疏元数据进度，但不写每项persistent progress或泄漏body；stdout总量<=1MiB。

原180秒包括预检、durable4.6MBintent、260目录和18,900文件chmod/fsync，粗略平均约105文件/秒。若把全部22,682项按这个数量级保守重新fsync，约216秒；另有3,522项chmod、复核、22,420derived删除、目录flush和receipts。600秒给出更合理一次完整尝试窗口，但这只是规划估计，磁盘stall可能超过它，**不能保证成功或省略fsync以迁就deadline**。已target文件可能已clean，fsync可能更快，也不能把这个可能性当作durability证据。不要只处理剩余3,522项，亦不接受只fsync目录替代regular fsync。

保留96,000,000B总维护headroom，无新增standard3GB charge、无重定义canonical schema；旧4.6MBintent已在普通全项目R中。新checkpoint16MB、三个小阶段receipt、<=1MiB输出及有限controller证据均在96MB内；实现/冻结前应记录实际新source/evidence大小并用fresh普通R吸收，不能隐去证据空间。维护自身无容器/镜像/下载；预检仍算全部真实ownimage与所有outstanding，不能直接写死它们为0/5GB。

fresh完整门禁：实际R + 全部既有Q/charge + 现有ownimage计费 +96MB <=12e9，实际常驻内存含原1GB host allowance <=16e9。不为性能放宽FD/文件/bytes上限或改并行度；当前260目录FD仍应实测可容纳。任何资源不足在mutation前拒绝。已知原Q5GB、unknown/never_reopen/cleanup_pending状态必须保持，绝不以回收旧cache为理由释放。

## 6. writer-free、兄弟cache与普通postguard

Controller需把新窗口内所有项目writer停在已知terminal状态；旧go.sh不遵循锁，单独flock并不构成无writer证明。以已掌握的项目执行receipt、实现者/审查者只读状态和明确不启动其他项目命令来建立窗口，不新增宿主进程/其他项目扫描。当前crypto覆盖已正常终止，其独立codecache的合法变化需要计入新的baseline。

**不要要求当前firecracker-code回到10:07旧摘要。** 之后已有授权crypto RED/GREEN/cover写该独立cache。新操作开始前，在锁内取得三份兄弟cache新完整metadata摘要并记录其来源；firecracker-code差异只承认已知授权单元运行，go-mod和原warden-lab按controller现有事实核实未发生未授权变化。新维护前后这三份摘要必须一致；`.cache`父因固定newjournal产生的已知目录metadata变化单列，不算兄弟cache mutation。

原22项scene metadata、全部journal/Q、never_reopen和原owner退休未知继续用既有controller只读验证流程核对；不修改旧recovery模块、不重演旧现场。维护child本身不调用Docker；如controller postflight需既有project-owned只读inventory，须仍按原精确范围另执行，不能扩成全宿主清理。

只有本次child已由wait确认终态后，才能进入以下结束审计；unknown存活状态先保留pending，不能假装进入postflight。确认终态后，无论成功或失败，都记录完整source manifest、旧intent/checkpoint仍匹配、权限未回退、兄弟cache/原scene/Q、六sysctls和ownobject事实。失败只执行普通全项目guard与只读metadata审计，维护不完成。成功需另跑普通完整Q guard，再独立评估 **R + 全部Q/charges + ownimage + 新标准3,000,000,000B** <=12e9及内存上限；即便容量适配也只是PG/material的资源前提，未批准创建charge、材料下载、PG、SQL/SCIM或任何业务外部执行。删除的blocks统计不是实际R下降证明，不能当作释放凭证。

## 7. 后续源码/fixture审查范围（目前不执行）

裁定后仅新固定continuation文件/fixtures与必要精确执行计划，old engine/generic trust/canonical schema不变。fixtures用生成的私有树与固定测试metadata绑定，不把真实intent/body放进Git；生产常量替换注入只允许明确测试边界。覆盖：错误旧intent/hash/终态/checkpoint无mutation；prefix中间洞/非前缀、missing/新增/alias/nlink/owner/type/size/mtime/原suffixctime变化；oldtarget模式集合不能泛化；现有新journal拒绝；准备file/parent fsync失败；中途chmod与逐filefsync失败；alreadytarget仍全部fsync且不重复chmod；ready file/parent fsync失败必须0unlink；unlink/rmdir/最终directoryfsync/result file或parent fsync失败保留全部journal和partial状态；正常完整删除与兄弟/保留项不变。

保存新prospective RED/GREEN/frozen cover source manifests和snapshots，明确哪些是fixture/静态路径，不重建旧失败、不为本子阶段重跑未改旧26fixtures/旧suite。独立source+execution-plan review必须在任何新actual之前。新增fixture可补本新路径fsync failure证据，但不能声称旧deferred fixture已经运行；旧审查记录保留。Task3/4原五轮与Q不受这次维护实现/审查影响，Task6原review fix1/5不重置。

## 8. 请求controller裁定/提供的具体上下文

**D1 — 单次兼容策略：** 是否批准“仅原精确SHA/已知-15/全文件存在/连续prefix恰19,160”的新固定入口？推荐批准该窄策略；若实际prefix不成立即停止，不自动接受任意混合状态。当前公开audit不能代替这个新事实。

**D2 — 私有metadata读取/新checkpoint授权：** 是否允许未来controller审计程序有界读取旧固定intent（仍禁止cache数据body）、生成上述固定私有checkpoint并发布SHA/字节数/逐项摘要结果？需确认全部stable字段、suffix原ctime、prefix顺序，以及新parent/lock身份。本实现者当前没有读取许可，也不需要收到私有body。

**D3 — 新journal与时间/资源：** 是否批准上述四个固定journal名字、16MBcheckpoint/64KiB阶段上限及600秒总时间盒（590+5+5），保持96MB维护headroom/原所有charge约束？推荐如此；不是延长原180秒或恢复原operation。

**D4 — writer与baseline：** 需要controller在新窗口前确认所有授权crypto/其他项目命令terminal、无旧go-build writer；提供新的三兄弟metadata摘要、原scene/journal/Q一致结果、fresh资源数值。原10:07firecracker-code摘要已不能直接复用。若要用prefix ctime执行窗口约束，还需明确wall-clock连续性；否则保留严格snapshot+writer前提，不猜测时间容差。

以上未裁定/未取得真实事实前，不写产品/测试源码、不运行任何cache操作、不动Git/index。Task6整体、真实SQL/IdP及Goal不因本proposal完成。
