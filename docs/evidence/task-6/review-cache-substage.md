# Task6固定旧cache资源子阶段：独立子agent首轮审查

来源：`/root/identity_cache_review`，gpt-6-astra/high；非真人审查。以下完整保留首轮报告，绑定BASE0a18e1a至HEAD3f41765；该报告没有批准实际操作。后续裁定/定向复审另行记录，不覆盖此报告。

### Spec Compliance

- ❌ **Issues found：执行计划需先消解全局处置约束与无参数维护入口之间的冲突。** 当前实现明确拒绝 `--dry-run`，计划也未明确本次实际删除如何满足第二身份审批要求，详见 Important finding。
- ✅ **其余已检查的资源子阶段要求符合。** 生产及测试源码仅新增 `scripts/identity_cache.py` 和 `scripts/test_identity_cache.py`；完整差异没有修改共享 trust、recovery、charge 或现有 Go profile。固定路径、严格预检、权限收紧、持久 intent、受界删除和失败保留均有对应实现。此结论不涵盖整个 Task6。
- ⚠️ **实际准入不能由本次差异证明。** 尚需控制器验证真实祖先路径、锁身份、旧 cache 来源、无并发 writer、完整资源账目及清理后的普通 guard；fixture PASS 不能替代这些条件。依据：`docs/evidence/task-6/cache-execution-plan.md:10`、`:11`、`:12`、`:42`。

### Strengths

- **权限例外范围明确。** `TighteningPlan` 只从调用方提供的受信父 FD 打开字面量 `go-build`；legacy 目录仅接受 0755/0775，普通文件仅接受 0644/0664，执行文件仅接受 0755。通用 `CachePlan` 仍拒绝组可写权限，没有放宽共享路径验证。依据：`scripts/identity_cache.py:82`、`:94`、`:145`、`:296`。
- **完整预检先于持久 intent 和 chmod。** 检查 256 buckets、名称前缀、175 字节 action index、单文件执行目录，以及 owner/group、设备、类型、链接数、重复 inode 和数量/字节上限；未知布局直接失败。依据：`scripts/identity_cache.py:94`、`:108`、`:132`、`:160`、`:181`。
- **路径操作受 FD 限定，没有缓存 body 读取。** 目录与文件打开均使用 nofollow；文件扫描只做元数据检查；生产源码没有 Go、Docker、网络、shell 或递归删除调用。删除只使用已识别条目的 `unlink` 和空执行目录的 `rmdir`。依据：`scripts/identity_cache.py:23`、`:148`、`:159`、`:217`、`:236`。
- **权限收紧和失败保留顺序合理。** intent 使用排他创建，文件和父目录 fsync 完成后再 chmod；只允许减少权限，逐项检查 held FD 与路径身份，并在全部完成后用严格引擎重新扫描。失败没有权限回滚、receipt 删除或自动重试路径。依据：`scripts/identity_cache.py:262`、`:303`、`:326`、`:345`、`:364`。
- **没有夸大 held FD 或 flock 的保证。** 最终 stat 到 unlink 之间仍有竞争窗口，代码和计划均明确要求 writer-free window；计划也明确旧 `go.sh` 不遵守项目锁，不能把锁本身当作静默证明。在该前置条件成立时，这一实现边界可接受。依据：`scripts/identity_cache.py:203`、`docs/evidence/task-6/cache-execution-plan.md:11`、`:36`。
- **成功和未知结果区分清楚。** 保留 root、256 buckets 和 metadata 文件；最终目录 fsync、metadata 重核后才写 completion result。计划要求 exit 0、durable completed result、源码哈希及实际 postguard 同时成立，不能用删除字节计数代替实际空间回收。依据：`scripts/identity_cache.py:240`、`:371`、`docs/evidence/task-6/cache-execution-plan.md:40`、`:41`、`:42`。
- **测试来源和覆盖边界披露真实。** 初始 import RED、缺失 API 的 RED、祖先 trust 失败和最终 26 PASS 均保留；whole-main fixture 只注入两个私有父目录，未修改生产 trust helper，也未声称证明真实项目祖先准入。依据：`docs/evidence/task-6/cache-substage-report.md:15`、`:17`、`:19`、`:20`、`:24`；`scripts/test_identity_cache.py:324`。

### Issues

#### Critical — Must Fix

- 未发现 Critical 问题。此结论以计划明确要求的受信 checkout 和无并发 writer 为前提，不是对恶意同 UID 并发攻击的安全证明。

#### Important — Should Fix

1. **[Plan-mandated] 全局 `--dry-run` / 第二身份审批约束与本次执行接口尚未形成一致、可审计的约定。**

   依据：`.superpowers/sdd/2-warden-security-plan/task-6-cache-review-dispatch.md:16`；`scripts/identity_cache.py:380`；`docs/evidence/task-6/cache-execution-plan.md:9`、`:14`、`:21`、`:24`。

   Dispatch 明确保留“处置动作都支持 `--dry-run`；破坏性动作……删除资源需要第二个身份审批”。目前 `main` 拒绝所有参数，唯一公开命令直接进入 chmod/unlink；私有 `CachePlan` 的只读构造能力不等于可用的 `--dry-run` 接口。执行计划要求独立源码审查和控制器准入，但没有明确哪份记录构成对这一次实际删除的第二身份批准。

   缓存维护是否属于上述“处置动作”存在范围解释空间；然而当前审查材料没有明确例外，不能默默将全局约束排除，也不能把本次源码审查当作实际删除授权。该问题来自计划同时规定“无参数入口”，不是实现者擅自扩大能力。

   **修复方向：** 在实际操作前给出明确书面范围裁定。若全局要求适用，提供仅作用于固定 cache 的 `--dry-run`，完成同样的预检并输出拟处理元数据，但不创建 intent/result、不 chmod、不 unlink；同时明确实际删除的第二身份批准记录。若认定这是不属于响应处置动作的独立维护流程，应明确依据、适用范围和仍保留的准入条件，再更新执行计划。

#### Minor — Nice to Have

1. **持久化失败 fixture 目前只覆盖 intent 的首次 fsync 失败。**

   依据：`scripts/test_identity_cache.py:300`；`scripts/identity_cache.py:278`、`:281`、`:357`、`:245`、`:375`。

   当前测试没有分别注入 intent 父目录 fsync 失败、已发生部分 chmod 后的 fsync 失败，以及删除后 completion result 写入/同步失败。静态实现会传播异常并保留 intent，因此未发现对应的错误恢复路径；补充少量定点 fixture 可更直接证明“部分变更/删除成功但结果未知”时不产生成功结论，也不允许盲目重试。无需扩大成旧套件回归。

### Cannot Verify / Evidence Limits

- **实际 ancestry 和项目锚点：** whole-main 测试替换了 `ROOT` 与 `trusted_directory`，故不能证明真实 `/home/postedism/Desktop/Warden/.cache` 或 `.cache/warden-lab` 可被准入。控制器必须执行计划中的真实路径检查。依据：`scripts/test_identity_cache.py:331`、`docs/evidence/task-6/cache-execution-plan.md:10`。
- **旧 cache 来源与 writer-free window：** 受认可的名字、模式和大小不能独立证明每个实际对象来自旧 Go 入口，也不能证明当前无写入者。计划正确把这些列为控制器条件；本次没有检查进程、运行旧脚本或遍历实际 cache。依据：`docs/evidence/task-6/cache-execution-plan.md:11`、`:55`。
- **实际资源与后验完整性：** 未验证当前完整 R、全部未释放 charge、Q5GB、owned images、维护 headroom、真实空间回收或清理后标准新 3GB 准入。计划保留这些要求，没有减记 Q 或用维护 allowance 替代新 3GB。依据：`docs/evidence/task-6/cache-execution-plan.md:12`、`:42`。
- **格式来源：** 计划提供固定 Go 1.26.10 源文件哈希和布局说明；本次检查了新 scanner 与该声明的一致性，没有再次读取工具链源码验证其真实性。依据：`docs/evidence/task-6/cache-execution-plan.md:47`。
- **证据核对：** 已处理完整 BASE `0a18e1a…` 至 HEAD `3f41765…` 审查包；分连续区段读取，重复 manifest 行采用精确重复比对压缩展示，并补读首次输出被截断的小段。独立解析确认六组 pre/post manifest 各含 139 个键且组内完全一致；最终两个源码的 diff 内容 SHA-256 分别为 `f608dc714b79dcc4f3c4c2071ba6dd561c88eec10c45fc905820ec447d8a1ede` 和 `807fc390ea6b807f895b39acfd9ffc48d143ccd5a3b3dc4f1f3d05cfdeb93bc2`，与最终 fixture manifest 相符。最终输出记录 26 tests / OK，无额外警告；这是已有执行记录，不是本 reviewer 重跑结果。依据：`docs/evidence/task-6/cache-cover-06/output.txt:29`、`docs/evidence/task-6/cache-cover-06/receipt.json:7`。
- **唯一额外依赖检查：** 为核实父 FD 的 nofollow/祖先信任契约，定点读取了未修改的 `scripts/runtime_lab_paths.py` 中 `trusted_directory`。其逐组件 nofollow 打开，并检查 owner 和可写权限；这只证明 helper 的源码行为，不证明实际宿主路径状态。依据：`scripts/runtime_lab_paths.py:13`。未扩展审查旧 recovery 或账目实现。
- **审查操作限制：** 未运行测试、实际 cache 操作、Go、Docker、PG、云或身份操作；未修改文件、Git/index/HEAD，未派生子 agent。控制器后续新增的 corroboration 文件不属于冻结差异，也未用来替代本次源码判断。
- **整个 Task6 仍未验收：** authn/JWKS/SCIM、持久迁移、真实 SQL/HTTP 撤销和实际 IdP 验证不在本次资源子阶段交付中；其缺失不作为本次 scoped review 的实现缺陷。依据：`docs/evidence/task-6/cache-substage-report.md:31`。

### Assessment

**Task quality：Needs fixes — 执行计划门禁需修正；未发现已证明的生产删除算法阻断性缺陷。**

**Reasoning：** 固定 FD 扫描、权限只收紧、durable intent 和未知状态保留实现较扎实，fixture 证据也如实限定了能力。实际执行前仍必须解决全局处置约束的范围冲突，并由控制器独立证明真实祖先准入、writer-free window 和完整资源 guard；本报告不批准实际 chmod/unlink。
