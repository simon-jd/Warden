# Task5 proposal-only：攻击语料与隔离矩阵

状态：**NEEDS_CONTEXT / 尚未授权实现或执行**。本文件是可审查设计，不是 Task5 验收记录。2026-10-24 只读取指定 brief、research、预算、公共代码和原始公开文档；不运行 Go、Docker、攻击、ABI 检查、系统扫描或私有现场操作，不修改产品、Gate/runtime、证据、STATUS、Git/index。本阶段唯一写入是本文件。research 中 PREREQUISITES 陈旧句已由控制器修复，不再列为待办。

## 1. 已知接口与未满足依赖

- `runtimes/runtime.go`：`Start(ctx, Spec) (Handle,error)`；`Spec` 只有 RunID、ImageDigest、Cmd、Limits、Network、AllowDomains。`Handle` 提供 Wait/Kill/Logs；Exit 提供 Code、OOMKilled、TimedOut、CgroupEmpty、PidsMaxEvents、PeakPids、LogsTruncated、DroppedLogBytes。没有 Env、额外挂载、任意网络拓扑、攻击入口证明、检测结果或单独可信 syscall 审计字段；本方案不得假定这些能力存在。
- `runtimes/conformance/guest/Dockerfile` 是 scratch，只包含 `/warden-probe`、`/write-probe`，UID/GID 65534，无 shell。`suite.go` 展示随机 RunID、digest、专属 lab ACK、真实入口、完整日志及清理要求。其七项测试不是 Task5 语料。
- Task1/2 已接受；依据 `docs/evidence/task-2/api-runtime/live/README.md` 和 `docs/evidence/task-2/lab-live/README.md`。后者保留其当时“Task2整体未完成”的历史语境，以更新的 API/live 验收为准，不改历史证据。
- Task3/4 各自原五轮上限已经用尽，未接受。Firecracker source95 的 VMM/kernel start 不等于 Ready 或 tenant EXEC。未知 Python ABI 使必要现场恢复停在 helper 之前。原 root-owned live/Q5GB 隔离未解，ordinary guard 失败；没有可执行语料的三 runtime 环境，也没有新 recovery、boot 或因果修复授权。

## 2. 最小未来文件边界

仅在后续单独 dispatch 与 review 后允许创建：

| 路径 | 职责 |
|---|---|
| `attacks/corpus/<id>/run.sh`、`expect.yaml` | 每个行为独立目录；有限脚本入口与原计划元数据 |
| `attacks/guest/main.go`、`script.go`、`bodies.go`、`Dockerfile` | 独立、可审查、静态 guest payload，受限脚本解释器及确定性有界行为；不改 conformance guest |
| `attacks/matrix/main.go`、`runner.go`、`classify.go`、`record.go` | 显式 lab admission 后逐项调用既有 Runtime；收集原始结果；纯分类；有界证据序列化 |
| `attacks/matrix/classify_test.go`、`runner_test.go`、`testdata/` | 纯 fixtures/fake Runtime；不得连接 daemon、启动 guest 或执行 run.sh |
| `attacks/README.md` | 语义、限额、专属 lab/tenant 前提、未执行原因及打包流程 |
| `docs/evidence/isolation-matrix.md` | 未来实际三 runtime 表，fixture 与真实执行分开；链接本次真实证据 |
| `docs/evidence/task-5/<session>/…` | 未来新会话的脱敏 manifest、typed results、完整有界日志、cleanup/检测凭据；不重用旧 live 目录 |

不新增 runtime adapter 或改变 Gate 来获得通过。CLI 必须使用后续明确指定的既有受信 lab 构造/授权入口；目前 `Runtime` interface 本身不证明 tenant 授权。若没有可复用入口，停止在接口注入的 runner 层，返回 admission 缺失；不得临时直连共享 daemon。必要导出/新入口是另一次明确评审的工作，不是本 proposal 的隐含修改。

`expect.yaml` 精确保留三字段：`{id, technique, success_signal}`，全部是非空字符串。例：`{id: metadata-ip, technique: T1552.005, success_signal: WARDEN_SUCCESS_metadata-ip}`。不得把 error 状态塞进 technique 或给 expect 强加 detector 字段。每份文件限制 4 KiB，拒绝重复 key、未知 key、多文档、别名/合并、非法 ID 和重复 ID。是否使用仓库既有 YAML 库需后续 named-source 核对；不在本阶段选新依赖或版本。行为限额、判定策略与 schema version 放 runner 的显式白名单及 manifest，不改变原 expect 格式。

## 3. 无 shell guest 的不可变材料方案

优选新增独立 scratch corpus 镜像，不向 accepted conformance 镜像添加 shell。使用一个静态项目自产 `/warden-payload`，包含 `run-script` 和有限 body dispatcher。每份 run.sh 是两行固定脚本：首行解释器声明 `/warden-payload`，次行是 `exec /warden-payload body <白名单id>`。其 exec 行采用 shell 兼容语法；既不承诺完整 POSIX shell，也不偷偷在 host 上使用 shell。

通过 `Spec.Cmd = ["/warden-payload", "run-script", "/corpus/<id>/run.sh", "--run-id", <RunID>]` 显式在 guest 执行。受限解释器只接受与镜像内 manifest 完全相同的字节和白名单 exec 行；拒绝变量、替换、重定向、管道、额外命令、相对路径和路径穿越。不依赖 shebang 自动传参，不依赖 Spec 不存在的 Env。读取 run.sh 后直接调用本程序已审查 body；进程子任务仅 exec 同一不可变 binary 的固定模式，不执行用户提供的程序。run.sh 是实际被解析的 guest 入口，不是 host 包装器或未使用的占位文件。

这需要控制器裁定“run.sh + 显式受限 guest interpreter”是否满足原计划，而不能把文件扩展名当作已获认可。**反弹 shell 特别边界**：本解释器仅支持固定 command token，不是通用 shell；一次固定 token 的反向连接只能证明连接/命令回路，不能冒充完整反弹 shell。优选把该目录的默认网络拒绝探针及受限命令回路材料保留，但完整 shell 行为标记 `unevaluated / shell_payload_not_admitted`。如果验收要求真实 shell，后续需要独立审核已有可获取的静态 shell 来源、许可证、哈希及有限调用方式，再决定是否以新 corpus digest 收录；此处不下载、不安装、不臆造版本或已有 shell。不能降低 UID、NNP、只读根或放开网络以求 success。

打包材料：guest 源码/编译输入、binary 哈希、每个 script/expect 哈希、image digest、架构、总字节和 corpus manifest。静态可执行性及依赖不是目前已验证事实，须未来 packaging profile 验证。runc/runsc 的不可变镜像导入、FC 的镜像/rootfs映射必须分别由其既有受信路径验证；`ImageDigest` 参数存在不等于三者支持此新 rootfs。FC Ready/EXEC 与 digest→实际文件一致性没有证明时，不启动攻击或把启动失败归为 blocked。

控制器补充named路径后做过一次限定字段读取：runc driver要求pre-imported image且实际target digest等于Spec.ImageDigest；gVisor当前只有binding，不能写成已验driver。FC `vm.go` 要求Spec digest匹配owned immutable manifest，agent.ext4和payload.ext4均以只读drive启动；guest/session是绑定Nonce/RunID的one-shot EXEC，不能把Ready或日志串当作EXEC已完成。rootfs入口从export提取payload、独立制作agent/payload ext4；控制器给定现有payload为固定32MiB，未来新binary+14个目录必须在该容量及现有构建边界内可容纳，并重新生成匹配的artifact/provenance。driver对artifact的较大校验上限不是扩容授权。未证明可容纳或须修改现有builder/runtime时，停止打包并列出兼容性缺口，不更改其代码。

## 4. corpus 覆盖及有限行为

下面是拟定的 **14 个目录**。每项都有上述 run.sh 与 expect.yaml，事件总量、字节和 wall time均受 guest 内部上限约束。共同 ceiling 保留原默认 `network=none`、root RO、NNP、UID65534、CPU1、memory512MiB、PIDs128、300s；单个行为一般 ≤15s、网络尝试≤2次/每次≤1s、日志≤64KiB，runner每次只运行一个 cell。仅收紧时间，不扩大任何默认权限。

| ID | 行为/资源硬界及证据要求 | 不得夸大的覆盖 |
|---|---|---|
| fork-bomb | 有限自复制链，最多160次创建尝试、≤15s；每次先记 attempt；只 exec 本 binary 的 sleeper；成功 reap 所有已知子进程，Wait后 cgroup空；PID limit事件和peak须来自Runtime | 达到guest内PID限制是 containment，不是host DoS；循环自然结束不证明限制生效 |
| memory-exhaustion | 最多申请并触碰640MiB，分块、≤15s、不落盘；入口后真实Runtime OOMKilled且空树可支持有界OOM containment | 分配报错、runtime缺证、未知终止不能算OOM blocked |
| disk-fill | 只写预置 `/disk-target` 单文件，最多16MiB、≤5s；记录写入字节/errno并闭合FD；RO下通常首写拒绝；不递归找可写位置 | 证明RO阻止写入不等于“磁盘满”事件；缺乏现有受限可写卷支持时，实际ENOSPC场景 unevaluated |
| proc-info | 最多4个预先白名单 `/proc` 路径，各≤4KiB；只记录分类/hash，避免落真实敏感内容 | 普通guest可见信息不等于host泄漏；无已审查lab synthetic host-canary时，跨边界泄漏结果 unevaluated |
| sys-info | 最多4个固定 `/sys` 路径，各≤4KiB，同上；只读 | 不递归扫描host；无明确保护对象不可将空内容算blocked |
| metadata-ip | guest 内对169.254.169.254单次有限连接/请求，仅在独立lab证明无真实metadata可达时允许 | host不访问metadata；连接失败只有在入口、route/策略及完整结果可证时才是网络阻断证据 |
| metadata-name | guest内固定 metadata.google.internal 名称路径；无公共resolver，禁用resolver fallback | 若无隔离本地解析材料，记 setup_missing；不把NXDOMAIN当隔离成功 |
| raw-socket | 只申请一种预定raw socket、立即close，无发包；≤1s；记录errno/返回值 | socket拒绝是此权限检查；允许创建不自动证明ARP成功或宿主逃逸 |
| arp-spoof | 构造≤1个synthetic ARP帧；默认无网络下检查接口/权限，绝不发到共享接口 | 无专属victim和私有L2拓扑时spoof实际效果 unevaluated；不得新增接口/修改宿主网络 |
| ptrace-other | 最多1个同guest专属子进程，≤1次attach与detach/reap，失败也清理 | same-guest child检查不代表跨sandbox/host进程隔离；跨边界需另有合法lab victim证据 |
| mount-unshare | 固定空目标、各一次有限syscall；无host路径和共享namespace；成功时及时回退/退出 | 操作成功是该原语被允许，不自动等于host escape；不能在host预建mount |
| kernel-module | 仅设计模块装载权限探针，不提供/加载真实module；严禁host模块变化 | 无风险且有语义的权限探针材料需评审；空/无效模块的EINVAL不能证明加载被策略阻断。完整load行为 unevaluated |
| dns-txt-exfil | 只使用合成无敏感token，≤1个TXT query；目的为独立lab私有collector，不用公共DNS | 默认none下无collector可用则明确未满足；loopback正例只是功能fixture，不证明越界外泄 |
| reverse-shell | 最多1个反向连接和1个固定无害命令、≤2KiB响应、≤5s；仅lab内目标，终止并reap | 无shell材料/越界collector时完整行为 unevaluated；仅connect或固定命令回显不冒充完整reverse shell |

技术标签是行为索引，不是“已证明ATT&CK攻击成功”。已核验原始MITRE文档的拟用映射：资源耗尽 T1499.001；逃逸原语相关 T1611；metadata T1552.005；非C2 DNS外泄 T1048.003。其余目录的精确 technique 需要后续逐项原始文档核对后才填入最终 expect；本阶段不凭猜测给 raw socket、ARP、ptrace、反弹shell硬套同一标签。不能以此缺项创建不完整可执行 corpus 并声称完成。

## 5. runner与分类状态机

每次生成新的RunID；manifest绑定 `{session, tenant_authority_ref, runtime, run_id, corpus_digest, image_digest, attack_id, attempt_ordinal}`。启动前要求受信lab/tenant授权及预算票据；runner本身不能创造这些权限。记录 Start、attack-entry、outcome、Wait、log收尾、Kill/cleanup、detector阶段的时间与错误。日志按上限流式收集；没有指定Handle日志流语义时，先以既有受信路径的已证明顺序为准，不能假定实时 streaming。read/close失败和超限一律保留原因；不得截断后继续给成功分类。

结果信封增加独立 `evaluation = unevaluated | error | evaluated`，`verdict = null | blocked | missed | detected`，并保留 `reason`、原始Exit及其known标志、entry/outcome证据引用、cleanup状态、`detector_state = unavailable | pending | complete | error`。不改 Runtime 接口；未知值不能用Go零值充当Code0或cleanup成功。

按顺序裁定：

1. 没执行或前置不满足 → unevaluated/null，例如 ordinary_guard_blocked、runtime_not_ready、payload_not_admitted、scenario_not_representable。
2. 发生Start/Wait/log/transport错误、没有有效入口、未匹配RunID、重复/矛盾outcome、任意truncation/dropped bytes、未知exit、未知/失败cleanup → error/null。调用Kill成功不等于cleanup已证；外层删除也不替代CgroupEmpty。runner必须在错误后仍走既有精确清理路径；清理不明则不再开下一cell。
3. 只有已执行、完整、来源绑定的记录可进入 evaluated。stdout success_signal 必须整行准确匹配，附属结构事件绑定本次RunID；它仅是候选成功声明。单独缺少marker或非零退出绝不够判blocked。还要有该行为明确的拒绝/限额证据：例如Runtime的OOM/PID计数，或不可变guest固定syscall观察、明确目标与errno，加上运行身份、正常收尾、无setup错误及空树。guest观察应明确标为guest证据，不能伪装成独立内核审计。
4. 只有攻击目标确实达成（由该行为验收predicate和必要的独立lab canary/collector证据支持）才可 `missed`；marker与证据冲突 → error。原语成功、跨边界成功、同guest功能fixture分开，不能混为host escape。没有可信保护目标/collector时保持unevaluated，而不根据marker“补齐”矩阵。
5. Task12之前永不输出detected。missed表示当前隔离目标实际达成且没有可用检测结论，显式附 `detector_state=unavailable`，不声称已验证检测器漏报。若控制器认为missed必须专指“在线检测器漏报”，则此前成功项保留evaluated observation但verdict=null/pending，不能悄悄改变语义。
6. Task12之后重跑阶段D矩阵。由独立可信检测存储按RunID、tenant/runtime身份、时间窗口、image/corpus digest、事件类型关联；由detector提供覆盖完成/事件ID凭据。guest stdout不得提供或替代检测证据。真正检测到对应攻击且基本执行/cleanup证据完整时verdict=detected，同时单独保留 containment=blocked/succeeded。成功且确认检测覆盖完成无命中才是严格missed；覆盖未知/检测输送错误则pending或error，不能算missed。旧矩阵不原地改写为新检测结果。

默认300s是上限，不是把任何300s超时都解释为防御。只有专门约定的限时行为、有效入口、相应真实Runtime.TimedOut及完整cleanup才能证明时间限制；本corpus其他意外超时均error。OOM同理不能用Code137替代OOMKilled。

## 6. fixture、实际测试与证据的边界

未来获批的 bounded **code-only profile** 才可原生运行Go纯分类/runner单测。明确目标 `TestMatrixClassifiesFixture`：成功fixture具有候选marker+完整目标证据，判missed且detector unavailable；失败fixture具有已进入攻击、明确拒绝证据且exit/cleanup/logs完整，判blocked。二者是内存记录，不是host假攻击脚本。按原计划先观察RED，再实现后GREEN，记录事实；不能现在编造RED。

同时表驱动覆盖：Start failure；缺entry；exit未知；日志截断/drop/read/close错误；Wait/transport失败；Kill错误/空树未知；超时/OOM无entry；marker伪造或与目标证据冲突；错误RunID、重复事件；fixture检测事件伪造；Task12未到却请求detected；detector覆盖未知；取消后仍清理。fake Runtime只返回记录和有界内存流，禁止os/exec、网络及真实driver构造。runner测试证明调用次序、取消/清理和拒绝继续调度，不能证明内核隔离。

未来完整Task5验收仍须每个required attack在runc、gVisor、Firecracker的真实矩阵、实际语义覆盖、复核cleanup，且明确每个未执行或无法表征cell。fixtures和旧七项conformance无论多少PASS都不能补格；有unevaluated/error或语义缺口时Task5不能宣称全部完成。

当前诚实矩阵为14×3共42个**全部unevaluated**：runc全部ordinary_guard_blocked；gVisor全部ordinary_guard_blocked + Task3 unaccepted；FC全部ordinary_guard_blocked + Task4 no Ready/EXEC。其中磁盘满、跨边界canary、ARP、module、DNS collector、完整reverse shell另有材料/场景阻塞。没有实际blocked/missed/detected格。后续证据页按此模板展示，不把空白、SKIP或“预期blocked”渲染为绿色通过。

## 7. 后续准入顺序与需要控制器裁定的事项

A. 仅设计裁定：认可状态信封与missed语义；认可restricted interpreter是否满足run.sh；确定完整shell、ENOSPC、ARP、module及cross-boundary canary等在既有限制内的可验收语义。当前无需用户即时输入；未决就保留NEEDS_CONTEXT。

B. bounded code profile：由控制器独立批准其源码清单、既有工具来源、时间/输出/cache/磁盘/内存上限及退出清理，才可原生Go fixture测试。不得把“只跑单测”当作ordinary guard豁免，也不得在Q5GB/未知ABI下自行调查或执行。此阶段不编译/运行攻击binary，不接入daemon。

C. packaging profile：ordinary guard有效、隔离现场问题经另项授权解决、资源票据明确，才可编译guest、检查静态性与架构、构建/导入新digest及逐runtime digest/rootfs材料验证。无下载/安装和虚构版本pin；新增外部软件先核对当前primary docs、来源和成本。仅执行审查过的无攻击启动/入口探针仍需本门批准，不能用Task2旧票据。

D. actual-test profile：三runtime各自可运行且受信路径被接受；新专属project lab，无共享victim/daemon/collector；tenant授权和默认保护经核验；逐cell预算、counter、完整日志与收尾方案已审查。网络类保持none，不开public callback/listener/DNS，不做host metadata请求、不改变网络/module/settings。若目前接口无法提供安全场景，不扩大权限，而是标未执行并继续保持Task5验收未完成。

E. 所有资源操作独立授权。Warden项目盘总12GB、总常驻memory16GB，打包/导入/日志/保留与既有隔离占用都计入，不能把Q5GB当已释放。单guest仍512MiB/PIDs128/CPU1，顺序执行；磁盘/内存票据需含outer服务及临时峰值。GPU不用，因此不触碰GPU/flock。若将来确需云，仍先Retail Prices API实价与创建前reservation，累计≤$5.40（$6×0.9），仅rg-warden-lab，四标签project/owner/ttl/est_usd_per_hour，不修改/删除rg-mlinfra-westus；本方案并不要求也不授权云资源、credentials、部署。

**ordinary guard当前受阻，因此B/C/D及任何实际资源准入不能现在执行。** 本proposal并未批准新code profile；即使未来另获合法的code-only准入，纯fixtures也不能解锁C/D或填入真实结果。仅A与公共材料审阅可继续。

## 8. 原始来源与未核验项

本次读取的本地公开代码：`runtimes/runtime.go`、`runtimes/conformance/suite.go`、`runtimes/conformance/guest/Dockerfile`；以及上述两个Task2 README。另经控制器明确允许，对`runtimes/runc/driver.go`、`runtimes/gvisor/binding.go`、`runtimes/firecracker/driver.go`、`runtimes/firecracker/vm.go`、`runtimes/firecracker/guest/session.go`、`runtimes/firecracker/cmd/rootfs/main.go`各做一次限定字段搜索读取。未扫描目录/私有scene，未读取完整17任务历史；没有假定未读driver实现、已安装软件版本或额外API能力。

2026-10-24只读核验MITRE原始文档（用于技术标签，不用于执行授权）：[T1499.001](https://attack.mitre.org/techniques/T1499/001/)、[T1611](https://attack.mitre.org/techniques/T1611/)、[T1552.005](https://attack.mitre.org/techniques/T1552/005/)、[T1048.003](https://attack.mitre.org/techniques/T1048/003/)。其余标签/软件实现细节保持待核验，不作新软件/API事实断言。以上阈值、文件名、协议及状态字段均为本proposal设计，不宣称已经存在或测试通过。
