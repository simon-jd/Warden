# 原 Task9 实现与有界验证准备裁定

root 已全文读取原唯一作者 8190B `task-9-proposal.md`（716ebd）；原计划三个测试、真实 PostgreSQL 持久状态以及 Task1 audit.AppendTx/Verify 保持，不复制审计算法。可信身份、角色 allowlist、UID/resourceVersion 条件绑定、先持久 intent 后外部动作和可恢复回收按原提案实施；真实身份接线、受监督 Expire 调度与实际 Kubernetes RBAC 仍分别验收，不把本地 adapter 替身写成这些实际通过。

[唯一镜像元数据事件](pg-metadata-events-20261025.json)记录 ffabfb fresh 与 9a9022 known0。postgres:18-alpine 本机固定 ID 为 `sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873`，Size432729433B；没有 pull/create/start 或测试。新 Docker config 仅 `{}\n`，不修改宿主 HOME；旧 Task16 停止规则、旧 native UNKNOWN9GB 常驻预留均保留，不能再跑第三 profile/sizing。

本次仅让同一作者准备一个精确 inert 材料/首 RED 包，SOURCE/Git/index 仍在 root。无需重复已知 image inspect 或已过 audit 全包/Task11/14 等。新的测试必须 PostgreSQL 真实事务与原审计链，首 RED 不得以构建失败、连接错误、skip 或前置错误冒充业务失败。

实际方案不能 publish 端口、host/bridge 网络或间接写 iptables；仅新且先证实不存在的本项目名字/namespace、network none 和 Unix socket。PG18 data mount 覆盖 image VOLUME，禁止遗留匿名卷；read-only/cap-drop/NNP/nonroot，临时 init server 不能冒充最终 readiness。只处理这次自有容器；不全局枚举或检查/信号旧 PID。

目前资源只作准备：完整新增 disk <=1750000000B，必须涵盖 image/daemon 保守峰值、全部 Go modules/cache/tmp/bin、PG 数据和证据；按 fresh R + Q5000000000B + 四旧 /tmp 保守131072B + 完整新增 <=12000000000B 才可另准实际。常驻旧 UNKNOWN9000000000B 加新增 <=7000000000B；不能以 GOMEMLIMIT 冒充 RSS 硬界。可准备使用同一已缓存 PG image 的受 cgroup 限制 Go 容器、只读固定 SDK/源码与独有缓存；尚未批准这个执行方案，不能执行 binary/container/probe 或下载。若 native Go 方案，须计编译器与 CLI 最坏并发，不复用旧 Task16 profile。

整体90秒含收尾，work<=65秒并留准确清理期限；不确定、超时或任何新自动审批拒绝即停并保留，不搜索阈值。root 全文 caller 与 fresh 门禁后才分别准材料/RED。原 Goal active，Task9/整个项目未完成，旧所有有限额度、Q、现场、12GB/16GB/Azure6USD 和发布限制不变。
