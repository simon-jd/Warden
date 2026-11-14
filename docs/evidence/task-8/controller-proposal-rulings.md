# Task8 只读方案裁定（2026-10-25）

[完整提案](controller-proposal.md)由 `vault_proposal` 子 agent（gpt-6-astra/high）准备，原样归档，属于方案/资料证据，不是人工标注或部署验收。当前没有 Task8 实现 dispatch、测试、Vault/PG 启动、Graph 调用、目录或 Azure 资源变更。

控制器独立核对了 [Azure engine API](https://developer.hashicorp.com/vault/api-docs/secret/azure)、[插件 v0.25.0 认证源码](https://raw.githubusercontent.com/hashicorp/vault-plugin-secrets-azure/v0.25.0/provider.go)、[PostgreSQL VALID UNTIL](https://www.postgresql.org/docs/current/sql-createrole.html) 和 [Shared Key 禁用语义](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)，检索日期 2026-10-25。其他引用保留为该子 agent 的资料，不冒充逐页控制器核对。v0.25.0 只是研究 pin，尚未批准安装版本或兼容组合。

Ruling: 免费 Community 的数据库动态凭证/Kubernetes auth 方案可作为未来独立源码方向，Azure engine 的实际根认证保持未准入 — 官方插件 WIF 属于 Enterprise，该 pin 的认证选择没有投影文件路径，Task7 的直接联邦不能自动移植给 Vault — 代价是该云门禁继续开放，不购买 Enterprise、不放静态 client secret、不使用 dev root/CLI/节点 IMDS 或部署 Azure VM/Arc 代替。当前也不自动 fork 插件。若未来评估小范围 Community 插件扩展，必须明确标为本项目修改、单独给出来源/版本/构建/安全方案与测试审查，不能伪称官方现成支持；本裁定未授权该实现。

Ruling: 保留真实 60 秒数据库凭证到期与同步 revoke 的新连接证明 — proposed Task6 PG 的 trust-only/reject-other-roles profile 不能证明密码检查 — Task8 后续需要单独审查的 SCRAM、TLS、正常登录正对照、server validity/lease 时间和精确 revoke/失败处理。现有连接、fresh login 与已签发 Azure token 分别观察；不以 sleep、网络失败、pool 关闭或租约记录消失当认证拒绝。生产 DB TTL<=1h/max_ttl<=4h，测试角色 default/max60 秒。实际 profile、材料与启动未获准入。

Ruling: 将原 IAM user/SA key 审计对应到 Azure 项目可用的长期云客户端凭证，并单独披露 provider key 存在 — 原测试命名统计的是 IAM/SA 客户端密钥，不是云提供方所有内部密钥；Blob 存储也由预算明确要求 — 完整授权边界内 Entra application/SP 密码和客户端证书等禁止凭证必须为零，不能漏页、漏类型或把 unknown 记成零。Storage 的两把 account key 存在数单列，不能写“物理零 key”；未来要求 Shared Key 显式禁用，平台不取值/保存/使用它们，account/service SAS 与 user-delegation SAS 分开判断。任何可用长期密钥、未审服务或无法建立完整范围均不能通过。此定义不声称已有实际零结果，也不把禁用 key 数改写为零。若要求物理全部 key 为零，则与 Blob 路径冲突，仍须另行解决。

Ruling: Azure lease 与 Graph 密码有效期必须分别核对 — Vault 删除租约/SP 的时间和已经签发 access token 的寿命不同；仅 TTL 配置不证明 app password 本身的 start/end 或原始有效期 — 未来需核验精确插件生成/删除路径、credential validity/lease 关系和实际终态。原 Task7 access-token 一小时门禁保持开放，不能由 DB/Vault lease 替代。

Ruling: 不从“Azure engine”目标推导出目录级写权限 — 动态 app/SP、Graph bootstrap、publisher 和审计读取不属于普通 RG 子资源，字面 RG-only 与最小权限仍需具体动作和能力裁定 — 现在仅准备代码前置条件，不创建身份/角色/目录对象、不添加广泛 Graph 权限。完整审计需独立权威项目 inventory、所有相关 credential 类型、授权可见性、分页/并发停写与孤儿核对；空配置、第一空页和权限拒绝保持 NOT_EXECUTED/INCOMPLETE。

本机三 Raft voter 只可称单宿主进程故障容忍，不称宿主 HA。提案内存/磁盘表仅候选 caps，不是新预算或当前 inventory；真正启动前仍要完整普通 R+Q/镜像/临时峰值和 <=12GB/16GB 检查，Q5GB/原现场不释放。初始 root、unseal、DB management 与迁移身份的保管/撤销必须具体审查，不宣称不存在这些信任材料。

当前只关闭 Task8 方案准备，未勾选 Task8/Task6/Goal。Task6 recorder 独立审查仍在进行，整体 BASE84018/fix2/5、Task3/4 上限、Task5 42 格真实缺口、Azure $6 与估算准入 $5.40、无宿主 k3s/iptables 更改及无公开发布/push 的边界均保持。
