# Task7 只读方案裁定（2026-10-25）

[方案原文](controller-proposal.md)由 `workload_identity_proposal` 子 agent（gpt-6-astra/high）准备，全文原样归档；这是子 agent 的设计与资料核验，不是人工标注或真实云验收。当前只关闭方案准备，不授予 Task7 产品实现、测试、云操作、安装或发布权限；Task6 recorder 的现有实现者仍独占产品源码与 Git/index。

控制器已独立核对下列官方页面（检索日期 2026-10-25）：[AKS 令牌说明](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview#service-account-annotations)、[可配置寿命限制](https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes)、[access token 的适用范围](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)、[system pool 限制](https://learn.microsoft.com/en-us/azure/aks/use-system-pools)、[第二资源组规则](https://learn.microsoft.com/en-us/azure/aks/faq#why-are-two-resource-groups-created-with-aks)。其余方案引用仍标为该子 agent 的资料来源，不冒充控制器逐页独立核验。

Ruling: 保留原 `exp - iat <= 3600` 的真实 access-token 门禁 — AKS 文档将投影断言与 24 小时 Entra token 明确分开，managed identity 不支持寿命策略；通用 registered-API 说明又不适用于 Microsoft 自有 API — 若后续找到受支持的免费方案需重新核对精确资源和签发语义，现在不以断言、缓存刷新、本地 expiry 截短或一次幸运样本代替，也不购买付费层。Entra Free 对 application-policy 的实际能力仍 unknown，不宣称 P1 是当前已证实的必要条件。此缺口不阻止未来独立的 source/fixture 层，但真实身份验收不通过。

Ruling: 将未来最小权限演示限定为读取本项目专用 conformance 容器中的非敏感证明 Blob — 原 Task7 需要具体最小权限边界而没有规定业务云操作，单独的只读证明对象足够检验联邦和资源访问 — 若选择不合适，只修改尚未部署的模板与测试；不扩展控制面产品功能，不授予 Contributor、订阅级 Reader、Graph、issuer 上传或 FIC 管理权限。未来应将 Storage Blob Data Reader 限到该专用容器；真实目标 ID、内容、价格与范围仍须准入，当前没有 Blob、角色绑定或云令牌。

Ruling: 保留 `169.254.169.254/32` 和 `169.254.169.252/32` 两个拒绝目标，明确后者仅是原 GKE 路径的回归目标 — Azure 不存在第二个等价 IMDS 地址的证据，端点缺席不能证明策略 — 后续需要单独审查有安全响应端点和正对照的专用测试形态；当前 loopback-only k3s 不能证明 Cilium 执行，没有宿主 k3s/iptables/CNI/路由变更或重开原五轮入口。静态策略、生成 fixture、真实默认 network-none 和真实 Cilium enforcement 必须分别记录。

Ruling: AKS 实际演练保持未准入 — B-series system pool、当前 system pool 配置与六 vCPU 区域限制、自动新建第二 RG 均存在具体前置冲突，不能靠预算文中的示例 SKU 或自定义 node RG 名消除 — 代价是该实际验收继续开放，不另建 RG、不增配额、不放宽标签/磁盘/费用规则。方案中 system-pool 页与 quota 页的差异需要真实部署方案前解决，不把推测写成支持性结论。

Ruling: k3s issuer 的 Blob 公共文档只可作为待审模板 — 用户保留公开发布限制，公钥文档也需要精确目标、内容、写入能力、密钥保管/轮换和预算证据 — 现在不发布 endpoint，不创建账号、资源或 credential。不得复制私钥、实际 token 或任意 SDK 错误正文到证据。

未来 source dispatch 应优先使用少量具体 Terraform/Kubernetes/Cilium 模板与有明确行为的局部校验测试，避免先建立通用观察/证据框架。原三个真实验收名称与含义保留；locally signed fixture 只能证明生成数据上的校验逻辑，不能证明实际 SA、Entra FIC/RBAC 或网络拒绝。精确文件/API/验证 profile 仍须单独 brief，当前没有实现 dispatch。

原 Task6 整体 BASE84018、fix2/5、Task3/4 的既有五轮上限、原恢复现场与 Q5GB、Task5 的 42 格真实空缺、12GB/16GB、Azure $6 与估算准入 $5.40 上限均保持。方案准备不勾选 Task7，不标记 Task6 或 Goal 完成；只做本地文档归档，不 push 或公开发布。
