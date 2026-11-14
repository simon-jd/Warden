# Warden Azure估算台账

约束：[AZURE-BUDGET.md](../AZURE-BUDGET.md)。总上限$6.00；开通硬门槛$5.40（90%）。
本项目已承诺新增估算：**$0.98**；剩余估算额度：**$4.42**。
这是累计承诺估算，不是实际账单。删除资源不会返还承诺；消费API金额为空，不能声明实际免费。
权威记录为同目录azure-spend.json；本表由工具在项目锁内生成，JSON先落盘。

| 资源/ID | SKU | 区域 | 单价/单位及Retail API原始路径 | 开始UTC | 计划结束UTC | 承诺估算USD | 实际删除UTC |
|---|---|---|---|---|---|---|---|
| resourceGroups/rg-warden-lab/providers/Microsoft.ContainerService/managedClusters/warden-lab-aks | free | swedencentral | aks_control_plane: 0.05/1 Hour × 5.25 [a7de2e5450a78d97ed20b43d9c5c14c0bf97adbc5b961d008dd3feacc1eeaa92]; vm: 0.0778/1 Hour × 5.25 [7dcbe61c664c222c87060b219763a0c5dab4117aeb9717e2e5dbadaf7955a547]; os_disk: 5.8072/1/Month × 0.0072 [b16a62c64a0edb516585e3dfe21721a1162badc634f96d4270b903bc4c8ba0f8]; load_balancer: 0.025/1 Hour × 5.25 [4363606d6e1daf692fc9234ca422039dcba267c06d0dc83f7dfdee6b288602b0]; load_balancer_data: 0.005/1 GB × 4 [4363606d6e1daf692fc9234ca422039dcba267c06d0dc83f7dfdee6b288602b0]; public_ip: 0.005/1 Hour × 5.25 [a71b73107d46b99984e2b3427828fba6a33cd23d691f6e280ecd8919236ff2ab]; network: 0.087/1 GB × 1 [955a2890612c0176e7833ddce0fc723c17f28beb644157ed91bf6a94f8ad15ec] | 2026-11-14T00:11:00Z | 2026-11-14T05:26:00Z | 0.97726184 | 2026-11-14T00:29:06Z |
| resourceGroups/rg-warden-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/warden-lab-controlplane | UserAssigned | swedencentral |  | 2026-11-14T00:11:00Z | 2026-11-14T05:26:00Z | 0 | 2026-11-14T00:29:06Z |

## Entra目录对象（不是订阅资源，不预留，按$0计）

Task 6、8、14只建过Entra目录对象，都归登录用户、名字以warden-lab-开头、标签project=warden，测完即删；合计应用13、服务主体12、用户本人的appRoleAssignment 2（Task 6）、客户端密钥12。它们不在rg-warden-lab里，所以不进上面的预留表。每个对象的ID和时间在各行的记录文件里。

| 任务 | 对象（数量） | 创建UTC | 删除UTC | 承诺估算USD | 单价来源 | 取价UTC | 记录 |
|---|---|---|---|---|---|---|---|
| 6 | warden-lab-api：应用1、服务主体1；用户本人对它的appRoleAssignment建过2个（01:17:06Z、01:23:34Z），第1个01:23:15Z删除，第2个随服务主体删除；没有客户端密钥 | 2026-11-11T01:16:38Z（应用）、01:16:40Z（服务主体） | 2026-11-11T02:38:55Z（服务主体）、02:39:16Z（应用） | 0 | Retail Prices API（serviceName含Entra、Active Directory）及微软External ID定价页：没有对应的计量 | 2026-11-12T06:42:01Z | evidence/task-6/entra-objects-20261110.txt |
| 8 keyprobe | warden-lab-keyprobe：应用1、客户端密钥1（Graph默认期限731天）；没有服务主体 | 2026-11-11T04:27:44Z（应用）、04:27:45Z（密钥） | 2026-11-11T04:27:48Z（应用连同密钥） | 0 | Retail Prices API（serviceName含Entra、Active Directory）及微软External ID定价页：没有对应的计量 | 2026-11-12T06:42:01Z | evidence/task-8/longlived-audit-live-20261110.txt |
| 14 run0 | warden-lab-respond：应用1、服务主体1、客户端密钥1（24 h） | 2026-11-11T04:34:09Z–04:34:11Z | 密钥在告警时由动作删除；2026-11-11T04:44:27Z（服务主体）、04:44:28Z（应用） | 0 | Retail Prices API（serviceName含Entra、Active Directory）及微软External ID定价页：没有对应的计量 | 2026-11-12T06:42:01Z | evidence/task-14/azure-entra-objects-20261111.txt |
| 14 run1 | warden-lab-respond-1…5：应用5、服务主体5、客户端密钥5（各24 h） | 2026-11-11T04:48:37Z–04:48:51Z | 密钥在告警时由动作删除；服务主体和应用2026-11-11T05:00:43Z–05:10:35Z | 0 | Retail Prices API（serviceName含Entra、Active Directory）及微软External ID定价页：没有对应的计量 | 2026-11-12T06:42:01Z | evidence/task-14/azure-entra-objects-20261111.txt |
| 14 run2 | warden-lab-respond-1…5：应用5、服务主体5、客户端密钥5（各24 h） | 2026-11-11T15:28:11Z–15:28:25Z | 密钥在告警时由动作删除；服务主体和应用2026-11-11T15:41:20Z–15:50:12Z | 0 | Retail Prices API（serviceName含Entra、Active Directory）及微软External ID定价页：没有对应的计量 | 2026-11-12T06:42:01Z | evidence/task-14/azure-entra-objects-20261111.txt |

- **流程偏差：取价晚于创建。** 这些对象都是2026-11-11（UTC）建的，单价核对是2026-11-12才做的（Retail Prices API 06:42:01Z，微软定价页06:49:07Z，记录见evidence/task-14/azure-entra-objects-20261111.txt），不是开通前先查单价、记台账。$0是事后核对的结果。
- 核对结果：Retail Prices API里Entra相关的计量只有Domain Services、External ID、Verified ID、SCIM provisioning API和B2C/B2X，没有按应用注册、服务主体、角色分配或客户端密钥计费的。
- 按令牌计费的只有External ID的M2M Authentication计量（$0.001/个）。它按认证事务计费，微软定价页把它列为External租户配置的附加项；这个租户是工作区租户（ARM /tenants：tenantType AAD、tenantCategory Home），订阅里External ID/B2C的计费关联资源（guestUsages、ciamDirectories、b2cDirectories）都是0个，所以不适用。假如适用：Task 14三次演练用实验密钥发出11134个client credentials请求（run0 1212、run1 4362、run2 5560），按每个请求一次事务算约$11.13；只算换到的6632个令牌也约$6.63；两者都超过$5.40门槛。

## 开通前规则与边界

- 精确Retail API meter/region/SKU/USD/Consumption/单位，原始报价快照与获取时间保留在JSON及其旁边的quotes目录；不默认免费层为0。
- 在任何创建前预留全部适用VM、OS HDD Standard_LRS 30–32GB、IP、网络、存储容量/操作、AKS基础计量与日志；锁内校验累计≤$5.40。
- 仅rg-warden-lab，所有资源（包括组）四标签齐全；rg-mlinfra-westus永远不可修改/删除；不设置订阅级提醒。
- >$0.02/h同会话销毁；结束时使用本会话reservation绑定清理。删除时间仅表示已收到Azure删除成功响应，费用不归零。
- 工具只做预留，不会创建资源。AKS：用户2026-11-13批准一个集群（warden-lab-aks，swedencentral）、AKS托管的节点资源组rg-warden-lab-aks-nodes（只认这一个名字，不认MC_*），演练上限$2（门槛$1.80，在$5.40之内，并计入其他worktree的台账）；同日批准节点用Premium SSD OS盘，以及由演练造成、演练后删除的Network Watcher（已有的不许动）。见aks-drill.md。部署代码必须独立审查成本覆盖、使用量上限和配额后才可开通。
- 台账里的资源ID只写到订阅之下（resourceGroups/...），报价路径只写仓库内相对路径；完整ID只在运行时由订阅文件拼出。
- 2026-10-23至2026-11-12：未开通Azure资源；留有记录的reaper运行结果都是rg-warden-lab不存在（group-absent，见evidence/azure-budget、evidence/task-6/entra-objects-20261110.txt、evidence/task-14/azure-entra-objects-20261111.txt）。
- Entra目录对象见上一节。
