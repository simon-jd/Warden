# Azure单价预查询（尚未开通资源）

日期：2026-10-23。来源：Azure Retail Prices API。原始响应包含查询URL、retrieved_at、完整Items和分页字段，见[AKS](prices/aks-westus2.json)、[B2s](prices/b2s-westus2.json)、[Hot LRS](prices/blob-westus2.json)。本轮均无NextPageLink，未漏后续页。

| westus2计量 | API单价USD | 单位 | 说明 |
|---|---|---|---|
| AKS FreeTierInfrastructureCost Uptime SLA | 0.05 | 1 Hour | 按预算文件保守计入；API isPrimaryMeterRegion=false，不能当所有AKS配置等价报价 |
| Linux B2s / Virtual Machines BS Series | 0.0416 | 1 Hour | 普通VM报价；不可误选Windows 0.0496，也不能视为AKS system-pool可用SKU；还须计盘/IP/其他适用项 |
| Hot LRS | 见原始逐项 | GB/月及10K/100操作等 | API有多种产品/层级/单位，不能取首条当Blob全成本；部署前必须按具体SKU和计量筛选 |

这些查询没有开始时间、结束时间或资源承诺，因此不构成开通批准或已消费金额。完整估算与硬门槛以[azure-spend.md](../../azure-spend.md)为准。尚未创建任何Azure资源，rg-warden-lab只读查询结果为不存在。

[微软API说明](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)区分零售价格、单位与分页；不能把CLI消费金额空值当零成本。

## 2026-11-13：AKS演练的新快照

[prices/aks-drill-20261113-swedencentral](prices/aks-drill-20261113-swedencentral)由`scripts/aks_drill.py prices`取得（AKS、Standard_B2as_v2、Premium SSD P4、Load Balancer（Global）、公网IP、带宽、Managed Identity）。估算和选用理由见[aks-drill.md](../../aks-drill.md)。同日早些时候取过一份westus2的快照，后来发现订阅的位置策略不允许westus2，那份已删除（在git历史里）。下面一节是2026-10-23的情况：节点组现已获批准；那时以为可用的B2s在westus2已不在本订阅的SKU列表里，系统池不支持B系列这一点仍然成立。

## AKS部署范围的待解决项

[AKS官方FAQ](https://learn.microsoft.com/en-us/azure/aks/faq)说明AKS自动创建第二个节点资源组，不能使用现有组。当前用户约束只允许rg-warden-lab，因此在资源组范围得到明确兼容配置/额外授权前不创建AKS，先完成本地k3s身份联合与AKS部署代码/测试。不会默许创建MC_*或其他节点资源组；也不会触碰rg-mlinfra-westus。此项不影响本机runtime与其他独立任务。

[System-pool官方文档](https://learn.microsoft.com/en-us/azure/aks/use-system-pools)也明确排除B系列，列出4vCPU/4GB及节点数量要求；[配额/SKU页](https://learn.microsoft.com/en-us/azure/aks/quotas-skus-regions)同样排除B系列，但较小VM说明细节与前页有差异。后续必须核对具体版本/API/非生产配置与共享6-vCPU上限。当前没有AKS实测，不能以单B2s参考价推导“可按此部署”，也不会为验证而擅自创建、升配额或扩展资源组。
