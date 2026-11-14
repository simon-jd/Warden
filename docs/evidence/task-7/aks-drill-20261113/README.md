# Task 7 的 AKS 演练：代码阶段（2026-11-13，home-ubuntu，worktree `aks-drill`）

这一阶段只写代码和离线测试，没有创建 Azure 资源（台账 $0）。演练本身、费用、硬停止和拆除见 [aks-drill.md](../../../aks-drill.md)。

[red-green/](red-green) 是每个代码改动先失败、后通过的输出：

| 文件 | 改动 |
|---|---|
| 01-probe-imds-* | 探针的 `imds` 用例（只读实例区域，带 `Metadata: true`） |
| 02-guard-aks-* | guard：AKS 集群、身份、节点组、`down`、`teardown-check`（RED 里的 GUID 是测试用的假订阅） |
| 03-aks-drill-mutations.txt | `scripts/test_aks_drill.py` 和脚本一起写的，不是先写；这里是两次变异检查，说明测试会失败 |
| 04-workload-exchange-* | `identity/workload`：服务账户令牌换 Entra 令牌 |
| 05-aksdrill-helpers-* | `controlplane/internal/aksdrill` 的离线帮手 |
| 06-makefile-aks-* | Makefile 的 AKS 目标 |
| 07-guard-review-* | 第一轮审查后的 guard：swedencentral 和位置策略、相对 ID、其他 worktree 的台账、Network Watcher 前后比较、角色分配检查（RED 之后测试又补了“策略定义里的默认值”两种情况） |
| 08-aks-drill-review-* | 第一轮审查后的 `aks_drill.py`：登录检查、节点组检查、整窗预留和过夜边界、主体记录、DNS 前缀（RED 之后测试的时钟移到了新快照之后） |
| 09-region-audience-* | Go 侧的 swedencentral 和证据里的受众摘要 |

三个实测（`make test-aks`）2026-11-14 在 AKS 上跑过，记录在 [live/](live/README.md)。`10-region-case-*`：runs/01 发现 IMDS 答的是 `SwedenCentral`，改成不分大小写比较。

查询记录（只读）：westus2 和 westus 的 VM SKU 列表和配额、订阅的策略赋值（含订阅 ID）在 `~/Desktop/warden-private-scratch/aks-drill-prep/`，不进 git。
