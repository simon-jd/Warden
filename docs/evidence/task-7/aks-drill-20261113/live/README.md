# Task 7 的 AKS 演练：实测（2026-11-14 UTC，2026-11-13 PST）

swedencentral，一次开通，同一会话内拆除。按 [aks-drill.md](../../../../aks-drill.md) 运行，源码 `8181227`（runs/02 加上随后提交为 `0de8117` 的 `IsRegion` 修正）。日志都经过脱敏：GUID 换成 `<id>`，API server 的 FQDN 换成 `<api-server-fqdn>`，home 路径换成 `~`；原始日志和含 ID 的 Azure 回答在 `~/Desktop/warden-private-scratch/aks-drill/`。

## 时间（UTC）

| 事件 | 时间 |
|---|---|
| 会话开始：preflight、reaper（两个组都不存在） | 00:10:16–00:10:18 |
| 硬停止定时器装好（04:11、04:31、04:51） | 00:10:27 |
| 预留（台账 start 00:11:00，ttl 05:26:00） | 00:10:35 |
| 资源组、托管身份 | 00:10:37、00:10:42 |
| AKS 集群建好（约 5 分钟；B 系列系统池被接受） | 00:15:36 |
| 联合凭据、kubeconfig、`warden-lab` 命名空间、标签检查（没有缺标签的） | 00:15:40–00:15:46 |
| runs/01、runs/02 | 00:16–00:21 |
| 手动 `make aks-drill-down` 开始 | 00:21:45 |
| 两个组删除完成（台账 `deleted_at`） | 00:29:06 |
| `teardown-check` | 00:29:15 |
| 手动停掉定时器、会话结束的 reaper（两个组都不存在） | 00:30:09 |

集群存在约 18 分钟。估算花费：按小时计的部分约 $0.05（0.31 h × $0.166/h）；每个小时计量都按整小时算、再加上全部预留的 4 GB LB 数据和 1 GB 出站，上限约 $0.27。台账的承诺估算仍是预留的 $0.98（规则：删除不退还）。

## 环境

Kubernetes v1.36.5，1 个 `Standard_B2as_v2` 节点（Ubuntu 24.04.5，内核 6.8.0-1073-azure，containerd 2.3.7），AKS 管理的 Cilium 1.19.9（`cilium-distroless:v1.19.9-261023`），见 [cluster-summary.json](cluster-summary.json)。

## 结果

| 测试 | runs/01 | runs/02 | 关键数字 |
|---|---|---|---|
| `TestSandboxCannotReachMetadata` | **FAIL 46/53**：7 个失败都是正对照，探针其实拿到了 IMDS，但 IMDS 答的是 `SwedenCentral`，测试按小写 `swedencentral` 比较（测试的错，`0de8117` 改为不分大小写） | **PASS 53/53** | 策略生效（agent revision）约 3.4–3.5 s；API server 存下的两份策略都保留了 `enableDefaultDeny: false`。有策略时沙箱和代理替身连 IMDS 3 s 超时、168.63.129.16 的 DNS 3 s 超时，集群 DNS、API server、源站、外网照常；对照 pod 一直能拿到 IMDS；删策略后又都能拿到 |
| `TestControlPlaneTokenIsShortLived` | **FAIL** | **FAIL** | 两个投射的 SA 令牌 `exp - iat` 都是 3600 s，绑定到 pod，TokenReview 接受；**换来的 Entra 访问令牌 `exp - iat` 86700 s（`expires_in` 86399 s）**，超过 3600 s。workload identity webhook 注入了 `AZURE_AUTHORITY_HOST`、`AZURE_CLIENT_ID`、`AZURE_FEDERATED_TOKEN_FILE`、`AZURE_TENANT_ID` |
| `TestSandboxSAHasNoBindings` | **PASS** | **PASS** | 87 个绑定，只有默认的 issuer 发现绑定；13 项敏感访问 0 项允许；0 个长期令牌 Secret；联合凭据扫描 2 个身份、1 条凭据（控制面的，正对照找到）、0 个应用；沙箱 SA 换令牌被拒（AADSTS700213），控制面 SA 换令牌成功；托管身份 0 个角色分配 |

结果 JSON 在 [runs/01](runs/01)、[runs/02](runs/02)，测试输出在 [test-aks-01.log](test-aks-01.log)、[test-aks-02.log](test-aks-02.log)。

## 拆除检查：FAIL（只因 Network Watcher 的 etag）

[down.log](down.log) 的 `teardown-check`：两个组都是 `ResourceGroupNotFound`；没有集群、没有 `project=warden` 资源、没有 `MC_*` 或被 `rg-warden-lab` 管理的组、没有 `warden-lab-*` 身份；角色分配 0 个（查了 3 个演练主体和两个组的作用域）。**但 `network_watcher`：“the Network Watcher that was there before has changed”，`ok: false`。**

只读核对：`NetworkWatcher_swedencentral` 的名字、组、区域、`tags: null`、`provisioningState: Succeeded` 都没变，**只有 etag 变了**（预留时记录的摘要和演练前读到的状态一致）。演练没有对它做任何操作（`down` 只在“原来没有”时才删，这次原来有）。Activity Log 里（00:32Z 查，按资源组和按资源 ID）没有这个 watcher 的写入记录，所以是谁写的没有直接证据；推测是 AKS 建 VNet 时 Azure 的 Network Watcher 自动启用又对已有的 watcher 做了一次写入，这只是推断。没有去改它，也改不回原来的 etag。

因为所有演练资源都已确认不在、重跑 `down` 改变不了 etag，定时器是手动停掉的（[timers-after.txt](timers-after.txt)：0 个），kubeconfig、kubectl 缓存、`az` 在测试 HOME 里写的设备 ID 都已删除。

**复核补充（2026-11-14）：**
- Network Watcher：ARM 的 `changedTime` 还是 2026-10-24，Resource Graph 没有它的变更记录，Activity Log 里它和 `NetworkWatcherRG` 从 11-10 起都没有记录。所以没有属性被改，也没有要恢复的东西。etag 是 Azure 自己刷新的，最可能是 Network Watcher 自动启用对演练新建的 VNet 做了处理：它是因演练而变的，但不是演练的代码改的。演练前只存了状态的摘要，没有存原始记录，“只有 etag 变了”是比较摘要得出的。拆除检查仍按严格标准记 FAIL。
- 订阅作用域：00:11:30（VNet 建好 4 s 后），`AzureContainerService` 对 swedencentral 执行了 `Microsoft.Network/locations/setResourceOwnership/action`，没有建资源。演练的 Activity Log 检查只按资源组和资源 ID 查，没看到这一条。用户账号在两个组以外没有写入。
- 角色分配：AKS 00:11:05 在节点组上建了两个（集群身份的 Contributor 和 `AzureContainerService` 的），00:25:03 随组删除。
- Entra：三个托管身份的服务主体（`warden-lab-aks`、`warden-lab-aks-agentpool`、`warden-lab-controlplane`）00:22–00:28 删除后在 Entra 的已删除项目里，30 天后自动清除，没有手动清除。
- 台账的开始时间记的是下一个整分钟 00:11:00（`aks_drill.py` 的 `start` 取下一分钟，定时器按它排），实际创建从 00:10:35 开始，对费用没有影响。

## 文件

| 文件 | 内容 |
|---|---|
| session-start.log、session-end-reaper.log | 会话开始的 preflight 和 reaper，结束的 reaper |
| plan.txt、up.log、state.json、cluster-summary.json | 计划和估算、`up` 的事件、状态（含登录检查）、集群摘要 |
| test-aks-01.log、test-aks-02.log、runs/ | 三个测试的输出和结果 |
| down.log、timers-after.txt | 拆除、拆除检查，定时器 |
| make-test.log、make-check.log | 演练后的 `make test`、`make check` |
