# Task 7 的 AKS 演练

状态：**2026-11-14 00:11–00:29 UTC 在 swedencentral 跑过一次，已拆除**（[实测记录](evidence/task-7/aks-drill-20261113/live/README.md)）。`TestSandboxCannotReachMetadata` PASS 53/53（runs/02；runs/01 因测试按大小写比较区域名 FAIL）；`TestControlPlaneTokenIsShortLived` **FAIL**：SA 令牌 3600 s，但换来的 Entra 访问令牌 86700 s；`TestSandboxSAHasNoBindings` PASS。拆除检查 **FAIL**：演练资源全部不在，但 `NetworkWatcher_swedencentral` 的 etag 变了（其他字段不变；演练的代码没有对它做任何操作，但它是因为演练才变的，见实测记录的复核补充）。台账承诺 $0.98，按集群存在的 18 分钟估算约 $0.05（上限约 $0.27）。

> **跑演练的人要全程盯着，最后亲手执行 `make aks-drill-down`，并确认它最后打印的 `teardown-check` 是 `"ok": true`。** 定时器和 reaper 只是兜底：它们都要 Azure CLI 的登录还有效，home-ubuntu 重启会丢掉定时器（见“剩下的风险”）。

## 批准范围和用户的决定

用户 2026-11-13 批准：一个 AKS 集群；除 `rg-warden-lab` 外，允许 AKS 托管的节点资源组，名字固定为 `rg-warden-lab-aks-nodes`；这次演练上限 $2，在 Warden 的 $6 之内。同日又决定：

- 节点 OS 盘可以是 Premium SSD P4（这次演练例外于 [AZURE-BUDGET.md](../AZURE-BUDGET.md) 2.7）。原因：这个订阅能给节点用的只有 B 系列 v2，它们不支持临时 OS 盘，AKS 的托管 OS 盘用 Premium SSD，`az aks create` 没有选盘 SKU 的参数。
- 允许 Azure 随集群的 VNet 自动建 Network Watcher，前提是演练造成的那个演练后删掉；不是演练造成的不许动。

[AZURE-BUDGET.md](../AZURE-BUDGET.md) 的其他规则不变：四个标签、先记台账再开通、在 guard 的锁里检查、同一会话内删除、先查配额、不碰 `rg-mlinfra-westus` 和别的项目、不设订阅级提醒。

## 区域：swedencentral

订阅有一条 deny 的策略 “Allowed resource deployment regions”（`sys.regionrestriction`），只允许 norwayeast、francecentral、denmarkeast、swedencentral、westus；westus2 不行。演练改在 **swedencentral**：`Standard_B2as_v2` 没有限制，`cores` 0/6，`standardBasv2Family` 0/10，AKS 有 1.36.5。swedencentral 已有 `NetworkWatcher_swedencentral`（在 `NetworkWatcherRG`，没有标签，不是 Warden 的），所以不会自动新建；演练绝不修改或删除它，拆除检查要证明它和演练前一样。

## guard 怎么管（`scripts/azure_guard.py`）

- 只认集群 `warden-lab-aks`、节点组 `rg-warden-lab-aks-nodes`（`managedBy` 必须是这个集群，四个标签齐全）和托管身份 `warden-lab-controlplane`。`MC_*` 或别的节点组一律拒绝。
- 集群配置必须正好是 `AKS_PROFILE`：免费层、Kubernetes 1.36.5、`--dns-name-prefix warden-lab-aks`（CLI 的默认前缀里有订阅 ID 的一段）、1 个 `Standard_B2as_v2` 节点、托管 OS 盘 30 GiB、Azure CNI overlay + Cilium 数据面、Standard LB 出站（1 个出站 IP）、OIDC issuer 和 workload identity、不开任何 add-on、不接 Log Analytics、没有诊断设置、不开 ACNS、关掉 CSI 驱动和 SSH、不自动升级。`scripts/aks_drill.py` 用同一个 `AKS_PROFILE` 生成 `az aks create`，建好后把 Azure 返回的集群逐项比对，不一致就立刻拆。
- 集群和身份只能作为一批预留；所有 Warden 台账里永远只能有一个 AKS 集群；演练合计 ≤ $1.80（$2 的 90%），整个项目仍 ≤ $5.40。
- **其他 worktree 的台账也算。** 台账和锁是每个 worktree 一份。预留时 guard 用 `git worktree list` 找到仓库的其他 worktree，只读地读它们的 `docs/azure-spend.json`（版本 1 和 2 都认；订阅或组不对就拒绝），同一个 reservation 只算一次，一起计入 $5.40、$1.80 和“只有一个集群”。别的 worktree 的锁拿不到（拿锁要在它们的目录里建锁文件），所以两个 worktree 同时预留仍有竞态；这次演练只在 `aks-drill` 一个 worktree 里预留。
- **锁内的只读检查：** 订阅里所有生效的位置策略（`az policy assignment list --disable-scope-strict-match`；赋值没给 `listOfAllowedLocations` 时读策略定义的默认值）都允许 swedencentral，否则拒绝；`cores`（上限必须是 6）和 `standardBasv2Family` 够 2 个 vCPU；节点组还不存在；Defender 的 `Containers`、`KubernetesService` 是 Free；记下 swedencentral 的 Network Watcher 状态（名字、组，以及 ID、标签、状态、etag 的摘要）。
- **台账里没有订阅 ID 和本机路径。** 资源 ID 只写到订阅之下（`resourceGroups/rg-warden-lab/providers/...`），完整 ID 只在运行时由 `.cache/azure-subscription` 拼出；报价路径只写仓库内相对路径。含 ID 的东西（集群和身份的原始回答、演练的主体 ID、kubeconfig）只放在 `~/Desktop/warden-private-scratch/aks-drill/`。
- `down`：先删集群（AKS 随之删节点组），再删 `rg-warden-lab`，等节点组消失（最多 30 分钟）。只有预留时记录“这个区域原来没有 Network Watcher”，它才删 `NetworkWatcherRG` 里的 `NetworkWatcher_<区域>`；swedencentral 原来有，所以永远不删。

## 会创建什么、多少钱

单价来自 Retail Prices API 的 swedencentral 快照（2026-11-13 23:58Z，[prices/aks-drill-20261113-swedencentral](evidence/azure/prices/aks-drill-20261113-swedencentral)，`scripts/aks_drill.py prices`；Load Balancer 的计量是 Global）。台账预留到最后一个定时器之后 35 分钟：5 小时 15 分。

| 资源（所在组） | SKU / 计量 | 单价 | 计划 3 h | 硬停止 4 h | 最后一次重试 4 h 40 min | 预留 5.25 h |
|---|---|---|---|---|---|---|
| AKS 集群 `warden-lab-aks`（`rg-warden-lab`） | 免费层；`FreeTierInfrastructureCost Uptime SLA` 按预算文件保守计入 | $0.05/h | $0.150 | $0.200 | $0.233 | $0.263 |
| 节点 VMSS，1 台（节点组） | `Standard_B2as_v2` Linux 按需 | $0.0778/h | $0.233 | $0.311 | $0.363 | $0.408 |
| 节点 OS 盘（节点组） | Premium SSD P4 LRS（30 GiB） | $5.8072/月 | $0.024 | $0.032 | $0.037 | $0.042 |
| Standard 负载均衡（节点组） | 前 5 条规则（AKS 建 1 条出站规则） | $0.025/h | $0.075 | $0.100 | $0.117 | $0.131 |
| 同上，处理的数据 | `Standard Data Processed`，按 4 GB | $0.005/GB | $0.020 | $0.020 | $0.020 | $0.020 |
| 出站公网 IP（节点组） | Standard IPv4 静态 | $0.005/h | $0.015 | $0.020 | $0.023 | $0.026 |
| 出站流量 | `Standard Data Transfer Out` 第一个付费档（每月 100 GB 的 $0 额度全订阅共用，不算），按 1 GB | $0.087/GB | $0.087 | $0.087 | $0.087 | $0.087 |
| 托管身份 `warden-lab-controlplane` 和它的联合凭据（`rg-warden-lab`） | Retail Prices API 没有 Managed Identity 的计量（快照 0 条） | $0 | 0 | 0 | 0 | 0 |
| **合计** | | | **$0.60** | **$0.77** | **$0.88** | **$0.98** |

AKS 自己还会在节点组里建 VNet、NSG、kubelet 和 add-on 的托管身份，可能还有路由表，都不计费。AKS 还会建角色分配：在节点组上给集群身份一个 Contributor，另一个给 `AzureContainerService`（2026-11-14 实测 00:11:05 建，00:25:03 随组删除）；并在订阅作用域对 swedencentral 执行一次 `Microsoft.Network/locations/setResourceOwnership/action`（00:11:30，调用者是 `AzureContainerService`，不建资源）。不建：Log Analytics、诊断设置、ACR、NAT Gateway、存储账户、Key Vault、任何 add-on。四个标签：集群的 `--tags` 由 AKS 复制到节点组和它建的 LB、IP、NSG、VNet、托管身份，`--nodepool-tags` 到 VMSS。集群建好后，`up` 先像 `down` 和 `reap` 那样检查节点组（名字、`managedBy`、四个标签），缺的标签补上，别的不对就立刻拆；最后逐个检查两个组里的每个资源，缺标签的补上集群的值，仍有缺的就拆除。这些资源上的 `est_usd_per_hour` 是整个集群的小时估算，不是各自的。

## 硬停止

- **不过夜：** 开始、硬停止（+4 h）、最后一次重试（+4 h 40 min）和 ttl（+5 h 15 min）都要在本地同一天，否则 `up` 什么都不做。
- **先查登录：** 在装定时器和预留之前，`up` 确认现在能拿到 Resource Manager 的令牌，也能拿到 Microsoft Graph 的令牌（要用刷新令牌），两者都还有 5 分钟以上。只读过期时间，不读令牌本身。
- **定时器：** 然后在 home-ubuntu 上建三个 systemd 用户定时器 `warden-aks-hardstop-<session>-{0,20,40}m`，在硬停止和之后 20、40 分钟各跑一次 `scripts/aks_drill.py down`。用户开了 lingering，定时器在登出后仍在；任何一个装不上，就不预留、不创建。已经删完时，后面的 `down` 只是空操作。
- `up` 任何一步失败都立刻 `down`。每个实测开始前检查离硬停止至少 15 分钟，否则不跑。资源的 `ttl` 标签是开始后 5 小时 15 分，过了以后 `scripts/azure_reaper.sh` 也会删集群。
- 按估算，到硬停止约 $0.77，到最后一次重试约 $0.88；之后每多一小时约 $0.17（不计按 GB 的部分），从最后一次重试起离 $2 还有约 6.5 小时。

## 剩下的风险（如实）

- **重启会丢掉定时器。** 它们是临时单元，home-ubuntu 重启后就没了，只剩 reaper（要有人跑）和手动 `make aks-drill-down`。
- **登录失效会让所有自动拆除都失败。** 定时器、reaper 和 `down` 都用 home-ubuntu 上的 `az` 登录。`up` 只能证明开始时能拿到令牌、能刷新；CLI 报不出刷新令牌还能用多久，也看不到学校租户的条件访问（例如登录频率）会不会在窗口内要求重新登录。登录一旦失效，只能有人重新 `az login` 再 `make aks-drill-down`。
- **所以跑演练的人要在场**，看 `make aks-drill-status`，测试完就手动 `make aks-drill-down`，并确认 `teardown-check` 通过。
- 拆完后集群的 OIDC issuer 不再能用，但 Entra 里给托管身份签过的访问令牌在 `exp` 之前仍然有效（没有角色，什么也做不了）。

## 拆除与验证

`make aks-drill-down`（定时器调用的也是它）：guard 的 `down`，然后 `teardown-check`（也可以单独 `make azure-teardown-check`），只读，以下全部成立才通过：

- `rg-warden-lab` 和 `rg-warden-lab-aks-nodes` 都是 `ResourceGroupNotFound`；
- `az aks list` 里没有 `warden-lab-aks`，也没有在这两个组里或用这个节点组的集群；
- `az resource list --tag project=warden` 为空；`az group list` 里没有这两个组、没有含 `warden` 的 `MC_*` 组、没有 `managedBy` 指向 `rg-warden-lab` 的组；`az identity list` 里没有 `warden-lab-*`；
- `az role assignment list --all` 里没有作用域在这两个组内的角色分配，也没有属于演练主体（托管身份、集群身份、kubelet 和 add-on 身份，`up` 记在私有目录）的；
- swedencentral 的 Network Watcher 和预留时记录的一样（名字、组、摘要都不变）；如果预留时这个区域没有，那它现在也必须没有（`down` 已删掉演练造成的那个）。

通过后才停掉定时器、删除本地 kubeconfig。

## 运行（再次审查、用户同意开通之后）

```sh
scripts/restore-tools.sh kubectl              # 已下载：v1.36.5，按 SHA-256 核对
az account show                               # 确认是 Azure for Students；登录太旧就先 az login
make azure-preflight; scripts/azure_reaper.sh  # 会话开始
make aks-drill-plan                            # 离线：预留计划和估算
make aks-drill-up                              # 先查登录、装硬停止，再预留、创建
make test-aks AKS_OUT=docs/evidence/task-7/aks-drill-<date>/runs/01
make aks-drill-status                          # 剩余时间、目前估算
make aks-drill-down                            # 手动拆除 + teardown-check（要看到 "ok": true）
scripts/azure_reaper.sh                        # 会话结束
```

运行时写到 `.cache/aks-drill/`（计划、状态、不含 ID 的集群摘要）和 `~/Desktop/warden-private-scratch/aks-drill/`（kubeconfig、含 ID 的原始回答、演练主体、Entra 令牌的原始 claims；从不写令牌本身）。

## 三个测试

`make test-aks` 逐个跑，一个失败不影响其他两个。跟踪的证据里没有 API server 的 FQDN、issuer 或非公开的 `aud`：issuer 写成占位符，除 `api://AzureADTokenExchange` 和 Resource Manager 以外的受众只写 SHA-256 摘要。Resource Manager 令牌的 `aud` 实际是不带结尾斜杠的 `https://management.azure.com`，和白名单对不上，所以这次也只写了摘要。

- **`TestSandboxCannotReachMetadata`**（`controlplane/internal/aksdrill`）：真实 Azure IMDS。三个探针 pod：沙箱（`warden.dev/sandbox=true`）、带出口代理标签的替身（`warden-system`、`app.kubernetes.io/name=warden-egress`，策略的第二份文档选它；AKS 上不跑 Envoy）、不带沙箱标签的对照；另有一个集群内的 busybox 源站。探针对 IMDS 只能发一种请求：实例所在区域（`/metadata/instance/compute/location`，`Metadata: true`），不能请求令牌端点。没有策略时三个都拿到 `swedencentral`，沙箱和代理替身直接问 168.63.129.16 上的 Azure DNS 也有回答（正对照）；只应用 `deny-metadata.yaml` 时这两个连不上 IMDS、168.63.129.16 没有回答，而集群 DNS、API server、源站、外网都照常（策略只拒绝），对照 pod 仍拿到 IMDS；删掉策略后又都能拿到。还记录 API server 存下来的策略是否保留了 `enableDefaultDeny: false`（CRD 不认这个字段就会丢掉它，那样只有 deny 的策略会把端点放进默认拒绝）。
- **`TestControlPlaneTokenIsShortLived`**（`runtimes/conformance`，AKS 目标）：用 `identity/kubernetes/controlplane.json` 的 pod 配置，加 AKS workload identity 的 pod 标签和 SA 上的 client-id 注解。逐个读挂载的令牌，记录 `exp - iat`；把受众为 `api://AzureADTokenExchange` 的那个经联合凭据换成 Entra 访问令牌（Resource Manager；身份没有任何角色），也记录 `exp - iat`。**任何一个超过 3600 s 就 FAIL**，照实记录；托管身份的 Entra 令牌很可能是 24 小时左右。
- **`TestSandboxSAHasNoBindings`**（同上）：原有的 RBAC、注解、长期令牌 Secret、敏感访问检查和植入绑定的正对照；AKS 上再加：订阅里所有用户分配托管身份和用户自己拥有的所有应用的联合凭据（只读扫描，也会读到别的项目的身份，只读不改），带这个集群 issuer 的不能有沙箱命名空间的 subject，同一扫描必须找到控制面那一条（正对照）；沙箱 SA 的令牌拿去换 Entra 令牌必须被拒（AADSTS70021 或 700213），控制面 SA 的必须成功（正对照）；托管身份的角色分配数（演练不给任何角色）。

## 和 k3s Cilium lab 的不同

- AKS 没有 gVisor，沙箱是普通 runc pod，只靠标签被策略选中。
- 不应用 `default-deny.yaml` 和 `egress-proxy.yaml`：里面的 DNS 规则要 Cilium 的 L7 DNS 代理，AKS 上那属于 Advanced Container Networking Services（付费 add-on）。
- Azure 的 IMDS 没有主机名形式，只测地址；代理那条路用带代理标签的替身直接连 IMDS 来测（策略管的是端点，不是 Envoy）。
- Cilium 版本由 AKS 决定，测试会记录。

## 文件

| 路径 | 内容 |
|---|---|
| `scripts/azure_guard.py`、`scripts/test_azure_guard.py` | AKS 的预留和前置检查、节点组、`down`、`teardown-check`、其他 worktree 的台账 |
| `scripts/aks_drill.py`、`scripts/test_aks_drill.py` | 价格快照、计划、`up`/`env`/`status`/`down`；离线测试用假的 az、git、systemd-run、systemctl、kubectl |
| `controlplane/internal/aksdrill` | `TestSandboxCannotReachMetadata`（AKS）和它的 pod、策略帮手 |
| `runtimes/conformance/identity_test.go` | 两个身份测试的 AKS 目标 |
| `identity/workload` | 服务账户令牌换 Entra 令牌、读 claims |
| `runtimes/conformance/guest/net.go` | 探针的 `imds` 用例 |
| `scripts/restore-tools.sh kubectl` | kubectl v1.36.5 |
| [evidence/task-7/aks-drill-20261113](evidence/task-7/aks-drill-20261113) | 代码改动的 RED/GREEN 输出 |
