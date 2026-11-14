# 云资源与预算约束（2026-10-23）

本文件的优先级高于五份 plan 里所有涉及云、SaaS、模型 API 和 GPU 的内容。两者冲突时，以本文件为准。

## 1. 授权范围

- **订阅**：Azure for Students。home-ubuntu 上的 `az` 已经登录。
- **总上限**：五个项目合计 **50 美元**。计入 Azure 用量和按量计费的模型 API；免费试用和免费层不计入。
- **各项目上限**：

  | 项目 | 上限 | 主要用途 |
  |---|---|---|
  | PathWatch | 20 美元 | 区域 A 常驻 1 台小 VM，区域 B 临时测量，AKS 和 VPN 演练，Traffic Manager |
  | Warden | 6 美元 | AKS 演练、日志存储、Stratus 的 Azure 技术、Key Vault |
  | Keel | 10 美元 | 商用模型 API。只有你提供 key、或 Azure 上能开通按量模型时才用 |
  | SponsorAtlas | 6 美元 | 临时 Windows VM（Power BI Desktop）、Blob、ADF |
  | Crucible | 0 美元 | 只用本机 RTX 4090 |
  | 预留 | 8 美元 | 估算误差、账单延迟、已有资源组的零星费用 |

- 超出上限，或者不在下文"允许清单"里的付费资源：只写代码，列出前置条件，不开通。
- Crucible 的多机 GPU 部分不在 50 美元内，先暂停，等你单独批预算（见第 3 节）。
- 已有资源组 `rg-mlinfra-westus`（Azure ML 工作区、存储、Key Vault、Log Analytics、App Insights）不属于这五个项目。**不许修改，不许删除。**

## 2. 共用规则（五个项目都适用）

### 2.1 资源组与标签
- 每个项目只在自己的资源组里建资源，命名为 `rg-<project>-lab`（例如 `rg-pathwatch-lab`）。
- 每个资源都打四个标签：
  - `project=<project>`
  - `owner=<project>-lab`
  - `ttl=<UTC 到期时间>`
  - `est_usd_per_hour=<估算>`

### 2.2 先估算再开通
这个订阅的消费 API 返回不了金额：2026-10-23 实测 `az consumption usage list` 的 `pretaxCost` 为空。所以查不到实际花费，只能靠估算台账控制。
- 每个项目维护 `docs/azure-spend.md`，每行一项资源，记录：资源、SKU、区域、单价（来源：Azure Retail Prices API `https://prices.azure.com/api/retail/prices`）、开始时间、计划结束时间、估算金额、实际删除时间。
- 开通任何资源之前，先把它写进台账，并确认：**本项目已估算花费 + 这次估算 ≤ 本项目上限 × 0.9**。不满足就不开通。

### 2.3 时间盒
- 单价 > 0.02 美元/小时的资源，必须设 `ttl`，并在同一个会话里删掉，不许过夜。
- 每个项目都提供：
  - `scripts/azure_reaper.sh`：只删本项目资源组里 ttl 已过期的资源。会话开始和结束时各跑一次。
  - `make azure-down`：删除本项目的整个资源组。

### 2.4 磁盘规格
VM 的 OS 盘一律用 Standard_LRS（HDD），30–32 GB。不用 Premium，因为 Ubuntu 镜像默认会挂 Premium 盘，要显式指定。

### 2.5 配额
每个区域 6 个 vCPU。各项目的演练错开时间。开 VM 前先跑 `az vm list-usage -l <region>` 看余量。

### 2.6 价格参考
westus2，Retail Prices API，2026-10-23 查询：

| 资源 | 单价 |
|---|---|
| B2ats_v2 Linux | 0.0094 美元/小时（spot 0.00846） |
| B1s Linux | 0.0104 美元/小时 |
| B2s Linux / Windows | 0.0416 / 0.0496 美元/小时 |
| D2as_v5 spot | 0.0159 美元/小时 |
| Standard 静态公网 IPv4 | 0.005 美元/小时（约 3.65 美元/月） |
| VPN Gateway VpnGw1 | 0.19 美元/小时，外加每条 S2S 连接 0.015 美元/小时 |
| VPN Gateway Basic | 0.036 美元/小时，不支持 BGP |
| AKS 免费层基础设施计量 | 0.05 美元/小时（按会计费保守计入） |
| Private DNS 区 | 0.5 美元/月 |
| DNS Private Resolver 出站端点 | 180 美元/月 |
| Traffic Manager | DNS 查询 0.54 美元/百万次 |

NAT Gateway（约 0.045 美元/小时）和 Standard 负载均衡（约 0.025 美元/小时）这次没查到，用之前先查实价。

### 2.7 禁止清单
- NAT Gateway
- DNS Private Resolver
- Azure Firewall、Application Gateway、Front Door、Bastion
- Event Hubs
- Sentinel、Defender 付费计划
- Premium / Ultra 磁盘
- 任何 GPU SKU
- Marketplace 付费镜像
- 预留实例、节省计划
- AKS Standard 或 Premium 层
- Log Analytics 大量导入：如果必须用，设每日上限 0.1 GB
- VPN Gateway：唯一的例外是 PathWatch 的 BGP 演练，规则见第 3 节

### 2.8 汇报
- 每个项目在 `docs/STATUS.md` 里每周写一次本项目的累计估算花费。
- 你每周看一次赞助余额：https://www.microsoftazuresponsorships.com/Balance

### 2.9 本机资源（home-ubuntu 共享）

**磁盘**：2026-10-27 用户批准把份额翻倍（Docker 数据已搬到第二块盘 /mnt/dev-data，不计入份额；系统盘剩约 588 GB，已用 64%）。五个项目新增占用合计不超过 196 GB：

| 用途 | 份额 |
|---|---|
| PathWatch | 12 GB |
| Warden | 24 GB |
| Keel | 16 GB |
| SponsorAtlas | 36 GB |
| Crucible | 28 GB |
| 共享模型缓存 | 80 GB |

- 模型统一放 `~/.cache/huggingface`，Keel 和 Crucible 共用，不重复下载。
- 下载超过 5 GB 的东西之前，确认剩余空间 ≥ 50 GB + 文件大小。
- checkpoint 最多保留 2 个。
- 清理 Docker 时只删本项目打了标签的镜像。不许跑全局 `docker system prune`。

**GPU**：只有一张 RTX 4090（24 GB，已有约 2.8 GB 被占用）。
- 所有 GPU 任务都包在 `flock /var/tmp/rtx4090.lock <命令>` 里排队。
- 单次占用不超过 4 小时。
- vLLM 设 `--gpu-memory-utilization 0.80`。
- 推理服务不许常驻：一批评测跑完就停。

**内存**：可用约 87 GB。每个项目的常驻服务合计不超过 16 GB。

**共享路径**：`/var/tmp/rtx4090.lock` 和 `~/.cache/huggingface` 是允许使用的共享路径，不算"修改本项目目录以外的东西"。

### 2.10 需要你手动注册的免费账号
下面这些账号要过邮箱验证，需要你自己注册，然后把凭证放到各项目的 `.env`（不进 git）：

| 账号 | 用途 |
|---|---|
| Snowflake 30 天试用（选 Azure 区域，例如 Azure West US 2） | SponsorAtlas |
| Databricks Free Edition | SponsorAtlas |
| Okta Integrator 免费账号 | Warden：Entra 免费层不支持给自定义应用做 SCIM 开通时才需要 |
| Slack 开发 workspace、Google OAuth 测试应用、Salesforce Developer Edition、GitHub 测试 org | Keel |
| Tableau Public | SponsorAtlas |
| 商用模型 API key（OpenAI 或 Anthropic，可选） | Keel：花费计入 Keel 的 10 美元 |

## 3. 各项目的替换方案

### PathWatch（上限 20 美元）

**总体变化**：AWS + GCP 改为 **Azure 两个区域 + home-ubuntu（充当本地机房）**。GCP/AWS 的 gap 暂时不补，简历上写 Azure 加混合云。

- **Task 1**：
  - Terraform state 改放 Azure Storage（azurerm backend，用 blob lease 加锁）。
  - CI 的 OIDC 改为 Entra ID 工作负载身份联合（federated credential）。
  - GitHub 上还没有仓库，这一项做到"本地可验证 + 写明前置条件"即可。
- **Task 2**：VNet、子网、NSG、路由表。不用 NAT Gateway，VM 直接挂 Standard 公网 IP 出网。
- **Task 3**：
  - 跨站互联改为 **WireGuard + FRR（BGP + BFD）**。区域 A 的 VM 充当 NVA：网卡开 IP forwarding，UDR 指向它，再和 home-ubuntu 互联。
  - 演练改成测量 BGP 计时器 vs BFD 的收敛时间。
  - 可选：VpnGw1 的 VNet-to-VNet BGP 演练。每次不超过 4 小时，最多 2 次。两个网关加连接约 0.41 美元/小时。
- **Task 4**：
  - Azure Private DNS 区，加上 VM 上的 CoreDNS 转发，**不用 Private Resolver**。
  - 公网故障切换用 Traffic Manager（priority 路由）和 `*.trafficmanager.net` 域名，不用买域名。
- **Task 10**：
  - 探测点：区域 A 常驻 1 台 B2ats_v2（5 周）+ home-ubuntu 常驻 + 区域 B 按"测量活动"临时开（每次 ≤ 48 小时，最多 2 次）。
  - ClickHouse 和 ingest 放在 home-ubuntu。
  - SLO 改为"N 个探针里至少 N−1 个有数据"。
- **Task 14–15**：
  - 常驻集群用 home-ubuntu 上的 k3s。
  - AKS 只在演练时开：免费层 + 1 个 B2s 节点，OS 盘 30 GB，演练完立即删。
  - Argo CD 同时管理 k3s 和 AKS。
  - 漂移检测改成 home-ubuntu 上的 cron 跑 `terraform plan`。

**估算**：

| 项 | 计算 | 金额 |
|---|---|---|
| 区域 A 常驻 | VM + IP + 盘，约 0.0164 美元/小时 × 840 小时 | 约 13.8 美元 |
| 区域 B 测量活动 | 2 × 48 小时 | 约 1.6 美元 |
| AKS 演练 | 约 0.13 美元/小时 × 8 小时 | 约 1.0 美元 |
| VPN 演练 | 约 0.41 美元/小时 × 3 小时 | 约 1.2 美元 |
| Traffic Manager | — | 约 1 美元 |
| **合计** | | **约 18.6 美元** |

如果你确认订阅里有免费服务（B2ats_v2 每月 750 小时），VM 这部分会变成 0，可以延长常驻时间或者多开一个区域。

### Warden（上限 6 美元）

- **gVisor**：在 home-ubuntu 上用 k3s + runsc RuntimeClass，替代 GKE Sandbox。
- **Firecracker**：直接跑在 home-ubuntu 上（`/dev/kvm` 可用），不需要嵌套虚拟化的 VM。
- **工作负载身份**：
  - AKS workload identity，只在演练时开；
  - 另外，把 k3s 的 service account issuer 发布到 Azure Blob 静态网站，和 Entra 做身份联合。这一项展示的是"自建集群到云"的身份联合。
- **IdP**：
  - OIDC 用 Entra ID 免费层。
  - SCIM：如果 Entra 免费层不支持给自定义应用做 SCIM 开通，就用 Okta Integrator 免费账号，或者 SCIM 校验客户端。
- **Vault**：放在 home-ubuntu。云 secrets engine 改用 Azure（动态 service principal），替代 AWS/GCP。
- **日志**：
  - CloudTrail / GCP 审计改为 Azure Activity Log，用 REST 轮询拉取。
  - AKS 审计日志：演练期间开诊断设置，写到存储账户。
  - VNet flow logs 写到存储。
  - 不开 Event Hubs。OpenSearch 放在 home-ubuntu。
- **Stratus Red Team**：用 Azure 和 Kubernetes 的技术，每个跑完立即清理。
- **估算**：AKS 演练约 2 美元 + 存储和日志约 0.5 美元 + Stratus 约 0.5 美元 + 其他约 0.2 美元，**合计约 3 美元**。

### Keel（上限 10 美元）

- **默认模型**：在 RTX 4090 上用 vLLM 跑开源模型，比如 Qwen3-8B、Qwen2.5-14B-Instruct-AWQ。τ²-bench 的用户模拟器也用本地模型。
- **商用模型**：只有你提供 key，或者 Azure 上能开通按量模型时才用，花费计入这 10 美元。对商用模型，评测只跑 1 个 seed 和一个子集。
- **MCP 集成**：依赖第 2.10 节那些开发者沙箱账号。账号没到位之前，先用录制好的 fixture 把测试跑通。

### SponsorAtlas（上限 6 美元）

- **Snowflake**：用 30 天试用。试用到期后，把 marts 导出成 Parquet 存到 Azure Blob，用 DuckDB 提供查询。站点和看板都切到这个只读副本。
- **Databricks**：用 Free Edition。
- **Airbyte、Airflow、OpenMetadata、Cube**：放在 home-ubuntu，注意 36 GB 的磁盘份额。
- **部署**：
  - 前端用 Azure Static Web Apps 免费层。
  - Cube API 用 Azure Container Apps 的消耗计划，最小副本设为 0，落在每月免费额度内。
- **Power BI**：Power BI Desktop 只有 Windows 版。优先用 NEU 账号的 Power BI 网页版来做报表；网页版不行的话，临时开一台 Windows VM（B2s），总共不超过 10 小时。
- **Task 16（Azure 复刻）升级为正式任务**：ADF + Fabric 试用（前提是 NEU 租户允许开 Fabric 试用）。按量费用计入本项目。
- **估算**：Windows VM 约 0.6 美元 + Blob 约 0.2 美元 + ADF 约 1 美元，**合计约 2 美元**。

### Crucible（上限 0 美元）

50 美元以内不租 GPU，而且 Azure for Students 本身没有 GPU 配额。

**用 RTX 4090 做的部分**：
- **W2（异步 GRPO）**：
  - 模型改用 Qwen2.5-0.5B 或 1.5B-Instruct；
  - 在一张卡上让 rollout 和 learner 分时、分显存运行；
  - 照样实现 policy 版本号、有界陈旧度和 verifier；
  - 留出集用 GSM8K 和 MATH-500 的子集。
- **W4（custom op）**：照原计划做。
- **W3（推理）**：
  - 单卡基线：Qwen3-8B，或 Qwen3-30B-A3B 的 4-bit 版本；
  - 回放器、路由器、扩缩容逻辑；
  - FP8 vs BF16 对比（4090 支持 FP8）；
  - EAGLE-3 改用较小的目标模型。

**暂停、等你批 GPU 预算的部分**：
- W1 全部：多机 burn-in、扩展实验、故障注入；
- W3 里的 P/D 分离和跨节点部署；
- 235B 模型。

这些部分的代码和单元测试照常写，但证据里要标明"未在真实多机上验证"。等你批了预算，再按原计划的 Task 1–5、13 租卡执行。

## 4. 一次性设置

- **资源组**：各项目在第一次需要云资源时自己创建，命名和标签按第 2.1 节。
- **订阅级预算提醒（可选兜底，需要你同意后才设置）**：
  - 这个订阅的 API 返回不了费用金额，预算提醒可能不会触发，所以只能当兜底。
  - 设置方法：用 `az rest` 调用 `Microsoft.Consumption/budgets`，金额 50，按月，在实际花费达到 50% / 80% / 100% 时发邮件给你。
- **每周检查**：你看一次赞助余额页面；五个项目汇报各自的估算台账。
