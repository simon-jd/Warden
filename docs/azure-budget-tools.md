# Warden预算工具

日期：2026-10-23（America/Los_Angeles）。最高约束为[预算原文](../AZURE-BUDGET.md)。所有Azure CLI调用显式绑定预期订阅，并验证Azure for Students/Enabled。预期订阅只从未跟踪的`.cache/azure-subscription`读取（一行订阅ID；本人所有的普通文件，组和其他人不可写，不能是符号链接）；文件缺失、不安全或格式不对时，工具在任何`az`调用之前拒绝。不接受命令行参数或环境变量替换；跟踪的文件里不放真实订阅ID或租户ID，台账`azure-spend.json`（version 2）只记订阅ID的SHA-256。设置（每个工作目录一次）：`az account show --query '{id:id,name:name,state:state}'`确认是Azure for Students且Enabled后，`umask 077; az account show --query id -o tsv > .cache/azure-subscription`。台账（跟踪的文件）里的资源ID只写到订阅之下（`resourceGroups/rg-warden-lab/providers/...`），完整ID只在运行时由订阅文件拼出，不写进任何跟踪的文件；报价和无计量报价的路径只记仓库内相对路径（仓库外的记为`<outside the repository>`，报价本身按SHA256存在quotes目录）。scope固定`rg-warden-lab`（AKS演练另加节点组，见下），不接受其他目标。`rg-mlinfra-westus`永远不可修改/删除。

## 预留

`python3 -B scripts/azure_guard.py reserve plan.json`仅预留估算，不创建资源。默认权威状态`docs/azure-spend.json`，旁边稳定的`.lock`用flock串行化预算检查/更新；fsync＋原子rename先落JSON，再生成Markdown。若第二步失败，已落盘承诺继续计入，修好后运行`render`恢复表格；不得重置台账或再次创建。删除仅填写deleted_at，不退还预算。同一资源ID（大小写不敏感）不能复用。

输入示例为[azure-reservation.example.json](azure-reservation.example.json)，这是离线演示，不是授权创建的计划。它选现有真实Retail API原始响应中General Block Blob v2 Hot LRS的精确meterId/名称/product/SKU/region/单位；数据容量、日志容量各1GB月，读取/写入/列举/其他操作各一个10K计费单位，按完整月保守计容量。实际部署必须重新核对产品配置、全部适用meter与每项数量，不能将示例当默认预算。

每个resource提供完整Azure ID、kind（当前仅storage/vm）、Retail SKU描述、product、region、UTC start/end和components。每个component包含category、原始quote路径、quantity和完整selector（meterId、meterName、serviceName、productName、skuName、armSkuName、armRegionName、unitOfMeasure）。quantity是**所选meter的计费单位数量**，不是美元，也不是未换算的操作次数；例如`10K`的quantity=1表示10,000次。小时meter数量不得小于计划时长。月容量quantity必须包含计划GB和计费月数；为避免月折算误差，示例按整月计入。

工具拒绝缺报价/多匹配/分页未完整/非USD/非Consumption/非base tier/未知单位/类别单位错配/负或非有限值/重复meter/倒置UTC/无法确认region。价格和数量最多18位有效数字、12位小数，避免极端精度输入绕过Decimal边界。原始quote按SHA256保存在`azure-spend.json.quotes/`；台账保存来源URL、获取时间、仓库内相对路径、hash及精确所选meter，表格列hash。测试只用临时台账；`--ledger/--markdown`支持离线演示，它们不能作为未来部署的授权凭据，部署必须读取默认权威路径。

storage必需capacity/operations/logs，VM必需vm/os_disk/public_ip/network/storage_operations/logs；可列多个读/写等operation meter。同一类别与meter不可重复。当前storage仅支持显式product=General Block Blob v2、sku=Hot LRS，所有容量/操作/日志quote必须匹配该平面命名空间产品、Hot层及LRS冗余；容量/日志只接受Hot LRS Data Stored，操作只接受该产品列出的读/写/列举/其他10K meter。不能用Hot LRS报价预留Cool GRS、Files、HNS等不同配置。Key Vault等尚无完整具体价格profile，直接拒绝，需后续带精确配置/报价扩展再审查。当前只支持Storage承载日志；Log Analytics必须有0.1GB/日上限的具体部署审查后再扩展。配置/单位正确不能证明使用量充分，未来开通代码仍须审查并限制实际GB/操作数/保留时间/网络字节，纳入其他适用meter，不能因免费层自动填0。

VM当前只接受sku=Standard_B2s、product=Virtual Machines BS Series、billing=on_demand、Ubuntu2204和Standard_LRS 30–32GiB OS盘声明。计算quote必须为该Linux产品/B2s SKU/B2s meter/Standard_B2s armSku/1 Hour，拒绝Windows、Spot、Low Priority、预留及未知配置。30–32GiB Standard HDD映射S4的32GiB计费档，磁盘quote必须为Standard HDD Managed Disks / S4 LRS / S4 LRS Disk / 1/Month，IO quote必须为该产品的S4 LRS Disk Operations / 10K；不能以S1–S3或Premium的quote替代。VM日志容量固定为上述Hot LRS平面Blob产品。确切配置与quote身份写入台账configuration/components。S4映射依据[官方磁盘容量表](https://learn.microsoft.com/en-us/azure/virtual-machines/disks-types)及[本轮原始Retail API响应](evidence/azure-budget/round-1/s4-retail.json)。

VM预留时读取`az vm list-usage --location REGION --subscription PINNED`，核对Total Regional vCPUs名`cores`上限6及可用量，聚合同批与尚未删除的本项目VM承诺（可能保守重复计入已运行VM）。创建前仍须再次读即时共享配额。没有创建wrapper，镜像来源、子资源ID/标签、网络及日志操作等完整实际消耗由后续部署单独审查。AKS：用户2026-11-13批准一个集群和名字固定的节点资源组`rg-warden-lab-aks-nodes`（不认MC_*），演练上限$2，区域swedencentral（订阅策略“Allowed resource deployment regions”只允许norwayeast、francecentral、denmarkeast、swedencentral、westus）。`reserve`只接受kind `aks`（集群`warden-lab-aks`，配置必须正好是`AKS_PROFILE`，七个计量见`AKS_METERS`）和`identity`（托管身份`warden-lab-controlplane`，以Retail Prices API对Managed Identity的空回答计$0）一起预留；台账里只能有一个AKS集群，演练合计≤$1.80。锁内还会：读订阅的位置策略（`az policy assignment list`，参数在定义里时读定义的默认值），不允许该区域就拒绝；把仓库其他worktree的台账（`git worktree list`）只读地计入上限和“只有一个集群”，同一reservation只算一次（别的worktree的锁拿不到，所以并发预留仍有竞态）；记录该区域Network Watcher的状态（名字、组和摘要）。`down`先删集群再删组，等节点组消失，只有预留时记录“原来没有”的`NetworkWatcher_<区域>`才删；`teardown-check`只读核对两个组、所有演练资源、两个组范围内或演练主体的角色分配都不在了，Network Watcher和预留时一样（或演练造成的那个已删）。节点用Premium SSD OS盘、由演练造成的Network Watcher（演练后删除）用户已于同日批准（`AKS_APPROVALS`）。见[aks-drill.md](aks-drill.md)。禁止的付费服务没有支持的profile，不可借通用resource create绕过约束。

## 清理与会话

`scripts/azure_reaper.sh`开始/结束各调用一次，默认只清已过期、归属标签正确、四标签合法且完整ID位于固定scope的资源。当前时钟不接受CLI或环境覆盖。列表全部验证后，再show所有候选确认ID/标签未变化，最后按唯一完整ID删除；失败则非零退出。标签可能在show与delete之间变化，Azure通用删除接口没有统一条件标签事务，仍需专用项目组和禁止外部并发改标签。

reserve返回四个必需标签，并额外返回warden_session/warden_reservation。结束时用`--end-session SESSION_ID`，仅额外清理ID、reservation、session和完整标签均匹配台账且>$0.02/h的本会话资源；未来TTL默认不会误删。必须在会话退出前执行并检查成功，不提供后台常驻守护。对于台账已知的本会话未删除高价ID，只要完整绑定/归属标签丢失或改变（即使rate被改为0），保留不确定资源、输出unresolved-session-cleanup并在任何删除前非零退出，dry-run也报告未解决；不能报告清理成功。其他会话或无可信台账的未知未来资源保持保留，不能凭名称或标签自称认领。默认只按到期和四标签清理的行为不变。

`make azure-down DRY_RUN=1`检查组完整ID、固定订阅、project/owner和合法四标签。去掉DRY_RUN=1才删除整个本项目组，包括其中资源；本任务不实际执行此删除。ResourceGroupNotFound才是安全no-op，权限/API其他错误都非零。成功删除更新历史删除时间但不减少估算。审计JSON写stdout，不输出token；删除逻辑仅fake az验证。

## 本机

`preflight`计算项目文件实际分配磁盘（包括.cache、.tools、.git；无法遍历则拒绝），当前占用＋声明新增＋下载≤12,000,000,000 bytes。常驻服务**合计**声明峰值≤16,000,000,000 bytes；调用方必须准确传入，默认0用于无服务场景，不是实际进程监控/资源预留。下载>5,000,000,000 bytes时磁盘剩余必须≥50,000,000,000＋下载量。不创建服务、不清未知Docker对象、不全局prune。Warden不需要GPU，未提供GPU wrapper；以后GPU调用仍需共享flock及≤4小时。
