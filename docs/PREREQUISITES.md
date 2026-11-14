# 当前部署与验收前置条件

更新：2026-10-23。最高约束为[AZURE-BUDGET.md](../AZURE-BUDGET.md)，替换原计划AWS/GCP/GKE/EKS资源与接口。原功能、安全默认值和测量数量保留；不要求新开AWS/GCP账号。

## 已核实的本机条件

当前实际宿主就是home-ubuntu（postedism-ubuntu-system-selfuse），不是另一台需要SSH的机器。sandbox隐藏部分设备/配置；require_escalated只读检查确认：containerd2.4.2、runc1.5.2、libseccomp2.6.0、runc-v2 shim已装，/dev/kvm对当前用户可写，az已登录Azure for Students且Enabled。sudo -n需交互认证；不读取密码、不修改sudo配置。Docker组可用，专用固定probe入口已独立审查并完成实测；后续新实验入口仍须按同一流程审查。

- runc：专用containerd daemon/socket、namespace warden-lab及cgroup v2 cpu/memory/pids delegation；不用既有共享daemon。[真实7项conformance已全部PASS/noSKIP](evidence/task-2/lab-live/README.md)，[API→PG→runc调度、丢失ACK两阶段退休及精确回收已真实PASS](evidence/task-2/api-runtime/live/README.md)，生产OIDC仍待Task6。
- gVisor：专用k3s的runsc RuntimeClass、真实pids128/CPU/内存约束和默认拒绝网络。若复用PathWatch k3s，必须通过公开配置交接namespace、RuntimeClass、kubeconfig和网络能力，不改相邻项目私有文件或共享服务配置。
- 当前host只读检查未发现k3s/kubectl/runsc/runsc-shim/cilium/Firecracker/jailer；没有安装或修改host服务。K3s需[明确配置自定义runtime](https://docs.k3s.io/advanced)，不能假定runsc自动识别；[runsc官方flags](https://github.com/google/gvisor/blob/master/runsc/config/flags.go)中oci-seccomp默认false，后续须显式启用并实测。宿主Sentry的pids计数不等于guest虚拟任务限额；须固定发行版并证明实际fork限制及可信计数。
- Firecracker：本机KVM、匹配的jailer/Firecracker/kernel校验digest、rootfs构建工具、快照路径。无需开嵌套虚拟化云VM。默认512MiB，128MiB只作显式测量。
- 新增磁盘≤24GB、常驻服务合计≤16GB；大型下载空间检查、仅清理本项目有归属证明的Docker资源。Warden无需GPU；如使用必须flock共享锁且≤4h。

## Azure预算与权限

- 仅rg-warden-lab、四tags、累计预估门槛$5.40，先Retail API单价与[台账](azure-spend.md)，再开通。rg-mlinfra-westus绝不修改/删除。现rg-warden-lab查询返回不存在，未创建本项目Azure资源。
- AKS仅短期演练：Free层、Standard_LRS HDD 30–32GB、同会话销毁高价资源；计入全部节点/盘/IP/适用网络/日志成本。B2s是普通VM报价，不能当已验证的AKS system-pool方案；[官方system-pool限制](https://learn.microsoft.com/en-us/azure/aks/use-system-pools)排除B系列，并列出节点大小/数量要求。后续须核对具体API/版本/非生产配置与共享6-vCPU配额，不能擅自提高配额或改SKU开通。开VM前查region实时余量，不因账单API无金额跳过估算。
- [AKS节点组限制](evidence/azure/pricing.md)：服务会另建node resource group，当前仅一个允许RG的范围尚不能容纳。[当前官方FAQ](https://learn.microsoft.com/en-us/azure/aks/faq#can-i-provide-my-own-name-for-the-aks-node-resource-group)仍说明node RG由服务创建且不能指定已有RG；改自定义名字并不消除第二组。实际创建保持门禁，先完成代码/估算，后续解决确切范围授权；不得擅自建MC_*。
- 2026-10-24补充核验OS盘前置条件：[AKS CLI](https://learn.microsoft.com/en-us/cli/azure/aks?view=azure-cli-latest#az-aks-create)的`--node-osdisk-type`仅选择`Managed`或`Ephemeral`，`--node-osdisk-size`最小30GiB；这些参数不等于显式选择Standard_LRS。[当前ARM schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters)也未列出agent-pool的storageAccountType字段，而[AKS存储默认说明](https://learn.microsoft.com/en-us/azure/aks/best-practices-performance-scale)描述ephemeral/Premium SSD/Standard SSD默认路径。因此目前尚未建立符合本项目HDD要求的显式AKS OS盘配置；这是部署仍受门禁的推论，不是实测API拒绝。不能把HDD的PVC/data盘StorageClass当成OS盘设置，也不能擅自换SSD或改托管VMSS绕过。后续具体部署方案须证明支持的合规路径，或在代码/完整报价/清理方案均可审查后提出确切例外需求。
- 不启用NAT Gateway、Event Hubs、收费安全计划或其他禁止清单项目。订阅级预算提醒需另行同意，当前不设置。

## 身份与Vault

- Entra免费OIDC：专用lab应用issuer/audience/client ID、JWKS、tenant/user映射、允许回调。短期令牌不输出至日志或git；k3s projected SA token与Entra做federation，OIDC metadata/JWKS按预算发布Blob静态网站。
- AKS workload identity只在演练时验证；k3s到Entra联合可独立完成。sandbox SA不得存在联邦凭证/RBAC云权限；控制面仅最小scope。
- SCIM免费层不可用时按新约束使用Okta Integrator（邮箱验证需用户）或SCIM校验客户端；准确区分协议验证与真实IdP分配/取消。
- SCIM方向：Warden提供自己的`/scim/v2/Users`端点，由IdP或校验客户端调用。[Entra SCIM Provisioning API](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/enable-scim-api)是Entra接收外部用户的另一项服务，要求P1及按调用计费；它不是本项目SCIM端点的前置条件，不开通该付费附加项。
- Vault本机raft HA/Kubernetes auth/database动态角色/Azure动态service principal engine；需最小Azure/Entra权限及无长期root云凭证的认证链。[Azure secrets engine的plugin WIF](https://developer.hashicorp.com/vault/docs/secrets/azure)标有Enterprise license要求；[Azure auth method的aks_wif](https://developer.hashicorp.com/vault/docs/auth/azure)属于另一组件，不能互相当作支持证据。[当前Community engine源码](https://github.com/hashicorp/vault-plugin-secrets-azure/blob/main/provider.go)的getTokenCredential明确只选client secret、Vault内部plugin identity或managed identity，没有直接读取Kubernetes federated token文件的分支；仅挂AZURE_FEDERATED_TOKEN_FILE不能作为通过证据。Task8须固定实际版本，验证免费可用的完整认证链与TTL，不购买license、不加入长期bootstrap client_secret；DB动态密钥等独立工作可继续。
- 零长期密钥审计需完整分页的Entra/app credential与相关身份配置读取权限；无权限/错误不写0。数据库TTL1分钟/撤销测试需真实数据库。JIT/响应审批需要两个有效身份，来自认证上下文。

## 网络、日志、检测与供应链

- metadata阻断按Azure IMDS地址/名称及实际k3s/AKS网络验证；Cilium/出口代理通过公开配置对接；none默认不得出网。Entra/Blob只允许控制面所需出口，sandbox不继承。
- Azure Activity Log REST只读拉取、短期AKS诊断审计到Blob、VNet flow logs到Blob、k3s审计、Tetragon、Warden审计；Vector/OpenSearch放本机并限制内存/索引/缓存/磁盘。不开Event Hubs；如确需Log Analytics，日上限0.1GB且先估算。
- Stratus仅Azure/Kubernetes专用lab技术，逐项成本/资源/清理记录；Atomic Linux与攻击语料只进隔离runtime。连续7天真实正常流量、告警与误报判定仍必须采集，不用fixture替代。
- GitHub授权仓库、受保护workflow/ref、OCI目标和Actions OIDC/attestation权限尚未提供；本地实现与测试继续，未经授权不push/发布仓库或镜像。
- EPSS/CISA KEV可读源、真实漏洞首次发现/关闭历史；没有实际历史则修复中位时长未知。
