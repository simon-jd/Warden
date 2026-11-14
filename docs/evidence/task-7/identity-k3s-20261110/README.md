# Task 7 本机部分：k3s lab 上的身份检查（2026-11-10，home-ubuntu）

在 Task 3 的 k3s lab 上跑了 Task 7 的两个本机测试，`TestControlPlaneTokenIsShortLived` 和 `TestSandboxSAHasNoBindings`。lab 用的是原来的 bridge CNI，没有装 Cilium。两个测试第一次都 FAIL，之后都 PASS，但原因不同：`TestControlPlaneTokenIsShortLived` 是改了控制面的 pod 配置（自己投射 3600 s 的令牌）以后通过的；`TestSandboxSAHasNoBindings` 通过是因为改了测试，系统没有改：测试改成接受 Kubernetes 默认的 issuer 发现绑定（每次核对它的角色），并修了写错的正对照（见下）。`policies/cilium/deny-metadata.yaml` 写好了，有离线检查，但没有应用到集群；`TestSandboxCannotReachMetadata` 没有写，原因见下（要 Cilium，阻塞 11）。和 Entra 的联合没有做（要用户）。

## 环境

- worktree `~/Desktop/Warden-task3`，分支 `task3-gvisor`。运行时的源码是 `1a92833` 加上和这些证据一起提交的改动。
- k3s v1.36.5+k3s1（[k3s-version.txt](k3s-version.txt)），节点和 Task 3 一样：单节点特权容器、`--internal` 网络、bridge CNI、没有 kube-proxy 和 CoreDNS。`make test-identity IDENTITY_REUSE=1`，跑在 `scripts/k3s_gvisor_lab.sh up` 起好的 lab 上（[up.log](up.log)）。
- 控制面镜像不在 lab 里。测试按 [identity/kubernetes/controlplane.json](../../../../identity/kubernetes/controlplane.json) 里 Deployment 的 pod 模板建 pod，只把镜像换成 lab 的 pause，其余照原样。令牌从节点上 kubelet 挂载的文件读（`/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/...`），只解码 claims，令牌本身没有写进任何文件。

## 运行

| 运行 | 时间（PST） | 内容 | 结果 |
|---|---|---|---|
| RED | 18:14–18:17 | 清单是普通写法（[controlplane-red.json](controlplane-red.json)：没关 automount，没有自己的令牌卷） | 两个都 FAIL（[red.log](red.log)、[red.jsonl](red.jsonl)） |
| GREEN | 约 18:18 | 改好的清单和测试 | 两个都 PASS（[green.log](green.log)、[green.jsonl](green.jsonl)） |
| conformance | 约 18:19 | `make test-gvisor GVISOR_REUSE=1`，确认 `a7515aa` 给沙箱 pod 加了 `warden.dev/sandbox` 标签以后还能跑 | `TestGVisorConformance` 7/7（[gvisor-conformance.log](gvisor-conformance.log)） |

## TestControlPlaneTokenIsShortLived

要求：控制面拿到的每个 service account 令牌 `exp - iat ≤ 3600 s`，属于 `system:serviceaccount:warden-system:warden-controlplane`，绑定到这个 pod，API server 的 TokenReview 接受它。

- **RED**：普通写法下，准入控制器给 pod 注入 `kube-api-access-qr8ht` 卷，请求的有效期是 3607 s。API server 默认开着 `--service-account-extend-token-expiration`，把它延长到 **31536000 s（365 天）**。其他几项都符合（绑定到 pod，TokenReview 通过）。
- **改法**：ServiceAccount 和 pod 都设 `automountServiceAccountToken: false`，自己投射两个令牌，都是 `expirationSeconds: 3600`：
  - `kube-api-token`：API server 的 audience，和 CA、namespace 一起挂在标准路径 `/var/run/secrets/kubernetes.io/serviceaccount`，集群内客户端照常能用；
  - `azure-identity-token`：audience `api://AzureADTokenExchange`，路径和 AKS workload identity 一样（`AZURE_FEDERATED_TOKEN_FILE`），留给以后和 Entra 交换。
- **GREEN**：两个令牌都是 **3600 s**，都绑定到 pod，TokenReview 都认成控制面的账号。`iss` 是 `https://kubernetes.default.svc.cluster.local`。

## TestSandboxSAHasNoBindings

检查沙箱 namespace `warden-lab` 里的每个 service account：没有 RoleBinding/ClusterRoleBinding 指向它（直接指、按用户名、或者通过 `system:serviceaccounts`、`system:serviceaccounts:warden-lab` 组）；没有把它连到云身份的注解（AKS、GKE workload identity，EKS IRSA）；没有长期令牌 Secret；13 项敏感操作的 SubjectAccessReview 全部拒绝。最后种一个 RoleBinding（`view`）当正对照，确认两种检查都看得到它，再删掉，确认都恢复。

- **RED 的两个原因**：
  1. Kubernetes 自带的 ClusterRoleBinding `system:service-account-issuer-discovery` 绑给了 `system:serviceaccounts` 组，也就是所有账号，沙箱的也算。它的 ClusterRole 只允许 `get` 四个 URL：`/.well-known/openid-configuration`、`/openid/v1/jwks`，以及两个带结尾斜杠的写法。也就是 issuer 的发现文档和公钥，联合时本来就要公开发布。它带 `rbac.authorization.kubernetes.io/autoupdate: "true"`，API server 启动时会重建。
  2. 正对照的判断写成了“正好一条绑定”，因为有上面这条，所以条件永远不满足，等满了 180 s 超时。这是测试的 bug。
  - 第一次运行里，13 项敏感操作也都被拒绝了（日志里没有 “allowed” 的错误）。
- **改法**（只改了测试）：只接受 `system:service-account-issuer-discovery` 这一条，而且每次运行都去读它的 ClusterRole，只有规则仍然只是这四个 URL 的 `get` 才接受，否则照样 FAIL。接受的绑定会写进结果的 `bindings_accepted`。正对照改成按名字找种下的绑定。离线测试 `TestIssuerDiscoveryIsAcceptedOnlyWhileItGrantsDiscovery` 覆盖了换角色、放进 namespace、多资源、多 URL、通配和多动词这些情况。要不要在真实集群里删掉这条默认绑定（要同时把 autoupdate 设为 false），留给用户决定，lab 里没有改。
- **GREEN**：账号只有 `default`；扫了 60 条绑定，除了上面这条没有别的指向沙箱账号；长期令牌 Secret 0 个；敏感操作 13/13 拒绝；种下的绑定 89 ms 后两种检查都看到，删掉后 99 ms 都恢复。
- gVisor 沙箱 pod 本身也不挂令牌（`gvisor.go` 里 `automountServiceAccountToken: false`），也没有网络，所以沙箱里拿不到这个账号的身份。
- 云那一侧的绑定（Entra 的联合凭据、EKS Pod Identity 关联）存在云里，这里查不到。

## deny-metadata.yaml 和 TestSandboxCannotReachMetadata

- [policies/cilium/deny-metadata.yaml](../../../../policies/cilium/deny-metadata.yaml)：两条 CiliumClusterwideNetworkPolicy，一条选沙箱（`warden.dev/sandbox: "true"`），一条选出口代理（沙箱的域名是代理替它解析和连接的）。两条都只有 `egressDeny`：`169.254.169.254/32`（各家 IMDS）、`169.254.169.252/32`（GKE metadata server）、`169.254.170.23/32` 和 `fd00:ec2::23/128`（EKS Pod Identity agent）、`168.63.129.16/32`（Azure WireServer）、`fd00:ec2::254/128`（EC2 IPv6 IMDS）。deny 优先于所有 allow，白名单打不开它们。`metadata.google.internal` 这类主机名会解析到这些地址，所以也被拦。
- 离线检查 `TestDenyMetadataPolicyCoversSandboxesAndTheirProxy` 在 `make test` 里，核对两条策略的选择器和地址清单，并确认它们不放行任何流量。
- **没有应用到集群**：lab 没有 Cilium（阻塞 11）。
- **`TestSandboxCannotReachMetadata` 没有写。** 现在的 lab 里，gVisor 沙箱是 `network: none`，节点也没有出去的路由，所以“连不上 metadata”什么也证明不了。要有意义，需要节点执行这条策略，有一个假的 IMDS，再用一个不带沙箱标签的对照 pod 证明它连得上。这些都要先有 Cilium lab。

## 宿主、负载和清理

- 宿主快照（受保护的 sysctl 和模块列表的哈希）在 lab 前后一样（[host-before.txt](host-before.txt)、[host-after.txt](host-after.txt)，`down` 返回 0，[down.log](down.log)）。完整模块列表前后的 sha256 也一样（[modules.sha256](modules.sha256)）。这个哈希 `9e93ec2d…` 就是 Cilium 那次之后的值（还带着阻塞 11 的 4 个模块），这次没有再多加载。
- load average：18:13:43 是 2.03、2.17、2.58（[before.txt](before.txt)，32 核，同时有其他项目在跑），18:19:41 是 2.89、2.33、2.51（[after.txt](after.txt)）。开始时根分区剩 99G（94%）。
- 节点容器 `warden-k3s-gvisor` 和网络 `warden-k3s` 已删除，lab 镜像 `warden-k3s-gvisor:lab`、`warden-lab/pause:1` 也已删除（`scripts/k3s_gvisor_lab.sh purge`）。

## 还缺的

- 和 Entra 的联合：k3s 的 issuer 要换成公开的 URL（`--service-account-issuer` 指向 Blob，并发布发现文档和 JWKS），Entra 应用上要建联合凭据。需要 Azure 和 Entra 权限（STATUS 阻塞 4、5）。
- 控制面代码还不会从文件读令牌。kubelet 在令牌有效期过了 80% 时会轮换它，所以客户端每次都要重新读文件。`main.go` 现在既不读 `/var/run/secrets/kubernetes.io/serviceaccount/token`，也不读 `AZURE_FEDERATED_TOKEN_FILE`。
- `identity/terraform/{gcp-wif.tf,aws-pod-identity.tf}`：要云，没写。
