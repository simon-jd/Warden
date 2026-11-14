# Warden 实现计划：多租户代码沙箱 + 检测响应 + 漏洞管理

**Goal:** 一个多租户的不可信代码沙箱平台，提供三种隔离运行时，并做到平台内没有长期凭证；同时为它和 PathWatch 的云环境配齐检测响应、漏洞管理和供应链流水线。

**Architecture:**
- **沙箱**：Go 控制面通过 runtime driver 调度任务，可选三种运行时：runc+seccomp、gVisor（GKE Sandbox）、Firecracker（跑在开了嵌套虚拟化的 VM 上）。
- **身份**：Okta（或 Entra ID）负责 OIDC 登录和 SCIM 开通；工作负载用 GKE Workload Identity 或 EKS Pod Identity；数据库等凭证用 Vault 动态密钥。
- **检测与响应**：日志经 Vector 归一化成 OCSF，存进 OpenSearch；检测规则用 Sigma 写成代码；告警触发 Go 写的 responder 执行处置剧本。
- **供应链**：CI 生成 SBOM，扫描漏洞，签名并附 provenance；Kyverno 准入策略只放行合格镜像。

**Tech Stack:**
- 控制面与运行时：Go、containerd、gVisor（GKE Sandbox）、Firecracker + jailer
- 网络与身份：Cilium（GKE Dataplane V2）、Okta 免费开发者账号或 Microsoft Entra ID 免费层、HashiCorp Vault
- 检测：Vector（VRL）、OpenSearch Security Analytics、pySigma（OpenSearch backend）、Tetragon
- 攻击模拟：Stratus Red Team、Atomic Red Team
- 供应链：Syft、Grype/Trivy、Cosign（keyless）、slsa-github-generator、Kyverno

**Spec:** 本文件第 0 节。云环境复用 PathWatch（项目 1）的 GKE、EKS 和网络。

> **资源约束更新（2026-10-23，优先于本计划其他内容）：** 云和付费资源以同目录的 `AZURE-BUDGET.md` 为准。本项目上限 6 美元。主要替换：
> - gVisor 和 Firecracker 都跑在 home-ubuntu 上（k3s + runsc；`/dev/kvm` 可用）。
> - 工作负载身份改为 AKS workload identity（只在演练时开），加上 k3s issuer 与 Entra 做身份联合。
> - OIDC 用 Entra ID 免费层，SCIM 视情况用 Okta Integrator。
> - Vault 的云 secrets engine 改用 Azure。
> - 日志源改为 Azure Activity Log、AKS 审计、VNet flow logs、k3s 审计和 Tetragon；OpenSearch 放在 home-ubuntu。
> - 文中出现的 GKE、EKS、AWS、GCP，都按上面的方式替换。

---

## 0. 设计要点（Spec）

**为什么做**

服务器上可投的安全岗有 76 条，其中 71 条在目标公司（OpenAI 18、Anthropic 10）。这些 JD 的常见要求：

| 要求 | 比例 |
|---|---|
| 漏洞管理 | 55% |
| 容器 / K8s 安全 | 41% |
| 事故响应 | 38% |
| 云安全 | 37% |
| IAM / 身份 | 34% |
| 密钥 / 加密 | 34% |
| AppSec / 代码审查 | 34% |
| 供应链 | 32% |
| Go | 32% |
| 威胁建模 | 24% |
| 检测工程 | 21% |
| SIEM | 18% |

infra 样本里，隔离和威胁建模在 6 条目标公司 JD 中列为要求：Modal 17501、Cognition 16338、Baseten 16110、OpenAI 17771、Cursor 16522、Notion 17607。

经历库这方面只有 Landlock/seccomp（linux-service-isolation-lab）和 Cosign/provenance（artifact-trust-gate）。

**目标**
1. 不可信代码可以按策略选三种运行时之一执行；默认无网络、只读 rootfs、非 root 用户、有 cgroup 限额。
2. 平台内没有长期凭证：
   - 租户用 OIDC 登录，SCIM 开通和停用；
   - 工作负载用联邦身份拿短期凭证；
   - Vault 发放动态密钥；
   - 运维访问走 JIT，需要审批。
3. 默认拒绝的网络策略 + 出口白名单代理；屏蔽 metadata server；能检测 DNS 外泄。
4. 检测响应：
   - 覆盖 AWS、GCP、K8s、运行时和控制面审计的日志管道（OCSF）；
   - Sigma 规则写成代码，有测试；
   - 产出 ATT&CK 覆盖矩阵；
   - 做攻击模拟，有自动处置剧本。
5. 供应链与漏洞管理：SBOM、扫描、签名、provenance、准入控制，按 EPSS/KEV 排优先级并跟踪修复 SLA。
6. 写威胁模型，并附 SOC 2 控制映射。

**非目标**
- 不做商业 EDR，也不做 SOC 2 审计。
- 不攻击任何第三方系统。
- 没有真实租户。真实交付以后另补。

**度量**
- 隔离矩阵：攻击类别 × 运行时，结果为拦截 / 检测到 / 漏掉。
- 各运行时冷启动 p50/p95，每节点能承载的沙箱数。
- 长期密钥数为 0，凭证平均 TTL。
- ATT&CK 技术覆盖数，模拟攻击的检测率、检测耗时、处置耗时，7 天正常运行下的误报数。
- 漏洞修复中位时长，未签名镜像的拦截率。

## Global Constraints

- **攻击范围**：攻击语料和模拟只在专用的 `warden-lab` 项目和账号里跑，不碰其他环境。
- **沙箱默认值**（租户策略没有显式放开时）：
  - 网络 `none`，rootfs 只读，`no_new_privileges`，uid 65534；
  - cpu 1、memory 512 MiB、pids 128、timeout 300 秒。
- **凭证**：平台内不允许长期云凭证。CI 和工作负载一律用 OIDC 或联邦身份；Vault 动态密钥 TTL ≤ 1 小时，`max_ttl` ≤ 4 小时。
- **处置动作**：都支持 `--dry-run`；破坏性动作（终止租户、删除资源）需要第二个身份审批。
- **检测规则**：每条规则都附正样例和负样例事件。
- **证据**：写进 `docs/evidence/`，格式同 PathWatch。

## Review Focus

1. **超时后沙箱里还有残留进程**：超时后杀掉整个进程组，并验证 cgroup 里已经没有进程。测试见 Task 2 的 `TimeoutKillsProcessGroup`。
2. **租户 A 用猜到的 run ID 读到租户 B 的输出**：所有读接口按 token 里的租户过滤，run ID 用 128 位随机数。测试见 Task 1 的 `TestCrossTenantReadDenied`。
3. **OIDC 签名密钥轮换期间验签失败**：遇到未知 `kid` 时刷新 JWKS；被移除的 key 在缓存 TTL 之后拒绝。测试见 Task 6。
4. **日志源突增导致事件丢失**：Vector 开磁盘缓冲，丢事件必须有计数和告警。测试见 Task 11。
5. **同一告警的处置剧本被执行两次**：按 `alert_id` 幂等，第二次是 no-op。测试见 Task 14。

## File Structure

```
warden/
  controlplane/  cmd/warden-api; internal/{api,authn,tenant,runs,scheduler,quota,audit,scim,jit}
  runtimes/      {runc,gvisor,firecracker}/; conformance/
  policies/      {seccomp,cilium,kyverno}/
  identity/      terraform（okta 或 entra、gcp-wif、aws-pod-identity、vault）
  detect/        {vector,ocsf,sigma/rules,sigma/tests,report}/
  respond/       playbooks/
  vuln/          prioritizer
  attacks/       {corpus,stratus,atomic}/
  supplychain/   脚本；.github/workflows/build.yml
  docs/          {threat-model.md,soc2-mapping.md,evidence/}
```

---

## 阶段 A：沙箱

### Task 1: 控制面骨架（API、租户隔离、审计哈希链）

**Files:**
- Create: `controlplane/internal/{api,runs,tenant,audit}/`、`controlplane/cmd/warden-api/main.go`
- Test: `controlplane/internal/api/api_test.go`、`controlplane/internal/audit/audit_test.go`

**Interfaces:**
- `POST /v1/runs`，header 带 `Idempotency-Key`。
  - 请求体：`{image_digest, cmd[], limits{cpu, memory_mib, pids, timeout_s}, runtime: "runc" | "gvisor" | "firecracker", network: "none" | "allowlist", allow_domains[]}`
  - 返回：`{run_id}`，run_id 是 128 位随机数的 base32 编码。
- `GET /v1/runs/{id}`、`GET /v1/runs/{id}/logs`。
- 审计：
  - `audit.Append(e Event) (seq uint64, hash [32]byte, err error)`，`hash = sha256(prev_hash || canonical_json(e))`
  - `audit.Verify(from, to uint64) error`

- [x] 写测试：
  - `TestIdempotencyKeyReturnsSameRun`：同一个 key 提交两次，返回同一个 run_id。
  - `TestCrossTenantReadDenied`：租户 B 的 token 读租户 A 的 run，返回 404（不暴露是否存在）。
  - `TestAuditChainDetectsTamper`：改动中间一条记录，`Verify` 在该 seq 处报错。
- [x] 运行：`go test ./controlplane/...` → 失败。
- [x] 实现：存储用 Postgres；审计表 append-only，用触发器拒绝 UPDATE 和 DELETE。
- [x] 运行 → 通过。
- [x] 提交：`git commit -m "controlplane: runs API, tenant isolation, hash-chained audit log"`

### Task 2: Runtime 接口、runc + seccomp 运行时与一致性套件

**Files:**
- Create: `runtimes/runtime.go`、`runtimes/runc/runc.go`
- Create: `runtimes/conformance/suite.go`
- Create: `policies/seccomp/default.json`
- Test: `runtimes/runc/runc_test.go`（调用 conformance 套件）

**Interfaces:**
```go
type Spec struct { ImageDigest string; Cmd []string; Limits Limits; Network string; AllowDomains []string }
type Runtime interface { Start(ctx context.Context, s Spec) (Handle, error) }
type Handle interface { Wait(ctx context.Context) (Exit, error); Kill() error; Logs() io.ReadCloser }
func conformance.Run(t *testing.T, rt runtimes.Runtime) // 后面三种运行时共用
```

- [x] 在 conformance 套件里写这些子测试：
  - `ForkBombCappedByPids`
  - `RootfsReadOnly`
  - `NoNetworkByDefault`
  - `RunsAsNonRoot`
  - `TimeoutKillsProcessGroup`：超时后 cgroup 里的进程数为 0
  - `MemoryLimitOOMKilled`
  - `SeccompBlocksMountAndPtrace`
- [x] 运行 → 失败。
- [x] 实现：用 containerd client 创建容器，配 cgroup v2 限额、只读 rootfs、seccomp 默认拒绝 mount/ptrace/kexec/bpf 等调用；`Kill` 用 cgroup.kill。
- [x] 运行 → 通过。
- [x] 提交：`git commit -m "runtimes: runtime interface, runc+seccomp driver, conformance suite"`

### Task 3: gVisor 运行时（GKE Sandbox）

**Files:**
- Create: `runtimes/gvisor/gvisor.go`（以 K8s Job 方式运行，`runtimeClassName: gvisor`）
- Create: `identity/terraform/gke-sandbox-pool.tf`（`sandbox_config { sandbox_type = "gvisor" }`）
- Test: `runtimes/gvisor/gvisor_test.go`

- [ ] 写测试：`TestGVisorConformance` 调用 `conformance.Run(t, gvisor.New(...))`。
- [ ] 运行 → 失败。
- [ ] 实现：Job 模板加上 cgroup 限额和网络策略标签；日志从 Pod 日志流读取。
- [ ] 运行 → 通过。
- [ ] 测量：跑 100 次，记录冷启动 p50/p95，写进 `docs/evidence/runtime-startup.md`。
- [ ] 提交：`git commit -m "runtimes: gVisor driver on GKE Sandbox"`

### Task 4: Firecracker 运行时

**Files:**
- Create: `runtimes/firecracker/{firecracker.go,rootfs.go,snapshot.go}`
- Create: `identity/terraform/fc-host.tf`（n2 VM，`advanced_machine_features { enable_nested_virtualization = true }`）
- Test: `runtimes/firecracker/firecracker_test.go`

- [ ] 写测试：
  - `TestFirecrackerConformance`：跑一致性套件。
  - `TestSnapshotRestoreFasterThanBoot`：从快照恢复的中位耗时 < 冷启动中位耗时。
- [ ] 运行 → 失败。
- [ ] 实现：
  - 镜像 digest → `docker export` → 生成 ext4 rootfs，按 digest 缓存；
  - 用 jailer 启动，每个 microVM 128 MiB；
  - 支持快照的创建和恢复；
  - 网络默认不接网卡。
- [ ] 运行 → 通过。
- [ ] 测量：冷启动 vs 快照恢复的 p50/p95；单台 VM 在出现内存压力之前能并发多少个 microVM。追加到 `runtime-startup.md`。
- [ ] 提交：`git commit -m "runtimes: Firecracker driver with snapshot restore"`

### Task 5: 攻击语料与隔离矩阵

**Files:**
- Create: `attacks/corpus/`，每个攻击一个目录，内含 `run.sh` 和 `expect.yaml`
- Create: `attacks/matrix/main.go`
- Create: `docs/evidence/isolation-matrix.md`

**Interfaces:**
- `expect.yaml` 格式：`{id, technique: "T1611" ..., success_signal: "<stdout 里出现的标记>"}`
- `matrix` 的输出：`attack × runtime → blocked | detected | missed`。`detected` 要等 Task 12 之后才能判定，阶段 D 完成后重跑一次。

- [ ] 写测试：`TestMatrixClassifiesFixture`，用两个假攻击（一个必然成功、一个必然失败）验证分类逻辑。
- [ ] 运行 → 失败。
- [ ] 实现攻击语料：
  - fork bomb、内存耗尽、磁盘写满
  - 通过 /proc 和 /sys 泄露信息
  - 访问 metadata（169.254.169.254 和 metadata.google.internal）
  - 原始套接字、ARP 欺骗
  - ptrace 其他进程、mount/unshare、加载内核模块
  - 用 TXT 查询做 DNS 外泄
  - 反弹 shell
- [ ] 运行 → 测试通过，并对三种运行时跑出矩阵。
- [ ] 提交：`git commit -m "attacks: corpus and isolation matrix across runtimes"`

## 阶段 B：身份

### Task 6: 租户 OIDC 登录与 SCIM 2.0

**Files:**
- Create: `controlplane/internal/authn/{verifier.go,jwks.go}`、`controlplane/internal/scim/`
- Create: `identity/terraform/idp.tf`
- Test: `controlplane/internal/authn/verifier_test.go`、`controlplane/internal/scim/scim_test.go`

**Interfaces:**
- `authn.Verifier.Verify(raw string) (Claims, error)`：校验 iss/aud/exp/nbf；JWKS 缓存 TTL 10 分钟，遇到未知 `kid` 立即刷新。
- SCIM 端点：`/scim/v2/Users`，支持 POST、GET、PATCH（`active=false`）、DELETE。

- [ ] 写测试：
  - `TestVerify_RejectsWrongAudience`
  - `TestVerify_JWKSRotation`：新 `kid` 触发刷新后验签通过；被移除的 key 在 10 分钟后拒绝。
  - `TestSCIMDeactivateRevokesSessions`：PATCH `active=false` 后 60 秒内，该用户的 API 调用返回 401。
  - `TestSCIMConformanceBasic`：create → get → patch → delete 往返一遍。
- [ ] 运行 → 失败。
- [ ] 实现。IdP 配置用 Terraform（Okta 或 Entra provider）。
- [ ] 运行 → 通过。
- [ ] 手工验证：在 IdP 里分配和取消分配一个测试用户，确认控制面同步变化。记录到 `docs/evidence/identity.md`。
- [ ] 提交：`git commit -m "authn: OIDC verification with JWKS rotation and SCIM provisioning"`

### Task 7: 工作负载身份与屏蔽 metadata

**Files:**
- Create: `identity/terraform/{gcp-wif.tf,aws-pod-identity.tf}`
- Create: `policies/cilium/deny-metadata.yaml`
- Test: `runtimes/conformance/identity_test.go`

- [ ] 写测试：
  - `TestSandboxCannotReachMetadata`：在沙箱里 curl metadata 的两个地址，都被拦截。
  - `TestControlPlaneTokenIsShortLived`：控制面拿到的令牌 `exp - iat ≤ 1h`。
  - `TestSandboxSAHasNoBindings`：沙箱 namespace 的 KSA 没有任何 IAM 绑定。
- [ ] 运行 → 失败。
- [ ] 实现：
  - 控制面 KSA 映射到 GSA，只给最小权限；AWS 侧的 worker 用 EKS Pod Identity。
  - 沙箱 namespace 的出口策略拒绝 `169.254.169.254/32` 和 GKE metadata server。
- [ ] 运行 → 通过。
- [ ] 提交：`git commit -m "identity: workload identity and metadata isolation"`

### Task 8: Vault 动态密钥与"零长期密钥"审计

**Files:**
- Create: `identity/terraform/vault.tf`（GKE 上的 Vault raft HA；配置 Kubernetes auth、database 和 GCP/AWS secrets engine）
- Create: `scripts/longlived_keys_audit.sh`
- Test: `identity/tests/vault_test.go`

- [ ] 写测试：
  - `TestDynamicCredsExpire`：数据库凭证 TTL 设 1 分钟（测试值），到期后登录失败。
  - `TestLeaseRevocation`：revoke 之后立即失效。
  - `TestNoLongLivedKeys`：审计脚本统计 AWS IAM user access key 和 GCP SA key 的数量，期望为 0。
- [ ] 运行 → 失败。
- [ ] 实现：控制面通过 Kubernetes auth 获取数据库动态凭证；responder（Task 14）用 GCP/AWS secrets engine 拿短期云凭证。
- [ ] 运行 → 通过。
- [ ] 提交：`git commit -m "identity: Vault dynamic secrets and long-lived key audit"`

### Task 9: JIT 运维访问

**Files:**
- Create: `controlplane/internal/jit/`
- Test: `controlplane/internal/jit/jit_test.go`

**Interfaces:**
- `Request(user, role string, d time.Duration /* ≤ 2h */, reason string) (id string, err error)`
- `Approve(id, approver string) error`：approver 不能是申请人。
- 批准后生成带时限的 RoleBinding 或 IAM 条件绑定；`Expire()` 由定时任务调用，回收到期的授权。

- [ ] 写测试：
  - `TestSelfApprovalRejected`
  - `TestGrantExpiresAndBindingRemoved`：用 fake clock
  - `TestAuditRecordedForGrantAndExpiry`：授权和回收两个事件都进了 Task 1 的审计链
- [ ] 运行 → 失败。
- [ ] 实现。
- [ ] 运行 → 通过。
- [ ] 提交：`git commit -m "jit: approved, time-bound operator access with audit"`

## 阶段 C：网络隔离

### Task 10: 默认拒绝、出口白名单与 DNS 外泄检测

**Files:**
- Create: `policies/cilium/{default-deny.yaml,egress-proxy.yaml}`
- Create: `controlplane/internal/scheduler/egress.go`：把租户的 `allow_domains` 下发给出口代理
- Create: `detect/dns_exfil/`
- Test: `runtimes/conformance/egress_test.go`、`detect/dns_exfil/exfil_test.go`

**Interfaces:**
- 出口代理二选一：Envoy（按 SNI/Host 白名单），或 PathWatch 的 Rust 代理加一个 SNI 过滤器。
- `dns_exfil.Score(queries []Query) Alert?`：单个 run 中子域名平均熵 > 3.5 bits/char 且查询数 > 30 次/分钟时告警（我的取值）。

- [ ] 写测试：
  - `TestAllowlistedDomainReachable`
  - `TestNonAllowlistedBlocked`
  - `TestDNSExfilAlert`：把 4 KiB 数据编码进 TXT 查询，触发告警。
  - `TestNormalDNSNoAlert`：常见的 CDN 域名不触发。
- [ ] 运行 → 失败。
- [ ] 实现。
- [ ] 运行 → 通过。
- [ ] 提交：`git commit -m "network: default deny, egress allowlist and DNS exfil detection"`

## 阶段 D：检测与响应

### Task 11: 日志管道与 OCSF 归一化

**Files:**
- Create: `detect/vector/{agent.toml,aggregator.toml}`
- Create: `detect/ocsf/{cloudtrail,gcp_audit,k8s_audit,vpc_flow,tetragon,warden_audit}.vrl`
- Test: `detect/ocsf/tests/*.toml`（`vector test` 单元测试）、`detect/tests/backpressure_test.sh`

**Interfaces:**
- 每个来源映射到对应的 OCSF 类：
  - API Activity 6003：CloudTrail、GCP 审计日志
  - Process Activity 1007：Tetragon exec 事件
  - Network Activity 4001：VPC flow log
- OpenSearch 每个 OCSF 类一个索引。

- [ ] 写测试：
  - 每个来源各一个 golden 样例，输入原始事件，断言输出的 OCSF JSON 与预期完全一致。
  - 背压测试：注入 10 倍突发流量，断言丢失事件为 0，或者 `vector_buffer_discarded_events_total` 有计数并触发告警。
- [ ] 运行：`vector test detect/ocsf/tests/*.toml` → 失败。
- [ ] 实现数据源：
  - CloudTrail：S3 + SQS
  - GCP 审计日志：log sink → Pub/Sub
  - GKE 和 EKS 的 K8s 审计日志
  - VPC flow log
  - Tetragon：TracingPolicy 采集 exec、connect、敏感文件访问
  - Task 1 的控制面审计日志
- [ ] 运行 → 通过。
- [ ] 提交：`git commit -m "detect: OCSF log pipeline with disk buffers"`

### Task 12: 检测即代码（Sigma）与 ATT&CK 覆盖

**Files:**
- Create: `detect/sigma/rules/*.yml`
- Create: `detect/sigma/tests/<rule_id>/{pos.json,neg.json}`
- Create: `detect/report/coverage.py`
- Create: `.github/workflows/detect.yml`

- [ ] 写测试框架 `detect/sigma/test_rules.py`：
  1. 用 testcontainers 起一个临时 OpenSearch；
  2. 写入每条规则的正、负样例；
  3. 用 pySigma 把规则转成 OpenSearch 查询；
  4. 断言正样例命中、负样例不命中。
- [ ] 运行 → 失败。
- [ ] 写 ≥ 30 条规则：
  - **云**：新建 access key、IAM 策略变更、关闭日志、Pod 访问 metadata。
  - **K8s**：exec 进 Pod、特权 Pod、非常规 SA 读取 secret。
  - **运行时**：沙箱里起 shell、非白名单出站、挖矿进程特征。
  - **控制面**：自我审批尝试、跨租户读取尝试。
- [ ] 运行 → 通过。
- [x] 用 `coverage.py` 从规则 tag 生成 ATT&CK 覆盖矩阵，写进 `docs/evidence/attack-coverage.md`。
- [ ] 提交：`git commit -m "detect: Sigma rules as code with tests and ATT&CK coverage"`

### Task 13: 攻击模拟与检测度量

**Files:**
- Create: `attacks/stratus/run.sh`、`attacks/atomic/run.sh`
- Create: `detect/report/detection_metrics.py`
- Create: `docs/evidence/detection-coverage.md`

**Interfaces:**
- `detection_metrics.py` 读模拟日志（技术 ID、执行时间）和告警（规则、告警时间），输出每个技术的：是否检出、检测耗时。

- [x] 写测试：`test_metrics_on_fixture`，fixture 里有 3 个技术、2 个被检出，断言检出率和检测耗时计算正确。
- [x] 运行 → 失败。
- [ ] 实现并执行模拟：
  - Stratus Red Team 的 AWS、GCP、K8s 技术（比如 `aws.persistence.iam-create-admin-user`、`aws.defense-evasion.cloudtrail-stop`、`k8s.privilege-escalation.privileged-pod`）
  - Atomic Red Team 的 Linux 用例
  - Task 5 的攻击语料
- [ ] 运行 → 测试通过；用真实数据出报告。
- [ ] 证据：检出率、检测耗时 p50/p95，以及 7 天正常运行下的误报数。
- [ ] 提交：`git commit -m "attacks: emulation runs and detection metrics"`

### Task 14: 响应剧本

**Files:**
- Create: `respond/{executor.go,actions.go}`、`respond/playbooks/*.yaml`
- Test: `respond/executor_test.go`

**Interfaces:**
- `Playbook{ID string; Trigger string /* rule_id */; Steps []Action; RequiresApproval bool}`
- 可用动作：`RevokeVaultLease`、`DisableAWSAccessKey`、`DisableGCPServiceAccountKey`、`IsolatePod`（打上 deny-all 网络策略的标签）、`CordonNode`、`SuspendTenant`
- `Executor.Handle(alert Alert, dryRun bool) (Result, error)`：按 `alert_id` 去重。

- [x] 写测试：
  - `TestPlaybookIdempotentPerAlert`：第二次执行是 no-op。
  - `TestDestructiveRequiresApproval`：`SuspendTenant` 没有审批时不执行。
  - `TestDryRunMakesNoChanges`：fake client 记录到的变更数为 0。
- [x] 运行 → 失败。
- [ ] 实现：云端动作用 Vault 发的短期凭证（Task 8）。
- [ ] 运行 → 通过。
- [ ] 演练：重放 Task 13 的一个场景，从告警到处置完成计时，写进 `docs/evidence/time-to-contain.md`。
- [ ] 提交：`git commit -m "respond: idempotent playbooks with approval and dry-run"`

## 阶段 E：供应链与漏洞管理

### Task 15: SBOM、扫描、签名、provenance 与准入

**Files:**
- Create: `.github/workflows/build.yml`
- Create: `policies/kyverno/{verify-images.yaml,block-kev.yaml}`
- Test: `policies/kyverno/tests/kyverno-test.yaml`

- [ ] 写 `kyverno test` 用例：
  - 未签名镜像 → 拒绝
  - 本仓库 workflow 身份签名、且带 provenance 的镜像 → 放行
  - 漏洞 attestation 里有 KEV CVE 的镜像 → 拒绝
- [ ] 运行：`kyverno test policies/kyverno/tests` → 失败。
- [ ] 实现 CI 流水线：
  1. build
  2. Syft 生成 CycloneDX SBOM，作为 attestation 附上
  3. Grype 扫描，有可修复的 critical 时失败，结果作为漏洞 attestation 附上
  4. Cosign keyless 签名
  5. 用 slsa-github-generator 生成 provenance

  准入策略：Kyverno `verifyImages` 要求签名身份等于本仓库的 workflow。
- [ ] 运行 → 通过。
- [ ] 提交：`git commit -m "supplychain: SBOM, scan, sign, provenance and admission policies"`

### Task 16: 漏洞优先级与修复时效

**Files:**
- Create: `vuln/{prioritize.go,feeds.go,sla.go}`
- Test: `vuln/prioritize_test.go`

**Interfaces:**
- `Prioritize(fs []Finding, epss map[string]float64, kev map[string]bool) []Ranked`，排序规则：KEV 优先，然后 EPSS 降序，然后 CVSS 降序，然后是否对外暴露。
- SLA（我的取值）：KEV 或 critical 7 天，high 30 天，其余 90 天。
- 每天拉取 EPSS 和 CISA KEV 数据，生成 Grafana 或 OpenSearch Dashboards 看板。

- [ ] 写测试：
  - `TestKEVRanksFirst`
  - `TestEPSSBreaksTies`
  - `TestSLABreachDetected`：用 fake clock
- [ ] 运行 → 失败。
- [ ] 实现。
- [ ] 运行 → 通过。
- [ ] 证据：修复中位时长、SLA 违约数，写进 `docs/evidence/vuln-sla.md`。
- [ ] 提交：`git commit -m "vuln: EPSS and KEV prioritization with SLA tracking"`

## 阶段 F：文档

### Task 17: 威胁模型、SOC 2 映射与证据索引

**Files:**
- Create: `docs/threat-model.md`、`docs/soc2-mapping.md`、`docs/evidence/README.md`

- [ ] 威胁模型：对 API、调度器、三种运行时、身份、日志管道、CI 逐个做 STRIDE 分析；画两棵攻击树——"租户逃逸到节点"和"凭证被盗"。每个威胁都要对应到一个控制，并引用相应 Task 的测试或证据。
- [ ] SOC 2 映射：把控制对到 CC6（逻辑访问）和 CC7（系统运维）的条目，作为附录。
- [ ] 证据索引：链接隔离矩阵、ATT&CK 覆盖、检测度量、处置耗时、漏洞 SLA。
- [ ] 验证：威胁模型里每一行都能点到对应的测试名或证据文件（`scripts/check_threat_model_links.py` 检查失效链接）。
- [ ] 提交：`git commit -m "docs: threat model, SOC 2 mapping and evidence index"`
