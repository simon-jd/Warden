# 原始计划验收账本

来源：`2-warden-security-plan.md`，保持功能与安全验收范围；2026-10-23的云/本机资源按最高优先级`AZURE-BUDGET.md`替换。此表是验收入口，不是通过声明；实际状态见 STATUS.md，只有命令和权威结果证明要求后才勾选。所有步骤都须含实现、RED/GREEN、独立审查、证据和本地提交。

| Task | 必须验证的行为 / 测试 | 必须的权威证据 |
|---|---|---|
| 1 | `TestIdempotencyKeyReturnsSameRun`、`TestCrossTenantReadDenied`（状态和日志均404）、`TestAuditChainDetectsTamper`；128位随机base32；Postgres append-only拒绝UPDATE/DELETE | `go test ./controlplane/...`、真实Postgres测试输出、迁移与触发器、API实现 |
| 2 | `ForkBombCappedByPids`、`RootfsReadOnly`、`NoNetworkByDefault`、`RunsAsNonRoot`、`TimeoutKillsProcessGroup`（cgroup=0）、`MemoryLimitOOMKilled`、`SeccompBlocksMountAndPtrace` | 实际containerd/runc、cgroup v2、只读rootfs/seccomp/NNP/资源配置、专用lab一致性结果 |
| 3 | `TestGVisorConformance`、k3s+runsc Job/RuntimeClass/logs、100次启动p50/p95 | home-ubuntu真实运行记录、RuntimeClass/节点配置、runtime-startup.md |
| 4 | `TestFirecrackerConformance`、`TestSnapshotRestoreFasterThanBoot`；digest→export→ext4缓存；jailer；无NIC；snapshot | home-ubuntu真KVM、启动/恢复p50/p95、内存压力前容量，runtime-startup.md |
| 5 | `TestMatrixClassifiesFixture`；fork/mem/disk/proc/sys/metadata/raw socket/ARP/ptrace/mount/unshare/module/DNS TXT/reverse shell语料 | 三运行时真实矩阵，缺数据为未验证；Task12之后重跑detected；isolation-matrix.md |
| 6 | `TestVerify_RejectsWrongAudience`、`TestVerify_JWKSRotation`（未知kid刷新/10分钟移除）、iss/aud/exp/nbf；`TestSCIMDeactivateRevokesSessions`（≤60秒）、`TestSCIMConformanceBasic` | 单元/HTTP+DB测试；Terraform IdP；实际分配与取消用户，identity.md |
| 7 | `TestSandboxCannotReachMetadata`（IP和hostname）、`TestControlPlaneTokenIsShortLived`（≤1h）、`TestSandboxSAHasNoBindings` | 真实AKS workload identity与k3s issuer/Entra federation、RBAC清单，控制面最小权限，metadata网络拦截 |
| 8 | `TestDynamicCredsExpire`（1分钟）、`TestLeaseRevocation`、`TestNoLongLivedKeys`（Azure/Entra长期云凭证=0） | Vault raft HA/K8s auth/DB和cloud engines；数据库实际登录过期/撤销；完整分页云盘点。现状（2026-11-12）：`TestNoLongLivedKeys`**部分，不算通过**——学校租户不允许完整分页盘点，只能查缩小后的范围（用户自己拥有的Entra应用+本订阅）。2026-11-11 04:27Z只读实测：不加过滤有2个（都属于用户别的项目，不是Warden的），exit 1；`--project warden`的0是在Warden没有任何对象时得出的，是空的。2026-11-12范围修复（`8c7b8c2`）后只读重跑：用户当时不拥有任何应用，范围里只有1个（别的项目的存储账户），不加过滤exit 1；`--project warden`范围为空，exit 3。keyprobe正对照说明检测本身有效。见STATUS Task 8 |
| 9 | `TestSelfApprovalRejected`、`TestGrantExpiresAndBindingRemoved`、`TestAuditRecordedForGrantAndExpiry`；≤2h | fake clock行为测试、真实binding适配器及回收证据、链审计 |
| 10 | `TestAllowlistedDomainReachable`、`TestNonAllowlistedBlocked`、`TestDNSExfilAlert`（4KiB TXT）、`TestNormalDNSNoAlert`；>3.5 bits/char且>30次/分钟 | 实际proxy+默认拒绝策略、run级域名下发、DNS判分测试与lab网络结果 |
| 11 | 六种来源逐字段golden；10倍流量零丢失或counter+alert | `vector test detect/ocsf/tests/*.toml`输出、真实Vector背压输出、磁盘buffer配置与监控告警 |
| 12 | ≥30条每条pos/neg、真实OpenSearch pySigma查询、ATT&CK tags | testcontainers/OpenSearch测试输出、转换器版本、规则/fixtures、attack-coverage.md及detect CI |
| 13 | `test_metrics_on_fixture`（3技术2命中）；Stratus Azure/K8s、Atomic Linux、语料 | 真实simulation与alert日志、检出率/延迟p50p95、连续7天正常误报数据、detection-coverage.md |
| 14 | `TestPlaybookIdempotentPerAlert`、`TestDestructiveRequiresApproval`、`TestDryRunMakesNoChanges`；所有6动作 | 持久幂等测试、双身份、dry-run、Vault短期云凭证；真实重放计时，time-to-contain.md |
| 15 | 未签名拒绝、正确workflow身份+provenance放行、KEV拒绝 | `kyverno test policies/kyverno/tests`；真实build→Syft CycloneDX→Grype fixable critical gate→Cosign keyless→SLSA provenance，CI/准入记录 |
| 16 | `TestKEVRanksFirst`、`TestEPSSBreaksTies`、`TestSLABreachDetected`；KEV>EPSS>CVSS>exposed；7/30/90天 | 真实feeds按日拉取/看板；测试；有来源的修复中位数/SLA违约数，vuln-sla.md |
| 17 | API/scheduler/三runtime/identity/log/CI STRIDE；2攻击树；CC6/CC7；每威胁控制与测试/证据链接 | threat-model.md、soc2-mapping.md、证据索引、`scripts/check_threat_model_links.py`及最终逐要求audit |

全局检查：攻击仅在专用 `warden-lab` 项目/账号；默认network none、readonly rootfs、NNP、UID65534、CPU1、512MiB、pids128、300s；无长期云凭证；Vault TTL≤1h/max≤4h；所有响应dry-run/破坏性第二身份审批；每规则pos/neg；证据含日期、版本、配置、数据路径。

新增资源验收：预算6美元/开通预估≤5.40美元、Retail API单价台账、仅rg-warden-lab四tag、高价同会话清理、reaper起止执行、make azure-down、保护rg-mlinfra-westus、本机磁盘12GB/服务16GB/GPU flock。云来源替换为Activity Log/AKS审计/VNet flow/k3s审计/Tetragon/Warden，不降低日志背压、规则正负样例、7天正常误报、隔离与TTL验收。
