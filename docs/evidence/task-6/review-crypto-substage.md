来源：`/root/identity_crypto_review`，`gpt-6-astra/high`；独立 subagent 审查，非人工审查。BASE `c43c74f63062e5c1bae7f30893ab37dc5d9d6f06`；source `6d02de4062c0ee1e5d62825df0ea670d54672b5e`；evidence `f4dd9dc75fbabce7b6d7d79eba5d8428f483a1ae`。以下为上一份完整最终报告原文。

### Spec Compliance

- ✅ **当前 crypto/JWKS unit 子层符合规格。** 审查范围为 BASE `c43c74f63062e5c1bae7f30893ab37dc5d9d6f06` → source `6d02de4062c0ee1e5d62825df0ea670d54672b5e` → evidence `f4dd9dc75fbabce7b6d7d79eba5d8428f483a1ae`，仅四个产品源文件；未发现阻断性缺项、越界功能或安全缺陷。
- ✅ 原始 `Verify(raw)` 与另名 `VerifyContext(ctx, raw)` 均保留；返回已验证的 issuer/subject 等信息，没有 token→Warden tenant 授权、自注册或调试绕过。见 `controlplane/internal/authn/verifier.go:43`、`:111`、`:117`。
- ✅ `identity-unit` 仅新增固定参数白名单、对应 label 与固定 authn 单包命令；既有其他 target、锁、资源额度、镜像/toolchain pin、网络与权限配置未修改。见 `scripts/firecracker_code.py:10`、`:34`、`:41`。
- ✅ SQL TenantAdapter、持久 active membership、SCIM、main composition、Terraform 与真实 IdP 操作均明确留待后续，未被冒充为本次交付。见 `docs/evidence/task-6/crypto-substage-report.md:9`、`:53`。**本结论不表示整个 Task6 或 Goal 完成，原 review fix count 1/5 不重置。**

### Strengths

- **固定信任边界清楚。** 构造器限定一个非零 tenant UUID 的 public-cloud Entra v2 issuer、与之精确对应的 HTTPS JWKS URL，以及非零 audience UUID；不接受 common/organizations、外部地址、userinfo 或 fragment。公开构造路径不暴露自定义 transport/TLS 绕过开关；私有测试注入仍验证配置。见 `controlplane/internal/authn/verifier.go:56`、`:72`、`:99`。
- **签名与解析约束落实。** JWT 限制总长度、header、kid 和签名长度；要求三个非空 canonical unpadded base64url 段；只允许 RS256，拒绝 `crit`、token-directed key headers 与 `b64`。JSON 递归检测重复解码成员名，限制深度，拒绝尾随值及原始无效 UTF-8；RSA 对原始 encoded header.payload 验签。见 `controlplane/internal/authn/verifier.go:117`、`:275`、`:288`、`:308`。
- **声明校验与授权职责分离。** 精确校验 issuer/version、非空 subject、指定 audience 成员、整数 exp/可选 nbf 与 `warden.access` scope；验签和 fetch 后再次检查时间。Graph/ARM audience、无 scope 的 ID token、roles-only app token 被测试拒绝。见 `controlplane/internal/authn/verifier.go:194`、`:266`；`controlplane/internal/authn/verifier_test.go:175`、`:211`。
- **JWKS 安装采用完整校验后原子替换。** response 必须为 200，最多 1 MiB、64 keys；任何空集、重复 kid、错误类型、不兼容 alg/use/key_ops、私钥字段或不合格 RSA 参数都会使整个响应失败。RSA modulus 限制为 2048–4096 bit，指数限制为 3–65537 的奇数，整数编码拒绝前导零。见 `controlplane/internal/authn/jwks.go:136`、`:177`。
- **轮换与过期逻辑符合安全要求。** 成功安装后的 TTL 精确为 10 分钟，边界使用严格 `Before`；失败不会延长原 snapshot 的 expiry。最终验签还检查 snapshot 当前性，避免已经取得的旧 key 在并发移除后继续获准。见 `controlplane/internal/authn/jwks.go:42`、`:115`；`controlplane/internal/authn/verifier.go:186`。
- **并发状态有界且同步一致。** cache、expiry、budget、waiters、inflight 与 refresh result 都在同一 mutex 下处理；keyset 发布后不再修改。已知且新鲜的 key 先于 waiter/budget 检查返回；未知 kid 共享唯一 refresh，加入者不重复消费预算；预算为 2/sec、burst 2，等待者上限 32，expired/empty 失败路径有 1 秒 backoff，没有 per-kid 状态增长。见 `controlplane/internal/authn/jwks.go:42`、`:100`、`:115`。
- **取消与网络资源边界合理。** 调用者具有最多 5 秒 context；共享 fetch 使用独立 3 秒 context，因此一个调用者取消不会取消其他调用者的请求。生产 transport 禁 proxy/redirect，使用正常 TLS trust，并限定 connect/TLS/header deadline、连接数量与 idle lifetime；已取得的 response body 使用 defer 关闭。见 `controlplane/internal/authn/verifier.go:72`、`:117`；`controlplane/internal/authn/jwks.go:115`、`:136`。
- **测试以可观察行为为主。** named audience/rotation 测试使用真实临时 RSA 签名，验证 A→B 立即刷新、TTL 前一纳秒接受及精确边界移除；其他测试覆盖篡改、malformed JWT/JWKS、失败不延长缓存、压力、取消、等待者上限及 token 在 fetch 期间过期。未依赖私有 cache 字段作为主要断言。见 `controlplane/internal/authn/verifier_test.go:187`、`:253`、`:280`、`:329`、`:353`、`:413`、`:431`、`:537`。
- **冻结证据可交叉核验。** RED 日志确为缺失实现符号的 compile/API failure，未被包装成行为失败；GREEN 与冻结 cover 均保存完整输出。冻结 cover 有 15 个 top-level、32 个 subtest PASS，无 FAIL/SKIP 或运行告警，包耗时 6.252 秒、wrapper 9.040243 秒。见 `docs/evidence/task-6/crypto-red-01/output.txt:5`、`crypto-red-01/receipt.json:8`、`crypto-cover-03/output.txt:5`、`crypto-cover-03/receipt.json:8`。
- **证据保留与范围压缩成立。** 只读 hash 检查核对了 full package SHA `cfca635d8e5acb5747f90694a54c76c8f2891f2d526601db8b2f1cc5d6ee3857`、scope-view SHA `560d8a61bf20ff04d4eccd41dd2b0e2956acfc142c9c8e6bcb6685c3cc0ead2e`；45 个保留 diff blocks 均逐字存在，417 个省略块的 block/body hashes 与当前 canonical 内容一致，458 个 evidence artifacts hashes 一致，三次 141/143/143 份 snapshots 与各自 pre/post manifests 一致。BASE/SOURCE 对照的 controller 脚本也明确逐字比较两个 commit，未把不同历史源码作为重复项省略。见 `docs/evidence/task-6/controller-crypto-verification-command-20261025.py:21`、`:31`、`:61`，以及 `controller-crypto-review-view-20261025.json:1`。
- **实际操作与声明边界诚实。** 三次 run 的 pre/post guard、精确 container removal、Q5GB 保留及六项 sysctls 都有记录；formatter 是祖先 metadata guard 拒绝后由 controller 关闭，未执行 native formatter。见 `docs/evidence/task-6/crypto-cover-03/postguard.json:14`、`crypto-cover-03/output.txt:101`、`crypto-format-01/preflight-failure.json:1`、`crypto-formatter-ruling-20261025.md:11`。

### Issues

#### Critical — Must Fix

- 无。

#### Important — Should Fix

- 无。

#### Minor — Nice to Have

- **并发回归可以进一步消除调度依赖并限制失败等待。** `controlplane/internal/authn/verifier_test.go:383` 启动第二个 verifier goroutine 后，没有确定它已经进入共享等待路径，随后便在 `:399` 释放 fetch；在某些调度下，第二个调用可能在刷新完成后直接命中新 cache。因此该用例的成功结果并非每次都证明第二个调用实际 join 过 inflight。另外 `release <- struct{}{}` 本身没有 timeout：若 handler 因 3 秒 deadline 提前退出，测试会等到外层 runner 超时才结束。建议为第二个调用加入明确的测试同步点，并将 release send 放进有 deadline 的 select，或使用单次关闭的广播 channel。现有生产 coalescing/cancellation 路径及独立的 waiter-pressure 测试支持本次通过，此项不构成验签安全阻断。

### Cannot verify

- ⚠️ **真实 Entra 互操作、实际 application registration/audience 配置及真实 delegated token。** 本次是实现者编写的本地签名/TLS fixtures，无法证明真实租户配置；不得将其记为人工 assignment、SCIM 或 Entra acceptance。见 `docs/evidence/task-6/crypto-substage-report.md:29`、`:53`。
- ⚠️ **完整身份授权链。** issuer/subject→持久 active user/tenant 映射、SCIM committed deactivation→401、管理员 bootstrap、真实 SQL/reopen 与 main 接线不在本次产品 diff；必须在对应后续阶段单独审查验证。见 `controlplane/internal/authn/verifier.go:1`；`docs/evidence/task-6/crypto-substage-report.md:53`。
- ⚠️ **动态 race-detector 证据。** mutex/immutable publication 路径经静态检查未发现数据竞争，但现有固定命令没有 `-race`；不能宣称 race detector 已通过。当前未发现需要为本次结论追加重跑的具体未解生产疑点。见 `scripts/firecracker_code.py:41`；`docs/evidence/task-6/crypto-substage-report.md:29`。
- ⚠️ **资源检查的时点限制。** 已读取后来提供的 controller postflight：2026-10-25 10:41:29Z，R 为 4,212,948,992 B、Q5GB 保留、own objects 为 0，原 22 项 metadata 与六项 sysctls 匹配；这是 controller 的实际记录，本 reviewer 未独立执行主机资源命令，也未重扫旧 cache 全文件 metadata。该记录明确 cache completion receipt 仍缺失、未重试维护，不证明旧维护已完成。见 `docs/evidence/task-6/controller-crypto-postflight-20261025.json:5`、`:33`。
- ✅ **审查操作检查：** 仅执行文件读取与无写入的 Python hash/manifest 对照；未运行测试、Go、Docker、PG、cloud、cache maintenance 或身份命令，未调用 Git 命令，未修改工作树/index，也未派生子代理。scope view 分段读取；输出被截断的 stat/hash 部分补读，没有另行扩大旧 Task1–5 源码语义审查。

### Assessment

**Task quality: Approved — 仅限当前 crypto/JWKS unit 子层。**

固定 authority、严格验签、完整 JWKS 替换、精确 TTL 与有界共享刷新形成一致的信任边界；冻结证据支持当前交付，未发现应阻断该子层的缺陷。并发测试同步建议为非阻断改进；整个 Task6、真实身份集成与 Goal 保持 OPEN。
