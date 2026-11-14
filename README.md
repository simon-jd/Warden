# Warden

设计与验收标准见 [2-warden-security-plan.md](2-warden-security-plan.md)，各任务的完成情况见 [docs/STATUS.md](docs/STATUS.md)。没有在真实环境验证过的部分都标为未验证。

## Azure预算与资源保护

云资源受 [AZURE-BUDGET.md](AZURE-BUDGET.md) 约束，累计承诺估算门槛$5.40，权威台账为 [docs/azure-spend.json](docs/azure-spend.json)。当前承诺$0.00，未开通Azure资源。工具只做预留/清理，不提供创建功能；AKS第二个node资源组超出当前授权，继续门禁。所有命令固定订阅与rg-warden-lab；rg-mlinfra-westus永远不可操作。

```bash
./scripts/azure_reaper.sh --dry-run       # 开始前检查
./scripts/azure_reaper.sh                 # 会话开始/结束清理已到期资源
./scripts/azure_reaper.sh --end-session SESSION_ID  # 结束时额外清理绑定本会话且>$0.02/h的资源
make azure-down DRY_RUN=1                # 核对后仅本项目整个组；实际销毁去掉DRY_RUN=1
make azure-preflight                    # 当前项目磁盘，无常驻服务的默认检查
python3 -B scripts/azure_guard.py preflight --download-bytes 6000000000 --service-memory-bytes 8000000000
make test-azure-budget                   # 临时台账和fake az，不调用真实Azure删除
```

报价选择、预留输入与部署前边界见 [使用说明](docs/azure-budget-tools.md)。本机检查需传入全部Warden常驻服务合计峰值内存，additional-bytes为下载之外新增磁盘；不启动服务、不下载、不清理Docker、不使用GPU。每次未来实际创建前仍须审查完整适用计费项与使用量上限，检查即时配额，先记录reservation，再把返回的所有标签应用到资源（组也必须四标签）；单次预留成功不能替代部署审查。

## Task 1：本地控制面

控制面使用 Go 1.26.10+ 和真实 Postgres 18（本地验证为 18.6）。当前实现持久化 run、租户过滤、审计链及 Task 2 调度/恢复/日志 core；Task 6 接入可信 OIDC 验证器。当前生产入口没有认证验证器，**所有 HTTP 请求均返回 401**，X-Tenant 或裸 bearer 文本无法获得权限。测试使用注入的明确 claims 验证器，未模拟生产登录成功。

测试入口（详见 [docs/STATUS.md](docs/STATUS.md)）：

```bash
make tools          # 把 Go 1.26.10、Vector 0.45.0、pySigma venv 恢复到 .tools/
make test           # 全部离线套件；Postgres/live/云/GPU 测试默认 skip
make check          # go vet、gofmt -l、shellcheck
make test-postgres  # 需要 Docker：临时 postgres:18-alpine，跑 Postgres 测试后删除
```

`make test-postgres` 只创建 `warden-task1-pg-*` 专用临时容器，不复用数据卷，退出时连同匿名数据卷删除；Postgres 仅发布到 127.0.0.1 的随机端口。每项测试使用独立 schema；没有 `WARDEN_TEST_DATABASE_URL` 时这些测试 skip，不会替换成内存数据库。没有本地 Go 时，`./scripts/go.sh` 仍可用容器里的 Go 运行。

连接已有专用数据库并启动控制面（不要使用测试数据库管理员凭证部署）：

```bash
export DATABASE_URL='postgres://warden:REPLACE@127.0.0.1:5432/warden?sslmode=verify-full'
export WARDEN_LISTEN_ADDR='127.0.0.1:8080'
./scripts/go.sh run ./controlplane/cmd/warden-api
```

启动会应用内嵌版本迁移；迁移账号需 DDL 权限，部署时应将迁移与普通应用账号权限分离。生产凭证管理由 Task 8 完善。默认仅监听 loopback；当前入口拒绝全部请求，以上命令用于数据库迁移/启动检查。不要将此阶段解释为可对外使用的已认证执行服务。

API 约定（可信验证器接入后生效）：

- `POST /v1/runs`：认证租户内的 `Idempotency-Key` 必填，1..256 bytes。成功及相同载荷重试均返回 201 `{run_id}`；同 key 不同规范化载荷返回 409。key 不跨租户共享。
- 请求 `image_digest` 只接受小写 `sha256:` 加 64 位十六进制的内容摘要，拒绝 tag/可变名称。运行层必须按该摘要解析已导入或受信来源的镜像，不能将其当作任意 registry 拉取地址。`cmd` 为非空字符串数组，首项非空，禁止 null 和 NUL。
- `runtime` 为 `runc`（默认）、`gvisor` 或 `firecracker`。`network` 为 `none`（默认）或 `allowlist`；仅 allowlist 可有且必须有 `allow_domains`。域名小写、去除末尾点、排序和去重；不接受 IP literal、URL、端口和通配符；解析后地址与 DNS 出口强制执行由 Task 10 负责。
- 默认 `limits` 为 cpu=1、memory_mib=512、pids=128、timeout_s=300；显式数值必须为正。没有服务端可信策略时，资源不得超过这四项上限且 network 只能为 none。rootfs_readonly=true、uid=65534、no_new_privileges=true 固定持久化，客户端不能覆盖。
- 请求限制 1 MiB；拒绝未知/大小写变体字段、重复对象键和尾随 JSON。缺省或 JSON null 的可选字段视为缺省；limits 的单个 null 数值也视为缺省。
- `GET /v1/runs/{id}` 返回 `{run_id,state,spec,created_at,updated_at,result,error_code,cleanup_pending,logs}`；日志 schema 见下方 Task 2。两者都先按可信租户查询 run；跨租户和未知 ID 一律 404。

租户授权在 `runs.Store.Create` 内、任何幂等查询之前执行，拒绝的请求不写 run 或 audit。通过 `Store.Policies` 注入 `PolicyProvider.PolicyForTenant(ctx, verifiedTenantID) (*Policy, error)`；策略只能来自服务端配置，不接收 body、X-Tenant 或其他请求声明。nil provider 或 nil 策略均使用全局默认上限。显式 `Policy.TenantID` 必须与已验证租户完全相同，错误/无效配置返回 503；请求超出策略返回 403。

`Policy.MaxLimits` 指定每项上限，零值继承全局默认，负值或非有限 CPU 属于配置错误；`AllowDomains` 精确列出允许的规范化域名，非空列表仅授权这些域名的 allowlist 网络，不隐含子域或通配符。`AllowedRuntimes=nil` 允许三种受支持 runtime，显式空数组全部拒绝。请求省略 runtime 仍默认 runc，若策略只允许 gvisor，调用方须显式请求 gvisor；不会偷偷切换运行时。更严格的策略也可下调上限。无论首次创建或同 key 重试，均重新查询并检查当前策略。

Task 2 worker 已调用 `Store.Authorize(ctx, storedTenantID, normalizedSpec)`，紧邻实际启动前重新授权，避免排队期间策略撤销后继续执行。provider 必须提供不可变策略快照；策略查询与排队事务不承诺分布式原子性。当前生产 main 不配置 provider，因此仅有默认限制，可信 OIDC 接入前仍全部返回 401。

审计 API 为 `(*audit.Log).Append(Event)` 与 `Verify(from,to)`；`AppendTx` 用于同 run 创建事务追加。序号从 1 开始、全局连续，哈希为 `sha256(prev_hash || canonical_json(event))`，初始 prev_hash 为 32 个零字节。`Verify` 包含区间两端，拒绝 0、反向或超过 bigint 的区间；部分验证以 from-1 的存储哈希为锚，完整验证应从 1 开始。篡改/缺失返回带 Seq 的 `IntegrityError`。UPDATE、DELETE、TRUNCATE 由数据库触发器拒绝。

Warden canonical JSON v1 明确定义为：UTF-8、唯一对象键、对象键按 Go 字符串顺序排序、无多余空白、Go encoding/json 字符串转义、数组保留顺序；最多嵌套 64 层。数字保留合法 JSON token 的原始拼写（审计 payload 的 1 与 1.0 不等价），不声称 RFC 8785。run 请求先经过类型检查/默认值/域名规范化，因此等价字段顺序和缺省值生成相同规范化 spec。追加时立即编码并保存独立字节快照，后续修改调用者 payload 不影响记录。

哈希链可检测数据变化，但无法抵抗拥有数据库超级用户权限的攻击者重写整条链；外部锚定和更严格的数据库角色划分属于后续部署工作。本地证据见 [Task 1 验证记录](docs/evidence/task-1/README.md)。

## Task 2：持久调度、恢复与日志

[实现与真实 PostgreSQL 证据](docs/evidence/task-2/scheduler/README.md)。调度默认关闭；设置 `WARDEN_SCHEDULER_CONFIG` 为可信本地 JSON 文件路径才启动后台 worker。HTTP 取消不会取消已经提交的作业；SIGTERM/SIGINT 取消 worker 并有界回收自身 handles。生产 HTTP 仍全部返回 401，不能用 tenant header 或裸 token 开通认证。

配置示例（数值必须来自实际受控 daemon，不可照抄 PID）：

```json
{
  "node": "home-ubuntu-owned-lab",
  "gate_dir": "/ABSOLUTE/PRIVATE/PERSISTENT/warden-gate",
  "concurrency": 2,
  "poll_ms": 250,
  "operation_timeout_s": 30,
  "drivers": {
    "runc": {
      "socket": "/ABSOLUTE/warden-lab/containerd.sock",
      "expected_daemon_pid": 1234,
      "trusted_owner_uid": 1000,
      "cgroup_root": "/sys/fs/cgroup/warden-lab",
      "images": {"sha256:REPLACE_WITH_64_HEX_DIGEST": "pre-imported-owned-image"}
    }
  }
}
```

`gate_dir` 必须已存在、由 worker UID 拥有且 mode 0700，祖先目录必须受操作员控制。同一 runtime node 的所有进程/driver 必须使用同一持久目录、同一已验证专用 daemon。目录内随机 authority 与 Postgres execution 绑定；换目录或复用 node 名称不会获得旧 node 的恢复权。禁止删除/轮换 run marker 或把旧目录复制到另一台 daemon 来声称恢复。当前生产构造器只支持 runc；未注册 gvisor/firecracker 明确失败，不降级。

构建后用宿主二进制及明确环境变量运行；普通 `scripts/go.sh run` 容器不提供运行时目录/daemon 的部署挂载：

```bash
./scripts/go.sh build -o .cache/warden-api ./controlplane/cmd/warden-api
# DATABASE_URL、WARDEN_LISTEN_ADDR 同上；以下路径必须是已验证的专用部署配置。
WARDEN_SCHEDULER_CONFIG=/ABSOLUTE/TRUSTED/scheduler.json ./.cache/warden-api
```

migration 2 保留原 run 和 append-only 审计。queued→starting 的 durable claim 提交成功后才允许一次 Start；提交结果不明不启动。worker 独占一个不重连的 Postgres session advisory lock；状态写入同时检查 generation、backend PID、合法前态，并与审计/结果/日志同事务提交。执行期间不持有行锁或审计 head 锁。有效 session 不会被恢复抢占；失联取消 worker，旧 session 不能重连提交旧结果。

跨进程文件 gate 在实际 Start 前 fsync `launching` marker，并持锁直到调用返回；成功确认后 fsync `started`。Reap 先持同一锁、持久撤销身份，再清理原 run；永不重启或更换 RunID。锁超时/清理失败保留 `cleanup_pending=true`，以后仅重试 Reap。进程崩溃或 Start 错误可能留下尚未完成的远端创建 RPC：此时即便 Reap 返回 not-found，marker 也保持模糊状态，API 返回 `failed` + `cleanup_pending=true`，初次 `error_code=runtime_start_ambiguous`，恢复时为 `creation_outcome_unknown`。**此状态不自动解除；只有原node kernel/disk清理证明与authority/run绑定的reconciliation可解除。固定独占lab已完成独立审查和真实两阶段永久退休验收，见[协议与边界](docs/api-runtime-lab.md)。没有通用fleet恢复或丢失证明后自动解锁接口；不能删marker，也不能把请求取消当作远端操作已停止。**

普通已确认执行的恢复在清理成功后记录 `interrupted`，日志 `lost`；清理失败记录 `failed` 且 pending。自然成功为 `succeeded`，非零退出、OOM、超时、Wait/日志失败均有安全 error code；原始内部错误、凭证和宿主路径不返回 API。`result` 为 runtime Exit 的现有 JSON 字段：`Code`, `OOMKilled`, `TimedOut`, `CgroupEmpty`, `LogsTruncated`, `DroppedLogBytes`, `PidsMaxEvents`, `PeakPids`；未得到可信 exit 时为 null。不能把 `failed` 终态等同于资源已清理，应同时检查 `cleanup_pending`。

`GET /v1/runs/{id}/logs` 最终 schema 为：

```json
{"logs":["output chunk\n"],"status":"complete","truncated":false,"dropped_bytes":0}
```

`logs` 保持 `[]string` 兼容，但数组项是 snapshot chunk，不承诺逐行分割。`status` 区分 `pending`、`not_started`、`complete`、`partial`、`lost`；正常空输出是 `complete` + `[]`。shutdown/恢复丢失不冒充完整空日志。聚合持久字符串内容最多 1 MiB；`truncated`/`dropped_bytes` 合并 runtime 与调度侧截断计数。NUL 或非 UTF-8 输出增加 `"encoding":"base64"`，所有 chunk 拼接后按 Base64 解码；编码后的持久内容也受 1 MiB 限制。其他输出是 UTF-8 且省略 encoding。日志读取超时会关闭 snapshot 并标记 lost；driver 必须遵守 context 和可关闭 snapshot 契约。

默认并发 2（上限 32）、poll 250ms、单次 DB/启动/cleanup/log snapshot deadline 30s。运行等待另受 spec timeout 与 runtime 自身 kill deadline 约束。实际 Postgres + 受控 runtime 边界测试、race、vet 已通过；这些测试不证明容器隔离或真实 API→runc 端到端执行。没有新增依赖、Azure 操作、GPU 或常驻测试服务。

## Task 2：专用本机 runtime lab

新增[固定 HTTP→PG→scheduler→runc 实验与原节点退休协议](docs/api-runtime-lab.md)已完成代码阶段：41项Python测试、capless私有PG代码测试与ABI/no-ack smoke通过。[SHA绑定证据](docs/evidence/task-2/api-runtime/README.md)。[独立代码审查](docs/evidence/task-2/api-runtime/review-code.md)与[带能力API/runc live、完整quiescence及清理证明](docs/evidence/task-2/api-runtime/live/README.md)均已通过，Task2已验收。

[lab使用与安全边界](docs/runtime-lab.md)。一次性scratch Docker镜像封装可信宿主runtime/ABI，只运行固定probe；项目内session可写，镜像输入只读。当前33项Python定向测试与无capability版本smoke通过；[真实七项 guest 全部 PASS、无 SKIP](docs/evidence/task-2/lab-live/README.md)。持久调度core及实际API→runc、模糊创建的quiescence/reconciliation均已验收，证据如上。外层live能力profile必须经独立审查，不能从smoke成功推导guest通过。

```bash
# 已有静态probe/test缓存，且项目/输入owner与mode满足文档要求时：
python3 -B scripts/runtime_lab_docker.py smoke --other-service-memory-bytes 0
python3 -B -m unittest discover -s scripts -p 'test_runtime_lab*.py'
# live一致性：
python3 -B scripts/runtime_lab_docker.py run --other-service-memory-bytes 0
```

wrapper固定本机Docker端点，先运行24GB项目磁盘/16GB合计内存guard，计入项目外owned镜像和日志；本次无其他Warden常驻服务才传0。外层硬限额4GB/512pids/2CPU，按完整ownership与精确ID回收，不使用Azure或共享containerd。
