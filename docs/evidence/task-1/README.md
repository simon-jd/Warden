# Task 1 实际验证记录

日期：2026-10-23（America/Los_Angeles）。范围：控制面本地实现、真实 Postgres 集成；首轮独立审查发现的问题已修复，[复审通过](review-final.md)（原问题见[首审记录](review-initial.md)）。不代表真实工作负载隔离、OIDC 或整个 Warden 完成。

## 实现版本与证据对应

- 前次最终验证实现 SHA：`7fb9bd73c903ff88a515160532d240318c5d276c`（2026-10-23，America/Los_Angeles）。对应 [green-final.log](green-final.log)、[vet.log](vet.log)、[vuln-after.log](vuln-after.log)；Go 1.26.10、pgx 5.11.0、x/text 0.43.0、Docker 29.9.1、Postgres 18-alpine（同本轮固定镜像 ID）。配置为独立 localhost Postgres/独立测试 schema、默认安全 spec、注入测试 claims、生产 nil 验证器。结论是当时 16 项行为测试通过；未覆盖无可信租户策略时禁止放宽，因此这些结果不代表此授权边界已验证。历史 RED 是该实现开发过程中的缺失实现快照，并非声称最终 SHA 仍应失败。
- 本轮修复实现 SHA：`7623fa52cba97d0bc8d02a1d7e68971b28ae1cf5`。先提交实现与原始日志，再由本证据提交引用这个已存在的 SHA。日期为 2026-10-23（America/Los_Angeles），[组件记录](review-1-components.log) UTC 时间为 `2026-10-24T02:24:35Z`。精确组件版本：Docker 29.9.1、Postgres 18.6、Go 1.26.10、pgx 5.11.0、x/text 0.43.0；模块全表和工具/数据库镜像 ID 均在该原始文件内。

## 环境与复现

所有命令从仓库根目录运行。Docker daemon 29.9.1；Postgres `postgres:18-alpine` 独立临时集群，监听仅 127.0.0.1 随机端口；每项测试使用随机独立 schema。测试无内存数据库替代，无跳过。`go.sh` 当前 uid/gid、只读容器根目录、cache 仅本项目，使用现有 `golang:1.26.8-bookworm` 镜像引导 `go.mod` 要求的补丁工具链。[实际 Go 版本](go-version.log)：go1.26.10 linux/amd64。

```bash
./scripts/test-postgres.sh test ./controlplane/... -count=1 -v
./scripts/test-postgres.sh test ./controlplane/... -race -count=1 -v
./scripts/go.sh vet ./controlplane/...
./scripts/go.sh run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./controlplane/...
```

脚本使用 `set -euo pipefail`；保存日志时使用 `2>&1 | tee 文件` 并开启 `set -o pipefail`，保留实际退出状态。临时数据库密码为随机值，未打印至证据。脚本 EXIT/INT/TERM trap 只清理自己的 `warden-task1-pg-*` 容器及其匿名数据卷（卷删除由本轮补修加入），不接触既有 Docker workload 或相邻目录。最终 `docker ps --filter label=warden.test=task1` 输出为空。

## RED → GREEN

- [环境初次失败](bootstrap-noexec.log)：Go 在 Docker tmpfs 默认 noexec 下无法启动测试二进制；这不是功能 RED。`go.sh` 将专用 `/tmp` tmpfs 标记 exec 后重新执行。
- [初始功能 RED](red-initial.log)：`./scripts/test-postgres.sh test ./controlplane/... -count=1 -v` 退出 1。API 缺失返回 404、审计 Append 返回 not implemented、表尚未迁移。测试代码先于实现；最小接口桩只用于让缺失行为实际失败而非编译错误。
- [首轮 GREEN](green-initial.log)：同命令退出 0；12 项初始测试通过。
- [审计头回退 RED](red-head-rollback.log)：`./scripts/test-postgres.sh test ./controlplane/internal/audit -run TestVerifyDetectsHeadSequenceRollback -count=1 -v` 退出 1，预期 seq=3，实际 nil。修复 Verify 对 head 序号小于验证终点的检查。
- [大小写字段别名 RED](red-case-alias.log)：`./scripts/test-postgres.sh test ./controlplane/internal/api -run TestRejectsCaseAliasedFields -count=1 -v` 退出 1；`CMD`/`Cmd`/`CPU` 被 Go 结构体解码当成合法字段。修复精确字段名检查，拒绝语义重复/别名。
- [null 命令参数 RED](red-null-command.log)：`./scripts/test-postgres.sh test ./controlplane/internal/api -run TestRejectsNullCommandArguments -count=1 -v` 退出 1，null 参数被静默转换为空字符串。修复原始 cmd 数组元素类型检查。
- [IP 冒充域名 RED](red-ip-domain.log)：`./scripts/test-postgres.sh test ./controlplane/internal/api -run TestRejectsIPAllowlistEntries -count=1 -v` 退出 1，127.0.0.1 与 169.254.169.254 被接受。加入 IP literal 拒绝；实际 DNS/出口限制仍由 Task 10 实施。
- [自查前一轮 race GREEN](green-race.log)：15 项通过。
- [最终 GREEN](green-final.log)：`./scripts/test-postgres.sh test ./controlplane/... -race -count=1 -v` 退出 0；16 项通过，race 无告警。API 包 1.579s，audit 包 1.437s。
- [vet](vet.log)：`./scripts/go.sh vet ./controlplane/...` 退出 0，无输出。`bash -n scripts/go.sh scripts/test-postgres.sh` 退出 0。

## 已验证的行为

- 同租户/同 key/同规范化载荷返回相同 128-bit 随机 base32 run ID；16 并发请求只落一条 run，首次创建只追加一条审计记录。
- 同 key 不同载荷返回 409；租户 B 同 key 独立创建；字段顺序、显式默认值和省略默认值等价。
- GET 与 logs 都使用租户过滤；跨租户和未知 ID 返回 404；有效所有者可读。
- 默认 network=none、只读 rootfs、uid=65534、NNP、cpu1/mem512MiB/pids128/timeout300 持久化；状态 queued，日志为空，未伪造执行完成。
- 缺失可信验证器、空 claims、无效/bare token、X-Tenant 无法绕过认证。
- run 与审计共事务；强制审计 INSERT 失败后 run 数仍为 0。
- UPDATE/DELETE/TRUNCATE 被数据库触发器实际拒绝。故意以测试数据库超级用户禁用单个触发器并篡改 seq=2 后，Verify 精确报 seq=2。
- 24 并发追加与首条记录构成连续 25 条哈希链；手工独立计算已知 JSON 的 SHA-256 fixture 比对；部分范围、缺失终点、调用者修改 payload、重复对象键均验证。

## 依赖扫描

初始锁定的 pgx v5.7.6 / x/text v0.24.0 和 Go 1.26.8 在 [扫描原始输出](vuln-before.log) 中报告 11 项可达漏洞，其中 pgx GO-2026-5004、x/text GO-2026-6629/5970、Go 标准库多项。未将初始版本当作可部署安全版本。

现锁定 pgx v5.11.0、x/text v0.43.0、Go 1.26.10；`go mod tidy` 已移除不再需要的 x/crypto。相同 govulncheck v1.9.0 再运行 [结果](vuln-after.log) 为 `No vulnerabilities found.`，退出 0。扫描结果取决于执行时 Go 漏洞库，并非未来供应链安全保证。

## 限制与下一步

- 生产 main 传入 nil 验证器，保持全部请求 401；Task 6 才会接入真实 OIDC。测试验证器只用于授权边界测试。
- 只持久化 queued run 和安全 spec。Task 2 需增加调度/状态迁移/日志写入；Task 3/4 需真实 runtime 环境。digest 为裸 `sha256:64hex` 内容地址，镜像导入/解析由运行层负责，不接受可变 tag。
- allowlist 当前实施规范化及可信租户策略授权；DNS 解析后禁止私网/metadata、网络强制隔离均未在本 Task 声称完成。
- 数据库迁移目前在启动执行；部署应分离 DDL 与应用账号。触发器不能阻止超级用户禁用保护或重写整个链，外部不可变锚定未实现。
- 部分 Verify 仅信任前一条存储哈希作为区间锚；完整验证必须从 seq=1 开始。数字规范化遵循 README 定义的 Warden JSON v1，不声称 RFC 8785。


## 独立审查 round 1 修复与实际验证

问题：前次实现只检查网络枚举和资源值为正，缺少可信租户策略，导致调用者可自行持久化 allowlist 或超过全局默认的资源。另有 `go.sh` 未转发文档指定的监听变量。两项均已修复，自查完成，等待独立复审；下列 GREEN 针对实现 SHA `7623fa52cba97d0bc8d02a1d7e68971b28ae1cf5`。

配置：与前次相同的真实独立 Postgres，所有数据库测试使用管理员仅为建临时 schema/故意篡改 fixture，不把管理员权限视为生产角色分离证明。API 使用 signed-A/signed-B 测试 claims；无策略 provider、返回 nil、租户 A 明确策略、仅 B 有策略、provider 故障/错租户/无效配置、撤销策略等均为进程内服务端注入。没有请求可自行提供策略。生产 main 仍是 nil auth 和 nil policy provider。

- [策略 RED 原始数据](review-1-red-policy.log)：`./scripts/test-postgres.sh test ./controlplane/internal/api -run TestTenantPolicy -count=1 -v`，退出 1。基于前次实现加测试/最小策略类型桩，6 组测试全部实际失败：无策略资源/网络放宽返回 201、跨租户及错误策略被忽略、policy 撤销/故障后同 key 仍 201、runtime 集合未限制。请求体 policy/tenant_id 原本由严格 schema 拒绝，新增测试同时保护这一已有边界；X-Tenant 不能挪用 B 的服务端策略。
- [策略 GREEN 原始数据](review-1-green-policy.log)：同一 focused 命令退出 0，6 组全通过，API 0.582s。明确 A 策略可持久化 gvisor、精确 api.example.com allowlist 及 CPU2/mem1024/pids256/timeout600；B、其他域名、每项超过已授权上限均 403。失败请求不产生额外 run/audit。provider 错误/错租户/空租户/无效限制/runtime/域名配置均 503。无策略网络只能 none，资源不超过 1/512/128/300。
- [全控制面 race GREEN 原始数据](review-1-green-race.log)：`./scripts/test-postgres.sh test ./controlplane/... -race -count=1 -v`，退出 0，22 项全通过，无 race 报告；API 2.257s、audit 1.454s。
- [vet 原始数据](review-1-vet.log)：`./scripts/go.sh vet ./controlplane/...`，退出 0，无输出。`bash -n scripts/go.sh scripts/test-postgres.sh` 退出 0。依赖与工具链未改变，本轮不重复已通过的可达漏洞扫描。
- 监听变量行为验证：实际在 Go 工具容器内读取变量，未启动网络服务。[RED](review-1-red-listen-env.log) 为 `WARDEN_LISTEN_ADDR=""` 并退出 1；转发后 [GREEN](review-1-green-listen-env.log) 为 `WARDEN_LISTEN_ADDR="127.0.0.1:19382"` 并退出 0。原始探针源码保存为 [review-1-listen-probe.go.txt](review-1-listen-probe.go.txt)，复现：

```bash
mkdir -p .cache/task1-listen-probe
cp docs/evidence/task-1/review-1-listen-probe.go.txt .cache/task1-listen-probe/main.go
WARDEN_LISTEN_ADDR=127.0.0.1:19382 ./scripts/go.sh run ./.cache/task1-listen-probe
```

策略接口供 Task 2：`Store.Policies` 接收 `PolicyProvider.PolicyForTenant(ctx, verifiedTenantID) (*Policy, error)`。nil 表示没有明确授权，仅继承全局默认；非 nil 返回值必须绑定同一 TenantID。MaxLimits 各项零值继承默认；AllowedRuntimes nil 允许三种、显式空集合全部拒绝；AllowDomains 精确列出可放行的域名，不隐含子域或通配符。请求 runtime 默认 runc，然后按集合授权，不静默更换 runtime。`Store.Create` 在任何事务/幂等 lookup 之前调用 `Store.Authorize`；同 key 重试仍查最新策略。Task 2 在出队启动前也须调用 Authorize，用数据库中存储的可信 tenant 重新检查。

结论边界：本轮验证控制面排队前授权，未实现运行时网络/资源隔离，未证明分布式策略存储与排队事务原子变更；排队期间撤销靠执行前重新授权处理。生产认证、执行调度、DNS/metadata 强制拒绝和数据库角色分离仍属于原记录列出的后续任务。


## 同轮补修：Postgres 匿名数据卷清理

被验证实现 SHA：`5f0920cabb4d6d495d7be19d754da3b8f14143f3`（先提交脚本修复/原始日志，再由本证据提交引用）。日期：2026-10-23 America/Los_Angeles；组件与 [review-1-components.log](review-1-components.log) 相同：Docker29.9.1、Postgres18.6、Go1.26.10。未修改 Go 控制面或依赖；前述 22 项 race/vet 结果对应相同 Go 源码，额外验证仅针对改动后的 harness 清理行为。

问题与配置：Postgres 镜像声明 `/var/lib/postgresql` 为匿名 volume；原 `docker rm -f` 删除容器会留下它。harness 现改为 `docker rm -f -v "$name"`，只删除它本次创建的容器及其匿名数据卷，无 volume prune 或其他全局清理。

精确命令：`./scripts/check-test-postgres-cleanup.sh`。脚本的 Docker 观察包装器仍执行真实 Docker 调用，仅在本次 `warden.test=task1` 容器创建后记录其容器 ID 和 inspect 的 Mount.Name，不查询其他容器/卷。harness 运行 `go version` 后退出，探针只检查记录的容器与数据卷；错误必须包含 `no such volume` 才判定卷已删除，其他 Docker 错误不能假装成功。

- [RED 原始数据](review-1-red-volume-cleanup.log)：退出 1。本次容器 `c6b472d583696e15492c16132e1ed2daf270479d9e23f5969577f343728d5ce5` 的实际卷为 `0ea3fcb6371b24f27c4c55cf8d41eaf7c379047c5d9e040010d4c20e4d8ea356`；容器退出后该卷仍存在。探针 EXIT trap 随后只删除这个由本次容器 Mount.Name 直接证明归属的测试遗留卷。
- [GREEN 原始数据](review-1-green-volume-cleanup.log)：退出 0。本次容器 `add9514d3c1923be393f03100a502308374eeeb0e18ed6da1e5eb5f98e541cf1` 的实际卷为 `d4fc8021c411db7f964ec23c7ef773e98bf189de6bb41bc3dde94998ea2aab8c`；harness 退出后 volume inspect 返回该 ID 的 `no such volume`，证明本次匿名卷被清理。
- `bash -n scripts/go.sh scripts/test-postgres.sh scripts/check-test-postgres-cleanup.sh` 退出 0。

观察边界：只证明本次新建容器的已记录卷会被清理。历史匿名卷没有可验证的容器归属，因此未删除任何未知历史卷；不将已有历史遗留描述为已清理。
