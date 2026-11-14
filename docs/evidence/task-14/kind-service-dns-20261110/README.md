# kind 上的 ClusterIP Service 和集群 DNS：阻塞 10 重跑（2026-11-10，home-ubuntu）

**结论：宿主 inotify 上限是 512 / 524288 时，kind 节点里的 kube-proxy 正常（Ready、0 次重启、日志里没有 `too many open files`），ClusterIP Service 和集群 DNS 都能用。阻塞 10 解决了。**

## 运行

- worktree `~/Desktop/Warden-task3`，分支 `task3-gvisor`。源码是 `c748a9d` 加上和这些证据一起提交的改动：新增 `TestKindServiceAndDNS`，Makefile 加了 `SERVICE_OUT`，改了注释。
- 18:26:17–18:28:51 PST：`make test-kind KIND_OUT=… JIT_OUT=… TERMINATE_OUT=… SERVICE_OUT=…`，日志在 [test-kind.log](test-kind.log)。kind v0.33.0，节点镜像 `kindest/node:v1.34.11@sha256:44e222ee…`，集群 `warden-respond`，网络 `warden-kind`，都是 `scripts/kind_lab.sh` 建的，结束时删掉。
- 在这之前有一次没跑起来（18:25:02–18:25:37，[test-kind-attempt1.log](test-kind-attempt1.log)）。那次用的是 worktree 的包装脚本 `.cache/mk.sh`。集群建好了，但 go 没有启动：`go: parsing $GOFLAGS: unterminated ' string`。原因是包装脚本在 GOENV 里写了 `GOFLAGS='-mod=readonly -buildvcs=false'`，`scripts/test-postgres.sh` 用 `read -ra` 拆 `$GO` 时不认引号。这次一个测试都没跑，集群被 trap 删掉了。第二次直接用 `make test-kind`，也就是 Makefile 自己的 GOENV（`GOFLAGS=-mod=readonly`）。`go test` 不写 VCS 信息，所以不需要 `-buildvcs=false`。

## TestKindServiceAndDNS（[service.json](service.json)）

| 项目 | 结果 |
|---|---|
| 宿主 inotify（测试读 `/proc/sys/fs/inotify`） | `max_user_instances` 512，`max_user_watches` 524288 |
| kube-proxy | 1 个 pod，Ready，重启 0 次，日志里 `too many open files` 0 行 |
| CoreDNS | 2/2 Ready |
| Service | `svc-server`，ClusterIP 10.96.18.247，名字 `svc-server.warden-sandbox.svc.cluster.local`，80 → 8080 |
| 第一次探测 | 三条路径的第一次尝试就成功了（`first_ok_after_first_attempt_ms` 都是 0） |
| 10 s 窗口，每次都新建 TCP 连接 | pod IP（对照，不经过 kube-proxy）174 次成功 / 0 次失败；ClusterIP 175 / 0；DNS 名字 175 / 0 |

PASS。这个测试检查的是环境，没有要改的代码，所以没有 RED 这一步，第一次跑就通过了。其他 live 测试还是直接探 pod IP，测量不经过 kube-proxy。

## 同一次 make test-kind 里的其他测试

`make test-kind` 退出码不是 0，因为 TerminatePod 那一项 FAIL 了，和以前一样，阈值没改。下面的 p50 和 p95 都是最近秩：n 个值排序后取第 ⌈p·n/100⌉ 个（`respond/kindlab` 的 `nearestRank`，`controlplane/internal/jit` 的 `p50p95` 同样算），不是算术中位数。
- `TestKindIsolatePodAndCordonNode` **PASS**（[kind.json](kind.json)）：10 个告警，从告警到两个方向的新连接都被拦，p50 55.2 ms、p95 79.8 ms（10 个值里的第 5 个和第 10 个；算术中位数是 58.4 ms，从 [kind.json](kind.json) 的 `runs` 重算）；对照路径 0 次失败；重放 10/10 都是 no-op；隔离前建立的连接在隔离后 1–10 s 里 90/90 个样本仍然可用（和 phase 5 的发现一样）。CordonNode 从告警到新 pod Unschedulable 175.7 ms。
- `TestKindTerminateClosesEstablishedConnections` **FAIL**（[terminate.json](terminate.json)）：不理会 SIGTERM 的 5 个目标，对端看到连接关闭用了 2044.5–2072.3 ms（p50 2065.7 ms），要求是 ≤ 1000 ms。会配合退出的目标 p50 52.2 ms。pod 对象最多 82.3 ms 就没了。
- `controlplane/internal/jit` **PASS**（[jit.json](jit.json)）：5 次授权，批准到 RoleBinding 生效 p50 8.6 ms，到期到删除 p50 11.1 ms。

## 宿主、负载和清理

- 宿主快照（受保护的 sysctl 和模块列表哈希）：18:25:02（[host-before.txt](host-before.txt)，第一次尝试之前）和 18:29:07（[host-after.txt](host-after.txt)）一样。完整模块列表前后的 sha256 也一样（[modules.sha256](modules.sha256)）。kind 节点也是特权容器，这次没有多加载模块。
- load average（32 核，同时有其他项目在跑）：18:25:02 是 8.72、6.03、3.99（[before.txt](before.txt)）；18:26:17 是 8.42、6.60、4.35（[before-attempt2.txt](before-attempt2.txt)）；18:29:07 是 2.32、5.18、4.23（[after.txt](after.txt)）。每个测试开始和结束时的值写在各自的 JSON 里。
- materialflow 的 kind 集群没有动过：前后 `kind get clusters` 都只有 `materialflow`（[clusters-before.txt](clusters-before.txt)、[clusters-after.txt](clusters-after.txt)），它的容器 ID 前后一样（[materialflow-before.txt](materialflow-before.txt)、[materialflow-after.txt](materialflow-after.txt)）。
- 结束后没有 `warden` 开头的容器和网络：kind 集群、`warden-kind` 网络和临时 Postgres 都删了，`.cache/kind` 是空的。
