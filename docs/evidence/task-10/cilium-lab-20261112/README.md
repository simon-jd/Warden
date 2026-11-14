# Cilium 上的 k3s + gVisor lab：Task 10、7、14 的 Cilium 部分（2026-11-12 至 11-13，home-ubuntu）

用户 2026-11-11 允许 lab 在宿主上加载 Cilium 需要的内核模块以后，Task 3 的 k3s + gVisor lab 有了 Cilium 模式（`scripts/k3s_gvisor_lab.sh up --cilium`，`make test-cilium`），三个任务的 Cilium 部分都在上面实测了。

- **Task 10：PASS。** `TestSandboxReachesOnlyTheEgressProxy` 在 `3a4f8a8`（runs/05-task10）和 `5c436a8`（runs/09-all，新起的 lab）上都是 40/40。沙箱（gVisor pod，`warden.dev/sandbox=true`）在 `default-deny.yaml` 和 `egress-proxy.yaml` 下只能到出口代理，出不出去由代理的白名单决定；同样的探测在策略之前全部能通（正对照），不带沙箱标签的对照 pod 在策略下也能通。
- **Task 7：PASS。** `TestSandboxCannotReachMetadata` 在 `3d92aae`（runs/07-task7）和 `5c436a8`（runs/09-all）上都是 33/33。lab 里用 169.254.169.254 上的替身当 metadata 端点；没有策略时沙箱按地址、按名字、经代理三种方式都拿到它的回答（正对照），有 `deny-metadata.yaml` 时三种都拿不到，删掉策略后又能拿到。
- **Task 14：按 Cilium 默认配置 FAIL，改配置后 PASS。** `IsolatePod`（打 `warden.dev/quarantine=true` 标签，`quarantine.yaml` 生效）**会切断**告警前建立的连接，12/12。但用 Cilium 的默认配置，告警到切断 p50 24232.0 ms、p95 32452.4 ms（最近秩，n=12，p95 就是最大值），**0/12 在 1 s 内**（runs/08-task14）。原因是 Cilium 给打了新标签的 pod 换安全身份要先等一个最多 30 s 的随机延迟（`identity-max-jitter`），再等 5 s（`identity-change-grace-period`）。lab 的 Cilium 配置把这两个都设成 0（`5c436a8`）以后，在新起的 lab 上 12/12 在 1 s 内切断，p50 318.0 ms、p95 356.0 ms（runs/09-all）。1 s 的要求没有改；默认配置下的 FAIL 照原样保留。
- **宿主的改动**（详见下面两节）：Warden 的 Cilium lab 一共让宿主加载了 10 个内核模块（2026-11-10 的 4 个和 2026-11-12 的 6 个）；**2026-11-12 的第一次运行还改了两个全局 sysctl**：`kernel.timer_migration` 1→0、`kernel.unprivileged_bpf_disabled` 2→1。之后加了防护，第二、三次运行宿主的 sysctl 没有变。

## 环境

- worktree `~/Desktop/Warden-next`，分支 `next-round`。lab 的代码在 `91a4429..dea027e`（oci_fetch、warden-node-init、world.py、探针的 net/stream 模式、restore-tools 的 helm 和 Cilium、`--cilium` 模式）和 `3681bc4..5c436a8`（见下面各节）。
- home-ubuntu：内核 7.0.0-42-generic，32 核，同时有其他项目在跑。lab 的容器都钉在 CPU 0-7、16-31（`WARDEN_LAB_CPUSET`），`make` 用 `taskset -c 0-7,16-31` 跑。
- k3s v1.36.5+k3s1，gVisor release-20261019.0。沙箱 pod 用 RuntimeClass `gvisor-netstack`（runsc `network=sandbox`，gVisor 自己的协议栈接在 pod 的 veth 上，所以 Cilium 的 BPF 管得到它）。
- Cilium 1.20.4（`beb276d2`，[cilium-version.txt](lab-run3/cilium-version.txt)）。chart 和镜像按 digest 取（`scripts/restore-tools.sh helm|cilium`，删除前的 receipt 在 [final/receipts](final/receipts)），helm v3.22.1 只用来 `helm template`。配置在 `runtimes/gvisor/lab/cilium/values.yaml`：kube-proxy replacement、原生路由、BPF masquerade 和 host routing、装 iptables 规则、L7 proxy（DNS 代理要用）、`devices: [eth0, eth1]`；`5c436a8` 起加了 `identityChangeGracePeriod: "0s"` 和 `identity-max-jitter: "0s"`（见 Task 14）。
- 节点：PID 1 是 `warden-node-init`（`/proc/sys` 只读，`/proc/sys/net` 除外）；chart 里所有挂节点 `/proc` 的地方都改成只读（`readonly_proc_mounts.py`，`3681bc4`、`082cc71`）；节点自己的网络命名空间里 `src_valid_mark=0`（`e50da44`，原因见 Task 10）。
- “外面”：`--internal` 网络 `warden-k3s-world`（198.18.18.0/24，不是 RFC 1918，Cilium 把它当 world），上面是 `world.py` 的替身：`.20` 放行源站 `origin-allowed`、`.21` 拦截源站 `origin-blocked`、`.22` 长连接 stream 服务、`.30` metadata 替身（169.254.169.254 在它自己的 lo 上，只有节点把 169.254.169.254/32 路由到 `.30`）、`.40` 记录每个查询的 DNS（外泄的终点）。lab 的 CoreDNS 只认这几个名字（`allowed.warden.test`、`blocked.warden.test`、`stream.warden.test`、`metadata.google.internal`，`exfil.warden.test` 转给 `.40`），别的都是 NXDOMAIN。
- 出口代理：Envoy v1.40.2，bootstrap 和监听器都是 `controlplane/internal/scheduler` 生成的，按沙箱源地址授权（和 Docker 版出口 lab 一样），在 `warden-system/warden-egress`。

## lab 的几次运行

| 运行 | 时间（PST） | 源码 | 做了什么 | up / down | 宿主 |
|---|---|---|---|---|---|
| run 1（[lab-run1-1945](lab-run1-1945)） | 11-12 19:45 – 23:26 | 未提交的工作区（`dea027e` 19:57 才提交），没有记录 | 调试，留下一个 `spike-s1` pod | up 成功；**down 失败：两个 sysctl 变了**（[down.log](lab-run1-1945/down.log)） | Cilium 启动时多加载 6 个模块；`kernel.timer_migration` 1→0、`kernel.unprivileged_bpf_disabled` 2→1 |
| run 2 第一次（[lab-run2-attempt1](lab-run2-attempt1)） | 23:34 | `3681bc4` | up 在 `readonly_proc_mounts.py` 失败（`kubectl` 打出的 JSON 是多个对象，`082cc71` 修） | up 失败，down 成功 | 没有变化 |
| run 2（[lab-run2](lab-run2)） | 11-12 23:36 – 11-13 08:27 | up 时 `082cc71` | runs/01–08，以及 [spikes](spikes) | 都成功 | 模块没有变化；完整 sysctl 只有计数器变了 |
| run 3（[lab-run3](lab-run3)） | 11-13 08:28 – 08:36 | `5c436a8` | runs/09-all：`make test-cilium`，即 `run --cilium`（up、所有测试、down） | 都成功 | 模块没有变化；完整 sysctl 只有计数器变了 |

run 2 在 runs/08 之后被我手动改过两次 Cilium 配置（spikes s6、s7：改 `cilium-config` 再重启 agent），之后只跑了 spike，没有再跑测试。

run 2 的节点是在 `e50da44` 之前起的。runs/02 之后（11-12 23:59），节点自己的命名空间是用 `docker exec warden-k3s-gvisor sysctl -w net.ipv4.conf.all.src_valid_mark=0` 手动设成 0 的，宿主的值没有动（[diagnosis.txt](runs/02-task10/diagnosis.txt)）。所以 runs/03–08 跑在这个手动改过的节点上；提交的修复 `e50da44` 是 run 3 新起的 lab（runs/09-all）验证的。

## Task 10：沙箱只能到出口代理

`controlplane/internal/ciliumlab/egress_test.go` 的 `TestSandboxReachesOnlyTheEgressProxy`。三个 pod：`egr-a`（沙箱，代理给它的源地址授权 `allowed.warden.test`）、`egr-b`（沙箱，没有授权）、`egr-ctl`（不带沙箱标签，对照）。先在没有策略时跑一遍全部探测，再应用 `default-deny.yaml` 和 `egress-proxy.yaml`（等 agent 的策略版本在所有端点上生效；runs/09-all 里每份约 0.43–0.45 s），再跑一遍。每个请求带随机的 nonce，替身的日志说明哪些请求真的到了。

| 探测（`egr-a`） | 没有策略（正对照） | 有策略（runs/05、09） |
|---|---|---|
| 经代理 CONNECT / HTTP 到 `allowed.warden.test` | 200，`origin-allowed` | 200，`origin-allowed`（源站日志里有 Host 为 `allowed.warden.test` 的请求） |
| 经代理到 `blocked.warden.test` | 代理 403 | 代理 403 |
| 直连 `.20`、`.21`（HTTP）、`.22:443`、API server（10.43.0.1:443）、节点（:6443）、169.254.169.254 | 都通 | 都是连接超时 |
| 直连 `blocked.warden.test`（先解析） | 通 | 解析失败（Cilium 的 DNS 代理只放行代理的名字） |
| DNS TXT 外泄：经集群 DNS / 直接问 `.40` | 都拿到 sink 的 TXT，sink 日志有两条 | REFUSED（rcode 5）/ 超时；sink 日志里没有 |
| 解析代理的名字 | 通 | 通（唯一放行的名字） |
| `egr-b`：连代理 TCP / 经代理 CONNECT | 通 / 代理断开（没有授权） | 通 / 代理断开 |
| `egr-ctl`（对照）直连 `.21`、TXT 外泄 | — | 都通，日志里只有对照的这两条 |

没有探测的：从沙箱到别的 pod 的 IP（例如另一个沙箱）和到节点上的 kubelet（:10250）。策略只放行 DNS 和代理，但这两类目的地没有实测。

运行（都在 run 2，源码见各自 run.log 的第一行）：

| 运行 | 源码 | 结果 | 原因和处理 |
|---|---|---|---|
| [01](runs/01-task10/run.log) | `b76d6a4` + 未提交的测试 | FAIL | 测试框架的“策略已生效”判断一直不成立（60 s 超时），改了框架（提交在 `c15fa66`） |
| [02](runs/02-task10) | 同上 | FAIL 32/40 | 有策略时 DNS 全部超时。Cilium 用 TPROXY 把查询转给自己的 DNS 代理，但节点的网络命名空间从宿主继承了 `src_valid_mark=1`，带标记的包反向路径查到本地路由，被当成 martian 丢掉（[diagnosis.txt](runs/02-task10/diagnosis.txt)）。`e50da44`：节点自己的命名空间设 `src_valid_mark=0`（宿主的不动） |
| [03](runs/03-task10)、[04](runs/04-task10) | `e50da44` + 未提交的测试 | FAIL 33/40 | 代理收不到沙箱的连接：`egress-proxy.yaml` 的入站规则在命名空间级策略里，选择器不带命名空间就只匹配 `warden-system` 里的 pod（[monitor-drops.txt](runs/04-task10/monitor-drops.txt)）。`3a4f8a8`：规则改成任何命名空间的沙箱，加离线检查 |
| [05](runs/05-task10) | `3a4f8a8` | **PASS 40/40** | |
| [09-all](runs/09-all) | `5c436a8`（新起的 lab） | **PASS 40/40** | |

## Task 7：沙箱拿不到 metadata

`metadata_test.go` 的 `TestSandboxCannotReachMetadata`。lab 原来没有 metadata 端点，所以先做了一个：`warden-k3s-imds` 在自己的 lo 上加 169.254.169.254，回答 `warden-lab-imds`；节点把 169.254.169.254/32 路由过去，CoreDNS 把 `metadata.google.internal` 解析到它。沙箱 `md-a` 的代理授权里**故意包括** `metadata.google.internal`，这样挡住代理那条路的只能是策略。

1. 没有策略：按地址、按名字、经代理三种都拿到 `warden-lab-imds`，替身日志里有这三个请求（正对照）；源站、DNS、经代理到 `allowed.warden.test` 也都通。
2. 只应用 `deny-metadata.yaml`：三种都拿不到（直连超时；名字仍然解析成 169.254.169.254，挡的是地址；代理连不上，探测读超时），替身日志里没有请求；同时源站、DNS、经代理的放行请求照样通（这份策略只拒绝，不该挡别的）。
3. 删掉策略：三种又都拿到（排除“替身坏了”）。
4. 三份策略一起（`default-deny`、`egress-proxy`、`deny-metadata`）：metadata 三种都拿不到，直连源站也不通，只有经代理的放行请求到了源站。

| 运行 | 源码 | 结果 |
|---|---|---|
| [06](runs/06-task7) | `3a4f8a8` + 未提交的测试 | FAIL 19/25：只应用 `deny-metadata.yaml` 时，连对照（源站、DNS、代理）都断了。Cilium 只要策略有出站规则（包括只有 deny 的）就把选中的端点放进默认拒绝，除非策略关掉它。`3d92aae`：两份文档都设 `enableDefaultDeny: false`，离线检查要求这一点 |
| [07](runs/07-task7) | `3d92aae` | **PASS 33/33** |
| [09-all](runs/09-all) | `5c436a8` | **PASS 33/33** |

## Task 14：IsolatePod 切断告警前建立的连接

`quarantine_test.go` 的 `TestQuarantineCutsEstablishedConnections`。三份策略都在（`default-deny`、`egress-proxy`、`quarantine`）。告警交给 `respond.Executor`，经真实的 `respond.Kubernetes` 适配器给 pod 打标签；适配器用的令牌属于只能 get/patch 沙箱命名空间 pod 的 ServiceAccount（10 分钟 TokenRequest；delete pod、exec、读 secret、改 kube-system 的 pod、删 Cilium 策略都被拒，记录在结果的 `responder_rbac`）。

- 每个 rep 新建一个 gVisor 沙箱，它唯一的长连接经出口代理（CONNECT `stream.warden.test:443`）连到 stream 服务，两个方向每 20 ms 各一行。告警前确认这条连接在过去 1 s 两个方向都有数据，并且从这个沙箱新发一个经代理的请求能到源站（正对照）。
- 计时从告警交给 executor（调用 `Handle` 之前）开始，到这条连接最后一行数据（任一方向）为止；连续 5 s 两个方向都没有数据才算切断，最多看 60 s。要求：最后一行在告警后 1000 ms 以内。
- 对照：另一个沙箱 `q-ctl` 自己的流经同一个代理，整个测试一直开着，每个 rep 里两个方向都不能断开超过 1 s，也不能被关闭。
- 切断后：从目标沙箱新发请求必须失败；同一告警重放必须是 no-op；第一个 rep 先 dry run（Preview，不打标签，1.5 s 内流量照常）。
- 同时每约 0.25 s 读一次 Cilium 端点（`cilium-dbg endpoint list`），看它的安全身份什么时候带上隔离标签。记录的是每次轮询**开始**的时刻，轮询本身（一次 `kubectl exec` 加 `cilium-dbg`）要多少时间没有记，所以身份变化发生在“最后一次没带标签的轮询开始”之后、“第一次带标签的轮询拿到回答”之前。

| 度量（12 个 rep，最近秩） | [08](runs/08-task14)：Cilium 默认配置，`be0fd0f`，run 2 | [09-all](runs/09-all)：身份设置为 0，`5c436a8`，run 3 |
|---|---|---|
| **告警 → 切断 p50 / p95 / min / max（ms）** | **24232.0 / 32452.4 / 10146.2 / 32452.4** | **318.0 / 356.0 / 299.5 / 356.0** |
| **1 s 内切断（要求）** | **0/12，FAIL** | **12/12，PASS** |
| 切断（5 s 没有数据） | 12/12 | 12/12 |
| 上行最后一行 p50 / max（ms） | 24074.0 / 32249.4 | 104.3 / 131.0 |
| 下行最后一行 p50 / max（ms） | 24232.0 / 32452.4 | 318.0 / 356.0 |
| 第一次看到身份带标签的轮询，开始于（ms） | 9916.5–32194.6；最后一行都在它之后 0.18–0.38 s | 每个 rep 的第一次轮询（开始于告警后 0–0.1 ms）就已带标签 |
| executor `Handle` p50 / max（ms） | 25.2 / 26.6 | 26.0 / 26.7 |
| 对照流最大间隔：上行 / 下行（ms） | 450.8 / 48.0 | 298.9 / 25.0 |
| 告警前新请求能到 / 切断后新请求失败 / 重放 no-op | 12/12 / 12/12 / 12/12 | 12/12 / 12/12 / 12/12 |
| load average（开始 → 结束，1 分钟） | 11.76 → 11.39 | 3.40 → 2.71 |

**runs/09-all 的 JSON 里身份字段不是测量值。** 每个 rep 的第一次轮询就已带标签，所以这次运行没有记下告警前的身份：`reps_detail[*].identity.before` 是 0，`last_poll_without_label_ms` 约为 −1.79×10¹² ms（没有这样一次轮询时的零时间减去告警时刻），`summary.alert_to_identity_with_label_ms`（p50 0.1 ms）只是第一次轮询的开始时刻，不是测到的身份切换。切断的计时不受影响。runs/08 的这些字段是真实的（例如 rep 00：before 63475，最后一次没带标签的轮询开始于 12443.4 ms）。`63cf71f` 之后，没有对应轮询的字段写成 null，汇总只算前面有一次没带标签轮询的 rep，其余的计入 `identity_labelled_on_first_poll`；已提交的 JSON 没有改。

逐个 rep（ms）：

| rep | 08：告警 → 切断 | 08：上行 / 下行最后一行 | 08：第一次带标签的轮询开始于（前一次没带标签的开始于） | 09：告警 → 切断 | 09：上行 / 下行最后一行 |
|---|---|---|---|---|---|
| 00 | 12879.2 | 12665.2 / 12879.2 | 12677.0（12443.4） | 330.2 | 116.2 / 330.2 |
| 01 | 28622.2 | 28402.2 / 28622.2 | 28399.6（28150.5） | 347.1 | 121.1 / 347.1 |
| 02 | 27953.2 | 27714.2 / 27953.2 | 27752.1（27496.9） | 299.5 | 71.5 / 299.5 |
| 03 | 28966.9 | 28737.9 / 28966.9 | 28787.1（28558.9） | 317.4 | 92.4 / 317.4 |
| 04 | 26864.0 | 26638.0 / 26864.0 | 26528.0（26265.7） | 356.0 | 131.0 / 356.0 |
| 05 | 20302.8 | 20066.8 / 20302.8 | 19923.6（19672.1） | 345.6 | 118.6 / 345.6 |
| 06 | 29358.2 | 29167.2 / 29358.2 | 29094.4（28840.6） | 302.8 | 75.8 / 302.8 |
| 07 | 24232.0 | 24074.0 / 24232.0 | 24039.1（23790.4） | 318.0 | 92.0 / 318.0 |
| 08 | 32452.4 | 32249.4 / 32452.4 | 32194.6（31951.7） | 342.9 | 115.9 / 342.9 |
| 09 | 14465.8 | 14253.8 / 14465.8 | 14136.4（13893.2） | 309.3 | 104.3 / 309.3 |
| 10 | 16430.9 | 16208.9 / 16430.9 | 16187.0（15959.0） | 324.6 | 118.6 / 324.6 |
| 11 | 10146.2 | 9938.2 / 10146.2 | 9916.5（9678.3） | 304.1 | 79.1 / 304.1 |

**为什么默认配置慢。** 标签本身很快就打上了（`Handle` 约 25 ms），慢在 Cilium：quarantine 策略按标签选端点，端点要换成一个带隔离标签的新安全身份，策略才对它生效；runs/08 里每个 rep 的最后一行都在第一次带标签的轮询开始后 0.18–0.38 s。agent 的 `--help` 里有两个默认值：`identity-max-jitter`（30 s，“开始处理 CiliumIdentity 更新前的最大随机延迟”）和 `identity-change-grace-period`（5 s，“端点身份变化后多久才用新身份”）。在 run 2 上逐个验证（[spikes](spikes)，`idlatency.sh`：打标签后每次轮询端点直到身份带标签）：

| spike | 配置 | 标签 → 身份带标签（轮询开始时刻，s） |
|---|---|---|
| [s5-default](spikes/s5-default/result.txt) | 默认 | 15.5、9.9 |
| [s6-jitter0](spikes/s6-jitter0/result.txt) | `identity-max-jitter=0s` | 5.1、5.0、5.0 |
| [s7-jitter0-grace0](spikes/s7-jitter0-grace0/result.txt) | 再加 `identity-change-grace-period=0s` | 0.12、0.10、0.11、0.12（都是第一次轮询） |

更早的三个手动 spike：[s1](spikes/s1.out)（[spike1.sh](spikes/spike1.sh)）是不经代理的直连流，只应用了 `quarantine.yaml`：标签打上后的 10.2 s 里两个方向一直通（最长间隔 22 ms），然后撤掉标签，对照流也没断（`analyze.py s1 st-t st-c`）；[s2](spikes/s2) 里标签打上 8.7 s 后身份还没变，这时从这个 pod 新建连接也照样成功；[s4](spikes/s4.out) 是不经代理的直连流：标签打上约 10 s 后身份变了（最后一次没带标签的轮询在 +9.99 s 返回，第一次带标签的在 +10.64 s 返回），流的最后一行在 +10.05 s（上行）和 +10.27 s（下行），对照流一直没断（[s4/poll](spikes/s4/poll)，`analyze.py s4 st4-t st4-c`）。

**改动。** `5c436a8` 在 lab 的 `values.yaml` 里把两个都设成 0，离线检查 `TestLabCiliumTakesLabelChangesInAtOnce`（RED/GREEN 在 [red-green/14-*](red-green)，GREEN 里有渲染出的 `cilium-config`）。代价（单节点 lab 上测不出来，没有测）：命名空间的标签一变，所有 agent 会同时去分配身份，没有错开；端点可能在别的节点知道它的新身份之前就开始用它，那些节点上的策略会短暂丢它的包。对被隔离的 pod 这是想要的，对别的标签变化不是。

**“切断”是什么。** 连接是被丢包，不是被关闭：两次运行里探针都没有看到连接关闭，stream 服务也没有记录关闭；切断后的新请求失败在解析代理名字（隔离连 DNS 也拒绝）。下行的最后一行比上行晚约 200 ms（runs/09），原因没查。

**判定。** 按计划的要求（1 s 内切断已建立的连接），Cilium 默认配置是 **FAIL**（runs/08），改了身份设置后是 **PASS**（runs/09-all）。两次的条件都只是这个单节点 lab：12 个 rep、经出口代理的连接、gVisor netstack 沙箱。只看了出站建立的连接（默认拒绝下沙箱没有入站连接）；不经代理的直连只有 spike s4 一次（默认配置）。

## 宿主：内核模块

lab 在每个阶段记录宿主加载的模块：`up` 开始时（`modules-before.txt`）、节点注册后（`modules-at-node-registered.txt`）、Cilium 就绪后（`modules-at-cilium-ready.txt`）、`up` 结束（`modules-at-up.txt`）、`down`（`modules-after.txt`）；run 1 之前 19:32 还有一份基线，每次运行前后我另外记了宿主的列表。[modules-attribution.sh](modules-attribution.sh) 把这些列表都按字节重新排序，逐段列出多出来和少了的模块（[modules-attribution.txt](modules-attribution.txt)）。

**怎么区分 lab 加载的和同一台机器上别的活动加载的：**
1. 时间窗。一个模块只有在 lab 的某个阶段之间出现，而且那个阶段里 lab 只在做一件事，才算 lab 的。2026-11-12 的 6 个都出现在 run 1 的“节点注册 → Cilium 就绪”之间（约 2 分钟，这时 lab 只在装 Cilium）；其他所有 lab 阶段都没有新模块。同一时期别的活动也在加载模块：11-10 17:57 之后到 11-12 基线之间多了 `btrfs`、`xfs`、`hfs`、`sch_netem`、`sch_tbf`、`tcp_bbr` 等 17 个。这段时间 Warden 的 lab 跑过，记了宿主模块列表的几次前后完全一样，所以不是它们加载的：11-10 的 Task 7 k3s lab（[identity-k3s-20261110](../../task-7/identity-k3s-20261110/modules.sha256)）、Task 14 kind lab（[kind-service-dns-20261110](../../task-14/kind-service-dns-20261110/modules.sha256)）和 Task 3 的 k3s + gVisor lab（18:32 [followups](../../task-3/followups-20261110/postflight.txt)、21:04 [review-fixes](../../task-3/review-fixes-20261110/conformance-rerun.log)），前后的 `modules_sha256` 都是 `9e93ec2d…`；11-12 09:28 的 Task 3 lab（[minor-fixes](../../task-3/minor-fixes-20261112/conformance-rerun.log)）前后都是 `ac85847d…`。Firecracker lab 不记模块列表，但它有记录的运行都在 11-10 15:24–17:14 PST（[payload-acl-20261110](../../task-4/payload-acl-20261110)、[live-20261110](../../task-4/live-20261110)；那里的时间有的是 UTC），在这段时间之前，而 17:57 的列表里没有这 17 个。
2. 功能对得上。这 6 个正好是 Cilium 数据面用的：`sch_ingress`、`cls_bpf`（tc BPF），`xt_TPROXY` 和它依赖的 `nf_tproxy_ipv4/6`（把流量转给代理的 iptables 规则，诊断里看到的 DNS 代理规则就是它），`xt_CT`（CT/notrack 规则）。
3. 引用计数。`xt_TPROXY`、`xt_CT`、`xt_socket` 只在 lab 的 Cilium 运行时被引用（2、3、1），lab 的节点删除约 2 分钟后都回到 0（[lab-run3/module-refcounts.txt](lab-run3/module-refcounts.txt)、[module-refcounts-after.txt](lab-run3/module-refcounts-after.txt)，每 10 s 一次）。现在它们都没人用（[final/proc-modules-final.txt](final/proc-modules-final.txt)）。

**run 1 的 `modules-added.txt` 是错的。** 它列了 `snd_soc_hda_codec`、`usb_storage`、`nf_tables` 等 15 个，`modules-removed.txt` 列了 9 个，有的两边都有。原因：19:45 的脚本还没有 `export LC_ALL=C`（`dea027e` 加的），`modules-before.txt` 是按用户的 locale 排序的，`down` 时 `comm` 比的是两种顺序（[down.log](lab-run1-1945/down.log) 里有 `comm: file 1 is not in sorted order`）。按字节重新排序后，这些模块在前后两个列表里都有，一直是加载着的，不是 lab 加的。文件原样保留。

**Warden 的 Cilium lab 加载的模块，一共 10 个：**

| 日期 | 模块 | 证据 |
|---|---|---|
| 2026-11-10（第二次尝试） | `geneve`、`xt_socket`、`nf_socket_ipv4`、`nf_socket_ipv6` | [../cilium-k3s-20261110](../cilium-k3s-20261110/README.md)（lab 前后的列表正好差这 4 个） |
| 2026-11-12（run 1，Cilium 启动时） | `cls_bpf`、`sch_ingress`、`xt_TPROXY`、`nf_tproxy_ipv4`、`nf_tproxy_ipv6`、`xt_CT` | modules-attribution.txt 的 “run 1: node registered -> Cilium ready” |

run 2、run 3 都没有再加载新模块（需要的都已经在了）。用户要卸载的话（需要 root；也可以重启）：

```sh
sudo modprobe -r xt_TPROXY xt_socket xt_CT cls_bpf sch_ingress geneve
# modprobe -r 会顺带卸掉不再被用的依赖 nf_tproxy_ipv4/6 和 nf_socket_ipv4/6；检查：
grep -E '^(xt_TPROXY|nf_tproxy_ipv4|nf_tproxy_ipv6|xt_socket|nf_socket_ipv4|nf_socket_ipv6|xt_CT|cls_bpf|sch_ingress|geneve) ' /proc/modules
```

**不算 Warden 的：** `nft_masq` 出现在 19:32 基线和 run 1 开始（约 19:45，`up` 一开始就记 `modules-before.txt`）之间，这段时间没有 lab 在跑，记录说明不了是谁加载的；Warden 的 lab 用的是 Docker 的 internal 网络和 Cilium 的 BPF masquerade，不用 nftables 的 masquerade。现在引用计数 0。`vxlan`、`xt_mark`、`ip_set` 在 2026-11-10 的 lab 之前就有了（`xt_mark` 在 lab 运行时多 2 个引用，lab 拆掉后回到 6，那 6 个是别人的）。

## 宿主：sysctl

- **run 1 改了两个全局 sysctl：`kernel.timer_migration` 1→0，`kernel.unprivileged_bpf_disabled` 2→1**（[host-before.txt](lab-run1-1945/host-before.txt)、[host-after.txt](lab-run1-1945/host-after.txt)，`down` 因此失败）。是 Cilium agent 写的：chart 用 hostPath 把节点的 `/proc/sys/kernel`（也就是宿主的）单独可写地挂给 agent，`warden-node-init` 把节点的 `/proc/sys` 设为只读管不到这个单独的挂载（[node-init-mechanism.txt](lab-run2/node-init-mechanism.txt)）。具体时刻不知道：run 1 只在 `down`（23:26）时比较，agent 一般在启动时写，所以多半是 19:46 前后。
- 之后的防护（`3681bc4`、`082cc71`）：chart 里挂节点 `/proc` 的地方全部改成只读；`up` 在 Cilium 就绪时就比较受保护的 sysctl，变了就停；agent 的 `/host/proc/sys/kernel` 不是只读也停（[agent-mountinfo.txt](lab-run3/agent-mountinfo.txt)）。run 2 和 run 3 的受保护 sysctl 前后一样，完整 sysctl 列表（这个用户读得到的全部，[sysctl-dump.sh](lab-run2/sysctl-dump.sh)）前后只差计数器（`fs.dentry-state`、`fs.inode-nr`、`fs.file-nr`、`fs.quota.*`、`kernel.ns_last_pid`、`kernel.pty.nr`、`kernel.random.uuid`、`net.netfilter.nf_conntrack_count`；[run 2](lab-run2/sysctl-full-diff.txt)、[run 3](lab-run3/sysctl-full-diff.txt)）。run 1 之前没有完整列表，所以 run 1 有没有改别的 sysctl 只能从这 15 个受保护的看。
- 现在的值（[final/sysctls-final.txt](final/sysctls-final.txt)）：`kernel.timer_migration=0`、`kernel.unprivileged_bpf_disabled=1`。恢复需要 root：`sudo sysctl -w kernel.timer_migration=1`；`kernel.unprivileged_bpf_disabled` 一旦是 1，内核不允许改回，只能重启后恢复成 2。在 CPU 8–15 上跑计时基准的那个项目，从 11-12 晚上起是在 `timer_migration=0` 下跑的。
- 2026-11-13 09:59 用户用 root 执行了 `sysctl -w kernel.timer_migration=1` 和上面的 `modprobe -r`：`kernel.timer_migration` 回到 1，10 个模块都卸掉了，没有多出别的模块；`kernel.unprivileged_bpf_disabled` 还是 1，要等重启（[final/host-restore-20261113.txt](final/host-restore-20261113.txt)）。

## 清理

[final/cleanup.txt](final/cleanup.txt)：run 3 的 `down` 删掉了节点、5 个替身容器和两个网络；`scripts/k3s_gvisor_lab.sh purge` 删掉镜像 `warden-k3s-gvisor:cilium` 和 `warden-lab/pause:1`；删掉了下载和 lab 状态 `.tools/cilium`（447M）、`.tools/helm`（59M）、`.cache/cilium-download`（19M）、`.cache/k3s-gvisor`（239M），删除前的 sha256 记在同一个文件里。之后没有 `project=warden` 的容器、网络和镜像。本地的 `python:3.14.4-alpine`（替身用的，kind lab 也用，原来就有）和 `envoyproxy/envoy:v1.40.2`（Docker 出口 lab 原来就有）没有删。重新跑要先 `scripts/restore-tools.sh helm` 和 `cilium`（按 digest 重新下载）。

[final/cleanup-2-20261113.txt](final/cleanup-2-20261113.txt)：之后补删了 cleanup.txt 没提到的残留：`/tmp/warden-chart-peek`（解开看模板的 Cilium chart）、Cilium 模式节点镜像的 BuildKit 缓存（10 条记录，约 14 MB；Task 3 节点镜像的缓存保留），以及 `scripts/test_oci_fetch.py` 每次 `make test` 漏在 `/tmp` 里的 20 个临时目录（`f2ae4e4` 修）。

## 文件

| 路径 | 内容 |
|---|---|
| [red-green/](red-green) | 每个代码改动的 RED 和 GREEN 输出（01–14；`*-test-bug.txt` 是测试本身写错的那次） |
| [runs/](runs) | 每次 `make test-cilium` 的日志和结果 JSON（01–08 在 run 2 上用 `CILIUM_REUSE=1`，09-all 是新 lab 上的完整运行） |
| [spikes/](spikes) | Task 14 的手动探索：s1、s2、s4（标签和连接），s5–s7（身份延迟和两个设置）；s3 只看了终端输出，没有保存 |
| [lab-run1-1945/](lab-run1-1945)、[lab-run2-attempt1/](lab-run2-attempt1)、[lab-run2/](lab-run2)、[lab-run3/](lab-run3) | 每次 lab 运行的宿主记录：模块列表、受保护的 sysctl、完整 sysctl、Cilium 状态、节点清单 |
| [final/](final) | 清理记录、最后的模块列表和 sysctl、删除前的 receipt |
| [scripts/](scripts) | 这些运行用的包装脚本（`run-tests.sh`、`up-run2.sh`、`down-run2.sh`、`run3.sh`、`gotest.sh`） |
| [modules-attribution.sh](modules-attribution.sh)、[.txt](modules-attribution.txt) | 模块的逐段对比 |
