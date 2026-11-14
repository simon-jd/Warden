# Cilium 上 k3s lab：中途停止（2026-11-10，home-ubuntu）

Task 10（默认拒绝 / 出口代理）和 Task 14（quarantine 切断已建立连接）的 Cilium 部分，以及 Task 7 里要 Cilium 的 metadata 测试，都要在 Task 3 的 k3s lab 上装 Cilium。这次装了两次，都没有跑到策略那一步，然后停了下来。

**停下的原因：第二次尝试时，宿主内核多加载了 4 个模块：`geneve`、`xt_socket`、`nf_socket_ipv4`、`nf_socket_ipv6`。** lab 节点是特权容器，Cilium agent 在节点里建设备、用 iptables 匹配时，内核会自己去加载缺的模块（内核用的是宿主的 modprobe 和宿主的 `/lib/modules`，节点里没有挂 `/lib/modules` 也挡不住）。没有 root 既拦不住，也卸载不了。这是改了宿主的状态，所以之后没有再起 Cilium。要继续需要用户决定（STATUS 阻塞 11）。sysctl 没有变化。

## 两次尝试

worktree `~/Desktop/Warden-task3`，分支 `task3-gvisor`，源码 `e7e25f1` 加上没有提交的改动（改动的副本在 [attempt/](attempt/)，见下）。命令都是 `scripts/k3s_gvisor_lab.sh up --cilium`（改过的版本）。

| 尝试 | 时间（PST） | 节点 PID 1 | 结果 | lab `down` 时的宿主快照 |
|---|---|---|---|---|
| 1 | 约 17:49–17:51 | `warden-node-init` 第一版：`/proc/sys` 只读、`/proc/sys/net` 可写，然后 exec k3s | Cilium 的 `mount-bpf-fs` init 容器起不来：kubelet 拒绝在私有挂载的 `/sys` 上做 Bidirectional 传播（[attempt1-mount-error.txt](attempt1-mount-error.txt)）。agent 没有启动 | 没有变化（`down` 返回 0；当时的 before/after 文件被第二次覆盖了，只剩终端输出） |
| 2 | 17:51:13–17:57:02 | 第二版：先把 `/` 设为 rshared（kind 的节点入口也这样做），其余同上 | agent 启动了，然后反复重启（17:57 前看到 4 次），日志里的错误是配置校验失败：`kube-proxy replacement (--kube-proxy-replacement) or BPF masquerade (--enable-bpf-masquerade) requires iptables rules (--install-iptables-rules="true")`（[attempt2-agent-error.txt](attempt2-agent-error.txt)，从终端抄下，节点拆掉后没留完整日志）。`up` 在等 DaemonSet 时超时（[up-attempt2.log](up-attempt2.log)） | **模块列表变了**（[host-before.txt](host-before.txt) 17:51:13、[host-after.txt](host-after.txt) 17:57:02），sysctl 没变 |

## 多出来的模块

- 17:57:02 的模块列表 = 17:51:13 的列表加上正好这 4 个：[modules-now.txt](modules-now.txt) 去掉这 4 行以后的 sha256（[modules-minus-4.sha256](modules-minus-4.sha256)）等于 [host-before.txt](host-before.txt) 里的 `modules_sha256`（`cab784bf…`）。
- 它们是在 lab 运行期间加载的。最可能是 Cilium agent 启动时探测隧道设备（geneve）和 iptables 的 socket 匹配（`xt_socket` 依赖 `nf_socket_ipv4/6`）造成的。这一点是推断：第一次看 `/sys/module` 时，这 4 个目录的时间都是 17:53:15，在 agent 第一次启动的时段里。后来再列一次，所有条目的时间都变成了 17:57:13（sysfs 的时间不可靠），所以没有留作证据。同一台机器上其他项目也在跑，但这 4 个模块正好对应 Cilium 的这两类探测。
- 现在的引用计数：`geneve` 0，`xt_socket` 0，`nf_socket_ipv4/6` 各 1（只被 `xt_socket` 引用）（[new-module-refs.txt](new-module-refs.txt)）。重启后就没有了。要立刻恢复，需要 root：`sudo modprobe -r xt_socket nf_socket_ipv4 nf_socket_ipv6 geneve`。
- 内核配置里这些功能都是模块（`=m`），不是内建：`NET_SCH_INGRESS`、`NET_CLS_BPF`、`NETFILTER_XT_TARGET_TPROXY`、`NETFILTER_XT_TARGET_CT`、`NETFILTER_XT_MATCH_SOCKET`、`VXLAN`、`GENEVE`（[kernel-config.txt](kernel-config.txt)）。`xt_TPROXY`、`xt_CT`、`sch_ingress`、`cls_bpf` 到现在也没有加载（[modules-now.txt](modules-now.txt) 里没有），`geneve` 和 `xt_socket` 在 lab 开始前也没有（见上面的哈希）。配置里避开了这些功能（tcx、原生路由、BPF TPROXY、不装 iptables 规则），但 agent 在校验配置之前就已经做了探测。

## 用的版本和配置

都按 digest 取，没有访问 GitHub：
- Cilium 1.20.4。chart 是 OCI 制品 `quay.io/cilium/charts/cilium`（manifest `sha256:712e1f65…`，chart 包 `sha256:505abff8…`，[chart-manifest.json](attempt/chart-manifest.json)）。镜像用 chart 的 `values.yaml` 固定的 digest：`quay.io/cilium/cilium@sha256:20fe92e4…`、`quay.io/cilium/operator-generic@sha256:7a7a3489…`（[cilium.receipt.json](attempt/cilium.receipt.json)、[operator-generic.receipt.json](attempt/operator-generic.receipt.json)，里面有每个 blob 的 digest）。
- helm v3.22.1，从 get.helm.sh 下载，sha256 `896cf636…`，只用来 `helm template`。
- 另外取了 CoreDNS 1.14.7、Envoy v1.40.2（和 Docker 出口 lab 同一个 digest）、python 3.14.4-alpine（和 kind lab 同一个 digest），准备给测试用，都没有用上（各自的 receipt 在 [attempt/](attempt/)）。
- 镜像用 `scripts/oci_fetch.py`（[副本](attempt/oci_fetch.py.txt)，5 个单元测试见 [test_oci_fetch.py.txt](attempt/test_oci_fetch.py.txt)，当时都通过）直接从 registry 拉成 OCI 归档，校验 index、manifest 和每个 blob 的 digest，再在节点里 `ctr import`，不经过宿主的 Docker 镜像库。
- k3s v1.36.5+k3s1，内核 7.0.0-42-generic，32 核。
- 数据面配置（[cilium-values.yaml](attempt/cilium-values.yaml)，渲染结果 [cilium-rendered.yaml](attempt/cilium-rendered.yaml)）：kube-proxy replacement、原生路由（`ipv4NativeRoutingCIDR` 10.42.0.0/16）、BPF masquerade、BPF host routing、BPF TPROXY、veth、tcx、`install-iptables-rules: "false"`、不装 Envoy DaemonSet 和 hubble、不用 sysctlfix。第二次尝试证明这组配置在 1.20.4 里不成立：kube-proxy replacement 和 BPF masquerade 都要求 iptables 规则。
- 节点改动（[k3s_gvisor_lab.sh.diff](attempt/k3s_gvisor_lab.sh.diff)、[node-Dockerfile.diff](attempt/node-Dockerfile.diff)、[nodeinit-main.go.txt](attempt/nodeinit-main.go.txt)、[restore-tools.sh.diff](attempt/restore-tools.sh.diff)、[coredns.yaml](attempt/coredns.yaml)）：Cilium 模式下节点 PID 1 是 `warden-node-init`，它先把 `/` 设为 rshared，再把 `/proc/sys` 设为只读（`/proc/sys/net` 除外，那是节点自己的网络命名空间）。原因是 Cilium agent 通过 `/proc/sys/kernel` 的 hostPath 写全局 sysctl（`kernel.timer_migration`、`kernel.unprivileged_bpf_disabled`，后者设为 1 以后重启前改不回来）。第二次尝试的宿主快照里，这两个值和其他受保护的 sysctl 都没有变化。

这些改动都没有提交，工作区已经恢复。副本留在这里，用户决定以后可以照着继续。

## 其他发现

- 所有 Cilium 策略选的都是 `warden.dev/sandbox: "true"`，但 gVisor driver 建的 pod 没有这个标签，所以在 Cilium 节点上，真实的沙箱 pod 不受默认拒绝、出口代理和 quarantine 的约束。已经在 `a7515aa` 修好（driver 加标签，Job 测试检查它）。这是唯一需要改的地方；策略文件本身没有在集群上用过，没有改。
- 如果要不加载新模块、也不装 iptables 规则，按这次看到的校验，只能关掉 kube-proxy replacement（ClusterIP 只靠 socket LB）并关掉 masquerade（世界网络里的容器自己加回程路由）。这个配置没有试，而且 agent 在校验之前的探测已经会加载模块，所以也不能保证不再加载别的。

## 没有做的

- Task 10：`default-deny.yaml`、`egress-proxy.yaml` 没有应用到集群；沙箱只能到出口代理、白名单仍然决定出口的结论没有实测。
- Task 14：`quarantine.yaml` 没有应用，Cilium 下已建立连接会不会被切断、多快切断没有测。1 s 的要求没有改。现在唯一的测量还是 kind/kindnet 的：已建立连接不断（[time-to-contain.md](../../time-to-contain.md)）。
- Task 7：`TestSandboxCannotReachMetadata` 没有跑。

## 负载和清理

- 17:59:15 的 load average：1.77、2.44、3.19（32 核，同时有其他项目在跑）（[captured-at.txt](captured-at.txt)）。
- 两次尝试的节点容器、`warden-k3s` 和 `warden-k3s-world` 网络都已经删掉。Cilium 模式的节点镜像 `warden-k3s-gvisor:cilium` 已删除，下载的 helm、chart 和镜像归档（`.tools/helm`、`.tools/cilium`、`.cache/cilium-download`）也已删除。
