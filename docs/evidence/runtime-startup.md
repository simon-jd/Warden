# 运行时启动与容量

计划里 Task 3（gVisor）和 Task 4（Firecracker）的测量都写在这里。每一行都对应 `docs/evidence/` 下已提交的原始日志。

## Firecracker（Task 4）

### 环境

- 主机：home-ubuntu（`postedism-ubuntu-system-selfuse`），Linux 7.0.0-42-generic，i9-13900K，32 核，内存 123 GiB；Docker 29.9.2，cgroup v2，systemd 驱动。2026-11-07 23:22 开机后没有重启，下面所有运行用的是同一个内核（[host-20261110.txt](task-4/live-20261110/host-20261110.txt)）。
- 同一台机器上同时有其他项目在跑。
- Firecracker v1.17.0 + jailer，guest 内核是官方 CI 的 vmlinux-6.18.54（sha256 `da5e0041…8188`，两个包相同），1 vCPU，不接网卡，rootfs 和 payload 盘都只读。
- 每次实测都是 `scripts/firecracker_lab.py <mode> --other-service-memory-bytes 0`（干净源码规则见 [firecracker-lab.md](../firecracker-lab.md)）。11-10 那几次从 detached worktree `.cache/fc-wt` 跑。11-13 那三次加了 `--without-corpus`（包里没有攻击 helper、语料和 Task 5 的文件），从干净的 worktree `~/Desktop/Warden-next` 直接跑。
- 外壳容器：boot/conformance/snapshot 是 4e9 字节，capacity 是 15e9 字节，都是 2 CPU。pid 上限是 512，只有 11-13 的 capacity-pressure 是 1024（`d8f553b`）。
- Linux 7.0 不在 Firecracker 1.17 持续测试的宿主矩阵里。这些结果只说明本机能跑，不代表上游支持。

### 每次运行

| 运行 | 源码 | 时间（PST，2026-11-10） | load average（1/5/15 分钟） | 结果 | 原始日志 |
|---|---|---|---|---|---|
| prepare | `122716c` | 15:28:09–15:28:22 | 15:30:02 采样 6.97 / 6.88 / 5.76 | 通过 | [122716c-prepare.log](task-4/live-20261110/122716c-prepare.log) |
| boot | `122716c` | 15:28:23–15:28:30 | 同上 | **PASS** | [122716c-boot.log](task-4/live-20261110/122716c-boot.log) |
| conformance | `122716c` | 15:28:37–15:28:54 | 同上 | **PASS**，7/7 | [122716c-conformance.log](task-4/live-20261110/122716c-conformance.log) |
| snapshot | `122716c` | 15:38:08–15:38:48 | 15:40:02 采样 9.94 / 9.09 / 7.25 | **PASS**，20 对 | [122716c-snapshot.log](task-4/live-20261110/122716c-snapshot.log) |
| capacity-benchmark | `122716c` | 15:39:47–15:40:24 | 15:40:02 采样 9.94 / 9.09 / 7.25 | **PASS**，32 台，右删失 | [122716c-capacity-benchmark.log](task-4/live-20261110/122716c-capacity-benchmark.log) |
| capacity-default | `122716c` | 15:40:31–15:40:53 | 15:40:02 采样同上；15:50:00 采样 10.64 / 12.92 / 10.18 | **PASS**，16 台，右删失 | [122716c-capacity-default.log](task-4/live-20261110/122716c-capacity-default.log) |
| prepare | `74791a2` | 16:13:45–16:14:00 | 开始 3.13 / 3.17 / 5.13，结束 3.55 / 3.26 / 5.13 | 通过 | [74791a2-prepare.log](task-4/live-20261110/74791a2-prepare.log) |
| capacity-pressure 第 1 次 | `74791a2` | 16:14:23–16:16:10 | 15 秒采样，1 分钟值 3.25–4.11 | **FAIL**（见下） | [74791a2-capacity-pressure-1.log](task-4/live-20261110/74791a2-capacity-pressure-1.log)、[host](task-4/live-20261110/74791a2-capacity-pressure-1.host.txt) |
| capacity-pressure 第 2 次 | `74791a2` | 16:17:14–16:19:00 | 15 秒采样，1 分钟值 3.20–4.17 | **FAIL**（同样的原因） | [74791a2-capacity-pressure-2.log](task-4/live-20261110/74791a2-capacity-pressure-2.log)、[host](task-4/live-20261110/74791a2-capacity-pressure-2.host.txt) |
| prepare `--without-corpus` | `37bcbe9` | **11-13** 10:35:42–10:36:37 | 没有采样 | 通过 | [prepare.log](task-4/without-corpus-20261113/live/prepare.log) |
| capacity-pressure 11-13 第 1 次 | `37bcbe9` | **11-13** 10:36:39–10:38:41 | 每秒采样，1 分钟值 6.73–8.97 | **PASS**，第 119 台出现内存压力 | [pressure-1.log](task-4/without-corpus-20261113/live/pressure-1.log)、[host](task-4/without-corpus-20261113/live/pressure-1.host.txt) |
| capacity-pressure 11-13 第 2 次 | `37bcbe9` | **11-13** 10:38:44–10:40:50 | 每秒采样，1 分钟值 4.90–7.92 | **PASS**，第 119 台出现内存压力 | [pressure-2.log](task-4/without-corpus-20261113/live/pressure-2.log)、[host](task-4/without-corpus-20261113/live/pressure-2.host.txt) |

- 时间：`122716c` 那几次取日志里第一条和最后一条 preflight 记录的 `at`；`74791a2` 那几次取包装命令记下的开始和结束时间（prepare 日志的第一行和最后一行，capacity-pressure 的 `.host.txt`）。
- load：`122716c` 那几次运行时没有记录 load，表里是 sysstat 每 10 分钟一次的采样里离运行最近的那一个（[sar-q-20261110.txt](task-4/live-20261110/sar-q-20261110.txt)），不是运行那一刻的值。`74791a2` 那几次是运行时直接读的 `/proc/loadavg`。
- 源码：lab 包绑定的是最后一次改动 `go.mod`、`go.sum`、`runtimes/` 和 `scripts/firecracker_*.py` 的提交，prepare 日志里的 `"source"` 就是它（`122716ccc850…`、`74791a2cc4eb…`）。`74791a2` 只加了 `capacity-pressure` 模式和 `fill` 探针，另外两种 capacity 模式没改。
- 11-13 那三次：时间取包装脚本在 `.host.txt` 里记的开始和结束。load 是宿主每秒读一次的 `/proc/loadavg`，和外壳 cgroup 的读数记在一起（`.cgroup.txt`）。Docker 容器不继承 `taskset`，所以一个旁路循环把每个 `owner=warden-lab` 容器 `docker update --cpuset-cpus 0-7,16-31`。两次的外壳都是在第一台 VM 之前绑上的，第 2 次在没绑的状态下有 50 ms（[pinned.txt](task-4/without-corpus-20261113/live/pinned.txt)、[README](task-4/without-corpus-20261113/README.md)）。
- 之前一次 capacity-pressure 没有真正运行：guard 因为 Task 3 留下的 `warden-k3s-gvisor` 容器拒绝了（[74791a2-capacity-pressure-refused.log](task-4/live-20261110/74791a2-capacity-pressure-refused.log)）。那个容器 2026-11-10 16:13 已经删掉（镜像保留）。

### 怎么计时

- **agent_ready**：从启动 jailer 开始，到 driver 经 vsock `CONNECT 52` 收到 guest agent 的 HELLO 为止。快照恢复时，加载快照的时间也算在里面。
- **driver start→EXEC ack**：从进入 `Driver.start` 开始（参数规范化、rootfs/agent/payload 的哈希校验、cgroup 预留、jailer、冷启动或恢复、BIND、EXEC），到收到 agent 的 EXEC ack 为止。`TestSnapshotRestoreFasterThanBoot` 比较的就是这个值。
- p50 是算术中位数（20 个值时取第 10、11 个的平均），p95 是最近秩（20 个值里第 19 个），和 `CompareStarts` 一样。
- VM 是默认规格：负载 512 MiB + 128 MiB 开销 = 640 MiB，探针 `uid`。快照测试冷启动和恢复交替跑 20 对；恢复用的基线快照在 BIND 之前生成，每次恢复都拿新的 run ID 和 nonce。没有人为加的延迟。

### 单次冷启动（`TestFirecrackerBoot`，`122716c`）

只有一个样本：agent_ready 746.96 ms，driver start→EXEC ack 881.84 ms。探针 `PASS uid`，VMM 的宿主 UID 2000000001，峰值 4 个 pid，结束后 cgroup 为空。

### 冷启动和快照恢复（`TestSnapshotRestoreFasterThanBoot`，`122716c`，20 对）

| 度量 | 冷启动 p50 | 冷启动 p95 | 恢复 p50 | 恢复 p95 |
|---|---|---|---|---|
| agent_ready（ms） | 766.53 | 857.73 | 371.69 | 446.95 |
| driver start→EXEC ack（ms） | 852.05 | 944.73 | 464.10 | 552.70 |

- 范围：冷启动 agent_ready 698.76–884.46 ms、start→EXEC ack 775.05–1010.28 ms；恢复 agent_ready 351.39–493.07 ms、start→EXEC ack 432.73–586.03 ms。
- start→EXEC ack 的中位数，恢复比冷启动少 387.96 ms（恢复是冷启动的 54.5%），测试要求"恢复中位数 < 冷启动中位数"，通过。
- driver 那一行和测试自己打印的汇总（日志里 `lab_test.go:115` 那一行）一致；agent_ready 那一行是从同一份日志里每一对的 `agent_ready_ns` 按上面的方法算出来的。日志打印了两遍（一次是保存的 run.log，一次是清理时读的容器日志），按 pair 去重后每种各 20 个。

### 内存压力前的并发数

三种 capacity 模式都在 15e9 字节的外壳里一台接一台地启动 VM，不退出；每启动一台就读一次外壳的 `memory.current`、`memory.events`（capacity-pressure 还读 `pids.current`），只要 `memory.events` 里的 max 或 oom 大于 0 就停。

| 模式 | VM | 探针 | 上限 | 实际同时运行 | 最后一台时的外壳内存 | memory.events max/oom | 结果 |
|---|---|---|---|---|---|---|---|
| capacity-default（`122716c`） | 640 MiB | `timeout`（空闲） | 16 台 | 16 | 1,506,492,416 B | 一直是 0 | PASS，右删失 |
| capacity-benchmark（`122716c`） | 128 MiB | `timeout`（空闲） | 32 台 | 32 | 2,547,073,024 B | 一直是 0 | PASS，右删失 |
| capacity-pressure 第 1 次（`74791a2`） | 128 MiB | `fill`（每台占住 48 MiB） | 160 台 | 100 | 12,703,633,408 B，pid 508 | 100 次读数都是 0 | **FAIL**：第 101 台没起来 |
| capacity-pressure 第 2 次（`74791a2`） | 128 MiB | `fill` | 160 台 | 100 | 12,737,736,704 B，pid 508 | 100 次读数都是 0 | **FAIL**：第 101 台没起来 |
| capacity-pressure 11-13 第 1 次（`37bcbe9`，外壳 1024 pid） | 128 MiB | `fill` | 160 台 | 119 | 14,999,887,872 B，pid 604 | 前 118 次是 0；第 119 台 max 432、oom 0 | **PASS**：第 119 台出现内存压力 |
| capacity-pressure 11-13 第 2 次（`37bcbe9`，外壳 1024 pid） | 128 MiB | `fill` | 160 台 | 119 | 14,999,965,696 B，pid 603 | 前 118 次是 0；第 119 台 max 388、oom 0 | **PASS**：第 119 台出现内存压力 |

- **右删失**：default 和 benchmark 都是到了预先定好的台数上限就停了，内存压力没有出现，所以只能说"至少 16 台 640 MiB / 至少 32 台 128 MiB 空闲 VM"，不知道真正的上限。
- **capacity-pressure 为什么 FAIL**：两次都是第 101 台 VM 在 `guest_ready` 阶段 15 秒内没等到 agent 的 HELLO（`"failure":"deadline","cause":"unknown"`），测试按设计判 FAIL，清理完成。那台 VM 的串口日志停在 `InstanceStart` 请求成功之后，两次除了时间和 run ID 完全一样（[第 1 次](task-4/live-20261110/74791a2-capacity-pressure-1-vm101-console.log)、[第 2 次](task-4/live-20261110/74791a2-capacity-pressure-2-vm101-console.log)）。这 17 行全是 Firecracker 自己的日志，`fc_vcpu 0` 收到 Resume 以后 guest 没有任何输出。正常启动时，Resume 之后 5 ms 内就有 vCPU 的第一次 IO 退出，接着是内核的 `Linux version`（[对照](task-4/payload-acl-20261110/lab-boot-9bb0f05-console.log)）。所以第 101 台的 vCPU 没有开始执行 guest 代码。当时外壳内存只用了 15e9 的 84.7% / 84.9%，`memory.events` 没有任何 max 或 oom。外壳的 pid 数 1 台时是 13 个，之后平均每台加 5 个（个别读数加 4 或 6），100 台时是 508 个；外壳 `pids.max` 是 512，第 101 台再要 5 个就超过上限。所以最可能的原因是**外壳的 pid 上限比内存先用完**。这一点是推断：外壳的 `pids.events` 没有记录下来，串口里也看不到失败的那一步。两次停在完全相同的位置，说明是个计数上的硬限制，不像负载造成的随机超时。**11-13 的结果有力地支持这一点**（但没有在 512 个 pid 下带新的 `pids.events` 记录重跑，源码和包也和 11-10 不同）：外壳换成 1024 个 pid 以后，第 101 台照常起来，那时外壳的 `pids.current` 是 513，比原来的上限多 1 个。两次运行的每次读数里，`pids.events` 和 `pids.events.local` 都是 `max 0`（[证据](task-4/without-corpus-20261113/README.md)）。
- **结论（11-13）**：在这个 lab 的外壳里（15e9 字节、2 CPU、1024 pid），每台占住 48 MiB 的 128 MiB VM 同时跑 118 台没有内存压力，第 119 台时出现。两次都是这样：`memory.events` 的 max 432 / 388，oom 0，那时 `memory.current` 离 `memory.max`（14,999,998,464 B）只差 110,592 B（第 1 次）和 32,768 B（第 2 次）。空闲 VM 仍然只有下界：640 MiB 至少 16 台，128 MiB 至少 32 台。这些都是这个外壳里的有界结果，不是物理主机的上限，也没有按每台的内存往上推算。11-10 在 512 个 pid 的外壳里只到第 100 台。
- 每台增加的外壳内存（第 1 台到最后一台的差除以台数减一）：空闲 640 MiB 约 87.6 MB，空闲 128 MiB 约 76.2 MB，`fill` 约 126.0 / 126.3 MB；11-13 不带语料的包，`fill` 第 1 台到第 118 台约 125.9 / 125.8 MB，每台正好 5 个 pid。
- 两次 FAIL 之后：supervisor 的失败清理路径删掉了 jail、资产和快照，会话交还 UID 1000，外壳 cgroup 已不存在，5 GB 预留已释放，没有留下 root 所有的文件，也没有留下容器或镜像。
- 要测到内存压力，要么提高外壳的 pid 上限，要么换每台占内存更多的 VM 规格。2026-11-13 用户同意只给 capacity-pressure 提高 pid 上限：从 `d8f553b` 起这个模式的外壳是 1024 个 pid，其他模式还是 512；从 `f0402c3` 起，每次读数也记外壳的 `pids.max`、`pids.peak`、`pids.events`、`pids.events.local`（[pids-limit-20261113](task-4/pids-limit-20261113/README.md)）。用的包是 `prepare --without-corpus`（`37bcbe9`）建的，没有攻击 helper、语料和 Task 5 的文件。
- 11-13 两次之后：lab 正常拆除，3 个会话的 5 GB 预留都释放了，没有留下容器、镜像或 root 所有的文件。宿主的模块、受保护的 sysctl 和 KVM 参数前后都没有变化（[host](task-4/without-corpus-20261113/live/host/)）。

## gVisor（Task 3）

### 环境

- 主机和上面一样：home-ubuntu，Linux 7.0.0-42-generic，i9-13900K，32 核，内存 123 GiB；Docker 29.9.2，cgroup v2（[host-20261110.txt](task-3/live-20261110/host-20261110.txt)）。同一台机器上同时有其他项目在跑。
- 单节点 k3s v1.36.5+k3s1，跑在特权 Docker 容器 `warden-k3s-gvisor` 里：私有 cgroup namespace，4 GiB 内存、4 CPU、4096 个 task，接在 `--internal` 网络 `warden-k3s` 上。gVisor release-20261019.0，RuntimeClass `gvisor` 对应 CRI handler `runsc`，配置是 `platform=systrap`、`network=none`、`in-sandbox-cgroup=v2`、`oci-seccomp=true`。lab 的说明见 [gvisor-lab.md](../gvisor-lab.md)。
- 节点的每个输入（k3s、runsc、各个配置、warden-gvisor-init）都按 sha256 记在节点输入清单里。两次运行的清单相同，清单本身的 sha256 是 `8eb468de…0499b`。
- 探针镜像和 runc lab 用的是同一个（`sha256:2f4ec662…55cf`），事先导入节点，`imagePullPolicy: Never`。

### 每次运行

| 运行 | 源码 | 时间（PST，2026-11-10） | load average（1/5/15 分钟） | 结果 | 原始日志 |
|---|---|---|---|---|---|
| conformance-run1 | `277050d` | 17:08:36–17:09:12 | 开始 5.59 / 6.31 / 5.68，结束 8.13 / 6.86 / 5.89 | **PASS**，7/7 | [log](task-3/live-20261110/conformance-run1.log)、[host](task-3/live-20261110/conformance-run1.host.txt) |
| coldstart-run1 | `277050d` | 17:10:59–17:16:38，其中冷启动 17:11:34–17:16:37 | 开始 9.73 / 7.79 / 6.32，结束 6.68 / 8.20 / 7.13；15 秒采样，1 分钟值 5.88–12.90 | **PASS**，conformance 7/7，冷启动 100/100 | [log](task-3/live-20261110/coldstart-run1.log)、[host](task-3/live-20261110/coldstart-run1.host.txt)、[原始数据](task-3/live-20261110/cold-starts-100.jsonl) |

- 每次运行都是一次完整的 `make test-gvisor`：起 lab、跑测试、拆 lab。时间取包装脚本在 `.host.txt` 里记的开始和结束，起 lab 和拆 lab 都算在里面；冷启动那一段的时间取测试汇总里的 `began` 和 `ended`。
- load 是运行时直接读的 `/proc/loadavg`（开始、结束，加上每 15 秒一次的采样，见 `.load.txt`）。
- 两次运行前后，宿主快照（受保护的 sysctl 和已加载模块列表的哈希）都没有变化。结束后都没有留下 `project=warden` 的容器或网络。

### 怎么计时

时间戳都是 Unix 纳秒。`start` 和 `wait` 是 driver 在宿主上记的。`init` 和 `exec` 是沙箱里的 warden-gvisor-init 记的，随 termination message 带回来。

- **start→init**：从进入 `Driver.Start` 开始，到 warden-gvisor-init 的 `main` 开始为止。中间依次是：参数校验；经 API 核对 kube-system、命名空间和节点的 UID；POST Job；Job 控制器建 Pod；调度；kubelet 建 pod 沙箱（runsc 起 sentry 和 gofer）；启动容器。
- **start→exec**：start→init 之后，再加上 warden-gvisor-init 里的准备，到负载 `execve` 成功为止（close-on-exec 管道收到 EOF）。准备包括：建 workload cgroup 并设 `pids.max`；私有 mount namespace；cgroupfs 改成只读；卸掉 termination log；去掉 capability；切到 UID/GID 65534；设 RLIMIT_NOFILE；装 seccomp。
  - 这是和 Firecracker 的 **driver start→EXEC ack** 对应的度量：两边都是从进入 driver 的 Start 开始，到负载开始执行为止。
  - 区别在终点：Firecracker 的终点是 agent 发回 EXEC ack，这里是沙箱里记下的 execve 时间。
  - 起点之后的步骤也不一样：Firecracker 有资产的哈希校验和 jailer，这里是 Kubernetes API 的往返和 kubelet。
- **start→wait**：端到端。start→exec 之后，再加上负载运行（`uid` 探针）、容器退出、读日志、前台删除 Job，直到 Job 和 Pod 对象都不在了。Firecracker 一节没有对应的度量。
- **跨时钟**：init 和 exec 用的是沙箱里的 CLOCK_REALTIME（gVisor 的 sentry 从宿主时钟取时间），start 和 wait 是宿主时钟。测试对每次运行都要求 start < init < exec < wait，100 次都满足。两边时钟的偏差没有单独测。
- **分位数**：p50 是算术中位数（100 个值时取第 50、51 个的平均），p95 是最近秩（第 95 个），和 Firecracker 一节、`CompareStarts` 一样。汇总是测试自己打印的。[quantiles.py.txt](task-3/live-20261110/quantiles.py.txt) 从每次运行的记录重算了一遍，结果一致（[输出](task-3/live-20261110/cold-starts-100.quantiles.txt)）。
- **规格**：内存、CPU 和探针和 Firecracker 的默认 VM 一样：负载 512 MiB + 128 MiB 开销 = 640 MiB 的 pod 内存上限，1 CPU，探针 `uid`。pid 和超时的上限不一样：这里是 32 个 pid、超时 30 s，Firecracker 默认 VM 是 128 个 pid、300 s（`runtimes/firecracker` 的 `Normalize` 默认值，`TestDefaultReservesKernelOutsideWorkload` 检查）。这 100 次里 `uid` 探针的 pid 峰值是 5–6 个，`PidsMaxEvents` 都是 0，没有一次超时，最长的 start→wait 是 3.96 s（[原始数据](task-3/live-20261110/cold-starts-100.jsonl)），所以这两个更低的上限在这些运行里没有起作用。
- **运行方式**：100 次串行，每次都是新的 run ID、新的 Job、新的 Pod 和新的 gVisor 沙箱。没有人为加的延迟，也没有预热的沙箱。第 52–56 次运行时，在节点上做了 pod cgroup 的正对照采样（节点里多跑了几次 `docker exec`，[pod-cgroup-positive-control.txt](task-3/live-20261110/pod-cgroup-positive-control.txt)），这 5 次的数据没有剔除，都在上面的统计里。

### 100 次冷启动（`TestGVisorColdStarts`，`277050d`）

| 度量（ms） | p50 | p95 | 最小 | 最大 |
|---|---|---|---|---|
| start→init | 523.85 | 695.17 | 465.82 | 837.37 |
| **start→exec** | **547.77** | **741.11** | 485.23 | 934.23 |
| start→wait | 2976.54 | 3079.62 | 2761.99 | 3956.18 |

- 100 次都是退出码 0、日志 `PASS uid`、`CgroupEmpty` 为 true，一共 100 个不同的 pod。每次结束后 Job 和 Pod 都已经删除。
- start→exec 超过 700 ms 的有 7 次，超过 900 ms 的有 1 次。
- 时间大部分花在 init 之前，也就是 Kubernetes 和 runsc 起沙箱的部分。warden-gvisor-init 内部（init→exec）p50 21.18 ms、p95 29.47 ms。
- exec→wait 的 p50 是 2433.17 ms。这一段包括负载运行、容器退出、读日志和删除，没有再细分。
- **和 Firecracker 比**：内存、CPU 和探针相同（pid 和超时上限不同，见上面的"规格"）时，Firecracker 冷启动的 driver start→EXEC ack p50/p95 是 852.05/944.73 ms（20 次），gVisor 的 start→exec 是 547.77/741.11 ms（100 次）。两组只能粗略对照：
  - 不是同一时间跑的，load 不一样；
  - Firecracker 的外壳是 2 CPU，k3s 节点是 4 CPU；
  - 起点之后的步骤和终点都有上面说的区别。
- **不在这 100 次里的：节点起来后的第一次运行。** 两次 conformance 的第一项（fork）start→exec 都是约 2.4 s（2453.17 / 2369.58 ms），其余各项是 495–581 ms。原因没有查，可能是第一次运行时 containerd 要解包镜像或第一次加载 runsc，没有验证。
- **"冷"的含义**：100 次冷启动排在 conformance 之后，那时节点、镜像和 containerd 都已经热了。这里的"冷"指每次都新建 pod 和 gVisor 沙箱。

### 读这些数字时要知道的

- **内存**：gVisor 不在沙箱里实施 `memory.max`，内存上限只在 pod 这一级（宿主 cgroup 上的 640 MiB），由 sentry、gofer、warden-gvisor-init 和负载共用。所以负载自己能用的是 640 MiB 减去其他部分用掉的，不是正好 512 MiB。超了的时候整个沙箱被杀，kubelet 报 `OOMKilled`、137，没有 supervisor 报告。conformance 的 `MemoryLimitOOMKilled` 就是这样判的。
- **pid**：pid 上限由沙箱里的 cgroup v2 实施。fork 那一项 `PidsMaxEvents` 为 1，峰值 32。
- **网络**：`network=none`，沙箱里只有 loopback。driver 拒绝 `Network: allowlist`，出口白名单目前只在 runc 上。
- **调度器**：还没有注册 gvisor 后端。这些数字是直接调 driver 测的（经过 `gvisor.Bind` 打开的 gate）。
