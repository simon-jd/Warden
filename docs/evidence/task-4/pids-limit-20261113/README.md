# Task 4：capacity-pressure 的 pid 上限（2026-11-13，只做了离线部分）

**后续（同日）**：用户决定给 lab 加一个不带语料的选项。用 `prepare --without-corpus` 建的包，capacity-pressure 两次都 PASS：第 119 台时出现内存压力，第 101 台时外壳是 513 个 pid，`pids.events` 一直是 0。11-10 的原因就此证实，是 512 个 pid 不够。见 [without-corpus-20261113](../without-corpus-20261113/README.md)。下面是那之前的离线部分，原样保留。

## 结果

- **原因还没有证实，capacity-pressure 没有实测。** 这一轮的规则是不构建、不运行、不读取 `attacks/` 下的东西。可是现在 lab 的 `prepare` 就要做这些，而每个 live 模式都要先 `prepare`（见下面），所以停下了。另外，钉住的 Firecracker 材料（`firecracker-materials`）在这台机器上只在 `~/Desktop/Warden/.cache/warden-lab/` 下，这一轮不能碰那个目录。另取就要重新下载：GitHub release 和 Firecracker CI 的 S3，四个文件约 35.5 MB。
- **代码按用户的同意改了，都是先 RED 后 GREEN。** 只有 capacity-pressure 的外壳 pid 上限从 512 提到 1024，其他模式不变（`d8f553b`）。容量测试每次读数都加上外壳的 `pids.max`、`pids.peak`、`pids.events` 和 `pids.events.local`，启动失败时再读一次（`f0402c3`）。这样下一次实测的日志本身就能说明是不是 pid 上限。

## 为什么没有跑

`scripts/firecracker_lab.py prepare` 从 `f64269a` 起会做这三件事：
- `scripts/firecracker_code.py build` 构建 `./attacks/cmd/warden-attack`；
- `export_probe` 用 `scripts/corpus_image.py` 的 `payload_files`，把这个 helper 和 Task 5 矩阵镜像的 shell 闭包放进 payload 盘；
- 用 `runtime_lab_docker.corpus_files` 把 `attacks/corpus/*` 读进包里。

`source_sha()` 也把 `attacks` 和 `scripts/corpus_image.py` 算进源码绑定。所以每个 live 模式都要构建和读取 `attacks/` 下的东西。这一轮没有建任何 Docker 对象，也没有改宿主。

## 原因：已有证据能说到哪

- 11-10 两次运行（`74791a2`）：100 台时外壳的 `pids.current` 是 508，`pids.max` 是 512，平均每台 5 个；`memory.events` 全是 0，内存 12.7e9 / 15e9（[runtime-startup.md](../../runtime-startup.md#内存压力前的并发数)）。
- 第 101 台的串口日志（[第 1 次](../live-20261110/74791a2-capacity-pressure-1-vm101-console.log)、[第 2 次](../live-20261110/74791a2-capacity-pressure-2-vm101-console.log)）都只有 17 行，全是 Firecracker 自己的日志；失败记录里 `rejected_lines` 是 17，`events` 是空的。也就是说，`InstanceStart` 成功、`fc_vcpu 0` 收到 Resume 以后，15 s 里 guest 一点输出都没有。对照一次正常启动的串口（[lab-boot-9bb0f05-console.log](../payload-acl-20261110/lab-boot-9bb0f05-console.log)）：Resume 之后 5 ms 内 vCPU 就有第一次 IO 退出，接着是 `Linux version 6.18.54+`。所以第 101 台的 vCPU 没有开始执行 guest 代码。
- Firecracker 的三个线程（`main`、`fc_api`、`fc_vcpu 0`）都起来了，串口里都有它们的日志。每台 5 个 pid 里另外 2 个是什么、第 101 台缺的是哪一个，当时没有记录，现在查不出来。
- 这和"pid 用完了"一致，但证明不了：没有 `pids.events`，也看不到失败的是哪一步。可能的机制之一是：vCPU 第一次 `KVM_RUN` 时，内核要为这台 VM 建一个任务（计在 VMM 的 cgroup 里），建不出来，`KVM_RUN` 就返回一个 Firecracker 会重试的错误。这一条没有验证。只读查看宿主：`/sys/module/kvm/parameters/nx_huge_pages` 是 `N`，`/sys/devices/system/cpu/vulnerabilities/itlb_multihit` 是 `Not affected`。

## 改了什么

- `d8f553b`：外壳的 pid 上限按模式定。capacity-pressure 是 1024；boot、conformance、snapshot、device-policy、capacity-default、capacity-benchmark 仍是 512。三处一致：Docker 的 `--pids-limit`（`live_args`）、宿主的 inspect 核对（`inspect_live`）、supervisor 读回的 `pids.max`（`validateOuterLimits`）。1024 的来由：这个模式最多 160 台，每台约 5 个，加上起步的约 8 个，约 808 个。每台 VM 自己的 scope 仍是 `pids.max` 64。
- `f0402c3`：`TestFirecrackerCapacity` 的每次读数改由 `readOuter` 读，包括外壳的 `memory.current`、`memory.events`、`pids.current`、`pids.peak`、`pids.max`、`pids.events`，以及内核有的话 `pids.events.local`。启动失败时，先记一次 `at the stop` 读数，再判 FAIL。
  - cgroup2 没有 `pids_localevents` 挂载选项时，`pids.events` 的 `max` 也算子树里碰到的上限，比如每台 VM scope 的 64；`pids.events.local` 只算外壳自己的。
  - 宿主的 cgroup2 没有这个选项，有 `pids.events.local` 和 `pids.peak`（只读查看 `user.slice`）。

## RED / GREEN

| 日志 | 内容 |
|---|---|
| [red-pids.log](red-pids.log) | 在旧的 `supervisor.go` 和 `firecracker_lab.py` 上：`TestOuterPidsRaisedForCapacityPressureOnly` FAIL，`TestOuterLimitsOnlyCanonicalPageFloor` FAIL（这个测试改成按模式取 pid 数了）；Python 的 `OuterPidsTests` FAIL，`DevicePolicyModeTests` ERROR（它的 capacity-pressure fixture 改成了 1024） |
| [green-pids.log](green-pids.log) | 改完以后同样的测试都 PASS；整个 `runtimes/firecracker` 包 ok；`test_firecracker_lab.py` 19 个 OK |
| [red-reading.log](red-reading.log) | 只加了 `TestOuterReadingIncludesPids`：`readOuter` 还没有定义，编译失败 |
| [green-reading.log](green-reading.log) | PASS；`TestFirecrackerCapacity` 在离线环境 skip；整个包 ok；`go vet` 没有报告 |

## 下一次实测

按 [firecracker-lab.md](../../../firecracker-lab.md)，从干净源码的 detached worktree 跑 `prepare`，再跑两次 capacity-pressure。读日志时：
- 第 101 台起来了，而且那时外壳的 `pids.current` 超过 512：说明 11-10 那次是 512 个 pid 不够。之后要么碰到 `memory.events` 的 max/oom，要么到 160 台的上限（右删失），要么在别处停下，都照实记。
- 还是在某一台停下：看 `at the stop` 那次读数。`pids.events` 增加了、`pids.peak` 到了 `pids.max`，是 pid 上限；都没有，就不是 pid 上限，照实记 FAIL 和看到的原因。
- 和 `74791a2` 比，包里还多了 `f64269a` 加进 payload 盘的东西，所以每台占的内存也可能变了，要重新看，不能直接拿 11-10 的数字比。

## make test、make check

在 `c2caee0`（这一轮最后的代码和文档）上，工作区干净时跑，`make` 用 `taskset -c 0-7,16-31`。两个都通过：[make-test-c2caee0.log](make-test-c2caee0.log)、[make-check-c2caee0.log](make-check-c2caee0.log)。
