# Task 4：不带语料的 lab 包，以及 capacity-pressure 实测（2026-11-13）

## 结果

- **capacity-pressure 两次都 PASS：第 119 台时外壳出现内存压力。** 每台 128 MiB VM 占住 48 MiB（`fill` 探针），外壳 15e9 字节、1024 个 pid。前 118 台同时运行时没有内存压力。读到第 119 台时，外壳的 `memory.events` 里 `max` 是 432（第 1 次）和 388（第 2 次），`oom`、`oom_kill` 都是 0，测试按设计在这里停下。
- **11-10 那两次 FAIL 基本可以确定是外壳的 512 个 pid 不够。** 这次第 101 台照常起来，那时外壳的 `pids.current` 是 513，比原来的上限多 1 个。外壳的 `pids.events` 和 `pids.events.local` 在两次运行的每次读数里都是 `max 0`，1024 个 pid 没有碰到上限。这是间接证据：没有在 512 个 pid 下带新的 `pids.events` 记录重跑，源码和包也和 11-10 不同。
- 这是在同一个外壳里测的有界结果，不是物理主机的上限，也没有按每台的内存往上推算。

## 新加的选项：`prepare --without-corpus`（`37bcbe9`）

用户 2026-11-13 的决定：给 Firecracker lab 加一个不带语料的选项，再用它跑 capacity-pressure。默认的 `prepare` 构建和打包的文件不变，还和 `f64269a` 一样带语料；不同的只有记录：包里的 `opt/warden/input/manifest.json` 多了 `"PackageVariant":"with-corpus"`，`package.json` 多了 `variant`，策略哈希也算进了变体。所以 `37bcbe9` 之前准备的默认包会被拒绝，要重新 `prepare`；改动之后还没有准备或实跑过带语料的包。
- 加了 `--without-corpus` 时：
  - `scripts/firecracker_code.py` 跑 `build-without-corpus`，不构建 `./attacks/cmd/warden-attack`；
  - payload 盘里没有这个 helper，也没有 Task 5 的 shell 闭包；
  - 包里没有 `attacks/corpus`。
  - `scripts/corpus_image.py` 的 `payload_files` 和 `runtime_lab_docker.corpus_files` 都不调用；没带这个选项时，它们的行为没有改。
- 包的 `manifest.json`（`PackageVariant`）、回执 `package.json` / `package-result.json`（`variant`）和 policy 哈希（`package_variant`）都记下是哪一种包，`with-corpus` 或 `without-corpus`。
- 每个实际模式都要带同样的选项，包的种类对不上就拒绝，在建会话之前。
- 外壳里的 driver 打开 manifest 时也核对：`with-corpus` 要有 `input/corpus` 目录，`without-corpus` 不能有。
- 默认 `build` 的构建命令一字没改，有测试钉住。

还有一点要知道：`firecracker.test` 是 `go test -c ./runtimes/firecracker` 编出来的，`runtimes/firecracker/lab_test.go` 引用了 `warden/attacks/matrix`，所以这个二进制里仍然编进了 `attacks/matrix`，不带语料的包也一样。它只在 conformance 模式里调用（`matrix.RunFromEnv`），capacity 模式不调用。`source_sha()` 的源码绑定也和默认一样，仍然包括 `attacks` 和 `scripts/corpus_image.py`。

### RED / GREEN

- [red.log](red.log)：在没改的 `firecracker_lab.py`、`firecracker_code.py`、`driver.go` 上跑，只改了测试。
  - Python：`PackageVariantTests` 的 7 个测试 FAIL 或 ERROR，一共 11 个 error、2 个 failure。
  - Go：`TestPackageVariantMatchesContents` 编译失败（`Manifest` 没有 `PackageVariant`，`checkPackageVariant` 未定义）。
  - 默认 `prepare` 的那个测试在旧代码上一直跑到最后，只在新加的参数上 FAIL，说明测试的假环境本身没问题。
- [green.log](green.log)：同样的测试都通过；`scripts/` 的全部 299 个 OK；`runtimes/firecracker/...` ok。
- 原来的 `DeviceReleaseTests` 的回执 fixture 加了 `variant`。
- `make test` 在 `aa93e0a` 上先失败过一次：两个 prepare 测试在 `TMPDIR=/tmp`、umask 0002 下 ERROR（[make-test-aa93e0a-fail.log](make-test-aa93e0a-fail.log)）。原因是假的 `package.tar` 可以被组写，`bounded_input` 拒绝了它；GREEN 用的是 worktree 里的 `TMPDIR`，那里的默认 ACL 把这个问题盖住了。真正的 CLI 总是在 `main()` 设的 umask 0077 下跑 `prepare`，所以 `61c7a0b` 让测试也这样。umask 0002 下改前 ERROR、改后 OK：[umask-fix.log](umask-fix.log)。

## 材料

钉住的 Firecracker 材料只读地从 `~/Desktop/Warden/.cache/warden-lab/firecracker-materials/` 复制到这个 worktree 的 `.cache`（用 `cat`，`~/Desktop/Warden` 里什么都没改），用之前逐个对照 `scripts/firecracker_lab.py` 的 `MATERIALS`：4 个文件的大小和 sha256 都相符，没有多余文件（[materials.txt](live/materials.txt)）。用完已经删掉。

## 实测

- 从 worktree `~/Desktop/Warden-next` 直接跑，源码 `37bcbe9`，`git status --short` 为空（每个 `.host.txt` 的第一行）。worktree 本身是干净的提交，所以没有另开 detached worktree；那样会在 `~/Desktop/Warden/.git` 里加 worktree 记录。
- 命令：`prepare --without-corpus`、`capacity-pressure --without-corpus`（两次），都带 `--other-service-memory-bytes 0`，在 `taskset -c 0-7,16-31` 下跑。包装脚本是 [run.sh](live/run.sh)。
- **CPU**：Docker 容器不继承 `taskset`。所以有一个旁路循环，每 0.2 s 把出现的每个 `owner=warden-lab` 容器 `docker update --cpuset-cpus 0-7,16-31`（[pinned.txt](live/pinned.txt)）。
  - 两个构建容器被绑时已经在跑。
  - 第 1 次的外壳：宿主第一次采样（8 个 pid，还没有 VM）时已经是 `0-7,16-31`。
  - 第 2 次的外壳：第一次采样（8 个 pid，还没有 VM）时还是 `0-31`，50 ms 后绑上。
  - prepare 里导出用的容器（建了不启动，马上删）没绑上，`docker update` 时它已经不在了（[pin-errors.txt](live/pin-errors.txt)）。
  - 外壳的 device gate 只核对容器的身份、状态和 PID，不核对 HostConfig，所以这个改动不影响它。

| 运行 | 时间（PST，2026-11-13） | 宿主 1 分钟 load（每秒采样） | 结果 | 日志 |
|---|---|---|---|---|
| prepare `--without-corpus` | 10:35:42–10:36:37 | — | 通过；包 20 个条目，没有 corpus/helper；`variant` 是 `without-corpus` | [prepare.log](live/prepare.log)、[回执](live/prepare-package-result.json) |
| capacity-pressure 第 1 次 | 10:36:39–10:38:41（测试 111.8 s） | 6.73–8.97 | **PASS**，第 119 台出现内存压力 | [log](live/pressure-1.log)、[host](live/pressure-1.host.txt)、[宿主侧 cgroup](live/pressure-1.cgroup.txt) |
| capacity-pressure 第 2 次 | 10:38:44–10:40:50（测试 116.8 s） | 4.90–7.92 | **PASS**，第 119 台出现内存压力 | [log](live/pressure-2.log)、[host](live/pressure-2.host.txt)、[宿主侧 cgroup](live/pressure-2.cgroup.txt) |

| 读数（外壳） | 第 1 次 | 第 2 次 |
|---|---|---|
| 1 台 | 231,186,432 B，13 pid | 232,128,512 B，13 pid |
| 100 台 | 12,696,641,536 B，508 pid | 12,694,564,864 B，508 pid |
| 101 台 | 12,823,973,888 B，**513 pid** | 12,820,803,584 B，**513 pid** |
| 118 台（最后一次没有压力） | 14,966,689,792 B，598 pid，`memory.events` max 0 | 14,955,077,632 B，598 pid，max 0 |
| 119 台 | 14,999,887,872 B，604 pid，**max 432**，oom 0 | 14,999,965,696 B，603 pid，**max 388**，oom 0 |
| 每台（1→118） | 125.9 MB，5.00 pid | 125.8 MB，5.00 pid |
| `pids.events` / `.local` 的 max | 每次都是 0 | 每次都是 0 |

外壳的 `memory.max` 读回是 14,999,998,464 B（15e9 按页取整）。第 119 台读数时 `memory.current` 离它只差 110,592 B（第 1 次）和 32,768 B（第 2 次）。

## 宿主

每一步前后都记了：受保护的 15 个 sysctl（和 k3s lab 用的同一张表）、模块列表、KVM 参数、Warden 的 Docker 对象，还有完整的 `sysctl -a`（只存了 diff 和哈希）。都在 [live/host](live/host/) 下。
- **模块**：三步前后都没有变化（`*.diff.modules.txt` 为空）。
- **受保护的 sysctl、KVM 参数**：没有变化。
- **完整的 `sysctl -a`**：变的有两类。
  - 一类是自己会变的计数：`fs.dentry-state`、`fs.file-nr`、`fs.inode-*`、`fs.quota.*`、`kernel.ns_last_pid`、`kernel.random.uuid`、`net.netfilter.nf_conntrack_count`。
  - 另一类是两次运行结束时各多了一个 veth（`veth4e5b591`、`veth5325079`）的接口 sysctl。现在两个都已经不在了。Warden 的外壳是 `--network=none`（lab 核对过 inspect），不建网卡；当时宿主上 materialflow 的两个容器在反复重启，veth 很可能是它们的，没有进一步确认。

## 清理

- lab 自己删掉了容器和镜像，3 个会话的 5 GB 预留都已释放，会话里没有不归 UID 1000 的文件。之后没有 `project=warden` 的容器或镜像。
- 这一轮的 scratch 按确切路径删掉了：`.cache/fc-run`、`.cache/firecracker-code`、3 个 `docker-firecracker-<session>` 会话目录、`.cache/warden-lab/firecracker-rootfs`、`.cache/warden-lab/firecracker-materials`、`.cache/warden-lab/docker.lock`。`.cache/warden-lab` 里别的 lab 原来的 4 个文件留着。`/tmp` 里没有这一轮的东西。

## make test、make check

在 `61c7a0b` 上，工作区干净，umask 0002，`make` 用 `taskset -c 0-7,16-31`。两个都通过：[make-test-61c7a0b.log](make-test-61c7a0b.log)、[make-check-61c7a0b.log](make-check-61c7a0b.log)。`go test ./...` 也编了 `attacks/` 下的 Go 包，并跑了它们的离线测试。
