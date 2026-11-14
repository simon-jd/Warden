# Task 3 实测：k3s + runsc（2026-11-10，home-ubuntu）

源码 `277050d`（worktree `~/Desktop/Warden-task3`，分支 `task3-gvisor`）。两次运行开始时 `git status --short` 都只有本目录未跟踪。每次运行都是一次完整的 `make test-gvisor`：起 lab（`scripts/k3s_gvisor_lab.sh up`）、跑 `TestGVisorConformance` 和 `TestGVisorColdStarts`、再拆 lab。

包装脚本是 worktree 里的 `.cache/task-3/evidence-run.sh`，副本见 [evidence-run.sh.txt](evidence-run.sh.txt)。它记下源码、git 状态、开始和结束时的 load average，以及前后的 `project=warden` 容器和网络；运行期间每 15 秒读一次 `/proc/loadavg`；最后附上 lab 前后的宿主快照（受保护的 sysctl 和已加载模块列表的哈希）。make 经过 `.cache/mk.sh`（副本见 [mk.sh.txt](mk.sh.txt)），它只多加了 `-buildvcs=false`：在 worktree 里，Go 的 VCS 标记认不出 `.git` 文件，会去读 `~/.git`。

| 运行 | 时间（PST） | 命令 | 结果 | 文件 |
|---|---|---|---|---|
| conformance-run1 | 17:08:36–17:09:12 | `make test-gvisor` | conformance 7/7 PASS；冷启动按设计 skip | [log](conformance-run1.log)、[host](conformance-run1.host.txt)、[load](conformance-run1.load.txt)、[节点输入](conformance-run1.node-manifest.txt) |
| coldstart-run1 | 17:10:59–17:16:38 | `make test-gvisor GVISOR_COLD_STARTS=100 GVISOR_OUT=…/cold-starts-100.jsonl` | conformance 7/7 PASS；100 次冷启动全部 PASS | [log](coldstart-run1.log)、[host](coldstart-run1.host.txt)、[load](coldstart-run1.load.txt)、[节点输入](coldstart-run1.node-manifest.txt)、[原始数据](cold-starts-100.jsonl) |

- `cold-starts-100.jsonl`：前 100 行每行是一次运行，字段有 run ID、pod UID、四个时间戳（`start_ns`、`init_ns`、`exec_ns`、`wait_ns`，都是 Unix 纳秒）、算出的三个间隔和 `Exit`。最后一行是测试自己算的汇总，和下面的重算结果一致。度量的定义见 [runtime-startup.md](../../runtime-startup.md) 的 gVisor 一节。
- `quantiles.py.txt`、`cold-starts-100.quantiles.txt`：从每次运行的记录重算 p50/p95/最小/最大的脚本和它的输出，另外算了测试没有汇总的两段：init→exec（warden-gvisor-init 内部）和 exec→wait。
- `pod-cgroup-positive-control.txt`：coldstart-run1 跑到第 52–56 次时，在节点上用 conformance 测试的同一条 `find` 看到了正在运行的 pod 的 cgroup。所以 conformance 日志里的 `gone=true` 是真的查到了"已经删掉"，不是路径写错了查不到。这次采样在节点里多跑了几个 `docker exec`，那几次的数据没有剔除。
- `host-20261110.txt`：主机、内核、Docker、k3s、runsc、Go 的版本，以及磁盘。
- `postflight.txt`：拆完 lab、删掉镜像之后的检查：没有 `project=warden` 或名字以 `warden-` 开头的容器、网络、镜像；worktree 和主 checkout 的大小。
- `make-test.log`、`make-check.log`：文档提交之后（`cf617b8`，工作区干净）在 worktree 里跑的 `make test` 和 `make check`，都通过。
- 两次运行的节点输入清单相同（`node-manifest.txt` 的 sha256 就是绑定用的 `NodeConfigSHA256`）。两次运行前后，宿主快照都没有变化；结束后都没有留下 `project=warden` 的容器或网络。
- 同一台机器上同时有其他项目在跑：两次运行的 1 分钟 load average 在 5.59–12.90 之间（32 核）。
