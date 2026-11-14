# Task 3 复核的小问题（2026-11-12，home-ubuntu）

独立复核在 `task3-gvisor`（`e39f0cd`）上又提了 5 条小问题（M1–M5）。下面是每条的提交和证据。代码的 3 条（M2–M4）都先写了在旧代码上失败的测试（RED），再改（GREEN），两次的输出在 [red-green/](red-green/)，文件名前的编号就是这里的编号。

| # | 问题 | 提交 | 证据 |
|---|---|---|---|
| M1 | STATUS 的 Task 3 行还说拆除"等 Job 和 Pod 都消失才返回"；`d0f0637` 以后拆除最多等 `TeardownTimeout`（默认 60 s），没确认就返回错误 | `63b15af` | 改成和 [gvisor-lab.md](../../../gvisor-lab.md) 一样的说法 |
| M2 | 普通 `make test` 依赖目录权限：umask 0002 下 clone 的仓库，`runtimes/firecracker` 的测试因为 `writable private ancestor` 失败，make 停在 test-go，Python、pySigma、Vector 都没跑 | `d1ab926`、`48090e3`（scratch clone 的日志） | [m2 RED](red-green/m2-test-tmp-preflight.red.txt)、[GREEN](red-green/m2-test-tmp-preflight.green.txt)，[umask/](umask/) |
| M3 | Job 期限结束的运行，如果读日志之前 pod 已经删了，日志的 404 直接成了错误，`TimedOut` 丢了；假 API 的 `/log` 不管 pod 还在不在 | `e8d6e13` | [m3 RED](red-green/m3-logs-gone-deadline.red.txt)、[GREEN](red-green/m3-logs-gone-deadline.green.txt) |
| M4 | gVisor 的 `Wait` 不按自己的 ctx 返回：并发的第二个 `Wait` 卡在 `waitMu` 上；ctx 已经结束的 `Wait` 要等拆除；ctx 的错误被存成运行的结果 | `89459b6` | [m4 RED](red-green/m4-wait-context.red.txt)、[GREEN](red-green/m4-wait-context.green.txt) |
| M5 | review-fixes 的 README 把 `873fad2` 叫作"重构，行为不变" | `e4c856d` | 改了 [README](../review-fixes-20261110/README.md) 的说法，提交本身没动 |

## M2：Go 测试临时目录的预检

`privateRoot` 的检查没有放宽。`make test-go` 现在先跑 `scripts/check-test-tmp.sh`：从 `.cache/test-tmp` 往上逐级检查，规则和 `privateRoot` 一样（group 或 others 可写就不行，root 的 sticky 目录除外），有不合格的目录就停下，列出这些目录和 `chmod go-w` 的修法，或者在 umask 022 下 clone 和运行 make。`scripts/test_makefile.py` 在自己的私有目录里放 `TEST_TMP`，分别让上级目录和 `TEST_TMP` 本身 group 可写；在旧 Makefile 上两种都 FAIL（make 跑了 go，退出码 0）。

[umask/](umask/) 里是三个 scratch clone（`/tmp` 下，结束后删掉了）。[clone-demo.sh](umask/clone-demo.sh) 用给定的 umask clone、跑 `make test`；工具和 module cache 链到主 checkout，和 worktree 一样。

- [clone-umask-0002-e4c856d.log](umask/clone-umask-0002-e4c856d.log)：改之前，umask 0002。clone 目录、`.cache`、`.tools` 都是 `drwxrwxr-x`。`warden/runtimes/firecracker` 14 个顶层测试 FAIL（算上子测试 33 个），29 行错误是 `writable private ancestor`；make 停在 test-go，后面的套件没跑。复核说的是 24 个；这次 `-shuffle=on` 数到的是上面的数。
- [clone-umask-0002-d1ab926.log](umask/clone-umask-0002-d1ab926.log)：改之后，umask 0002。`make test` 在预检处停下，列出 clone 目录和它的 `.cache`，给出 `chmod go-w` 这两个目录。照着 chmod 之后再跑 `make test`（umask 还是 0002）：通过。
- [clone-umask-0022-d1ab926.log](umask/clone-umask-0022-d1ab926.log)：改之后，umask 0022：`make test` 通过。

## M3：pod 连同日志已经不在

API server 只在 pod 还在时给日志。lab 上 Job 期限到时，pod 变成 `Failed` 之后紧接着就被删了（[timeline.txt](../review-fixes-20261110/job-deadline/timeline.txt)），所以 `Wait` 读日志时可能已经是 404。现在 404 时 `observe` 也去读 Job 的条件（和 SIGTERM 报告时一样，最多等 `JobConditionWait`）：是期限，就照样返回带 `TimedOut` 的退出结果，丢掉的日志算截断（`LogsTruncated` 为 true，`DroppedLogBytes` 是 0，丢了多少字节不知道）；不是期限，丢日志仍然是错误。假 API 的 `/log` 在 pod 不在以后回 404。新的三个"pod 先没了"的用例在旧代码上 FAIL（`gvisor: logs: API server: HTTP 404`）。lab 的一致性测试没有 Job 期限的用例（超时那项是 supervisor 自己的超时），所以这条路径只在离线测试里跑过。

## M4：`Wait` 和 ctx

和 runc（`runtimes/runc/handle.go`）、Firecracker（`runtimes/firecracker/vm.go`）一样：第一个 `Wait` 在一个 goroutine 里开始跟踪运行（`track`），它跟到运行结束、拆除，然后才给出结果，每条路径都是这样，和以前一样。每个 `Wait` 等这个结果，或者自己的 ctx 先结束时立即返回 `ctx.Err()`；ctx 的错误不会存成结果，之后的 `Wait` 还能拿到退出结果。放弃这个运行的调用方调 `Kill`（调度器在 `Wait` 超时后就调 `Kill` 和 `Reap`，`controlplane/internal/scheduler/scheduler.go`）；`Kill` 现在也会停掉 `track` 的跟踪，这样结束的运行返回 `ErrKilled`。没人 `Kill` 的话，运行结束后照样拆除。

原来的 `TestWaitTearsDownWhenItsContextEnds` 断言的是旧行为（ctx 结束的那个 `Wait` 返回前就删掉运行），换成了 `TestWaitWhoseContextEndsLeavesTheRunFollowed`：`Wait` 立即返回，运行没有被它删掉；运行结束后没有 `Wait` 在等也照样拆除（DELETE 一次），之后的 `Wait` 拿到退出结果和日志。加上 `TestWaitWithAnEndedContextReturnsAtOnce`、`TestConcurrentWaitsHonourTheirOwnContexts`，三个在旧代码上都 FAIL：第二个 `Wait` 1 s 后还卡着；ctx 已经结束的 `Wait` 等了 2.0 s（测试里的 `TeardownTimeout`）；之后的 `Wait` 返回的是缓存的 `context deadline exceeded`。M4 没有改 gVisor 包的其他测试；GREEN 里整个包加 `-race` 跑了 3 轮，都通过。

## lab 上的检查

- [conformance-rerun.log](conformance-rerun.log)：所有 driver 改动之后（源码 `48090e3`），`make test-gvisor` 一次：`TestGVisorConformance` 7/7，7 次运行后节点上的 pod cgroup 都已经不在，宿主的 sysctl 和模块列表前后一样，结束后没有 `project=warden` 的容器和网络。make 在 `taskset -c 0-7,16-31` 下跑；lab 的节点容器用 `docker update --cpuset-cpus 0-7,16-31` 绑到同样的 CPU，是在它已经启动以后（日志里那一行记了当时的状态），启动和绑定之间没绑的那段时间没有测。模块列表的哈希和 11-10 那次不一样，这次前后相同，中间为什么变了没查。100 次冷启动没有重跑，[runtime-startup.md](../../runtime-startup.md) 里的数字还是 `277050d` 的。
- [postflight.txt](postflight.txt)：lab 拆掉以后还剩两个 Warden 镜像（这次 `up` 之前有没有没记），`scripts/k3s_gvisor_lab.sh purge` 删掉以后，没有 `project=warden` 或 `warden` 开头的容器、网络、镜像，`/tmp` 下没有 scratch clone。

## 最后的 make test、make check

- [make-test.log](make-test.log)、[make-check.log](make-check.log)：在最后的代码和文档 `80a2af2` 上，worktree 里直接跑 `make test`、`make check`（make 在 `taskset -c 0-7,16-31` 下），开头记了 head 和 `git status --short`（干净，跑完也干净）。两个都通过：Go 28 个包 ok（`runtimes/firecracker` 也 ok，预检没拦）；`scripts` 的 unittest 204 个（含 M2 的预检测试）、detect 的 37 个（1 个 skip）、pySigma 14 个（2 个 skip）、Vector 38 个都通过；`make check` 的 go vet、gofmt、shellcheck 都没有报告。
