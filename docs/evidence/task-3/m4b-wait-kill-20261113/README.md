# M4b：`Kill` 拆除期间的 `Wait`（2026-11-13，离线）

## 问题

`runtimes/gvisor/gvisor.go` 里 `Kill` 在整个拆除期间（最多 `TeardownTimeout`，默认 60 s）拿着 `r.mu`。`track` 被 `Kill` 停下以后也要拿 `r.mu` 才能发布结果，所以 `Wait` 要等 `Kill` 的拆除结束。可是 `Kill` 的注释说没看到容器退出的 `Wait` "returns ErrKilled, at once"，`Wait` 的注释说 Kill 之后 "ends without an exit, promptly"，`TestWaitAfterKillReturnsAtOnce` 的注释说 "as the runc and Firecracker handles return promptly"，[gvisor-lab.md](../../../gvisor-lab.md) 也写 "promptly: after `Kill` it returns `ErrKilled`"。这些说法说过了。

## 对照

- `runtimes.Runtime`（`runtimes/runtime.go`）只有方法签名，没有规定 `Kill` 之后 `Wait` 多快返回。
- runc（`runtimes/runc/handle.go`）：`Wait` 等后台 goroutine 关 `done`。这个 goroutine 看到退出以后还要调 `Kill`（`killOnce`，会等进行中的 `Kill` 结束），再 `cleanup`（最多 15 s），然后才关 `done`。所以 `Kill` 之后的 `Wait` 也是在 kill 和清理以后才返回。
- Firecracker（`runtimes/firecracker/vm.go`）：`Kill` 调 `retire`，拿着 `retireMu`。`collect` 读帧出错以后也调 `retire`，要等 `Kill` 的 `retire` 做完才关 `done`。也是在拆除以后。
- 三个 driver 的 `Wait` 都是先 `select` 自己的 ctx，ctx 结束就返回，不经过任何锁。
- 调度器（`controlplane/internal/scheduler/scheduler.go`）把 `Wait` 的错误一律记成 cleanup pending；`collect` 读日志有自己的超时。

## 结论

`Kill` 之后 `Wait` 等拆除是对的：三个 driver 都是这样，结果只在拆除以后才有。所以这里收窄说法，不改成提前返回。

但同一个原因带出一个真问题。`Kill` 持锁期间，第一个 `Wait` 在 `tracking.Do` 里也要拿 `r.mu`，于是连自己的 ctx 都不理，要等 `Kill` 的拆除结束。runc 和 Firecracker 的 `Wait` 不会这样，[STATUS](../../../STATUS.md) 和 gvisor-lab.md 也说 ctx 结束时 `Wait` 立即返回。`Logs` 和 `Timings` 同样被卡住：调度器的 `collect` 超时以后会把日志算成丢了。这个改了。

改动：`Run` 加了 `teardownMu`，`Kill` 和 `track` 的拆除轮流做。两边调 API 时都不拿 `r.mu`，所以 `Wait`、`Logs`、`Timings` 不用等拆除。`Kill` 之后的 `Wait` 照旧在拆除确认以后才返回 `ErrKilled`；`Kill` 的拆除失败时，要等 `track` 自己再试一次拆除之后。

## 测试

RED（[red.log](red.log)）：在没改的 `gvisor.go` 上跑，只改了 `gvisor_test.go`。GREEN（[green.log](green.log)）：改了以后同样的测试，再加整个 `runtimes/gvisor/...` 的 `-race -count=3 -shuffle=on`，都通过。

| 测试 | 条件 | RED | GREEN |
|---|---|---|---|
| `TestWaitDuringKillHonoursItsContext` | `Kill` 拆除中（假 API 的 pod 一直不消失），第一个 `Wait` 带 50 ms 的 ctx | FAIL，1.999 s 后才返回（测试的 `TeardownTimeout` 是 2 s） | PASS，0.06 s |
| `TestLogsAndTimingsDuringKillAnswer` | 同样条件下调 `Logs`、`Timings` | FAIL，1.999 s | PASS，0.01 s |
| `TestWaitDuringKillReturnsAfterTheTeardown` | 收窄后的说法：正在跟踪的 `Wait` 在 `Kill` 的拆除确认之前 200 ms 内没有返回；确认以后返回 `ErrKilled`；DELETE 只有 `Kill` 的一次 | PASS | PASS |

第三个改前改后都 PASS，因为它固定的是原来就有的行为。

## 没做的

按要求没有跑 gVisor lab。这次只改了 driver 里的加锁，lab 上的 `TestGVisorConformance` 没有重跑。

## make test、make check

在 `c2caee0` 上，工作区干净时跑，`make` 用 `taskset -c 0-7,16-31`。两个都通过，日志和 Task 4 这一轮的放在一起：[make-test-c2caee0.log](../../task-4/pids-limit-20261113/make-test-c2caee0.log)、[make-check-c2caee0.log](../../task-4/pids-limit-20261113/make-check-c2caee0.log)。
