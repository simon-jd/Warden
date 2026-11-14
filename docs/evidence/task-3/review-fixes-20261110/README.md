# Task 3 的审查修复（2026-11-10 晚 – 11-11，home-ubuntu）

独立审查对分支 `task3-gvisor`（`8667bde`）提了 21 条。下面是每条的提交和证据。代码和构建的问题（1–11）都先写了在旧代码上失败的测试（RED），再改（GREEN），两次的输出在 [red-green/](red-green/)，文件名前的编号就是这里的编号。9 是变异测试：把 `releaseFailedSession` 的 Lchown 遍历删掉，旧测试照样通过，新测试失败。

| # | 问题 | 提交 | 证据 |
|---|---|---|---|
| 1 | gVisor `Wait` 出错时不拆掉 Job 和 Pod；跟踪 Pod 时一次 API 错误就放弃 | `d0f0637` | [01](red-green/01-wait-teardown.red.txt) |
| 2 | `Kill` 或 `Reap` 之后 `Wait` 一直不返回；Job 没有 pod 时 `Wait` 一直等；跟踪时被 `Kill` 返回 404 | `c73cb7c` | [02](red-green/02-wait-after-kill.red.txt) |
| 3 | supervisor 的 select 可能先拿到退出、丢掉 exec 状态 | `0911847`（只移动代码）、`8ded85d` | [03](red-green/03-exec-status.red.txt) |
| 4 | `k3s_gvisor_lab.sh run` 会拆掉不是它起的 lab | `b7def15` | [04](red-green/04-lab-run-ownership.red.txt)，[lab-checks](lab-checks/run-refuses-and-identity-reuse.log) |
| 5 | `TimedOut` 永远不会是 true（期限在 Job 上，pod 的 reason 不会是 `DeadlineExceeded`） | `dcf3d9e` | [05](red-green/05-job-deadline.red.txt)，lab 上的事件顺序 [job-deadline](job-deadline/README.md) |
| 6 | lab 脚本会删掉或加入不是 Warden 的 `warden-k3s` 网络 | `55d8f71` | [06](red-green/06-lab-network-labels.red.txt) |
| 7 | trampoline 改凭据前没有 `runtime.LockOSThread` | `4c03ef5` | [07](red-green/07-lock-os-thread.red.txt) |
| 8 | identity 测试在注册清理之前就建了 namespace；`IDENTITY_REUSE=1` 时 409 不处理 | `873fad2`（把建 namespace 和账号挪进 `createNamespace`；不完全是重构：整份 manifest 读完、检查完才发第一个请求，ServiceAccount 的 namespace 和 manifest 的 Namespace 不同时多了一个 `t.Fatalf`，账号改在 manifest 的 namespace 的路径下创建。仓库里的 manifest 是 Namespace `warden-system` 和它里面的 ServiceAccount、Deployment，对它发出的请求和顺序不变）、`30f72c2` | [08](red-green/08-identity-namespace.red.txt)，[lab-checks](lab-checks/run-refuses-and-identity-reuse.log) |
| 9 | 失败清理的所有权检查不会失败 | `13ba326` | [09](red-green/09-chown-walk.red.txt) |
| 10 | Unix socket 路径随 checkout 路径变长，worktree 里 bind 失败 | `a229a70` | [10](red-green/10-socket-path.red.txt) |
| 11 | worktree 里 Go 的 VCS stamping 失败；`go list` 没有输出时退回检查 `.` | `276a734` | [11](red-green/11-makefile.red.txt) |
| 12 | gVisor 冷启动的规格不是"和 Firecracker 默认 VM 一样"（pid、超时不同） | `2e662fc` | [runtime-startup.md](../../runtime-startup.md) |
| 13 | p50/p95 没说是哪种算法 | `5e1f6f2` | [time-to-contain.md](../../time-to-contain.md)、[task-14 README](../../task-14/kind-service-dns-20261110/README.md) |
| 14 | Task 4 的 make test 数字没有提交的日志 | `b22456c` | [t4-make-test-final.log](../../task-4/live-20261110/t4-make-test-final.log)、[t4-make-check-final.log](../../task-4/live-20261110/t4-make-check-final.log) |
| 15 | STATUS 的磁盘数字没有测量记录 | `3648937` | [postflight.txt](postflight.txt) |
| 16 | Task 4 两份 README 里有没有原始输出的数字 | `d35015c` | 去掉了，或者改指 [sar-q-20261110.txt](../../task-4/live-20261110/sar-q-20261110.txt) |
| 17 | "外壳的 pid 上限比内存先用完"写成了事实 | `aaf5cae` | 改成推断 |
| 18 | `TestSandboxSAHasNoBindings` 是改了测试才通过的，却和令牌的修复写在一起 | `26576c3`（STATUS）、`87e1623`（Task 7 证据、follow-ups 索引、PRIORITIES） | — |
| 19 | 冷启动第 52–56 次和正对照采样同时跑，没说 | `4268d56` | [pod-cgroup-positive-control.txt](../live-20261110/pod-cgroup-positive-control.txt) |
| 20 | 一次没有日志的 `GVISOR_REUSE=1` 运行被当成结果 | `463c8d4` | 改成"不是证据" |
| 21 | make 日志没记源码版本和 git 状态 | 本目录的 make 日志 | [make-test.log](make-test.log)、[make-check.log](make-check.log) |

## lab 上的检查

- [job-deadline/](job-deadline/README.md)：Job 的 `activeDeadlineSeconds` 到期时，k3s 上事件的实际顺序（源码 `30f72c2`）。驱动和 `gvisor_test.go` 的假 API 按这个顺序改。
- [lab-checks/](lab-checks/run-refuses-and-identity-reuse.log)：lab 已经起着时，`scripts/k3s_gvisor_lab.sh run true` 退出码 1，lab 还在。先放一个带多余账号的 `warden-system` namespace，再跑 `make test-identity IDENTITY_REUSE=1`：两项 PASS，结束后 `warden-system` 已删除。
- [conformance-rerun.log](conformance-rerun.log)：所有 driver 改动之后（源码 `a505196`，之后没有再改 `runtimes/`、`scripts/` 和 `Makefile`），`make test-gvisor` 一次：`TestGVisorConformance` 7/7，7 次运行后节点上的 pod cgroup 都已经不在，宿主的 sysctl 和模块列表前后一样。100 次冷启动没有重跑，[runtime-startup.md](../../runtime-startup.md) 里的数字还是审查修复之前 `277050d` 的。

## make test / make check（源码 `1dd3d8e`，工作区干净）

在 worktree 里直接跑 `make test`、`make check`，没有经过 `.cache/mk.sh`。日志开头记了源码版本和 `git status --short`。
- `make test` **通过**（[make-test.log](make-test.log)）：
  - Go 28 个包 ok，和上一轮一样。
  - Python 测试：`scripts/` 203 个 OK，比上一轮多 15 个（`test_makefile.py` 4 个、`test_k3s_gvisor_lab.py` 11 个）；`detect/report` 和背压 helper 37 个 OK（live 1 个 skip）；pySigma 和 OpenSearch helper 14 个 OK（live 2 个 skip）。
  - Vector：38 个 `vector test` 用例 passed，背压配置 validate 通过。
- `make check` **通过**（[make-check.log](make-check.log)）。
- 这次提交只加了这两个日志和文档里的这几行，没有改测试读的文件。

## 结束检查

- [postflight.txt](postflight.txt)（2026-11-10 21:09 PST，源码 `463c8d4`）：lab 拆掉、镜像 purge 以后，没有 Warden 的容器、网络、镜像；每个路径单独 `du -sh`；宿主的 inotify 和模块列表哈希。
- [final-check.txt](final-check.txt)（2026-11-11 07:34 PST，源码 `87e1623`，最后的 make test 之前）：没有 Warden 的容器、网络、镜像。审查点名的 `/tmp/warden-cilium-render.yaml` 和 `/tmp/warden-scan` 已经不在；删之前里面是什么没有记录。上一次尝试留下的 `/tmp/w3-final.sh`（它写 make 日志用的脚本）已删除。
