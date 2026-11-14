# Task 2 runtime核心：本地实现与证据

最新scoped修复：[round-2 cleanup故障回收](round-2/README.md)，实现`2c27f783536ce9c6b9954885948fcd01418deae1`；9项Python回归通过，真实lab与scheduler门槛不变。

日期：2026-10-23。原始实现gitSHA：`0e722e81f7e6e08956533f92115045ddc1e67381`。首审修复实现：`978e93d98a2190bc1995ce98c1274a0324057aa1`；新增12项focused runtime回归、8项path guard测试及完整说明见[round-1](round-1/README.md)。以下原始记录保留历史原貌，最新安全边界以round-1与runtime-lab.md为准。

**最新结论：Task2已完成。runtime核心、独占lab、调度core及API/runtime入口均经过独立审查；[真实七项guest全部PASS/noSKIP](lab-live/README.md)，[真实HTTP→PG→runc及两阶段原node退休、审计与普通UID回收复核全部通过](api-runtime/live/README.md)。原计划Task2现已勾选，Goal继续active。**

以下环境/RED/GREEN及未完成范围记录为runtime核心最初提交时的历史；真实guest最新结果以上方链接为准。

## 环境、版本与配置

- `scripts/go.sh`使用Go toolchain **1.26.10 linux/amd64**（wrapper基础镜像1.26.8，go.mod触发1.26.10）；完整依赖：[versions.txt](versions.txt)。
- containerd Go client **v2.4.2**；runtime-spec v1.3.0；x/net修补至**v0.61.0**；x/sys v0.49.0；govulncheck v1.9.0。
- 控制器实际宿主preflight：home-ubuntu，containerd2.4.2、runc1.5.2/libseccomp2.6.0可用；现有daemon共享，禁止向它启动guest。当前sudo非交互不可用，不更改sudo或系统服务。
- 单元测试使用t.TempDir模拟cgroup文件协议，**不是实际kernel隔离测试**。生命周期double仅替代外部task exit/cleanup事件，测试本地handle取消/超时/错误传播；不能证明containerd/runc实机正确。
- driver要求专用socket路径含`/warden-lab/`，固定cgroup root `/sys/fs/cgroup/warden-lab`，namespace `warden-lab`。image已导入并核验裸digest，无pull或mutable fallback。allowlist未实现时拒绝启动。
- 默认强制只读rootfs、UID/GID65534、NNP、dropcaps、private namespaces、seccomp default-deny与cgroup v2限额。默认network none；Limits由可信调用者提供，API正常默认1CPU/512MiB/128pids/300s，driver不替代tenant授权。
- 当前项目cache约**2.1GB**；静态probe约1.9MB，OCI约1.9MB，lab test约25MB。总预算12GB，lab runner daemon1GiB/lab subtree16GB；与其他常驻服务总计仍须由控制器核对。

## RED/GREEN原始路径

| 验证 | 命令 | 原始证据 / 结论 |
|---|---|---|
| 初始测试编译修正 | `scripts/go.sh test ./runtimes/runc -run TestRejectsUnsafeLaunchBeforeConnecting -v` | [red-validation.txt](red-validation.txt)：Pids.Limit新版为指针的编译问题；**不是有效RED**，随后修正 |
| 安全验证、builder、日志、cgroup协议RED | `scripts/go.sh test ./runtimes/runc -v` | [red-core.txt](red-core.txt)：危险输入被接受、安全spec缺失、日志丢失、symlink被接受、subtree未空却声称成功 |
| 对应GREEN | 同上 | [green-core.txt](green-core.txt) |
| 独立生命周期RED | `scripts/go.sh test ./runtimes/runc -run 'TestWaitCancellation\|TestTimeout\|TestNaturalExit' -v` | [red-lifecycle.txt](red-lifecycle.txt)：caller取消导致cleanup未执行、超时/清理错误未报告、残余进程未杀 |
| 对应GREEN | `scripts/go.sh test ./runtimes/runc -v` | [green-lifecycle.txt](green-lifecycle.txt) |
| 默认设备deny被资源设置擦除 | `scripts/go.sh test ./runtimes/runc -run TestOCIDevicePolicy -v` | [red-device-policy.txt](red-device-policy.txt) → [green-device-policy.txt](green-device-policy.txt)：保留默认deny |
| 恢复ID验证RED | `scripts/go.sh test ./runtimes/runc -run TestReap -v` | [red-recovery.txt](red-recovery.txt)；最终runtime回归GREEN |
| 关闭exit channel伪报success | `scripts/go.sh test ./runtimes/runc -run TestClosedExit -v` | [red-closed-exit.txt](red-closed-exit.txt) → [green-closed-exit.txt](green-closed-exit.txt) |
| 补充本地driver配置/canceled setup回归 | `scripts/go.sh test ./runtimes/... -v` | [green-driver.txt](green-driver.txt)；不是实际daemon集成 |
| 真实guest外部门槛 | `scripts/go.sh test ./runtimes/... -v` | [conformance-not-executed.txt](conformance-not-executed.txt)：七项全部NOT EXECUTED/SKIP，未取得真实RED或GREEN |

## 最终检查

- `scripts/test-postgres.sh test -race ./... -count=1 -v` → [race-final.txt](race-final.txt)：**22项真实Postgres控制面测试 + 14项runtime单元测试通过，7项真实guest SKIP**。TestConformance外层显示PASS是Go的子测试聚合行为，不能当作七项隔离通过。guest最后只改了清理syscall，之后覆盖该包再次race：[runtime-final.txt](runtime-final.txt)。
- `scripts/go.sh vet ./...` → [vet-final.txt](vet-final.txt)，exit0无输出；最后guest更改后再vet runtime：[vet-runtime-final.txt](vet-runtime-final.txt)。
- 初次govulncheck：[govulncheck-initial.txt](govulncheck-initial.txt)，发现传递依赖x/net0.58.0的4漏洞。升级到当前0.61.0后，`scripts/go.sh run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` → [govulncheck-final.txt](govulncheck-final.txt)：**No vulnerabilities found**。
- `scripts/build-runtime-lab.sh` → [build-lab.txt](build-lab.txt)：静态guest/test编译及OCI生成，**没有运行guest**。`bash -n scripts/build-runtime-lab.sh scripts/run-runtime-lab.sh`通过；无ack runner拒绝：[lab-no-ack.txt](lab-no-ack.txt)。
- `git diff --check`通过。初次全suite本地回归另保留[race-all.txt](race-all.txt)、[vet.txt](vet.txt)。

## 未完成范围与边界

1. 尚未在专用daemon执行七项fork/readonly/network/nonroot/timeout/OOM/seccomp。没有伪造真实kernel结果，也没有向共享daemon创建容器。当前root runner要求root能力，尚未运行；控制器后续可审查专用容器lab方案。
2. 尚未实现跨进程持久claim、scheduler registry、执行前按存储tenant调用Store.Authorize、状态/审计跃迁、日志持久化与API真实logs。生产main仍因未接OIDC而fail closed；已提交run仍queued。
3. deterministic run ID支持恢复：容器/快照/cgroup名为`warden-<runID>`，`Driver.Reap(ctx,runID)`仅杀/删，不重启。scheduler必须先持久独占claim，再恢复并将中断记失败，禁止重新启动同一次run。
4. 日志是前1MiB的内存snapshot，溢出丢弃，worker进程崩溃会丢失；后续持久层须明确记录lost/interrupted，不能伪报完整日志。IO drain/cleanup错误返回给调用者；自然退出也cgroup.kill并验证整个subtree空。
5. 本地测试覆盖builder/文件协议/handle行为；真实containerd API运行、镜像导入与runc/kernel行为仍属于lab验收。guest裸fork helper目前只支持linux/amd64。

具体部署与命令见[专用lab说明](../../runtime-lab.md)。官方依据：[containerd release](https://github.com/containerd/containerd/releases/tag/v2.4.2)、[Go client](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)、[cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)。
