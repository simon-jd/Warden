# Task2 core 首审修复 round 1 / 5

日期：2026-10-23。FIX_BASE：`ee8c4b2`。修复实现 SHA：**`978e93d98a2190bc1995ce98c1274a0324057aa1`**。

本轮只修runtime core与专用runner边界，不关闭真实lab、scheduler两个外部门槛。七项真实guest仍未执行；root runner没有执行；Goal与Task2整体状态不变。

## 首审三项 Important

| 问题 | 修复 | 测试 / 原始证据 |
|---|---|---|
| exit到达即Cancel，丢FIFO尾部却成功 | drain先有界等待Wait/EOF；结束后Close；1秒或ctx到期才Cancel/Close并返回明确截断错误 | `TestDrainWaitsForTailAfterExitBeforeCancel`使用真实OS pipe，先写尾部并关闭writer，再延迟20ms启动reader，等效“exit已到但tail尚未消费”；旧实现输出空tail。`TestDrainTimeoutReturnsTruncationError`验证未结束FIFO报错并解除reader阻塞。[red-core.txt](red-core.txt) → [green-core.txt](green-core.txt) |
| root runner alias/预存文件越界写与清理 | 入口`python3 -B`；路径每组件O_NOFOLLOW、核验root/可信operator owner与不可group/other写（root sticky tmp例外）；legacy配置/log/root/state/io/socket含dangling alias一律拒绝；独占0700随机session，配置/log以O_EXCL|O_NOFOLLOW 0600创建；daemon root/state/socket/config/log通过session FD锚定；只清本次session对象，shutil.rmtree(dir_fd)不跟symlink | `python3 -B scripts/test_runtime_lab_paths.py`，8项真实临时FS测试，覆盖lab和祖先alias、6个预存regular/dangling目标、owner/mode、独占session、artifact alias/mutable、session被改名替换、daemon子目录alias。原始新guard缺失RED：[red-path-guard.txt](red-path-guard.txt)，GREEN：[green-path-guard.txt](green-path-guard.txt)。无root/daemon/cgroup调用 |
| socket名称无法保证专用daemon | Config新增显式ExpectedDaemonPID / TrustedOwnerUID；New及每次实际gRPC dial/reconnect核验组件no-follow/owner/mode、socket类型、SO_PEERCRED PID/UID。部署runner的PID取自自己Popen child，非猜测/租户输入 | socket/parent/dangling alias、regular file、错误PID、owner、writable parent、构造后socket替换，另用实际containerd client连接临时inert gRPC Version fixture，证明安全dialer生效。没有连接任何实际containerd daemon。[red-core.txt](red-core.txt)、[focused-race.txt](focused-race.txt) |

## 三项 Minor

- pause已在seccomp allowlist，裸fork child阻塞在kernel pause，避免EPERM忙循环。`TestPauseIsAllowedWhileMountRemainsDenied`在旧policy下RED，修复后GREEN。
- fork至少创建16个child才接受EAGAIN；driver在真实cgroup启动前记录pids.events max baseline，退出后计算增量并读pids.peak；共用suite要求max增量>0、peak==配置32，同时subtree为空。`TestPidsEvidenceNeedsEventsAndRealLimitPeak` RED→GREEN验证文件协议数据解析；补测malformed/backwards拒绝。**这些本地文件测试不是实际pids限制通过，真实suite仍SKIP**。[red-pids-evidence.txt](red-pids-evidence.txt)、[focused-race.txt](focused-race.txt)。lab内核现须提供pids.peak。
- 1MiB日志溢出由Exit.LogsTruncated / DroppedLogBytes明确报告。`TestLogOverflowReportsDroppedBytes`期望4字节buffer收到7字节时dropped=3，旧实现false/0出现RED，修复后GREEN。scheduler必须存储这两个字段；drain异常另有明确截断error。进程崩溃内存日志丢失仍待持久层记录interrupted/lost。

## 命令与最终检查

```bash
scripts/go.sh test ./runtimes/runc -run 'TestDrain|TestSocket|TestLogOverflow|TestPause' -v
scripts/go.sh test ./runtimes/runc -run TestPidsEvidence -v
scripts/go.sh test ./runtimes/runc -race -count=1 -run 'TestDrain|TestSocket|TestLogOverflow|TestPause|TestPidsEvidence|TestContainerdClient' -v
python3 -B scripts/test_runtime_lab_paths.py
scripts/test-postgres.sh test -race ./... -count=1 -v
scripts/go.sh vet ./...
scripts/build-runtime-lab.sh
bash -n scripts/run-runtime-lab.sh scripts/build-runtime-lab.sh
git diff --check
```

- [focused-race.txt](focused-race.txt)：12项focused runtime tests通过。
- [race-all.txt](race-all.txt)：**22真实PG + 26runtime unit通过，7真实guest SKIP**；外层TestConformance的PASS不代表guest gate通过。
- [vet-all.txt](vet-all.txt)：exit0，无输出。
- Python path tests实际普通uid执行，仅创建temp文件；本sandbox将/tmp owner映为65534导致安全guard正确拒绝，故通过require_escalated以真实host ownership视图运行这8项普通用户测试。**不调用sudo/root runner/daemon/cgroup。** GREEN为真实host文件所有权结果。
- [build-lab.txt](build-lab.txt)：static guest/test与OCI构建通过，没有运行guest；[lab-entry-refused.txt](lab-entry-refused.txt)为无ACK入口明确拒绝。Python AST与bash语法检查通过。
- Go1.26.10，依赖版本不变；go.mod只将既有containerd/api、grpc、protobuf移为direct import。本轮按控制器要求没有重复govulncheck，上轮修补后无已知漏洞的证据保留。

root runner仍须安全复审后才执行。当前workspace/cache/lab为775会被新guard拒绝；已在[操作说明](../../../runtime-lab.md)写明普通用户先`chmod go-w . .cache .cache/warden-lab`，runner不会自行修改现有权限。Session的root-owned日志/config保留，不执行自动chown或跨目录清理。

## 持续未完成

真实7项、root runner实际执行、跨进程持久scheduler/claim、执行前tenant重授权、状态/审计迁移、日志持久化/API执行接线，均继续由控制器后续独立子步骤验收。没有fixture冒充关闭这些问题。
