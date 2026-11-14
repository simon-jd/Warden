# Task2 scheduler core 独立首审

Reviewer：/root/scheduler_review。BASE d44821b，HEAD 08b0383。实现77e4e05。以下为控制器归档摘要，保留独立verdict、findings及行号；审查者未运行重复suite或修改checkout。

## Spec Compliance

- ❌ Issues found：日志超时存在资源回收竞态，未完全满足有界worker生命周期；要求的迟到server创建行为回归尚未实现。
- ✅ durable claim提交后才启动、同session/generation围栏、状态/结果/日志/审计原子提交、stored-tenant策略复核及unavailable-runtime fail closed有对应实现：controlplane/internal/runs/execution.go:66、122、171；controlplane/internal/scheduler/scheduler.go:130、185、198。
- ⚠️ 实际API→runc、原daemon quiescence/reconciliation仍是明确后续门槛，不据此否定获准core范围；生产verifier仍nil：controlplane/cmd/warden-api/main.go:64；scheduler/README.md:31。

## Strengths

- DB session持有执行权，claim commit失败不返回可启动对象，执行期间没有跨Wait的事务；状态更新验证前态/generation/backend PID并与审计提交（execution.go:66、122、171）。
- gate稳定inode flock、文件/目录fsync，先永久消耗身份后Start，Reap先撤销，未知创建状态跨重试保持（runtimes/gate/gate.go:96、152、164、196）。
- 真实PG backend termination、commit timeout、terminal audit rollback、多进程竞争、迁移/audit hash有行为证据；normal/race最终输出通过（test-final.txt:55、race-final.txt:55）。
- HTTP取消后执行、跨租户404及持久结果联合测试（api_test.go:507）；日志聚合上限、NUL/非法UTF-8及读失败处理（scheduler.go:277）。
- 明确区分runtime fake与容器隔离；RED、已修正fixture失败和不存在卷检查有上下文，不当作当前测试失败（README.md:5、41；postgres-cleanup.txt:5）。

## Important

1. 日志snapshot超时后发布时reader和读取goroutine可永久泄漏。位置controlplane/internal/scheduler/scheduler.go:283、285、290、353。时序：collect goroutine取得reader后在发送opened前暂停；deadline分支发现channel空走default返回；恢复后发送到无人接收的buffered channel再阻塞Read，已没有timeout Close。即使Logs()未违反契约也能发生，重复突破worker资源上限。现有scheduler_test.go:597仅覆盖deadline前已发布reader。修复须明确发布/取消所有权交接，迟到reader也关闭；增加可控时序回归证明Close及读取goroutine退出。

2. 迟到server创建回归缺少实际迟到创建状态。位置runtimes/gate/gate_test.go:146、172、174、177及scheduler_test.go:681。现有fake仅返回不确定RPC error、Reap永远nil，没有延迟materialize资源。补充可控fake：Start报错但保留待完成创建，第一次Reap在不存在时成功，随后释放远端创建，再由新gate/worker恢复；始终不terminal-clean、不第二次Start，后续Reap精确处理同RunID且ambiguity不自动清除。

## Minor

固定候选窗口可能暂时闲置额外worker：execution.go:49；scheduler.go:70。Candidates把有效session的starting/running计入最早128条；若跨进程活跃作业占满窗口，额外worker反复ErrBusy，暂时看不到后续queued。timeout/完成通常解除，不判永久饥饿或本轮阻断。后续可分页/跳过忙候选并保留执行权检查。

## Assessment

Task quality：Needs fixes。核心DB/runtime双层围栏及保守ambiguity方向正确，须先修复snapshot泄漏并补齐指定回归。

核查：未运行重复suite、未修改checkout/index/HEAD；输出截断处仅补读package内main/execution片段。唯一unchanged-code定向检查针对Start后取消setup context是否影响guest生命周期，读取runc/driver.go:53与handle.go:71，确认detached context。
