# Task2 scheduler core：round1独立复审

Reviewer：/root/scheduler_rereview1。FIX_BASE08b0383，HEADe8c3789；codeea41312。以下为独立复审结论。

- **Important 1：迟到 snapshot reader 泄漏 — ADDRESSED。** `controlplane/internal/scheduler/scheduler.go:287、:300、:374` 改为无缓冲所有权交接：未交接时由 producer 在取消后关闭 reader；交接后由 caller 负责超时关闭；`sync.Once` 避免重复关闭。`controlplane/internal/scheduler/snapshot_test.go:18、:31` 确定性地等待超时返回后释放 snapshot，并在 fixture 清理前检查关闭及 Read 退出；提供的 RED→GREEN 输出与代码一致。

- **Important 2：缺少实际迟到 server 创建回归 — ADDRESSED。** `controlplane/internal/scheduler/scheduler_test.go:737、:774` 的 backend 在 Start 返回错误、首次 absent Reap 及持久 failed/pending 后才实际创建同 RunID 资源。`:785、:792、:804` 用新 adapter/gate/worker 恢复，验证精确删除迟到资源、保留无关资源、仅一次 Start、三代持久执行身份，以及每次均保持 ambiguity/cleanup_pending、无伪造 Result。

- **修复新增破坏：无。** 未发现新引入的 Critical、Important 或 Minor 问题。

- **范围外观察：无新增。** 已延期的候选窗口 Minor 不重开；实际 API→runc 和原 daemon 静止证明/reconciliation 仍为后续 Task 2 门槛。

- **核查：** 已检查包内 focused、完整 normal/race、RED→GREEN、vet manifest 和精确 fixture 清理证据；normal/race 均为 55 个顶层、68 个含子用例 PASS，无 SKIP/race report。未重复运行测试或 git，未修改 checkout/index/HEAD；首次工具输出截断后，仅补读包内遗漏区段。

- **Fix round：All findings addressed, no new Critical/Important breakage。** 两项 Important 均关闭；本结论仅接受此轮 core 修复。
