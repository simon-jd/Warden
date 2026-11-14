# Task 2 core：独立复审 round 1

日期：2026-10-23。审查者：独立代理 `/root/task2_review`。范围：`ee8c4b2..2456e06`，只检查原 finding 和修复新增退化。未重跑已记录测试，未执行 root runner，未访问共享 containerd。

- 原 Important：IO 提前 Cancel 丢尾部、root lab 路径/symlink 越界、socket 别名不能证明独立 daemon，均 ADDRESSED。证据分别为真实 OS pipe、临时文件系统、实际 Unix listener/gRPC fixture；这些不代表真实容器隔离通过。
- 原 Minor：允许 pause；fork 验收要求至少 16 children、真实 pids.events 增量与 peak=32；Exit 提供 LogsTruncated/DroppedLogBytes，均 ADDRESSED。
- 新 Important：`runtime_lab_runner.py` 的 cleanup 将 cgroup.kill、daemon terminate/wait 放在同一个 try。kill 写入抛 OSError 后会跳过 daemon 回收，随后关闭锚定 FD，可能遗留 root daemon。必须独立 best-effort 收尾并聚合错误；未确认空树时保留状态。需故障注入测试证明 kill 写入失败仍回收自己的 daemon。
- 真实七项 guest、root runner、scheduler/API 持久执行接线继续 OPEN，不在本次 core 修复完成范围。

结论：core fix **Needs fixes**；没有 Critical；Task 2 整体未验收。控制器已交原实现代理修复 round 2/5。完整逐项审查结果记录于本次协作消息，修复实现和测试见下一轮证据。
