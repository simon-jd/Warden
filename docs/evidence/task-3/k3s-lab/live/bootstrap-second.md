# 第二次 bootstrap：入口失败，保留私有现场

UTC 2026-10-24T16:43Z，源码 `3d87ef6`、运行时 HEAD `a4e6fb0`。此前同源码的真实零 capability 挂载检查通过后，控制器执行固定 bootstrap。见 [run metadata](bootstrap-second-run.json) 和 [完整公开输出](bootstrap-second.txt)。

结果 **exit 2，未观察到 Node Ready、公开 cluster identity 或成功 cleanup marker**。输出只有固定入口的 `RuntimeError` 与 host 收尾的 `PermissionError` 类型；此时不猜测 k3s 是否已经 exec，也不声称完整清理。

[只读状态](second-failure-state.json) 确认精确容器已 `exited`、PID 0、Running false、restart 0、非 OOM，实际入口运行约 2.41 秒。outer session 仍为 UID1000/0700、device66307/inode55586536；内部 `session-224a50855c9a6da6` 为 root UID0/0700。本次容器、镜像和 6GB charge 保留，没有重启或凭外层退出直接释放。

[本次 manifest](second-manifest.json) 的 674 个文件摘要为 `585eabd7b4d7d77088468b5981fcf26eb4c64cd02d169f082990e6a794d517c0`；四个复制 controller 已与 `3d87ef6` 内容核对，见 [verification](second-verification.json)。另保留 [identity](second-identity.json) 和 [未释放 charge](second-charge.json)。导入前项目 3,520,335,872 bytes 加 6GB 保守预留低于 12GB，服务峰值声明仍为 7GB、外层 4GB/512 tasks/2CPU。

root-owned 私有子目录使普通 UID 的完整磁盘检查按设计拒绝，因此这里**没有新的完整磁盘 postflight 声明**。新导入和对象启动保持门禁。诊断只允许从已验证停止的本次精确容器，通过固定日志 archive 流在最多 32MB 内存中分析，不新增磁盘副本，不输出原始私有内容或凭证，不修改权限。后续回收须有适用于这个已执行入口的具体证明，不能套用第一次“从未 exec”的清理特例。

16:52Z 只读核验六项受保护 sysctl 仍匹配；没有 Azure/GPU 操作。原实现者进行第 3 轮定位与生命周期修复；整体 Task3、driver、guest 限额、conformance 和 100 次启动验收均未完成。
