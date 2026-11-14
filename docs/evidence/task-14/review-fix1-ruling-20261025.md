# 原 Task14 独立审查修复第 1/5 轮

初审全文见 [review-local-executor.md](review-local-executor.md)：Spec Issues found / Quality Needs fixes，0 Critical、1 Important、0 Minor。root 接受 I1；已有 SOURCE `2ff0602893bbe39ebc472da79fbd8f518bedc3f9`、EVIDENCE `955ef5da9d0044ab7ec1d8d4db31c8cd38286175`、原三项 RED 与 81 项 PASS 不重写、不重跑。此轮属于原 Task14 连续修复历史，不恢复 Task6、Task11 BP 或 Task16 额度。

I1：当前仅创建者在获得锁后同步父目录；另一个 opener 可打开尚未确认目录项持久化的已存在文件、先取得锁并跳过目录 fsync，随后写入 intent 并调用 client。文件 fsync 不能替代父目录 fsync。

限定修正：获得 flock 并通过既有文件校验后，每次成功打开 journal 都必须先成功同步其父目录；失败保持 fail closed，在任何 intent/client 前返回 ErrStorage。保留新建文件所需的文件同步。允许一个最小、非导出的初始化测试 seam 来确定性注入目录同步失败和观察此边界；不增加可配置的生产绕过、全局 hook、框架、元控制器或其他行为改动。README 仅同步这一持久性说明。

验证仅覆盖 I1：先新增对“创建但尚未锁定/未确认目录持久化”的真实临时文件的回归，证明旧条件会漏掉同步；目录同步失败必须阻止 client，成功路径必须先同步后调用。用实际 create-before-lock 交错或等价窄初始化 seam，不伪称物理断电证明。第一次 RED 前保留旧 created 条件，只可增加必要 seam 与回归。作者先交精确 inert caller、冻结输入和受影响测试清单；root 全文核对并通过 fresh 资源/namespace 门禁后才准一次 RED。根因修正及最终一次受影响覆盖另行准入，禁止重复全 81 项或 Task12/Task11/Task16 测试。

源码/索引以 `955ef5da9d0044ab7ec1d8d4db31c8cd38286175` 为本轮 BASE 交回原唯一作者。root 协调文档不 stage，不混入修复提交。旧报告与原件保持原字节；另建 fix1 报告及公开逐字 mirror、新原件 namespace、限定 SOURCE 和独立 EVIDENCE 提交。完成后交还索引，由 root 对准确 BASE..HEAD 做一次定向独立复核，只判断 I1 与修正引入的问题。

原 90 秒整体界限（含收尾）、2 GB 新预留、1 GiB 新磁盘峰值、Q 5 GB、旧 native UNKNOWN 9 GB 预留、12 GB/16 GB、正常审批路径和失败即停保持。无新下载、云、服务、宿主更改或公开发布准入。全 Task14、真实身份/动作适配器/多步骤/contain 演练和整个 Goal 均 OPEN；Goal active。
