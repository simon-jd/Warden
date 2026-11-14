# Task15 首次语义 RED 准入裁定

root 668ca6 全文核对精确原 caller 和两个输入；HEAD 6f8af6e，原唯一作者已交回且未运行测试、CLI 或提交。冻结 stub 及测试原件与 caller 一并保留。逐字提取 Python body，仅将 stdin 换为本地 .py.txt 启动；不改代码。

仅准 root 在下一次 fresh azure_guard.py preflight 成功后执行此 body 一次。外部 89 秒＋1 秒 kill grace，内部 88 秒，AS 1GiB、CPU45秒、单文件32MiB、NOFILE64、CORE0。完整新增256MiB含源码/临时/输出；Q5GB额外保留，旧UNKNOWN9GB加新1GiB合计10073741824B，download0。既有 /tmp 精确新路径先确认不存在，caller mkdir exclusive；失败保留，不重试或删旧文件。没有子进程/下载/CLI/服务/云/宿主或GPU动作，没有HOME/umask更改。

期望8项测试、四个既定业务断言FAIL、0错误/跳过，caller exit1。root须全文读取原输出并核对确切失败、原件归属及输入未变后才能接受RED；任何异常/超时停止并记录。4个通过项只证明拒绝无效输入，不能冒充全部GREEN。原始DB marker仅synthetic presence；GREEN前必须核对真实固定Grype DB及KEV结构/来源/时效，不能让marker成为可释放条件。

不重跑旧Task11/12/14、material或catalog，不恢复Task6/11BP/16旧额度；Q/现场/UNKNOWN/12GB/16GB/公开发布边界保持。SOURCE/index仍归原作者，协调档案不纳其提交。全Task15/Goal保持OPEN active。
