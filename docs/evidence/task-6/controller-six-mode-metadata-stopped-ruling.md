# 六目标有限批次停止裁定

root已全文读取独立复核 `review-six-mode-metadata.md`，Spec Issues found / Quality Needs fixes，0 Critical、1 Important、1 Minor。接受I1：新增fixture `controller-six-mode-metadata-verification.py:112–116` 在原child_end已耗尽后使用无timeout的第二次communicate。外层45秒alarm不能替代原每child≤5秒/剩余wrapper时间边界；alarm直接os._exit还可能跳过失败留存。这是精确的本次load-bearing阻塞，不能给整个SOURCE/verification批次PASS。

四个实际FD和四个fake事件/静态六映射均已按其已运行路径PASS；没有实际timeout。原PASS证据不重分类为运行失败，也不能覆盖未执行的timeout分支。SOURCE d05a374、EVIDENCE a014316及作者report/所有旧证据字节保持。原Task6 5/5、material额外1/1成功耗用保持；六目标覆盖1/1、唯一独立复核1/1（失败）均已消费。额度立即停止，无源码/夹具修补、补测、重跑、第二review、新轮次或改名循环。

## 精确最小未应用差异

只针对本次I1，供以后另行授权评估；本文件不是执行许可，也不是已验证补丁：

1. 保持既有绝对child_end和wrapper END，首次communicate在child_end之前预留固定、有界的kill/drain/wait收尾时间；不得在到期后创建新的5秒或45秒。
2. 捕获TimeoutExpired时，先保留异常中已有的原始partial stdout/stderr、timed_out=true、terminal_known=false、原child_end以及仍持有的owned child handle/身份和临时树，并在任何后续收尾前写入失败记录；不伪造exit/empty输出。
3. kill/drain/wait仅能使用同一child_end的正剩余量；移除line116的无timeout communicate。任何不能在该截止内确认终态的情况立即停止批次，保留unknown与owned handle/临时数据，不把kill请求当终态、不清理unknown子进程仍可写的树。外层45秒仍只是更外层上界，不作子进程续时或成功证明。

该最小差异未应用、未执行、未独立审查；本次不请求或自行授予修补额度。后续若要执行，需要单独明确授权并解决真实可执行的同截止收尾/终态留存，不能修补或复活本次终态。

## M1与actual边界

M1接受并记为Minor：作者report第64行“before/after bytes+metadata”过强。实际snap留存的是SHA256和metadata，原始预期raw另在argv；动态envelope正文未保存且临时树已删除，不能补造/通过重跑回填。原报告原样保留，本裁定澄清，不称完整前后字节转录。该Minor连同原四项递延Minor进入最终审查清单，不从记录中丢弃。

actual未准入、未执行任何六模式操作。除本次复核失败外，Task16原native子孙终态/持续停写、当前dirty source资格、生产路径fresh absence/ownership、资源/时钟/二进制信任等原门禁依然各自未满足；容器已删除不证明旧native终态。不扫描PID、不重发旧PID/PG信号、不重放material、不改现场/Q、不以hash替代authority。

root转向原Task11独立日志归一化工作，不把它作为Task6新阶段或新轮次。Task6/Task16/Goal保持OPEN，原预算/12GB/16GB/scene22/Q5000000000releasedfalse/宿主隔离和公开发布限制不变。本次没有自动审批拒绝；后续若有，仍必须原文报告并遵守。
