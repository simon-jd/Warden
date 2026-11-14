# 第三次固定bootstrap实测失败

源码e91e9ad、执行HEADb89835a；此前fixed recovery及ordinary完整postflight真实成功。本次原始公开输出为bootstrap-third.txt，exit2，总27.81s；容器实际Started17:35:43.698Z→Finished17:35:49.306Z、exited/PID0/restart0/OOMfalse。固定安全stage为node-startup/runtime，未取得Ready/identity或完整cleanup marker；不能据此推断具体cause。

镜像sha256:53914c90accfbe8f1e11b530a7ae42edc9d1a79e098a01d50d14f244b5991514（685,369,702B），CID57a48b46ee5477bf65fdb6ae60bf5b7766c652630c7f2549b3e1e013a696c360，session454fc203bfa3b1bb6296520028e6a1cd。outer DEV66307/INO56011098 UID1000/0700；rootchild session-365b23ee00074b56 DEV66307/INO56011150 UID0/0700，保留6GBcharge、496,609,280B rootfs.tar及原image/container，不启动新import或重试。rootfs.tar在失败后保留体现已修复的tar生命周期契约。

公开state/mount/caps/limits见third-failure-state.json；四个copied controller与source commit字节摘要吻合，674inputs/manifestf6da1b8e…及固定etc→run alias见third-verification.json。新manifest/identity/charge分别归档，私有内容未读。preimport项目3,521,900,544B＋6GBreserve=9,521,900,544B≤12GB，service声明7GB≤16GB；六protected sysctls仍匹配。当前不是ordinary完整postflight，未声称完整磁盘walk成功或charge释放。

下一步按fix round4规则换fresh实现者，先仅固定内存诊断和最小源码/回收方案；新源码独立复审后才执行恢复/新bootstrap。Azure承诺估算0、无Azure/GPU变更。Task3仍OPEN。
