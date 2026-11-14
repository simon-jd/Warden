# 用户恢复后的原现场目录恢复

这次只完成原停止现场的物理目录恢复。原文件、journal、authority、RunID、两次失败历史及 Q=5,000,000,000B 均保留；没有启动新 VM、执行租户或修改宿主 k3s/iptables。原 owner/Gate 退休仍 cleanup_pending，creation_outcome 仍 unknown，旧 node 永不重新开放。Task4 与整个项目仍未完成。

- 先决核验：[preflight.json](preflight.json)，源0c7dedb/helper72675e91、双历史和清点摘要匹配，计入 Q/H 后9,823,279,616B。
- 条件授权：[controller-ruling.md](controller-ruling.md)，只允许同一固定操作中的一次 restore。
- restore 实测 UTC08:22:35.982077→08:23:05.267250，exit0/29.285231s；独立 postflight UTC08:23:52.468008→08:23:58.687361，exit0/6.219474s。原始日志及元数据作为新文件添加到[原 source 证据目录](../recovery-live/0c7dedbf38499ee991f879e93e43b9f5df9bb7f4/)，没有改动暂停时的 README/index 或原证据。
- [独立只读复核](restored-audit.json)确认22项清点/双历史摘要不变、九个目录 UID1000、全部普通文件元数据不变，原及两个 helper 的 CG 路径缺席，Warden 容器/镜像0、helper临时预留0。
- 已保存的普通完整检查实际计数整个项目4,182,470,656B，再加仍未释放的 Q5GB，总计9,182,470,656B；服务声明1GB host allowance，六项受保护 sysctl 一致。

控制器记账修正：restore 前的本地提交尝试被 docs/evidence/plan-review.md 的末尾空行检查阻止，未产生提交；已写入的条件授权仍在工作区，实际调用使用未变的已审查 source/helper，并再次执行其锁内身份、预算与全部门禁。随后修正文档空行并将原授权、交接和新证据一起提交，没有改写失败记录或产品代码。

后续只进入原第五轮 B 段的有界诊断代码/测试和独立复审，不增加因果轮次。用户最新要求保留 Q；本轮不授权 Q 释放或新 VM。
