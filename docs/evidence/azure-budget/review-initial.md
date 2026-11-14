# 预算先决条件：独立首审

日期：2026-10-23。审查者 `/root/azure_budget_review`，范围 `6b3593d..3afa92f`；读取完整brief/report/diff及绑定预算文件。没有重跑已有31项测试；补充复现仅使用临时台账及既有fake az边界，无Azure操作、repo/index/HEAD修改、特权runner或共享daemon操作。

Spec：**changes required**。Quality：**changes required**。无Critical，两项Important：

1. `azure_guard.py:325/348/273`：声明配置未绑定计费报价。真实存档示例把资源sku从Hot LRS改Cool GRS仍接受Hot LRS报价并预留$0.1448；30GB VM也接受S1 LRS fixture磁盘报价。必须将支持配置的tier/redundancy/product、磁盘size/SKU及compute计费配置与精确报价绑定，未知profile拒绝。这属于配置不符，不能仅以“用量数量仍需人工审查”解释。
2. `azure_guard.py:408/414`：已知本会话高价资源缺失/改变绑定标签时，保留是安全动作，但命令仍返回0。临时复现预留$0.03/h未来资源、移除warden_reservation，再end-session session-1，退出0、无删除、deleted_at仍null。必须非零报告未完成清理，不能让“检查命令成功”误认同会话销毁已完成。

已认可：固定订阅/组、完整ID、四标签、API失败关闭、全列表与候选复核、dry-run、稳定锁/原子落盘、累计不退款、报价哈希与本机检查；AKS第二组仍门禁。31项行为/RED、真实存档tier解析、实际缺组start/end no-op证据支持报告。

仍未验证：真实删除、真实VM配额响应、部署完整计费/用量、runtime guard接线及实际资源标签；报告已披露。控制器交原实现代理修复round1/5，未创建云资源。
