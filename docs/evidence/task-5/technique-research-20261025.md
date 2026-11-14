# Task5 行为索引的原始来源补充

2026-10-25只读核对 MITRE 原始页面；用于未来 expect.yaml 的候选索引，不是语料实现、攻击执行或检测覆盖证据。42格真实矩阵仍全部未执行。

| 候选行为 | 原始来源与核对版本 | 边界 |
|---|---|---|
| ARP欺骗 | [T1557.002 ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)，v1.1，页面修改2025-10-24 | 需要受控目标缓存/流量效果；只申请raw socket不证明ARP效果。 |
| ptrace其他进程 | [T1055.008 Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008/)，v2.0，2026-05-12 | 该技术涉及对其他进程的观察/控制或注入；同guest子进程attach是有限原语检查，不是跨沙箱或注入成功。 |
| 反弹shell中的shell执行 | [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)，v1.4，2026-05-12 | 标签索引shell部分；connect或固定字符串回显不证明完整shell交互/越界回连。 |
| 内核模块 | [T1547.006 Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006/)，v1.4，2025-10-24 | 页面包含模块与启动持久化情境；权限探针不能宣称实际load、持久化或Rootkit覆盖。 |
| proc/sys系统信息 | [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082/)，v3.0，2026-09-11 | 普通guest信息可见不等于宿主敏感信息泄漏；跨边界结论另需受控canary。 |
| raw socket相关通信 | [T1095 Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)，v2.4，2026-09-03 | 页面描述协议通信；socket创建/拒绝仅证明能力边界，不计完整C2技术验收。 |

表中将索引与可证明行为区分，是控制器依据来源作出的范围判断。没有因此准许发送ARP、加载宿主模块、访问真实metadata、开放公网回连或改变默认无网络策略。其余已有T1499.001/T1611/T1552.005/T1048.003核对记录保留在原proposal，不重复抓取或改写。
