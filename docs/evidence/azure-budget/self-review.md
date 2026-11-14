# 预算保护自审

日期：2026-10-23 America/Los_Angeles（UTC 2026-10-24）。自审不是独立复审。

- Scope：全部az调用显式固定已只读确认的Students订阅ID；没有target/subscription覆盖选项；资源ID严格完整解析，拒绝其他组/订阅/编码/嵌套scope。rg-mlinfra-westus仅被保护警示提及。
- Reaper：组核对ID/name/四标签，只有精确ResourceGroupNotFound才no-op。列表先整体验证，选中资源全部重新show比对，再按唯一ID删除；dry-run无Azure mutation。缺归属资源retain，自己标签损坏fail closed。默认future TTL retain；session-end还需完整ledger/tag/session/reservation绑定。
- Down：整组显式固定scope，核对组与四标签；仅fake边界验证删除。删除无JSON返回也算成功；异常读取和删除响应均不伪装不存在。Azure删除成功后只追加删除时间，历史费用不减。
- 估算：Decimal、累计5.40门槛；flock稳定锁在原子rename之外，锁内重新读账并验证总额；没有释放/退款命令。JSON先落盘，Markdown失败时保留已承诺费用，render可恢复视图。quote原始bytes只读一次后解析/hash/存档，避免两次读取分叉。
- 报价：完整meter/product/SKU/region/unit，USD Consumption base tier，类别单位/服务匹配。实际55条Blob快照测试发现相同meter跨tiers，修成先精确base-tier选择再唯一性；没有选首条。多个操作meter可共存。未使用免费层默认0。
- 配额：VM查询真实az边界（测试替换为fake）region cores行，必须limit=6，聚合同批和未删除项目VM承诺；可能保守重复计已运行VM。没有实际VM创建，配额并未被预留；创建前须即时重读。
- 本机：完整项目分配磁盘+声明增长/下载，读取失败不当0；12GB/16GB与大下载50GB+体积边界有行为测试。不清理、不创建服务、不用GPU。内存是调用方必须准确提供的本项目合计峰值，不是进程监控。
- TDD：初始行为RED、覆盖单位RED、空删除响应/重复ID RED、quota/批聚合RED、不可遍历目录RED、真实tier报价RED均保留。早期quota分支缺直接测试时删除该函数，先补测试再重实现，并观察批量quota独立RED。首次测试down写回了空的默认台账/视图（仍$0.00，没有测试reservation写入），已将所有删除测试也隔离到临时路径；最终31项测试全部临时台账。

## 剩余边界

没有创建wrapper，类别/单位正确不能证明数量覆盖所有实际消耗。未来部署必须审查具体配置、全部适用meter及使用量上限、组和子资源标签/绑定、Ubuntu镜像来源、即时共享配额，读取默认权威台账；备用ledger只供离线测试/计划，不授权部署。AKS第二node RG仍无授权，强制拒绝。Log Analytics未支持，须带0.1GB/日具体实现后再审查。不提供常驻reaper；高价资源结束清理依赖会话调用且须检查成功。show/delete之间无统一Azure标签条件事务，避免外部并发改标签。台账不是已结算账单，也不抵抗有写权限的人主动篡改/删除。真实Azure删除仅fake测试，实际验收只做本组不存在的安全no-op。
