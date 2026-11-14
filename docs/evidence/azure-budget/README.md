# Azure预算与资源保护证据

日期：2026-10-23 America/Los_Angeles（原始UTC时间2026-10-24）。实现提交：`38771399948944c9570cd205e297007584179d16`。证据在实现提交后生成/最终复验，自审见[self-review.md](self-review.md)，等待控制器独立审查。未更改原17Task勾选或整体Goal。

版本：Python 3.14.4；Azure CLI/Core 2.91.0，telemetry 1.1.0，现有ml extension 2.45.0；未安装/更改插件。版本原始输出见[host-session-start.json](host-session-start.json)。只读核对的配置：Azure for Students / Enabled，订阅`<subscription-id>`；仅`rg-warden-lab`；`rg-mlinfra-westus`永远保护。累计承诺台账仍为**$0.00**，硬门槛$5.40，总上限$6.00；这是新增承诺估算，不是实际账单。

## 最终命令与结论

| 命令 | 结论 | 原始路径 |
|---|---|---|
| `make test-azure-budget` | 31项通过；独立临时目录/台账、真实本地锁/文件/Decimal逻辑，fake az外部边界 | [green.log](green.log)、[verification.json](verification.json) |
| `bash -n scripts/azure_reaper.sh`、`git diff --check` | 退出0 | [verification.json](verification.json) |
| `reserve docs/azure-reservation.example.json --ledger TEMP/ledger.json --markdown TEMP/spend.md` | 真实存档Retail报价精确base-tier选择，临时承诺$0.1448；不写项目台账，不调用Azure | [real-quote-smoke.json](real-quote-smoke.json)；实际报价[source](../azure/prices/blob-westus2.json) |
| `az account show --subscription PINNED --query {id:id,name:name,state:state}` | 固定Students订阅，Enabled | [host-session-start.json](host-session-start.json) |
| `az group show --name rg-warden-lab --subscription PINNED` | 开始/结束均精确ResourceGroupNotFound | [host-session-start.json](host-session-start.json)、[host-session-end.json](host-session-end.json) |
| `./scripts/azure_reaper.sh` | 实际开始调用返回group-absent，退出0，无mutation | [host-session-start.json](host-session-start.json) |
| `./scripts/azure_reaper.sh --end-session budget-evidence-20261023` | 实际结束调用返回group-absent，退出0，无mutation | [host-session-end.json](host-session-end.json) |
| `make azure-down DRY_RUN=1` | 实际dry-run返回group-absent，退出0，无mutation | [host-session-end.json](host-session-end.json) |
| `python3 -B scripts/azure_guard.py preflight` | 实际项目分配磁盘2,184,663,040 bytes，小于12GB；声明服务内存0（没有启动服务）；空闲385,384,325,120 bytes | [host-session-start.json](host-session-start.json) |

## RED与修复

- [red-initial.log](red-initial.log)：功能缺失，成功路径RED（当时azure_guard尚不存在）。
- [red-cost-coverage.log](red-cost-coverage.log)：operation不能用capacity单位、同类别多meter、down记录历史。
- [red-empty-delete.log](red-empty-delete.log)：CLI删除成功可无JSON输出，重复资源ID不能两次删除。
- [red-vm-quota.log](red-vm-quota.log)、[red-vm-batch.log](red-vm-batch.log)：单区域6-vCPU读数及同批聚合，不独立重复消费headroom。
- [red-unreadable-disk.log](red-unreadable-disk.log)：不可遍历目录不能当0磁盘。
- [red-real-quote-tier.log](red-real-quote-tier.log)：真实Blob快照中同meter有多tier；按USD Consumption tierMinimumUnits=0再要求唯一，避免误选首条或拒绝真实base tier。

测试还覆盖外组/外订阅/伪造ID/缺错标签/非法UTC/未过期保留、恰好过期唯一ID删除、非404与权限失败、标签变化二次读取、dry-run零mutations、受保护组拒绝、环境不能改scope、5.40边界/超预算/并发/重复/负值/单位/币种/缺或歧义报价、删除不退预算、session/reservation绑定、高价未来资源保留或本会话清理、本机磁盘/16GB内存/大下载边界。没有源码grep测试。

## 边界

真实Azure验收仅包含读取与不存在组的安全no-op。**没有创建或实际删除Azure资源，没有设置订阅提醒/策略，没有修改其他项目或既有服务。** 删除API调用、错误、quota返回结构通过fake az验证，不能称为真实删除/创建/共享配额预留。未读取或公开token、.env、登录缓存。

工具只reserve，没有创建wrapper；报价类别与单位正确不保证数量足够。实际开通前仍须审查具体配置、所有适用meter、使用量与日志/流量上限、镜像/子资源与四标签、默认权威台账及即时6-vCPU配额。AKS第二node RG仍未获授权，强制门禁；Log Analytics暂不支持，需要0.1GB/日具体实现后审查。内存/新增容量为调用者合计声明，preflight不监控或预留进程资源。没有GPU工作或常驻reaper；高价资源须结束前执行session清理并确认成功。show/delete之间仍存在并发标签变更窗口，专用scope不能由其他操作者并发改标签。

## 独立审查修复round-1

审查基线3afa92f；修复7906ba660b315d6011d4a6425d0ef71b68d1894c。两项Important（计费profile未绑定、已知同会话高价绑定丢失错误退出0）已修，40项相关测试通过，待控制器复审。新证据与来源见[round-1索引](round-1/README.md)；本轮没有真实Azure创建/删除，权威累计承诺仍$0.00。
