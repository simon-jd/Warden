# 预算独立审查修复 round-1

日期：2026-10-23 America/Los_Angeles（UTC 2026-10-24）。审查基线`3afa92f`，控制器审查记录`4e90e50`保留；修复提交`7906ba6`（完整SHA及各源文件SHA256见[verification.json](verification.json)）。证据在修复commit后绑定，未再次重复完整suite。Python 3.14.4；本轮没有运行真实az、安装组件或改变本机/订阅服务。公共Retail Prices API只读一次，删除路径全部fake az。

## 两项Important及修复

1. SKU/product/磁盘/计算计费配置未绑定quote：现在只支持显式General Block Blob v2 / Hot LRS平面Blob，声明product和SKU与全部Storage meter严格匹配，容量与日志均为Hot LRS Data Stored，操作为该产品明确的读/写/列举/其他10K meter。计算仅显式on_demand、Ubuntu2204、Standard_B2s、Virtual Machines BS Series / B2s meter，不能替换Windows/Spot/Low Priority。30–32GiB Standard_LRS只能选Standard HDD Managed Disks / S4 LRS / S4 LRS Disk容量和S4 LRS Disk Operations IO；S1–S3拒绝。配置与quote selector都写入reservation。Key Vault等没有支持的完整profile，直接拒绝。
2. 已知同会话高价资源失去绑定仍退出0：现在以ledger中requested session未删除高价ID为依据，即使当前rate改0或归属/session/reservation标签丢失，也输出unresolved-session-cleanup，保留资源并在任何候选删除前非零退出（含dry-run）。wrong-session仍安全保留；默认到期reaper仍只要求合法四标签和完整scope，不因附加绑定丢失而改变到期行为。

S4=32GiB依据[官方Standard HDD容量表](https://learn.microsoft.com/en-us/azure/virtual-machines/disks-types)，[s4-retail.json](s4-retail.json)保存实际公共API URL/时间/完整response：Standard HDD Managed Disks、S4 LRS Disk、1/Month及S4 LRS Disk Operations、10K，共2条；报价不是实际用量。B2s compute身份来源沿用[真实原始B2s响应](../../azure/prices/b2s-westus2.json)，Storage真实错配测试沿用[55条Blob快照](../../azure/prices/blob-westus2.json)。没有开通任何资源。

## TDD命令、原始输出与结果

首次focused7运行（`python3 -B -m unittest`加以下7个完整test名称，`-v`）得到`Ran 7 tests ... FAILED (failures=31)`，含子测试；修复后相同7项通过。原始[red.log](red.log)、[focused-green.log](focused-green.log)。

```text
scripts.test_azure_guard.AzureGuardTests.test_real_archived_storage_quote_cannot_price_different_declared_profile
scripts.test_azure_guard.AzureGuardTests.test_storage_quote_sku_or_product_cannot_disagree_with_declared_profile
scripts.test_azure_guard.AzureGuardTests.test_thirty_to_thirty_two_gb_disk_cannot_use_s1_to_s3_or_other_product
scripts.test_azure_guard.AzureGuardTests.test_vm_compute_billing_and_linux_product_must_match
scripts.test_azure_guard.AzureGuardTests.test_keyvault_profile_requires_future_exact_priced_support
scripts.test_azure_guard.AzureGuardTests.test_known_high_cost_session_lost_binding_reports_incomplete_without_deleting
scripts.test_azure_guard.AzureGuardTests.test_default_expiry_still_deletes_owned_resource_with_lost_extra_binding
```

补充declared compute product错配后先运行：

```bash
python3 -B -m unittest scripts.test_azure_guard.AzureGuardTests.test_vm_compute_billing_and_linux_product_must_match -v
```

输出`Ran 1 test ... FAILED (failures=1)`，见[red-declared-compute-product.log](red-declared-compute-product.log)，再补对应product声明校验。最后一次完整相关suite：

```bash
make test-azure-budget
```

[green.log](green.log)：`Ran 40 tests in 10.537s / OK`。包含全部原31项、实际存档Hot LRS→Cool GRS或不同product拒绝、每类storage meter身份错配、30/31/32GiB配S1/S2/S3拒绝及配S4正例、compute billing/Windows/Spot/Low Priority错配、Key Vault未支持拒绝、同会话缺/变reservation/session/owner/project/rate保留且非零、wrong-session安全、混合到期候选与unresolved/dry-run零mutation、默认expired行为保留。删除/配额API只在fake az边界；所有文件锁/Decimal/账本逻辑真实执行，全部临时账本。

`bash -n scripts/azure_reaper.sh`及`git diff --check`均退出0，原始命令/输出见verification。当前真实权威ledger仍0条reservation、**$0.00**累计承诺。没有真实删除/创建或订阅/global服务变更。

## 自审与边界

逐项检查profile在计价前拒绝配置错配，不把它混为数量/用量限制；同会话high-cost识别来自可信ledger，不接受当前标签降rate掩盖；失去owner也会先被识别为unresolved，所有候选删除前统一退出。真实保存quote与四标签、默认fixed subscription/scope、预算累计不退还、并发锁均保持原行为。自审不是控制器独立复审。

尚需未来具体部署审查全部数量、适用meter（含网络/日志操作等）、使用量上限、子资源/镜像配置、即时共享配额和实际部署tag绑定；此次没有部署wrapper。未知profile拒绝，AKS第二RG仍未授权。show/delete窗口、手动会话清理和非实际账单估算边界保持；不声称真实Azure删资源验收。完整追加报告：[budget-report.md](../../../../.superpowers/sdd/2-warden-security-plan/budget-report.md)。
