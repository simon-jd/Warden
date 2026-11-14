# Task 1 独立审查（首轮）

日期：2026-10-23。审查实现：7fb9bd73c903ff88a515160532d240318c5d276c；基线6834fa3。审查者：独立子代理 task1_review（gpt-6.1-sol）。范围：Task1规范合规与代码质量；只读检查完整diff及实现报告，未重复既有测试。

结论：Spec不通过，代码质量需要修复。

## 已确认的证据

- 创建run与audit同事务，有触发器失败实际回滚测试。
- Postgres租户/幂等唯一约束和16并发测试；runID为crypto/rand16字节base32。
- GET与logs按token tenant过滤，跨租户/未知ID404。
- UPDATE/DELETE/TRUNCATE触发器；中间记录篡改定位及独立SHA-256 fixture；16项真实Postgres/race结果可查。
- 未配置真实OIDC时main全部401；未伪报runtime执行。

## Findings

1. **Important**：runs/runs.go:106、109、123，api/api.go:93。请求可直接把网络设为allowlist或将资源设为任意正数，没有可信租户策略授权，违反Global Constraints“租户策略没有显式放开时”。queued不构成授权边界。要求在持久化前默认拒绝放宽，并验证可信策略显式允许，含无策略/明确策略测试。
2. **Minor**：scripts/go.sh:10与README.md:28。工具容器未转发文档所示WARDEN_LISTEN_ADDR，会静默忽略配置。要求转发或修正文档。
3. **Cannot verify**：审查diff未含PathWatch格式基准。控制器随后只读核对PathWatch公开docs/evidence/README及plan Global Constraints：必须包含日期、实现git SHA、版本、配置、原始数据路径、结论、边界。Task1缺实现SHA，已纳入round1证据修复；未读取相邻项目私有配置或状态。

## 后续

修复round1由原实现者执行，必须保存RED/GREEN、提交并做scoped re-review。该记录保留首轮失败，不能将其覆盖成通过结论。
