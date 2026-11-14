# 漏洞优先级与修复 SLA（Task 16）

## 结果

| 度量 | 值 |
|---|---|
| 修复中位时长 | **未知**：没有真实的发现清单和修复历史 |
| SLA 违约数 | **未知**：同上 |
| EPSS 发布 | 模型 `v2026.06.15`，score_date 2026-10-26T12:03:22Z，395,492 个 CVE |
| KEV 目录 | 版本 `2026.10.26`，dateReleased 2026-10-26T22:24:24Z，1,758 条 |
| KEV 里有 EPSS 分数的 | 1,758 / 1,758 |
| EPSS 中位数：KEV / 全部 | 0.53742 / 0.00632 |
| EPSS ≥ 0.1：KEV / 全部 | 1,324（75.3%）/ 17,497（4.4%） |

原始输出：[task-16/feeds-live-20261027.json](task-16/feeds-live-20261027.json)（2026-10-27 13:27Z 的 `make vuln-feeds`，含两个 feed 的 sha256）。

## 数据来源

- EPSS：`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`（匿名 GET）。
- KEV：`https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`（CISA 官方 GitHub 镜像）。
- 两个 feed 都通过了 `vuln.ParseEPSS` / `vuln.ParseKEV` 的全量校验：CVE 格式、重复、取值范围、日期、`count` 与条目数一致、JSON 重复键。新鲜度：拉取时间和 EPSS 发布时间都在 48 小时以内。

## 规则（`vuln/`）

- 排序：先 KEV，再 EPSS 降序，再 CVSS 降序，最后对外暴露的优先；排序稳定。EPSS 未知按 0 排，但输出里单独标 `epss_known`。
- SLA：KEV 或 critical（标签为 critical 或 CVSS ≥ 9）7 天；high（标签为 high 或 CVSS ≥ 7）30 天；其余 90 天。按经过的时间算，截止时刻算作达标。

## 没做的

- 发现清单：本机没有 Grype/Trivy 扫描结果，也没有修复记录。等 Task 15 的 CI 产出扫描结果后，用 `make vuln-feeds VULN_FINDINGS=<file>` 计算。
- 每日定时拉取：要装 cron 或 systemd timer，属于宿主配置，这次没装。现在只能手动跑 `make vuln-feeds`。
- Grafana / OpenSearch 看板：没做。
