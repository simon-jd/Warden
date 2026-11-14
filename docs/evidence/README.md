# 验收证据索引

每份证据记录日期、已验证实现的 git SHA、组件版本、配置、命令、原始数据路径、观察结果、结论与边界。先提交代码，再用后续证据提交绑定实现 SHA。模拟/fixture 仅支持本地逻辑验证；真实运行时、云和连续观测需要独立证据。

- [当前完整任务状态](../STATUS.md)
- [初始环境](environment.md)

以下验收尚未完成：三运行时隔离矩阵、冷启动测量、IdP 分配/取消、工作负载身份、Vault TTL/撤销、云日志与背压、真实攻击检测、7 天误报、真实处置计时、供应链准入、漏洞修复 SLA、最终逐条审计。

- [Task1：控制面、租户授权与审计链](task-1/README.md)（22项真实Postgres测试；独立复审通过）
- [原始验收账本](../ACCEPTANCE.md)
- [外部验收前置条件](../PREREQUISITES.md)
- [计划审阅与执行裁决](plan-review.md)

- [Task2 runtime核心](task-2/README.md)：后续真实lab、HTTP→PG→runc及调度退休已验收，见[实测与限制](task-2/api-runtime/live/README.md)。
- [Azure Retail API预查询与范围边界](azure/pricing.md)

## Task17 current analysis

2026-10-25, BASE `f127289b159a69b89045b16a3fcee0cd7562ac8d`.
The [threat model](../threat-model.md) and [indicative CC6/CC7 mapping](../soc2-mapping.md)
are subagent-produced analysis, not human annotation, real-cloud evidence or an
audit opinion. Only Tasks1/2 are accepted; other tasks and the overall Goal remain
OPEN. The original [Task6 actual failure](task-6/controller-material-actual-blocker-20261025.md)
is retained and its final5/5 chain is closed without repair/retry.

## Current isolation evidence

- [Task2 seven real runc conformance behaviors](task-2/lab-live/README.md): actual
  kernel/lab results with the cited version/configuration limits.
- [Task2 real HTTP → PostgreSQL → runc and node retirement](task-2/api-runtime/live/README.md):
  fixed test identities; no production OIDC or general fleet recovery claim.
- [Task5 isolation matrix](isolation-matrix.md): all42 attack cells remain
  unevaluated; previous runc conformance does not fill these cells.
- [Task5 classifier fixture report](task-5/classifier/6cedf69d7da82e7fd2cd80c69d5d9bfb5b0024aa/README.md):
  fabricated subagent fixtures only, not actual attacks or human labels.
- [gVisor binding scope](../gvisor-backend-binding.md) and
  [Firecracker finite diagnostic evidence](task-4/round-5-b/0da497136069bf045912f257f7c6d26c962f9d34/README.md):
  partial implementation, with actual runtime acceptance still open.

## Pending integrations

Expected destinations below are literal repository paths, deliberately not links
to missing files. Do not create placeholder measurement artifacts to pass a link
check. Existing [acceptance requirements](../ACCEPTANCE.md) and [current status](../STATUS.md)
record the obligations. Task17 final index integration remains OPEN until genuine
future evidence exists and is linked here.

| Evidence | State and exact expected destination | Required producer / evidence boundary |
|---|---|---|
| Isolation attack matrix | Present: [docs/evidence/isolation-matrix.md](isolation-matrix.md);42 unevaluated cells | Task5 real entry/objective/exit/log/cleanup evidence across three runtimes; later Task12 detected rerun |
| ATT&CK coverage | Present: [docs/evidence/attack-coverage.md](attack-coverage.md), local conversion/tag component accepted | Task12 has32 rules/64 synthetic fixture contracts; [independent review](task-12/review-local-component.md) approved local component. Real OpenSearch positive-hit/negative-miss and live detection remain UNRUN; [Task5 technique research](task-5/technique-research-20261025.md) is research only |
| Detection metrics | Partial: `docs/evidence/detection-coverage.md`, rendered from the Task 5 corpus runs on runc and gVisor under the online detector (`docs/evidence/task-13/emulation-20261114/`) | Only one successful corpus run to score (not detected), so no latency p50/p95; Atomic/Stratus live runs and the seven-day normal false positives still pending |
| Time to contain | Missing/pending: `docs/evidence/time-to-contain.md` | Task14 [local executor component accepted](task-14/local-component-review-ruling-20261025.md): local approval contract/preview/journal, original81PASS plus fix1 affected34PASS and independent review. Genuine identity/action integration and replay/contain timestamps remain UNRUN |
| Vulnerability SLA | Missing/pending: `docs/evidence/vuln-sla.md` | Task16 sourced feeds and remediation history, median repair time and SLA breaches; historical scan is not a repair-time series |

Validate existing local links with `python3 -I -B scripts/check_threat_model_links.py`.
This verifies destinations/fragments, not measurements or control effectiveness.

- [Task15：供应链源码与本地扫描组件](task-15/local-component-review-ruling-20261025.md)（初审3I及原fix1/5保留；两个新业务RED后13个scan方法PASS，同一原reviewer复核I1/I2/I3均ADDRESSED；仅本地组件接受，Docker/CI/真实签名、provenance、KEV及集群准入仍UNRUN；[完整报告](task-15/fix1-report.md)、[复核全文](task-15/review-local-component-fix1.md)）

- [Task15唯一真实OCI发布前置包](task-15/task-15-real-oci-readiness.md)与[33路径冻结清单](task-15/task-15-real-oci-source-manifest.json)：只读准备已交协调父审，保护/配额、永久公开metadata及技术门禁仍缺；没有上传或CI许可。
- [Task9首RED实际2/2停止记录](task-9/first-red-final-stop-ruling-20261026.md)：PG启动失败、无业务测试结果，自有PG已清理；草稿未验收，不能重命名绕过额度。

- [Task9 logger修正唯一诊断](task-9/pg-logger-corrected-result-ruling-20261026.md)：完整State/log证实本次initdb POSIX共享内存ENOSPC，PG未ready，无业务RED；原业务2/2及总诊断2/2全部spent，自有容器已按owner删除，仅保留[未应用初始化mmap候选](task-9/pg-initdb-mmap-UNAPPLIED.diff.txt)。
- [Task15原连续第2/5轮CODE复核](task-15/code-readiness-r2-20261026/root-ruling.md)：4I未闭包、产品未应用；旧fix1接受不变，有限新修订/复核额度已消费，不自扩轮次。[原review](task-15/code-readiness-r2-20261026/review.md)及[独立预算账本](task-15/code-readiness-r2-20261026/allocation-ledger.json)保留。

- [Task10唯一Envoy公共metadata结果](task-10/envoy-metadata-20261026/root-reconcile.json)：index/amd64 manifest留存，config redirect被原门禁拒绝，单次停止；没有layers/runtime/Cilium真实验收。

## Task 6/8/14 真实 Entra（2026-11-10 至 11-12，worktree `cloud-identity`）

- 说明和数字：[identity.md](../identity.md)（Task 6）、STATUS 的 Task 8 行、[time-to-contain.md](time-to-contain.md)（Task 14）；复审修复第 1 轮的 RED/GREEN 日志在 task-6、task-8、task-14、azure-budget 下的 `tdd-review-round1-20261112.txt`。
- 2026-11-12 移走的原始输出：gitignored 的 `.cache/task6-idp/` 和 `.cache/task8-14/`（含真实租户 ID、用户对象 ID 和订阅 ID）原样移到所有 worktree 之外的 `~/Desktop/warden-private-scratch/`（目录 0700、文件 0600），没有删除。
- 移走后的 grep（2026-11-12，值只放在 shell 变量里，没有打印；三个 Warden worktree 的全部文件，含未跟踪和 gitignored 的）：没有文件含租户 ID 或用户对象 ID。订阅 ID 还在：本 worktree 未跟踪的 `.cache/azure-subscription`（`scripts/azure_guard.py` 和长期密钥审计按设计从这里读）；本分支 64 个跟踪的旧证据文件（2026-10 的 reaper 记录、`task-6/crypto-*` 里的源码快照、task-9/10 的原始事件；其中 40 个后来在 `1b537e3` 脱敏，见下一条）；主 checkout 和 task3 worktree 里 `implementation/warden` 版本的 `scripts/azure_guard.py`、`docs/azure-spend.json` 等（本分支 `61e6c60` 已去掉）和主 checkout 里 15 个未跟踪的 `.superpowers` 审阅 diff。仓库公开前还要处理这些文件和 git 历史里的订阅 ID。
- 订阅 ID 脱敏（2026-11-12，`1b537e3`）：64 个文件里的 40 个把订阅 ID 换成 `<subscription-id>`，别的字节不变：`azure-budget/README.md`（第 5 行正文）、`azure-budget/host-session-start.json`、`azure-budget/host-session-end.json`、`azure-budget/red-empty-delete.log`、35 个 `azure-budget/reaper-*` 记录和 `task-9/r1-source-and-review-package-native-20261026.json`。改之前核对过：跟踪的文件里没有记录这 40 个文件的摘要或字节数，也没有记录其中含 ID 的行、JSON 字符串或连续几行的摘要（sha256、sha1、sha512、md5、git blob，全长和 12/16 位前缀，hex 和 base64）；唯一命中的是 `docs/azure-spend.json` 里订阅 ID 本身的 SHA-256，这是设计如此。剩下 24 个没改，因为别的证据记着它们的字节，改了这些记录就对不上：
  - 13 个文件自身的 sha256 记在别的文件里：`task-6/crypto-red-01/red-source/`、`task-6/crypto-unit-02/source-snapshot/`、`task-6/crypto-cover-03/source-snapshot/` 下的 `scripts/azure_guard.py` 和 `scripts/test_azure_guard.py`（分别记在 232 个和 200 个文件里）；`task-10/score-first-green-20261026/native-requests-and-results.json`；`task-9/first-green-a-20261026/native-events.json`、`task-9/fix1-red-a-20261026/native-events.json`；`azure-budget/` 下的 `reaper-task15-final5-end-20261026.json`、`reaper-task9-business-red-c-end-20261026.json`、`reaper-task9-pg-mmap-validation-end-20261026.json`、`reaper-user-resume-20261025-start.txt`。
  - 11 个 reaper `.txt` 记录自己的 `raw_sha256` 或 `log_sha256` 就是含 ID 那一行的摘要（第一个还记在 [plan-review.md](plan-review.md) 里）：`azure-budget/` 下的 `reaper-controller-recorders-source-checkpoint-20261025.txt`、`reaper-diagnostics-review-checkpoint-20261025.txt`、`reaper-identity-code-checkpoint-20261025.txt`、`reaper-firecracker-enumeration-checkpoint.txt`、`reaper-firecracker-material-code-checkpoint.txt`、`reaper-firecracker-material-refusal-end.txt`、`reaper-firecracker-round-3-checkpoint.txt`、`reaper-firecracker-round-5-a-checkpoint.txt`、`reaper-firecracker-round-5-checkpoint.txt`、`reaper-firecracker-static-abi-start.txt`、`reaper-user-pause-end.txt`。
  2026-11-14 的私有仓库（`b55b49f` 的树，单个根提交，不含 git 历史）把这 24 个也换成了 `<subscription-id>`，Entra 应用、服务主体和密钥的 ID 换成 `00000000-0000-0000-0000-0000000000NN` 形式的占位符（同一个 ID 同一个占位符），并删掉了几段代理流程说明。树里记着的这些文件的 SHA-256 摘要和字节数指的是改动前的原件，原件在本地的完整 git bundle 里。
- git 历史（2026-11-12 查的，本轮没有改写任何提交；合并或公开前要由用户决定）：
  - 另一个项目的标识（应用名、第二个应用名、appId、对象 ID、客户端密钥 keyId、project/owner 标签、存储账户名；当前文件里已由 `ebe5212`、`52f10a2` 换成占位符）还在本分支的历史里：`32b294f`、`cf7253b`、`3caba19`、`ce67603`、`2833a1d` 加进来，`ebe5212`、`0905613`、`52f10a2` 去掉，`32b294f` 到 `580f770` 之间 42 个提交的树里至少有其中一个。这些提交只在 `cloud-identity` 上，这个分支没有远端，所以合并前还能改写；合并进 `implementation/warden` 以后就进了主线历史。
  - 订阅 ID：`git log -S` 找到 50 个加入或去掉它的提交，48 个在本分支的起点 `b80c1aa` 之前，也就是 `implementation/warden` 本身的历史；本分支的 2 个都是去掉它的（`61e6c60` 改 `scripts/azure_guard.py`，`1b537e3` 脱敏 40 个证据文件）。改写这部分历史会影响主线。
  - 租户 ID 和用户对象 ID：本分支能到达的提交里都没有。
