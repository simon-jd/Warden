# Task15 唯一真实 OCI 前置包：root 交接

原唯一作者按[用户有限授权](../../COORDINATOR-TASK15-REAL-OCI-READINESS-20261026.json)交回[8144B提案](task-15-real-oci-readiness.md)及[5728B manifest](task-15-real-oci-source-manifest.json)；root4586f8全文读取。197d99[有界核对](real-oci-allowlist-root-check-20261026.json)确认33项/140901B与f5ebf06100660ae930d33b0bdb5acfc9fde97eb1各Git blob一致，并逐字归档两原件。作者本来按工作区冻结；Git绑定是本次root补核，不倒改作者原记录。该快照不能替换成后续Task9改动后的工作区或整段Git历史。

只读账号结果属于作者报告：JDinSeattle、plan/private quota null；候选HTTP404；私有库第一页筛warden为[]。前三项原tool ID在作者压缩后未保留，不能冒充root已获原始tool凭证；第四项508248 known0。没有重新查询来制造历史证据。账号套餐、可用权限、剩余额度和可用受保护私有owner全部仍未知。

[GitHub保护文档](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)与[额度文档](https://docs.github.com/en/billing/reference/product-usage-included)已由root定向核对：Free私有库不能满足所需分支保护；包含额度不等于这个账号的剩余额度。[固定SLSA文档](https://github.com/slsa-framework/slsa-github-generator/blob/v2.1.0/internal/builders/container/README.md)同时明确公开Rekor泄露私有repo名，以及必须完整版本tag而非SHA。tag非immutable，未授例外，不能默认为满足用户固定pin要求；不得减弱透明日志或签名身份来消除冲突。

这是一次可审准备交回，不是可直接执行的发布方案。现有workflow push会触发、无声明timeout/concurrency；private SLSA opt-in/实际兼容、大小写preflight、可生成真实signed-KEV负例的隔离路径、原CLI宿主凭据/缓存边界及真实DB/catalog兼容均未完成。不能原样push冻结workflow，不能以关闭签名/KEV校验或第三方signed镜像替代本仓库三条真实验收。提案的三OCI对象仅是未来定义，尚无任何实际digest或验收收据。

协调父可据两原件决定必要下一步：先确认既有、无新增费用的合格私有owner及足够免费余量/硬停止；明确永久公开repo/workflow/ref/commit/digest/签名身份metadata的范围；后续才可能对精确private repo/package、有限上传、保护/手动CI/收尾分别取得人类授权。现在没有付费套餐升级、repo创建、push/upload、CI、package或Rekor发布许可；提案付款选项也不构成预算授权。工作流/fixture/pin冲突仍须未来准确源码审查，不在本次单次准备后自开修订循环。

旧HOME条款是SOURCE/宿主约束；真实Task12自动审批usage失败及同原路径恢复见既有记录，不是Task15 HOME工具拒绝。此段无新自动审批拒绝，不绕过旧拒绝。原Task15 fix1/5、所有旧失败/耗尽额度、Q5GB/UNKNOWN9GB/四tmp128KiB/12GB/16GB/Azure6USD/现场及无宿主权限保持。Task9原作者独占SOURCE/index继续，root仅归档公开协调证据，尚未stage。Task15真实验收UNRUN，Goal active，整个项目未完成。
