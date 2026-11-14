# 固定旧构建缓存维护与响应处置的范围裁定

独立子agent `/root/identity_cache_review`（gpt-6-astra/high，非真人）对 source7be15fa/evidence3f41765 的首轮审查提出 Important、plan-mandated 冲突：原Global Constraints要求处置动作支持 `--dry-run`、破坏性动作经第二身份审批，而本次维护入口按原裁定拒绝全部参数。首轮审查保留，不能把源码review或fixture当作实际删除授权。

Ruling: 本次仅回收固定 `.cache/go-build` 中已确认且可离线重建的旧 Go 派生产物，是开发资源维护，不属于安全告警触发的响应处置动作 — 原计划Task14明确将处置接口定义为 `Executor.Handle(alert Alert, dryRun bool)`，包括撤销租约、隔离Pod、CordonNode、SuspendTenant等；本入口不调用这些接口，不改变租户、运行中工作负载、云资源或身份权威 — 若范围判断错误，代价是旧构建对象需要离线重编译；这不能成为删除证据、原现场、身份记录或其他资源的先例。

因此保留此固定无参数维护入口，不把独立审查者冒充第二操作身份，也不虚构第二身份批准。原Global Constraints关于响应动作的dry-run与第二身份审批要求没有撤销，后续Task14及任何租户/云资源响应删除必须满足。此裁定仅解释这一精确旧cache维护范围，不批准本次实际chmod/unlink，不授权一般删除工具或任何云/身份操作。

执行计划须明确上述分类，并继续保留所有真实操作门禁：冻结source/sourcehash及真实祖先/锁身份、旧cache来源、controller确认无并发writer、普通UID/GID1000、完整只读白名单预检、durable intent先于任何收紧、未知/部分状态不重试、不回退权限；fresh完整项目R＋所有Q/ownimage＋96MB保守维护headroom须在12GB内，常驻内存含1GB host allowance在16GB内。实际后需另核普通完整guard、原现场/兄弟cache不变、durable completed与sourcehash，新增标准3GB测试预留仍另行评估。

只读构造不是公开 `--dry-run`，也不在此声称已经提供该接口。固定维护流程的预检和失败闭合设计仍由原source审查及本次定向复审评价。需要未来更广维护能力时必须单独提出并审查，不能复用本裁定。

原审查Minor（父目录/部分chmod/删除后result fsync失败fixture尚未分别注入）保留为deferred，静态路径传播错误并保留intent，但不把未运行fixture写成已验证。后续最终全分支审查必须看到此项；实际超时、异常或缺结果一律未知并停止该操作。Task6原业务/SQL/真实IdP、Task3/4原轮次和Q5GB、Task5真实42格及整体Goal均保持未完成。
