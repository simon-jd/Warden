# 原Task15 第1/5轮定向修复裁定（原初审保留）

root已全文读取唯一独立review并逐字归档 [8500B全文](review-local-component.md)，SHA892767434ae5278a729db65752187ccba6e075f736347dfabfdb0650785fa017。Spec Issues found / Quality Needs fixes，0C/3I/0M。当前source75a141d、evidence94da92d及metadata890b55c全部保留；第一次真实RED4业务FAIL与15PASS不改、不重跑当新进展。Task15进入原第1/5修复轮，不另开阶段或额度；旧Task6/11BP/16耗尽保持。

I1：Dockerfile只COPY controlplane，dockerignore也只准该树；现控制面实际导入warden/runtimes、gate及runc，本地包不会由go mod download提供。只补必要runtime source及明确transitive本地依赖至context/COPY，不扩上下文到cache、Git、证据、私有现场。静态核对既有真实import即可；不为这一小配置修正写字面镜像测试。Docker镜像实际构建仍UNRUN、完整peak未准，不以静态修正冒充实际build；若需build须另交真实预算和精确caller。

I2：生产读取onlyFixed/onlyNotFixed/vexDocuments与固定Grype真实only-fixed/only-notfixed/vex-documents不符，空mapping/缺字段/排除package也可放行；默认不include matcher suppressions使ignoredMatches空仍漏项。按固定v0.121.0 primary原字段及类型建立完整必需profile、拒缺/过滤/排除，workflow显式开启matcher suppressions。暴露后的ignored/suppressed仍须保留原report并按已有拒绝边界处理，不能写scanComplete true放行漏项。

I3：缺失/null/非法severity目前可被当非critical放行。按固定severity枚举及类型在决策前校验，合法Unknown为显式用例；只完善本次真实决策所用的必需字段，不扩成新schema框架。

仅原作者：本次root协调commit的fresh BASE后接管限定源码/index。第一步只修真实profile fixture、写I2/I3两个新业务回归及必要Unknown正例并交inert首RED caller；生产逻辑/Docker/workflow先保持旧行为。测试直接调生产函数，不复制判断，不以import/setup/异常当RED。root全文读精确body并fresh门禁后只运行新回归一次，再准最小修正和一次受影响scan覆盖；未变renderer/旧15全批/Task11/12/14/catalog/material不重跑。共享scan fixture实际改动的直接受影响旧scan tests可在最终一次cover中包含，不扩大mock/哈希/元控制器。

允许源码最多controlplane/Dockerfile、.dockerignore、.github/workflows/build.yml、scripts/supplychain.py、scripts/test_supplychain.py；policies/kyverno/README.md只在本次profile说明确受影响时作最小改动。两policy生成器/真实三密码fixture/SLSA URI及格式不因未证实疑点顺手修改。固定primary文本可读；不下载或运行工具/DB，不改CLI模式。

执行预算仍完整新增256MiB，另保守128KiB覆盖两个已保留/tmp树并加Q5GB；fresh R+Q+new+held<=12GB。new1GiB+oldUNKNOWN9GB计16GB；每实际caller89秒TERM+1秒KILL/内部88秒、AS1GiB/CPU45/FSIZE32MiB/NOFILE64/CORE0、全新独占namespace，失败/未知/超时停止保留。先交稿，不授测试/guard/formatter/Git运行；之后root逐项另准。没有HOME/umask/host/GPU/服务/云/publish或旧现场动作。

最终冻结后只准准确SOURCE与独立新EVIDENCE/完整fix1报告提交，再同一原reviewer一次定向复核I1/I2/I3及fix带入新问题。实际SLSA predicate/cert、Cosign/Kyverno bundle/lookup/CLI credentials/cache、Docker/CI/真实registry/集群/原三密码验收仍OPEN UNRUN；不把文档不确定项当已证实URIbug，不扩大本修复。全Task15/Goal OPEN active。
