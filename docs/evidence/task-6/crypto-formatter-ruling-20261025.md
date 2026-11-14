# 一次固定gofmt源码编辑裁定

实现者已取得真实compile RED并保存事前快照和前后manifest；当前crypto实现尚未完成最终覆盖/独立review。本裁定不是测试或业务验收。

Ruling: 允许普通UID1000仅执行cachedGo1.26.10的固定`bin/gofmt -w`，只格式化`controlplane/internal/authn/verifier.go`、`jwks.go`、`verifier_test.go` — 这是可逆的源码编辑工具操作，避免为格式化另加容器profile模式，不属于host Go编译/测试授权 — 若目标或输出不符，最多源码格式需要重做，不能使用该裁定运行其他主机程序或绕过后续隔离测试。

前置检查：固定binary及三个目标都须nofollow普通文件、正确受信owner、单链接；binary无组/其他写权限或setuid/setgid，记录其SHA256、size、mode及目标源码前后hash。只有显式上述三个路径和`-w`，不接受选择器/额外文件/其他工具链。`GOMAXPROCS=2`、`GOMEMLIMIT=256MiB`、umask0077、10秒墙钟上限；无下载、网络、服务、Go build/test或其他目录修改。

sourcehash会因格式化变化，须单独记录为编辑，不能声称测试期间源码不变或重新构造RED。之后所有Go单元运行仍使用已批准的capless/UID1000/netnone/ROsource/2GB固定identity-unit容器及fresh guard、完整manifest和cleanup；生产API/SQL/SCIM/真实Entra、维护超时状态/Q、所有原轮次/预算及发布限制保持。根ledger和本裁定为controller文档，不放进实现者source/evidence提交。

## 本次机会关闭：前置祖先检查拒绝，未执行

实现者的记录器额外使用shared `trusted_directory`验证binary父链；因组/其他可写目录拒绝，尚未读取/校验binary或执行gofmt，三个源码文件未变。这是本地严格metadata guard拒绝，不是自动审批拒绝或gofmt程序失败。

Ruling: 取消上述原生formatter机会，不再依据较弱检查尝试，不放宽helper或改父权限；改用普通源码编辑手工规范格式并继续原固定unit profile — 主机binary的祖先信任未成立，格式化不值得新增执行面 — 代价是手工格式整理，不能用其绕过编译/安全测试。没有新增profile alias、其他工具链或hostGo授权。保留此次真实前置拒绝记录；不要为无源码变化重跑旧测试，最终source稳定后再按原有限TDD/冻结cover完成。
