# Task15 原连续第5/5轮终止裁定

同一原作者和同一原reviewer已完成原2/5至5/5；最后原文见 code-r5-review-20261026.md。原轮次及所有失败永久保留，不开R6、不换阶段名续修。源码仍未应用；只接受之前fix1组件，不接受本轮readiness或整Task15。

root全文读取R5 packet（8382B，SHA256 7bb4751fbb2eb19718b75802f602dcca09b861ecdc9b1706d743578d0fa3e878）、13803B精确差分、完整36路径/171572B allowlist及proof模板。原件位于 .superpowers/sdd/2-warden-security-plan/task15-r5-20261026.packet.json.gz，旧R2/R3/R4原件同目录保留，未改产品/index。

sole bcdd43 known0：两项新增候选合同检查PASS，1611B stdout、stderr空，0.063秒，自有子组已知收尾、源pin不变。只证明生产subjects接受CVE-2020-5410固定候选并拒绝错误CVE；不是registry/签名或真实准入。完整request/fresh/result见 code-r5-pure-native-20261026.json。剩余CODE配额容不下完整render文件树，实际权限检查UNRUN，不借额重复旧成功覆盖。

第5轮裁定：权限准备、候选一致性及manifest计数在源码层解决；整体仍Needs fixes。一个根本阻塞是：真实OCI验证尚无能在原整体90秒边界内产出可信、可归因证据的执行闭包。具体仍缺（1）固定TUF/bootstrap及transitive路径，宿主registry请求和容器共同受强制出网控制，兼容真实GHCR认证；（2）认证同digest scan attestation并将其report/catalog hash和predicate绑定本地评估字节，不能把缺失/坏attestation的拒绝冒充KEV拒绝；（3）整体timer须覆盖input/render/account/assess及最终完成检查，并保留cleanup。以上均未补写或测试。

最小后续替代是一次真实、可审查的信任与出网边界实现，或primary-supported authenticated offline OCI layout并具等价签名材料验证；二者现在都未建立，且不能在已耗尽5/5中继续修。保留main/_network硬STOP；三条真实Kyverno密码学验收、CI/签名/发布全部UNRUN，无新发布/宿主/费用权限。转入另有明确授权的Task9固定镜像兼容性前置，不能重跑Task11/已过catalog或复活任何旧额度。Goal active、项目未完成。
