# 原 Task15 静态方案及首材料准备裁定

root `19375a` 全文读取8189B [原方案](implementation-proposal-20261025.md)，保持原文，不修改其历史。原静态agent在工作前因 `Selected model is at capacity. Please try a different model.` 失败；替换为同级标准模型的唯一作者，无并行writer，也不是自动审批拒绝。当前HEAD `641af091cd46f0b1b83103ed8a35bbe5de037a3e`，SOURCE/Git/index仍归root。

root核对[Kyverno v1.19.2官方release](https://github.com/kyverno/kyverno/releases/tag/v1.19.2)及固定processor源码，确认存在VerifyAndPatchImages调用；这不是运行证明。[官方SLSA README](https://github.com/slsa-framework/slsa-github-generator)说明v2.1.0后不积极维护，原任务仍保留该generator，兼容性/真实生成与验签不得假定。

web对API/test.go的cache miss不是审批拒绝。正常公开文本读取 `4186fd` 取得官方release JSON78263B和固定test.go37743B；[metadata记录](official-static-metadata-20261025.json)绑定已查明的archive53485462B/SHA357eaf1d…、checksums830B/SHAf06301ce…、bundle10079B/SHA c6299581…。没有下载archive或执行工具。`dff406`补看同一test.go发现invalid policy会被跳过，但未在该文件定位到“Skip计passed”的计数分支；该更具体断言仍待作者给正确固定源码位置，不能当已证实事实。无论如何，零退出/Skip/未匹配都不能代替预期rule实际验签。

Ruling：原6.46GB完整流程估算不能准入，因为必须另加现有R约4.7GB和Q5GB，约16.16GB大于12GB；“接近扣Q后的7GB”漏算R。所有DB更新重叠/镜像层/build cache和输出须计入，不能释放Q或假定old UNKNOWN已清理。完整扫描/CI/真实准入目前关闭；没有新material/CLI/源码实际准入。

Ruling：漏洞attestation须来自一次未过滤的完整扫描结果；不能把--only-fixed后的结果当完整findings，因为不可修复但已列KEV的项会被遗漏。修复可用critical的阻断从该完整结果独立判断。固定Grype版本/JSON字段/新鲜DB与KEV出处尚未核定，当前不取DB或运行Grype。

仅准原作者继续准备精确inert首材料caller，不执行。范围可限既定一个archive+checksums+bundle，全部官方TLS地址和固定hash/字节，新的项目私有namespace；无授权头、registry/Docker凭据或任意重定向。完整本轮新增预留400MiB（368MiB材料上界含archive/临时重复/展开/bundle/log，另32MiB源码/证据/元数据），Q5GB额外计入fresh guard。新内存预留1GiB+旧UNKNOWN9GB仍计入16GB，不准扫描旧PID/服务RSS或私有scene。实际tar展开未知，仅用256MiB硬上限，不冒充实测。

Sigstore bundle可按官方metadata固定hash保存，但当前没有可用验证器/完整信任根闭包，不能声称publisher bundle已密码验证。作者须给最小bootstrap方法或明确改用TLS取得官方API digest的完整性边界；不为bootstrap引入无限工具链。即便之后下载/安全解包通过，也不准执行Kyverno/--version，更不准签名/发布/真实registry或集群。root先全文核对caller及fresh资源/namespace/归属与限额后才另作一次材料裁定。

所有身份未绑定保持失败关闭；第三方签名镜像不替代thisrepo workflow。未来策略须避免只对可信imageReference匹配而令范围内其他镜像直接绕过。无GitHub发布、凭据、宿主k3s/iptables/sudo或GPU操作；原Task6/BP/Task16额度不变。全Task15及Goal仍OPEN，Goal active。
