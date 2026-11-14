# 原Task15 源码实施裁定

上一Goal回合为PROGRESS，当前HEADc92b6ff；本回合开始reaper67e876 known0确认项目RG不存在。root `b5e304` 全文读取6142B [源码准备](source-preparation-20261025.md)。它提供固定CLI依赖写路径线索及完整CI/策略路径；没有运行CLI或写产品。

Ruling：不重设HOME/home/CODEX_HOME。原准备建议私有HOME不能执行；CLI继续关闭，须在固定keychain/TUF实现上确认其他环境变量足以隔离凭据/缓存。此项不阻碍仅stdlib生产渲染/完整扫描处理代码。没有CLI运行、权限改变、下载、网络registry或bootstrap准入。

Ruling：UNBOUND字样不构成不可满足的签名身份。未绑定默认策略必须真正拒绝，生产renderer在完整合法绑定缺失时先报错、不输出可部署允许策略。真实identity依未来可信GitHubcontext绑定；本地synthetic配置只证明格式和产出，不冒充真实签名。

完整源码目标仍为原Task15所有步骤：控制面OCI构建、Syft CycloneDX签名attestation、未过滤完整Grype结果及可修复critical gate、完整漏洞attestation、Cosign keyless镜像签名、SLSA generator provenance，以及精确签名/来源/同digest/KEV准入和原三真实验收manifest。真实发布/三密码用例/集群仍UNRUN，不用本地语义替代；全build/DB峰值旧方案仍关闭。

第一批仅编写scripts/supplychain.py非空语义stub和scripts/test_supplychain.py真实调用测试，准备精确inert首RED caller。stub不得产生可执行允许策略或签名/网络动作，返回明确unimplemented结构而非以导入/异常错误冒充RED。测试覆盖合法synthetic绑定渲染、未绑定/错误digest拒绝、完整扫描的fixable critical、不可修复KEV、related CVE，以及ignoredMatches/DB证据缺失失败。测试直接调用生产函数/CLI，不复制生产判断。固定Grype JSON/DB/KEV字段仍需primary核定，未确认字段不得编造已支持。

纯源码/stdlib测试完整新增上界256MiB，含源码64MiB、临时128MiB、输出64MiB；内存预留1GiB+旧UNKNOWN9GB，fresh资源门禁另加Q5GB。没有实际执行/测试/formatter/提交准入，root读首caller并fresh后单独准入。之后才正常实现全部限定路径，覆盖所有原CI功能，不削减最终验收；一次必要本地覆盖及独立审查仍须完成。

SOURCE/Git/index需本次root协调提交后的fresh BASE再交原唯一作者；旧Task16/BP dirty与root协调证据不纳作者提交。原Task6/BP/Task16耗尽、Q5GB、private scene/UNKNOWN9GB、12GB/16GB、无host更改/无GPU/无推送发布全部保持。Goal active，全项目和Task15 OPEN。
