# 原Task14本地执行器实现裁定

root全文读取8183B[原作者方案](implementation-proposal-20261025.md)，只读准备完成，没有产品/执行/提交权限被追认。按原Task14推进独立可验证的SuspendTenant本地执行器、持久尝试去重、真实磁盘journal与认证审批合同；真实Vault/Azure/K8s适配器、可靠告警来源和真实处置演练仍OPEN。

接受保守的一步剧本子集、严格JSON-as-YAML、已知未实现动作显式Unsupported、失败关闭与无重试语义。保留原Steps接口；多步骤执行/其他动作属于未完成原Task14范围，不能把这一子集报成完整剧本实现。Azure动作名只是未实现合同，不是已核实Graph/Vault能力。

接受配置固定本地journal、fsynced intent先于client调用、重启Unknown永久抑制重复尝试；这是attempt suppression，不是外部exactly-once或已成功处置。未完成/损坏/容量不足不自动修补、删除或重新执行。Close有在途操作时应明确拒绝且保留锁/FD，或其他同等有界安全方式；不能释放锁后仍向旧FD写完成记录。输入与凭证不进入持久指纹/错误。preview不打开journal，不消费批准或去重状态。

真实身份尚缺：审批端口返回经认证且授权的issuer/subject、明确租户/alert/playbook/action/resource绑定与时效，第二身份必须不同。单测recording authority/client只证明本地合同，不证明OIDC/真实吊销/审批系统。ctx deadline依赖合作client与本地存储，不许声称能够强制中断任意文件I/O或非合作客户端；外部受界caller才是实际测试时间盒。

原30秒/512MiB/128MiB cold-build估计未核实，不直接执行。原scripts/go.sh会启动host-network Docker并自动下载toolchain，本组件禁用。08ff96 normal0只读确认native PATH无Go；acea1b normal0只读确认本项目固定缓存Go1.26.10 VERSION（2026-10-19），bin/go与compile为UID1000普通非symlink只读可执行文件，未执行Go/无下载/写入。可准备直接使用此既有缓存的离线caller，不能因此扩到旧Task16 runner/试验或旧native终态。

拟定首次caller整体90秒（work75/cleanup10/kill5），CPU60/AS4GiB仅为逐进程限制；GOMAXPROCS2、编译-p1，GOMEMLIMIT为协作目标不是硬RSS配额，组合新增驻留预留2,000,000,000B（旧9,000,000,000B+新≤16GB）。完整新增磁盘预留1,073,741,824B含cache/tmp/run/source/evidence，Q5GB不变；必须fresh R+Q+新增≤12GB/MemAvailable≥2GB/UID1000/新namespace不存在，才可单独准入。原方案更小限额不追认；此为原Task14首次未执行边界选择，不是旧Task6/16 cap搜索。caller还须说明文件大小与输出分开、有界原始留痕/清理及超时失败停止，目录预算不能假装硬quota。

实现者先准备原三个mandatory测试和可编译非空语义stub，精确firstRED caller交root FULLREAD后才执行；新Go导入/编译/资源/超时不是语义RED。首个结果先交root，不自动GREEN；之后正常原Task14 TDD/冻结一次覆盖及独立审查，不扩旧Task12/Task11成功测试。任何新明确自动审批拒绝保留并停止该动作，不换入口/actor绕过。

源码只准respond/{actions.go,executor.go,ledger.go,executor_test.go,ledger_test.go,README.md,playbooks/suspend-tenant.yaml}，不得改go.mod/go.sum、已有runner、Task16/BP/Task12源码或已验材料。当前裁定仍INERT，root提交协调文档并交明确fresh BASE/SOURCE/index后才开始写源码。首次真实Go命令须另作精确准入；没有服务、云、GPU、host k3s/iptables/sysctl、公开发布或旧场景/Q权限。Goal active，全Task14/项目仍未完成。
