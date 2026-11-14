# Task11 初始方案裁定

root全文读取子agent的8146B方案 `local-pipeline-proposal.md`（cafecafb7a48ca4ec1f347642b2ee047e1870181402fc451ee897537c474873c）。它是子agent设计，不是用户审批、已执行测试或已实现管道。接受六种源标签、五个归一化文件/六套golden、固定OCSF类/索引、显式reject、真实本地Vector测试与仅本地HTTP背压对端的范围；真实REST/Storage/集群/Tetragon/OpenSearch采集和Warden exporter仍OPEN，不称已接通。

Ruling: 原方案new_max2978564032B加既有约4.3GB和Q5GB会超过12GB，因此不可直接执行。突发源改为按需流式生成，不把32,320个16KiB payload另存600MiB spool；所有源/测试spool合计改为16MiB，IDs/计数/输出也在既定driver/evidence预算内。修订new_max=2366195648B（6*(268435488+67108864)+50000000+200000000+4096+2000000+262144+67108864+16777216+16777216）。这仍保守计入六个buffer最大值，未启动配置也不因此省略；fresh ordinary R+Q+尚未计入R的新增峰值必须<=12000000000，实际开销计一次、不能漏掉归档解包重叠/目录开销或使用旧R准入。不能满足则不开跑，不释放Q或清现场。代价：更小spool会将压力传递给流式producer；必须分别记录目标速率/实际写入/接收/停顿，不谎称受背压时仍实现精确320/s。

Resident暂按old UNKNOWN保守9GB+Vector3GB+driver/peer1GB=13GB，不能当已测RSS；fresh可用量和各实际进程上限仍需核定。child/readiness/kill/drain/peer join都必须在既定绝对截止内，先留TimeoutExpired partial/unknown再收尾，无截止后communicate、未知终态删树或参数阈值搜索。没有任何Task16新调用或旧PID/PG权限。

材料进展：web transport cache miss后，root以受限15秒/CPU5/AS128MiB的只读公共文本调用f2a424 normal0取得两份官方文本，未下载二进制/归档/源码包、未执行Vector或测试。公开摘录 `root-publisher-text-20261025.json`，原暴露返回另留ignored retention；摘要不称完整wire。官方0.45.0-SHA256SUMS的musl包预期SHA256=0588f529200befa3237481255b9b7715316de73d626e1d01042e054f92205c71；预期值来自publisher文本，不是下载包自报hash。OCSF v1.3.0 system.json证实继承base_event且actor/device required；这只补齐该父定义，不是完整递归object/profile闭包的证明。

继续原Task11静态准备：仅核对剩余固定0.45.0 CLI/test/buffer/metric定义和1.3.0递归必需字段，给出最小工具获取与首个RED的精确有界命令。允许读取官方文本（含有界stdlib HTTPS文本回退，不执行远端代码），不下载binary/archive、不安装/执行Vector或测试、不写产品、不修改Task1审计schema或Git/index。根目录版本/材料/schema已确认且root核定fresh预算/精确命令后，才由唯一实现者进入源码/TDD。该静态交回必须短，不另造通用recorder/controller/hash证明框架。

Warden原审计缺少time/actor/src：不补造、不以tenant当actor、不以collector_observed_at冒充原发生时间、不声称verify原hash-chain；缺上下文的raw事件可见拒绝，synthetic envelope只证明映射fixture。Task1/live exporter缺口保留；System完整闭包及pinned Vector行为仍待核对。原Task6失败/所有轮次和actual CLOSED、Task16dirty/oldnative、Q/scene、Azure6/本机12GB16GB/GPU锁/宿主隔离/禁公开发布保持；不把初始方案或材料读取记为Task11/Goal完成。
