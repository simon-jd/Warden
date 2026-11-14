# Task9 首次 RED：静态审阅与一次实际门禁

root2ed546全文读8128B准备/12349B caller/1668B freeze，161c0a读本次五SOURCE差异，82c93d全文读21851B精确材料表。首三个原计划测试先成功real Request+PostgreSQL+AppendTx，预期三项业务FAIL；必须出现self-approval/外部grant缺失/真实审计缺grant-expiry的具体断言及Task1 Verify正标记。连接、构建、skip、Request前置失败都不算RED。迁移新测试不在此轮运行。

本目录保留五路径初始stub/测试/迁移快照及四个准备原件，均未运行。首caller SHA294179ca8d24c335a00baf3e8df8f247675ac7a614738f08fdf5869a3cc87fa5，material SHA1ca3cbfa3cf4a3ba960dc4ced03f8eb24d2e8429e9ae5e7b0e34d3d08b54fbbd，freeze SHA8f498b9220b29dd8b26753950a1896631265df3a6e2a3abf810872eb2e5be6a8。不得替换body或复用已存在N；native原正常审批路径执行，任一拒绝不换入口。

仅 fresh R+Q5000000000+held131072+完整new1748683264<=12000000000 且MemAvailable>=6500000000、UID1000、项目/cache安全父目录、四旧tmp保留、新N不存在后，才准唯一一次精确outer：timeout --signal=TERM --kill-after=4s 86s python3 -B -，stdin为已核body。caller再检查两个精确自有container名不存在。此为原Task9功能测试，不是Task15隔离probe或旧Task16 profile/sizing；没有拉镜像、网络发布或宿主iptables动作。

new resident6500000000+oldUNKNOWN9000000000=15500000000B<=16GB；具体Go1GiB/PG512MiB cgroup+单个CLI4GiB AS+parent256MiB AS=6174015488B，剩余325984512B作daemon/开销保守预留。parent hard4GiB仅让child预执行设自身soft4GiB，parent soft256MiB不提高。完整disk预留包含已缓存image1GB、Go472MiB、PG192+8MiB、两个shm1MiB及host/daemon40MiB。现有镜像无下载/构建/重复展开，root仅接受这次只读rootfs/no volumes+有界tmpfs的新增估算，不把未知新image当已闭包。

整体90秒含TERM/KILL，work65/cleanup82/status85；所有CLI须known group cleanup后才下一CLI。只按新随机owner标签清理这两个新名，no global list/旧PID扫描/信号；未知即STOP保留，不启动另一实际。输出128KiB总界，保留N/raw/native请求结果；无语义RED则不自动调界重试。成功RED也只交root，不自动实现、GREEN或提交。

SOURCE/index目前在root；legacy Task16/BP dirty未改，旧任务计数不重置。此静态裁定不是fresh成功或已执行。固定ending reaper480e33已知本项目RG不存在，本次测试不创建云资源。Task9/Task15/Goal保持OPEN active。
