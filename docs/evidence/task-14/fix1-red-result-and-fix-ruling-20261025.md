# Task14 原 fix1：真实 RED 及修正准入

fresh `9bf6f0` known0：R4589907968 + Q5000000000 + 新1073741824 = 10663649792B ≤ 12GB，服务预留11GB。sole actual `b8ce2a` / session15114 → `7150de` known1，7.3955秒。root `c8055a` 全文读取 977B stdout、0B stderr、1188B status 和 2385B request，八份原件/冻结源码副本在 [fix1-red-first-20261025](fix1-red-first-20261025/)；完整请求、结果和poll见 [fix1-red-native-events-20261025.json](fix1-red-native-events-20261025.json)。

3 FAIL / 0 PASS / 0 SKIP，恰好父项和 failure/success 两子例；两个 FIX1_RED_REQUIRED，均真实观察 syncs=0 / mutations=1，非编译/setup/cleanup错误。own_group_absent=true，源码/module/freeze不变，新namespace61186048B，post MemAvailable85835063296B。root接受该真实语义 RED，旧条件与这次失败证据保持，不重跑。

原唯一作者现仅准 I1 行为修正：保留新建文件的文件 fsync，每次成功获得锁并通过原校验后无条件要求父目录同步成功，失败在 intent/client 之前返回 ErrStorage。同步 README 说明；不再扩 seam、接口、功能或其他测试。原测试字节保持，除非代码编译或本次直接必要问题需先报告。

准备一次冻结受影响 cover：新增回归加直接受影响的 journal 初始化/重开/失败用例，清单交 root；不重跑整81或其他Task。无需新增formatter调用，保持Go格式即可。唯一cover caller仍先由root全文核对/fresh门禁后才执行；目前没有 Go、formatter 或 Git 提交准入。完整报告另建 fix1 mirror，原报告/raw不覆盖。第1/5轮持续，全部资源、现场、旧额度与发布限制保持，Goal active、全Task14 OPEN。
