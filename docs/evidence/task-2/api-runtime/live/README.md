# Task 2：真实 HTTP → PostgreSQL → runc 与原节点退休

2026-10-24T05:29:07Z 至约05:29:21Z（本地2026-10-23）。首次reviewed实机运行exit0；`TestHTTPPostgresRuntime` **PASS，2.16秒，无SKIP**。源码09eed7b，证据a894232，独立代码审查已通过，运行HEAD为仅文档后续提交3db4a15。原始输出：[live-first.txt](../live-first.txt)。生产OIDC仍由Task6实现；这里使用明确的测试身份验证器。

命令：`python3 -B scripts/runtime_lab_docker.py api --other-service-memory-bytes 0 --reviewed-live-profile`。普通宿主UID1000运行；受限Docker lab外层4GB/512PID/2CPU，独占PG512MiB/128PID/1CPU，私有network namespace，无host端口；guest自身network none。没有Azure/GPU、下载或共享daemon操作。

| 验证 | 实测 |
|---|---|
| HTTP真实提交、可信stored tenant再次授权 | 固定fixture通过；排队后策略撤回的run拒绝启动 |
| 成功及最终日志、租户B读取、同key幂等 | 成功run K5HAFNJHZXUERZF6GPML5LDJDI，Code0，`PASS uid`，cgroup空；跨租户404、幂等断言通过 |
| 自然失败 | P7WROBMVRQ6Q6JEFUWNVS4HRUI，Code1，exit_nonzero，完整日志，cgroup空 |
| 超时 | X6UFO3GGROOV5QQ4G5KMK2FPII，Code137，TimedOut=true，PeakPids8，cgroup空 |
| acknowledged-start恢复 | FMAWUNLAQQW45TY7GTOGRFGDEM，原worker被kill/reap后仅Reap；interrupted/worker_lost，logs lost，result null，无pending |
| 未收到gate启动确认的真实任务 | GHELQEWRWGIXBMOPG46AVTVMFI，先保持不确定状态；永久retire原node并核验清理后interrupted/node_retired，logs lost，result null，无pending |
| 审计 | 26 entries，完整Verify=PASS，事务包含原authority/run/proof SHA |

原节点authority为`api-lab/2aaa4fc36625512da0d88d43d963d658`；原daemon PID26、worker PID101，captured cgroup device30/inode1866459。实际两阶段先封闭旧authority、杀完整树并观察退出，再由原Popen拥有者reap和FD锚定数据清理，最后核验pidfd HUP、空树、原目录nlink0及无替换项。最终retired记录及binding/consumed markers原样保留于[gate](gate/retirement)。proof SHA256为`c259ee523728debb30625f4d4a6a1ab0d6c6d7d6d70c600b044817ce80a8daf0`；与HTTP fixture审计输出及归档文件哈希一致。

该lost-ack场景在真实runc Start成功后、gate确认前人为阻塞，不声称重现containerd服务端延迟发布竞态；后者另由调度core状态化边界回归覆盖。永久退休是本次独占node的最小协议，不是通用fleet重启或supervisor丢失后恢复接口。

普通UID后验收见[postflight.json](postflight.json)：精确outer32b825…、PGb59f7e…、镜像f06028…已删除，项目ownership范围内container/image空；原cached PG镜像保留。保留session仅config/log/gate，root/state/io/socket均已移除，文件UID/mode和inode信息已记录；daemon已reap、cgroup空是内层协议的真实通过条件，外层删除不替代这些证据。669个输入与代码阶段manifest逐项一致。

运行前资源guard：project2,482,290,688bytes＋5,000,000,000预留≤12GB；合计memory4,536,870,912bytes≤16GB。结束后[guard](postflight-budget.txt)：project2,482,614,272bytes，service0，outstanding import charge0。对象删除不证明Docker content store所有字节已物理GC；仍保留原预算工具的保守语义与禁止global prune边界。

本门槛结合[真实七项conformance](../../lab-live/README.md)、各core/入口独立审查，支持控制器接受Task2。Task3–17及整体Goal继续进行；没有真实Entra或Azure部署声明，累计Azure承诺估算仍$0.00。
