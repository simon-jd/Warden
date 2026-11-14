# 第四次固定bootstrap就绪超时

source6f52f54、执行HEAD3cac95a；round4代码复审及第三次场景fixed recovery/ordinary postflight真实成功后运行。原始公开输出bootstrap-fourth.txt：exit2、总268.70s，stage=node-startup/code=timeout。容器Started18:09:45.433Z→Finished18:13:45.831Z、exit2/PID0/restart0/OOMfalse。未取得Ready/identity/完整cleanup marker。

运行中公开profile第四次exactCID9a22e3c1817441fa2c4f50616e68a333d2a06c98641d430a05a810ea3f7cac50确认4GBmemory=memoryswap、512tasks、2CPU/非privileged/private命名空间（fourth-running-profile.json）。仅一次own exactsystemdscope只读采样（fourth-running-resources.json）确认memory.swap.max/current均0、实际memory.max3,999,997,952B≤4GB、当时memory.peak403,394,560B/pids.peak85；不是完整峰值或guest proof。观察脚本最初误要求memory.max精确4e9而assert失败；后记录实际内核按页取整值，并仅修正观察假设，运行时/host控制项无改动。

image sha256:2504a55c791dba7ca00cadae8b11f937aea70ac9149243eb83e590d343bc44a3，Size685,374,913B。session b5370b6ce57638aee676a14c3c272592，outer DEV66307/INO56143028/UID1000/0700；child session-7ca9caee772671b1 DEV66307/INO56143043/UID0/0700；tar DEV66307/INO56143030/UID1000/0600/496,619,520B。原container/image、privatechild/tar和6GBcharge保留，不新import/直接重试。

fourth-failure-state.json公开存档674inputs/manifest1d1a5fc3…、四controller/source摘要吻合、六sysctl仍匹配。preimport项目3,523,809,280B＋6GBreserve=9,523,809,280B≤12GB/service7GB≤16GB。此时不是ordinary完整postflight，不声称privatechild内部形状/清理成功。Azure承诺估算0，无Azure/GPU动作。

进入fix round5/5，fresh实现者优先固定日志/源码定位readiness阶段和必要safe诊断，不再次盲目启动。Task3及Goal仍OPEN。
