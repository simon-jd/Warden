# Task9 新增单次PG启动诊断：静态门禁

用户[新协调授权](../../COORDINATOR-TASK9-DIAG-TASK15-CODE-20261026.json)db8c44已全文读；它仅新增DIAGNOSTIC_ONLY1/1，原业务FIRST_RED2/2仍SPENT。Task10唯一作者已交回8174B方案并停止，无其他source/index writer。SOURCE/index在root。Task15 CODE准备尚未开始。

root406e74全文读取12283B最终body、16042B从已消费b的diff、7410B说明及1295B冻结。移除全部Go/测试/SDK/proxy/source复制；固定image、PG data/tmp/shm/memory/server配置不变。仅新PG使用local logger1MiB/1file，日志完整捕获且全CLI总131072B；溢出/超时/身份或清理不明均UNKNOWN_FAILURE。只查询新CIDfile、实际run回执和Id/Name/随机owner一致的对象。无旧PID/旧容器查询或宿主网络操作。

新独占N .cache/task9-pg-startup-diagnostic-20261026-a、新容器warden-task9-pg-diag-20261026-a必须先不存在。Root需fresh R+Q5000000000+held131072+完整new1254803968<=12000000000B，MemAvailable>=5500000000，oldUNKNOWN9GB+new5.5GB=14.5GB；完整new含local日志至少2097152B以及40MiB全部namespace/raw/public/Git/index/daemon开销。旧a/b及四/tmp保留，未删除或返还任何额度。新body固定SHA d4f01316984c4d33425c0e4dcc006a1d22becceee8b99ca9e91016ff8341da70。

满足fresh后，仅root原正常审批路径准一次精确outer timeout --signal=TERM --kill-after=4s 86s python3 -B -，stdin为已核新body。整体90秒，work65/readiness30/cleanup82/status85不变。捕获ready及notready两路径的State和tail80，再按CID/name/owner清理并精确absence。状态0/DIAGNOSTIC_RECEIPT_COMPLETE只说明观察和清理收据完整，不说明PG成功、业务RED、产品完成或旧nativequiescence。

本裁定不是fresh结果或执行本身。任何自动拒绝原文保留并停，不换入口；任一结果后停，不能从此授权自动纠正启动配置或开新PG/Go/tests/产品修复。后续Task15有限CODE只有本作者停止/root串行所有权后才准备。Goal active、原Task9/Task15/整个项目未完成。
