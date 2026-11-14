# Task14 原修复 1/5：定向 RED 准入

root `4d6550` 全文读取 2353B freeze 与 8166B caller，`01ec7f` 全文读取三文件最小差异。私有实例接口默认真实 fsync；原 created-only 条件保留。回归用真实创建前锁屏障，第二 opener 打开 existing；仅新 `TestJournalCreationDurabilityBeforeClient/{failure,success}`，预期 3 FAIL / 0 PASS / 0 SKIP、两个 FIX1_RED_REQUIRED，任何 setup/cleanup/build/未知均不接受为 RED。

仅准一次精确 body 7374B / SHA256 `9718e674584ba22b6fca3a93adbb8c5e0d151ff0196ceefc4cf705db249ff945`，新 `.cache/task14-fix1-red-20261025-a`。literal `/usr/bin/timeout --signal=TERM --kill-after=4s 86s /usr/bin/python3 -I -B /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task-14-fix1-red-command.py.txt`；正常 native 审批与 fixed 离线 Go1.26.10、90秒含收尾/WNOWAIT 原界限不变。先 fresh 未改资源 guard 已知0，完整新增1GiB+Q5GB与11GB服务预留通过，再由同 body 复核 UID/可用内存/新 namespace/冻结输入。失败/未知/超时/审批拒绝即停，不重跑或调限额。

不授 GREEN、formatter、提交、云/服务/宿主操作或旧测试重跑；旧81PASS与初审失败保留。本文件属root协调，作者不stage。
