# 原 Task14 fix1：唯一受影响覆盖准入

root `a30176` 全文读取3553B freeze及8169B caller，`6f4f05`核对I1条件和README差异。原RED测试与私有seam不变；行为将created文件fsync与每次locked/validated打开的父目录fsync分离，失败均在intent/client之前关闭。

接受所列7top/27sub=34项一次受影响覆盖：新create-before-lock两子例，加锁/重开/绑定、损坏/私有路径拒绝及部分写/同步失败。完整原81不重复，approval/parser/preview/capacity及其他Task不选。expected34PASS/0FAIL/0SKIP，stderr0；失败/未知/超时/审批拒绝即停止，无自动重跑/调阈值。

精确body7339B / SHA256 `a44c383e2114aa2d515df75025244cb6480fac268ea38d2d99bd7d5435bf59a0`，全新 `.cache/task14-fix1-cover-20261025-a`，literal `/usr/bin/timeout --signal=TERM --kill-after=4s 86s /usr/bin/python3 -I -B /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task-14-fix1-cover-command.py.txt`。先fresh未改资源guard known0，再本body检查新namespace/UID/MemAvailable/九冻结输入。沿用离线固定Go、WNOWAIT、90秒含收尾与原12GB/16GB/Q5GB/旧UNKNOWN9GB预留。没有formatter/新材料/云/服务/宿主权限。

结果须root全文读原件后另准提交与定向独立复核，不自动接受组件或全Task14。旧81/本次RED/初审失败原样保留。root协调文件不由作者stage，Goal active。
