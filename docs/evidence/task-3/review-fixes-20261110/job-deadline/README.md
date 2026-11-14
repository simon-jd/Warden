# Job 的 activeDeadlineSeconds 怎样结束一次 gVisor 运行（2026-11-10，home-ubuntu）

lab：`scripts/k3s_gvisor_lab.sh up`（源码 `30f72c2`，20:57 起），k3s v1.36.5+k3s1，gVisor release-20261019.0。命令：`scripts/k3s_gvisor_lab.sh env docs/evidence/task-3/review-fixes-20261110/job-deadline/run.sh`，控制台输出在 [run.log](run.log)。

`run.sh` 在 `warden-lab` 里先后建两个 Job，`activeDeadlineSeconds` 都是 6，Job 本身由 [job.py](job.py) 写出（[supervisor.job.json](supervisor.job.json)、[bare.job.json](bare.job.json)）：

- `supervisor`：和 `gvisor.go` 的 `job()` 一样的 pod（PID 1 是 `warden-gvisor-init`，`-timeout-s 300`，所以先到的是 Job 的期限），负载是 `/warden-probe hold`。
- `bare`：没有 supervisor，PID 1 直接是 `/warden-probe hold`，代替"写不出报告的 supervisor"。

每个 Job 和它的 pod 的 watch 事件都按 kubectl 收到的样子保存（`*.job-events.json`、`*.pod-events.json`），[timeline.py](timeline.py) 按顺序把它们列成 [timeline.txt](timeline.txt)。

两次的顺序一样（括号里是 resourceVersion，supervisor 那次）：

1. Job 控制器给 pod 打上 deletionTimestamp，容器还在运行（378）；
2. Job 加上 `FailureTarget=True`，reason `DeadlineExceeded`（380）；
3. kubelet 停掉容器，pod 变成 `Failed`，pod 自己的 `status.reason` 是空的（385）。supervisor 那次容器退出码 137，termination message 是 supervisor 的报告：`"timed_out":false`、`"cgroup_empty":true`、`"error":"supervisor got terminated"`。bare 那次退出码 143，message 是空的；
4. Job 加上 `Failed=True`，reason `DeadlineExceeded`（387）；
5. pod 被删掉（390）。

所以 pod 的 `status.reason` 从来不是 `DeadlineExceeded`（那是 pod 级 `activeDeadlineSeconds` 才有的，驱动不设）。原来 `observe` 在没有报告时用它判断 `TimedOut`，这个判断永远是 false；有报告时 supervisor 报的是 SIGTERM，`Wait` 返回错误。修复后 `Wait` 在这两种情况下读 Job 的条件。`gvisor_test.go` 的 `jobDeadline` 按上面的顺序模拟。

两个 Job 结束后都用前台删除删掉了，`run.log` 里能看到。
