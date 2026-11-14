# Task 2：真实 runc 七项一致性结果

执行于2026-10-24T04:01:43Z（America/Los_Angeles为2026-10-23）。入口实现SHA `ff6c1e2`，执行时HEAD `d44821b`；后者只增加控制器文档。已先独立审查入口，再由控制器运行固定受信probe。命令和完整SHA/文件hash见[verification.json](verification.json)，原始输出见[lab-conformance.txt](../lab-conformance.txt)。

**七项全部PASS，无SKIP；进程退出码0。Task2整体仍未完成，持久调度/API→runc验收另行推进。** 本次没有Azure资源创建、GPU使用或共享containerd操作。

| 真实guest行为 | 实测 |
|---|---|
| fork上限 | pids.events max增量1、peak32、退出0、cgroup空 |
| 只读根 | guest写入得到EROFS、退出0、cgroup空 |
| 默认无网络 | 仅loopback；本地route lookup返回ENETUNREACH、退出0 |
| 非root | guest UID/GID非0、退出0 |
| 父子超时清理 | 退出137、TimedOut=true、peak8、整个cgroup空 |
| 内存OOM | 退出137、真实oom_kill计数、OOMKilled=true、cgroup空 |
| seccomp | filter mode2；mount/ptrace均EPERM、退出0 |

七项均LogsTruncated=false、DroppedLogBytes=0，总3.21秒。真实guest没有先前实机RED记录；TDD RED/GREEN属于已归档的单元/行为层。

外层临时Docker为4,000,000,000 bytes/512pids/2CPU（kernel实际memory.max向页边界取3999997952），无额外swap、只读、无网络、私有namespace，仅本次项目session bind；有限capability及外层LSM放宽的审查边界见[入口审查](../lab-wrapper/review.md)和[运行说明](../../../runtime-lab.md)。它用于固定受信探针，不是任意外层root代码的安全边界。

运行前项目allocated2,186,227,712 bytes，导入预留3GB、下载0、其他Warden服务声明0；未突破12GB/16GB门槛。镜像输入总191,391,251 bytes，文件清单见[manifest.json](manifest.json)。本次镜像`sha256:1969d3d20532a18fd87d99d789749764bfc003002dc28e31169774ff2207b8ac`与容器`9c9f5ba1a17b817e1584a0cf0c337a2aa125ac36d301cec565245aa0b92e8fa4`均按精确ID删除；[post-run.json](post-run.json)再次查到本项目带标签镜像/容器为空，普通用户preflight通过（allocated2,186,362,880 bytes）。[charge.json](charge.json)语义释放为true，不代表Docker content store所有字节已物理GC。没有执行prune。

[containerd.log](containerd.log)记录七个快照删除，driver全部返回CgroupEmpty=true且没有cleanup错误；独立daemon与数据目录在runner收尾中回收。本次保留的session及两个0600日志/config已精确交回UID1000，见post-run ownership。外层对象删除不能代替guest内层清理断言；这里两类证据均保留。
