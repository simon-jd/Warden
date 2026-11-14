# Task 4：修好 /dev 之后的第二个失败——宿主 ACL 进了 guest 镜像（2026-11-10）

修好 devtmpfs（`928d2e3`）之后，第一次实机 `boot`（worktree 在 `9bb0f05`，15:24 PST；当时的 load average 没有留下记录，sysstat 15:20 和 15:30 的 1 分钟值是 10.32 和 6.97，见 [sar-q-20261110.txt](../live-20261110/sar-q-20261110.txt)）guest 已经 Ready，agent 收到 BIND/EXEC，但探针 `uid` 以退出码 1 结束，输出 38 字节（[lab-boot-9bb0f05.log](lab-boot-9bb0f05.log)，串口见 [lab-boot-9bb0f05-console.log](lab-boot-9bb0f05-console.log)）。这次失败后 supervisor 的失败清理路径正常：cgroup 清空、会话目录交还 UID 1000、5 GB 预留释放，没有留下 root 文件。

用同一份镜像直接跑 Firecracker 复现，输出是 `guest agent failed: permission denied`。交叉替换（[bisect.txt](bisect.txt)）：新 agent 盘 + 10-24 的 payload 盘通过，新 agent 盘 + 新 payload 盘失败，所以问题在新 payload 盘。

原因（[image-acls.txt](image-acls.txt)）：10-24 之后，项目目录树被加了默认 ACL（`user:grokbot:r-x`）。lab 的 rootfs staging 目录是 0700 新建的，继承下来的 ACL 是 `mask::--- other::---`；`mke2fs -d` 会把源目录的所有 xattr 原样复制进 ext4，于是 payload 盘根目录带着 `system.posix_acl_access`，其中 other 没有权限。guest 里探针以 UID 65534 运行，`chroot /payload` 后连根目录都进不去，exec `/warden-probe` 返回 EACCES。10-24 的镜像是在加 ACL 之前做的，所以没有这个问题。

修复：`BuildExt4` 在调用 `mke2fs` 之前遍历 staging，删掉 `system.posix_acl_access` / `system.posix_acl_default`，还有其他任何 xattr 就拒绝构建（不跟随链接）。单测 `TestExt4BuilderDropsHostACLs`。宿主的 ACL 本身没有动。
