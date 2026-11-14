# Task 4：guest 在 Ready 之前退出的原因（2026-11-10）

## 结论

guest 内核本身启动正常。退出的是 PID1（`/agent`）：

```
[    0.729224] devtmpfs: mounted
[    0.733076] Run /agent as init process
guest agent failed: guest mount /dev: device or resource busy
[    0.740734] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100
[    0.753372] Rebooting in 1 seconds..
```

官方 CI 内核 6.18.54 的配置里有 `CONFIG_DEVTMPFS_MOUNT=y`，内核挂好根文件系统后会自动把 devtmpfs 挂到 `/dev`（上面的 `devtmpfs: mounted`）。agent 的 `guest.Boot()` 又去 `mount("devtmpfs", "/dev")`，同一个超级块挂在同一个挂载点上，返回 `EBUSY`。agent 以退出码 1 结束，PID1 退出导致内核 panic；`panic=1` 让它 1 秒后重启，`reboot=k` 让 Firecracker 把重启当作关机退出。整个过程约 2 秒，和 10-24 实机第三次 boot 的 `TestFirecrackerBoot (2.12s)` 吻合。当时只保留了串口日志的前 16 KiB 开头部分，所以看不到这一行。

修复：agent 先读 `/proc/self/mountinfo`。如果 `/dev` 上已经是 devtmpfs，就只做 `MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NOEXEC`（加上原本要的 nosuid、noexec）；`/dev` 上是别的文件系统或者条目解析不了，就拒绝启动。单测 `TestDevMountReusesKernelDevtmpfs`。

## 怎么得到的

- 时间：2026-11-10 15:17 PST（UTC 23:17），home-ubuntu，Linux 7.0.0-42-generic（i9-13900K），32 核，同时有其他项目在跑。当时的 load average 没有留下记录；sysstat 每 10 分钟的采样里，15:10 和 15:20 的 1 分钟值是 8.43 和 10.32（[sar-q-20261110.txt](../live-20261110/sar-q-20261110.txt)）。
- 用户已经在 `kvm` 组里，所以这次没有经过 Docker 外壳和 jailer，直接以 UID 1000 运行官方 `firecracker`（`--no-api --config-file`），stdin 接 `/dev/null`，串口（ttyS0）完整写进文件。这只是诊断方式，不是 Task 4 的验收路径。
- 用的就是 10-24 失败那次的包（源码 `95fa55dc`）里的文件，sha256 和 `.cache/firecracker-code/package.json` 的 manifest 一致：
  - firecracker v1.17.0 `99ad0f5c…a7a5`
  - kernel vmlinux-6.18.54 `da5e0041…8188`
  - agent.ext4 `373369db…e18f`
  - payload.ext4 `be216aeb…f521`
- 机器配置与 driver 相同：1 vCPU、640 MiB、只读 rootfs + 只读 payload 盘、vsock CID 3、无网卡，内核参数 `console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/agent WARDEN_FC_GUEST=1`（[vm-original.json](vm-original.json)）。
- 命令：`python3 -I -B direct_probe.py <dir> agent.ext4 hello original`（[direct_probe.py](direct_probe.py)），输出 `VMM exited rc=0 before HELLO`。

## 文件

| 文件 | 内容 |
|---|---|
| [serial-original-agent.log](serial-original-agent.log) | 原 agent，完整串口日志（21,437 字节），到 `Firecracker exiting successfully` 为止 |
| [serial-fixed-agent.log](serial-fixed-agent.log) | 修复后的 agent，同样的内核和 payload 盘。串口里没有 panic，停在 agent 启动、payload 盘（vdb）挂好之后，之后由脚本 kill。脚本那次的输出（包括收到 HELLO 的时间）没有保存 |
| [vm-original.json](vm-original.json) | 诊断用的 Firecracker 配置 |
| [direct_probe.py](direct_probe.py) | 诊断脚本：启动 VM，经 vsock UDS `CONNECT 52` 读 HELLO，可选再发 BIND/EXEC |

修复后的 agent 镜像（agent `df6bc162…15d4`，ext4 `1c54c39a…b764`）是用宿主的 mke2fs 1.47.2 临时做的，只用来确认诊断，不是 lab 包。当时还用同一个脚本直接跑了 7 种探针（uid、readonly、network、seccomp、fork、oom、timeout），输出没有保存，所以这里不算任何结果。guest 一侧的实测是 Task 4 的实机运行（conformance 7/7，见 `docs/evidence/runtime-startup.md` 和 [live-20261110](../live-20261110/)）。
