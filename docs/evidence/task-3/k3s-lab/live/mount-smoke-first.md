# 实际零 capability 只读挂载检查

UTC 2026-10-24T16:40Z，源码 `3d87ef6`、运行时 HEAD `b0e954d`。独立 round2 复审通过后，由控制器执行固定 `mount-smoke --reviewed-mount-profile`。命令和范围见 [run metadata](mount-smoke-first-run.json)，完整公开输出见 [raw output](mount-smoke-first.txt)。

**PASS / exit 0**。固定入口实际核验了本次 session 的目录身份、0700、只读挂载及私有 namespace/propagation；host 对允许公开文件的前后 SHA/metadata 检查通过。模式使用相同数值 UID、零 capability 和默认 security profile，没有 remount、读取 session 内容或启动 k3s。这证明新初始 RO bind 可用，不证明 RW remount 或节点 Ready。

本次 rootfs 内容 496,036,546 bytes、tar 496,599,040 bytes，实际导入 image Size 685,366,790 bytes。导入前项目占用 3,519,954,944 bytes，加 6GB 预留为 9,519,954,944 bytes；服务峰值声明仍为 7GB，外层保持 4GB/512 tasks/2CPU。流程用时 25.97 秒，host 最大 RSS 803,096KiB；这些不是节点峰值。

精确容器 `07fe2cb5d9c34ef463bb8e7eb0605d2b30c45baad4c92697f8a154e4b950f2df` 与镜像 `sha256:a8f96ce567f24db99831479ef974490912ab16e7b56cffe03db16247f9f80698` 均已移除。独立 [postflight](mount-smoke-first-postflight.json) 复核完整 `--all` Warden 列表为空、charge 已释放、session 仅三个公开文件且 UID1000/0700，项目约 3.02GB、常驻服务 0，六项受保护 sysctl 不变。

[新 manifest](mount-smoke-first-manifest.json) 记录 674 个文件，SHA256 为 `585eabd7b4d7d77088468b5981fcf26eb4c64cd02d169f082990e6a794d517c0`；四个复制 controller 的摘要已逐项与 `3d87ef6` 核对。另保留 [image identity](mount-smoke-first-identity.json) 和 [released charge](mount-smoke-first-charge.json)。无 Azure/GPU 操作，累计 Azure 承诺估算 $0.00。接下来仍须单独执行 bootstrap，Task3 与 Goal 保持进行中。
