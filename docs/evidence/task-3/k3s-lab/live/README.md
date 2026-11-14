# Bootstrap 首次实机尝试：挂载失败，未启动 k3s

2026-10-23 本地 / UTC 2026-10-24。已审查源码 `a3193fb`，运行时 HEAD 为仅追加文档的 `d925e3f`。固定命令、时间和范围见 [first-run.json](first-run.json)，完整公开输出见 [bootstrap-first.txt](bootstrap-first.txt)。

结果为 exit 2：Docker/runc 在 OCI init 阶段将 `/proc/1962670/fd/6` bind mount 到 `/session` 时返回 `EINVAL`。k3s 尚未 exec，因此没有节点 Ready、cluster identity、guest 或 conformance 通过结果。

实际打包 rootfs 496,033,251 bytes、tar 496,599,040 bytes，导入镜像 Size 685,362,655 bytes。新 [manifest](first-manifest.json) 的 674 个文件记录绑定本次镜像；控制器逐项核对四个复制 controller 的 hash 与 `a3193fb` 内容一致，见 [verification](first-verification.json)。导入前项目 3,518,332,928 bytes 加 6GB 预留仍低于 12GB；服务峰值声明 7GB，未改变外层 4GB/512 tasks/2CPU。

[只读现场](first-failure-state.json) 确认精确容器为 `created`、PID 0、Running false、启动/结束时间为零、restart count 0；原 session 的 device/inode、UID1000、0700 和三个公开文件均匹配，没有 inner data 或临时密钥。控制器据此只删除本次精确归属容器，再删除精确镜像，使用带 `--all` 的完整标签列表确认均不存在，才释放 charge。[回收记录](first-failure-cleanup.json) 和 [released charge](first-charge-released.json) 已归档。这仅适用于本次明确未执行的 OCI mount 失败，不是任意已启动节点的退休证明。

现场同时证实旧 `scoped_ids('image')` 的默认列表漏掉已被容器引用的无标签镜像；加 `--all` 才列出它。该共享枚举缺口与可用的 FD bind 路径已交原实现者进行第 2 轮修复，独立审查前不重试节点启动。

[最终 postflight](first-postflight.json)：本项目约 3.02GB、常驻测试服务 0，所有 Warden 容器/镜像与 outstanding charge 均为 0，六项受保护 sysctl 值不变。没有 Azure/GPU 操作，Azure 累计承诺估算仍为 $0.00。Task3 与 Goal 继续进行。
