- **跨 mount namespace 的字面 FD bind Source 不可用** — **ADDRESSED（代码层）**。`scripts/k3s_lab.py:57` 改为固定 session 实路径的 RO/rprivate bind；`:337` 从仍持有的目录 FD 提供身份。`scripts/k3s_lab_init.py:238` 在内容访问前核验身份、0700、RO、namespace/propagation；`:268` 仅通过已验证 FD remount，并复核其余 flags；`:289` 保证握手失败不进入 prepare、snapshot 或 cleanup。真实 mount/remount 仍待 controller 验证，未冒称启动成功。

- **默认 image ls 漏掉 used untagged/intermediate 镜像** — **ADDRESSED**。`scripts/runtime_lab_docker.py:65` 的共享枚举统一使用 `--all`，保留标签和 exact-ID 校验。`scripts/test_runtime_lab_docker.py:275`、`:294` 与 `scripts/test_k3s_lab.py:213` 覆盖残留不释放 charge、runc/API/k3s 完整计费；lost-import recovery 的既有测试同步覆盖完整枚举。

- **New Breakage in the Fix Diff：None。** `scripts/k3s_lab.py:376` 强制独立 mount-profile gate；`:57` 的新 probe 保持零 capability、默认 security profile、固定资源及唯一 RO bind。`:302` 的 snapshot 漂移失败保持 sticky，阻止后续容器/镜像删除及 charge release。

- **Out-of-Scope Observations（非阻断）**：`scripts/k3s_lab.py:400` 是未修改的既有问题：顶层 `finally` 仍按 pathname 无条件删除 `rootfs.tar`，即使内部已发现 session 路径漂移；可能删除替换目录中的同名文件。应在后续修复中纳入 FD 身份及保留现场门槛，本轮不据此重开旧 finding。

- **Checks**：核对 raw covering 37＋19＋5＋5、final-focused 18、final lifecycle 1，合计 67 distinct PASS、无 SKIP。仅做一次 focused unchanged 检查，核对新模式与既有 host cleanup/charge、NOFOLLOW_DIR 的交接；未运行测试、Docker、mount、ABI 或 live，未修改文件/index/HEAD。

- **Fix round：All findings addressed, no new Critical/Important breakage。**
