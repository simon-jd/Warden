# Socket 测试权限诊断（2026-10-23 本地）

本次只定位并验证此前五项 runc socket 测试的目录权限前置条件；没有修改实现、路径安全校验或宿主目录权限，也没有运行整个 suite。

宿主普通 UID 1000 的进程 umask 为 `0002`。已固定的 Go 1.26.10 源码 `src/testing/testing.go:1481` 用 `os.Mkdir(dir, 0o777)` 创建 `t.TempDir()` 的编号子目录，因此它在这个环境中成为组可写目录。`validateSocketPath` 按既有安全契约拒绝该祖先，先前失败有具体原因。

只将测试子进程 umask 设为 `0077`，使用此前保留的 standalone `runc.test`，五项定向测试全部 PASS、无 SKIP。该二进制 SHA256 `549b93ec4a32f266610606ec9777d5c5418c9a486dace68543cf1591a60be383` 与上一级 `api-code-manifest.json` 的 `opt/warden/input/runc.test` 一致；从 `f232b0d` 到本次 HEAD `0be4325`，`runtimes/runc` 源码没有变化。

- [原始命令、环境与二进制摘要](verification.json)
- [五项原始输出](focused.txt)

此结果解除“失败祖先尚未定位”的记录；原始失败证据保留。后续可信测试入口需要显式设定进程 umask 或自行创建安全权限的测试目录；不能放宽运行时校验，也不能据此把此前整个 suite 写成通过。
