# 初始环境检查

日期：2026-10-23。目录：/home/postedism/Desktop/Warden。

- 当前树仅 README、PORTFOLIO-README、17 项任务计划、GOAL、启动脚本；无既有代码或 git 提交。
- 已读取三份要求文档，Goal 已存在并为 active（复用）。此前没有可归类的实现轮次；本轮初始化为首次进展。
- Ubuntu 26.04 x86_64，Docker daemon 29.9.1 可用，psql client 18.6 可用。
- 主机 PATH 中 Go、terraform、kubectl、runsc 不可用；本地有 golang:1.26.8-bookworm 与 postgres:18-alpine 镜像，可用专用容器验证。
- 不读取相邻项目私有文件，不触碰已有 Docker workload；只创建 warden 前缀临时容器。
- 尚未验证任何云或真实隔离环境。

## 后续只读检查

- 本地非root/只读Go容器实际执行 `go version` 成功，输出 go1.26.8 linux/amd64；该版本仅是引导工具链，Task1漏洞检查后升级要求见Task1证据。
- 本地镜像ID：golang `sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d`；postgres `sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873`。
- `stat -fc %T /sys/fs/cgroup` 为 cgroup2fs，controllers包含cpu/memory/pids；这不证明本进程有delegation或可运行隔离套件。
- `/dev/kvm` 不存在。宿主containerd socket存在但属已有共享服务，不用于本项目测试。Firecracker真实验收需要独立lab硬件/VM。
