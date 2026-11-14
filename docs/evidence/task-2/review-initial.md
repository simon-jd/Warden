# Task2 runtime核心独立首审

日期：2026-10-23；BASE270635f、HEAD ee8c4b2；审查者task2_review（gpt-6.1-sol），只读分块检查3007行diff及锁定containerd的IO/Task生命周期源码；未重复测试、未访问共享daemon、未执行root runner。

结论：核心需要修复；Task2整体仍未完成。

## Important

1. handle.go:97在等EOF之前调用streams.Cancel；containerd v2.4.2实际Cancel关闭stdout/stderr pipe，可能丢未读尾部且Wait返回nil。应先有界等待EOF，仅超时取消并报错；须覆盖exit先到/输出未读完。
2. run-runtime-lab.sh:13/22/43/56/60没有检查lab父路径、预存toml/log和dangling symlink，root写入及cleanup可逸出。首次root运行前必须建立可信owner、独占路径边界，拒绝链接/预存目标，只清本次对象。
3. driver.go:28仅socket路径含warden-lab不证明专用；symlink可别名到共享socket。必须检查每个组件、可信owner/socket类型与部署端专用daemon归属。
4. 真实七项guest全部SKIP，root runner未运行，unit fixture不能证明kernel隔离、OOM、超时清空或实际Reap。
5. scheduler/API持久claim、执行前重授权、真实状态/审计/logs仍未接。控制器拆分为后续集成子步骤，不因此关闭Task2门槛。

## Minor / 后续验收要求

- fork asm pause未被seccomp允许，会EPERM忙循环，须调整。
- 单凭EAGAIN不足证明pids controller命中；真实结果需pids.events max和峰值/限制数据。
- 日志1MiB截断应有机器可读truncated/dropped标识供持久化使用。

## 已核对的优点和边界

driver复核digest/ID/cmd/network/数值；强制readonly/UID65534/NNP/dropcaps/private namespaces/资源且保留device deny；cgroup.kill后等待populated=0；独立timeout和cleanup错误可见；Reap不重启；证据如实写SKIP。不能用局部16GB subtree或本目录cache量证明所有项目服务/镜像预算，需后续本机资源guard。

原实现者执行round1，安全复审前不执行root runner；真实lab与scheduler后续独立验收。首次发现完整保留，不改写成已通过。
