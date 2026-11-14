# 运行时部署前检查

日期：2026-10-23。代码基线：9491c96。本页记录环境及官方接口事实，不是实际运行时验收，也不包含启动/容量测量。

## 本地环境

[初始环境](environment.md)已确认主机cgroup v2，但没有专用delegation授权；共享containerd不用于攻击/沙箱测试。`/dev/kvm`不存在。Task2/3/4真实一致性需专用warden-lab节点与配置，缺口不能以fake client或OCI JSON检查代替。

## GKE PID限制差异

2026-10-23查阅[GKE节点配置官方文档](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/node-system-config)，其PID management表对podPidsLimit规定最小1024。Warden要求默认128，因此仅配置GKE node pool不能直接满足此验收。

[Kubernetes PID限制说明](https://kubernetes.io/docs/concepts/policy/pid-limiting/)将通用限制配置置于kubelet节点级；不能在通常稳定的Job/Pod资源结构中发明pids字段。需按实际集群版本核实能力，不得因Terraform schema接受某字段就断言API配置/真实隔离通过。

[gVisor cgroup文档](https://gvisor.dev/docs/user_guide/systemd/)支持宿主资源映射；[兼容性说明](https://github.com/google/gvisor/blob/master/g3doc/user_guide/compatibility.md)提示guest内部计量与资源执法的区别。Task3应实现实际可执法且可观测的128边界，未证明前拒绝启动不合规任务。不得把1024或可被用户提高的soft ulimit当等价结果。

## 超时清理的判定

[内核cgroup v2文档](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)描述cgroup.events的populated覆盖后代子树；只有父cgroup.procs为空不足以证明没有后代进程。Kill/timeout需要cgroup.kill、等待子树为空与真实conformance证据。

## 后续权威证据

Task2需要7项真实一致性结果；Task3需要真实GKE一致性与100次启动p50/p95；Task4需要KVM/jailer/rootfs/snapshot、一致性、冷启/恢复及压力容量测量。上述全部未在本页执行。版本、lab资源归属、镜像/kernel digest和原始数据路径须随真实执行另行记录。
