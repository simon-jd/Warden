# 本机Docker lab入口：代码阶段证据

状态：**DONE_WITH_CONCERNS**，仅代码与capless ABI smoke；七项真实guest及API→runtime调度**未执行/未验收**。live profile须控制器独立审查后另行运行。

代码SHA：`ff6c1e2658de22586546089fd522726d0e9bb243`，前置实现`f1f736c`，基线`362df97`。时间：2026-10-23 America/Los_Angeles（UTC2026-10-24）。

- `python-tests.txt`：33项focused Python测试通过，含native paths/cleanup、真实SIGTERM、精确ID回收、未知/unowned拒绝、12GB/16GB guard、持久失败导入charge和安全evidence handoff。
- `capless-smoke.txt`：普通非root UID65534、drop ALL、默认AppArmor/seccomp、无host bind；固定版本检查通过。containerd/ctr/shim2.4.2、runc1.5.2、libseccomp2.6.0、Python3.14.4。没有guest执行。
- `identity.json`：该次实际image ID与完整ownership/session/ttl标签。`manifest.json`：191,391,251 bytes、666文件的SHA256及Python路径。
- `charge.json`：3GB预留已按成功导入/精确ID删除语义释放；不声称Docker content store已物理GC。失败/不确定导入保留charge，后续preflight累加。
- `post-cleanup.json`：独立只读检查，project-tagged images/containers均空，tar已删除，charge released。
- `post-cleanup-budget.txt`：没有剩余常驻服务，普通用户最终磁盘预算检查通过。
- `report.md`：完整实现报告、自审、TDD过程与尚待独立审查的能力/cgroup/cleanup边界。

外层4GB/512pids/2CPU，private namespaces；live有限cap profile与外层AppArmor/seccomp放宽**尚未实测**。SYS_ADMIN/BPF存在显著宿主内核暴露。真实root→operator UID交回、内层empty cgroup/task/snapshot回收证据仍需live验证，不能以Docker删除成功替代runtime.Kill验收。
