# Task5 后续材料与入口的只读核对

控制器在`84018e5`后的未改运行时源码中核对以下具体边界；未执行Go、guest、shell、攻击、mount、容器或资源操作。它们是后续设计依据，不是真实矩阵结果，也不授权修改Task4核心或重试启动。

| 源码 | 观察 | 后续影响 |
|---|---|---|
| [runc.go:74](../../../runtimes/runc/runc.go) | OCI配置给`/dev/shm`独立tmpfs、mode1777、size65536k；rootfs仍只读、network namespace仍私有，Spec默认限制未改。 | 可能在既有策略内设计真实、有限ENOSPC测试，而非依赖不存在的任意可写卷接口。必须先实测该挂载及配额，最多其容量加一次固定失败写，明确sandbox内填满与宿主存储影响的不同目标；当前没有执行或归类。 |
| [guest/bootstrap.go](../../../runtimes/firecracker/guest/bootstrap.go) child部分 | 切入payload后只给proc、1MiB mode0755的dev tmpfs和只读sysfs；agent自身的16MiB`/tmp`不是payload内可写空间的证明。 | 不把agent的可写临时目录当作租户目录；payload ENOSPC仍未表征，不扩大挂载/权限来补格。 |
| 同一child的mode switch与最终unix.Exec | 只接受fork/readonly/network/uid/timeout/oom/seccomp，最终执行`/warden-probe <mode>`。 | shell材料存在也不能直接推出Firecracker能执行run.sh。未来语料接线须单独设计、测试、审查最小guest入口变化，保留原probe及权限/生命周期边界；不得回到已耗尽的Task4因果loop或宣称guest Ready。 |

此前[方案](controller-proposal-draft.md)关于完整ENOSPC与shell入口的缺口继续开放；这些具体源码事实可用于缩小后续工作。只有runc配置候选，不是三运行时通用能力或新增执行票据。42个真实格仍全部unevaluated，原现场/Q5GB/五轮上限保持。
