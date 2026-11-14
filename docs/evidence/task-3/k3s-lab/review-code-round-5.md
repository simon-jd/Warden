- **① 原第四次 Ready/CRI 与持续 EMFILE — NOT ADDRESSED（原验收阻断仍在）。** `docs/evidence/task-3/k3s-lab/round-5/README.md:28` 的故障链与缓存 pinned 源码一致：CNI watcher 创建失败使 CRI 服务未注册，238次等待及48次动态证书 watcher EMFILE均未被修复。原进程 RLIMIT/FD 使用量与共享 UID inotify 配额使用量未测得，不能确定资源不足的具体来源。API-serving、50项测试或未来单次 helper probe 成功均不能证明 Node Ready；真实 Ready/CNI/cgroup 验收继续 OPEN，见同文件`:63`。

- **① FlexVolume 固定空目录 — ADDRESSED（代码层）。** `scripts/k3s_lab.py:278` 在 immutable tar 中预建固定目录及父目录，root-owned/0755、无插件文件；`scripts/test_k3s_lab_round5.py:27` 验证实际 synthetic tar 输出。消除了缺目录时向 RO root 执行 mkdir 的条件，未将原 FlexVolume 或 EMFILE 错误加入允许列表；不等于已验证后续 watcher 正常。

- **② 第四次 fixed recovery 与受限资源诊断 — ADDRESSED（代码层）。** `scripts/k3s_lab_recover.py:22`、`scripts/k3s_lab_recovery_init.py:17` 固定第四次 CID/image/labels、outer/child身份、124/0/154227B三文件和新 tar 身份。`:116` 在初始 RO 完整 shape/≤33MB allocation 检查后、任何 remount 前调用一次诊断；`:44` 只枚举 `/proc/self/fd` 条目、保守在4096处拒绝，读取自身 nofile limits，单次 `inotify_init1(CLOEXEC|NONBLOCK)`，成功 FD 经 finally 关闭，不读 targets 或其他 PID。`:25` 与宿主 `scripts/k3s_lab_recover.py:33` 严格限制字段、整数范围、enum/errno一致性及 canonical JSON＋原 marker＋换行；exit0另行验证。受支持 EMFILE/ENFILE/other syscall 失败作为数据允许必要清理；未知读数、close失败、shape或协议异常保留现场/charge。

- **② 恢复安全链与预算 — ADDRESSED（保持原边界）。** `scripts/k3s_lab_recover.py:59` 保持两cap、256MB memory=swap、32tasks、1CPU、ROroot/private namespaces及唯一原 RO rprivate bind；`:155` 保留完整6GB outstanding、全部 owned images 的2×Size＋64MB、helper64MB及其余整个项目 allocated accounting。`:214` 保持 immutable argv/code hash、exclusive durable journal和失答保守处理；`:242` 起依次确认对象移除、ordinary guard、held tar/parent/pathname复核、unlink/fsync，最后 durable release。未知结果不提前释放；unlink后失败可能已无tar但仍留charge。当前真实 recovery 尚未执行，不构成 cleanup 或原 Popen/GoGate 退休证明。

- **③ 固定 query 阶段与计数 — ADDRESSED。** `scripts/k3s_lab_init.py:527` 增加固定 last_stage、attempts及五类失败计数，均饱和于240；超时只输出这些 enum/count。没有输出 stderr、HTTP body、Node JSON或异常消息；kubectl参数、期限、API `ok`、Node Ready及后续最终Ready复核条件未放宽。`scripts/test_k3s_lab_round5.py:118` 覆盖五阶段实际 query-loop 行为和私有内容不外泄。

- **New Breakage：None。** 本轮新增代码未发现 Critical、Important或Minor问题；原持续EMFILE是未关闭的既有验收阻断，不计作新增问题。

- **Out-of-Scope Observations：None。**

- **Checks：** 已核对报告命令、RED六项/十处失败、中间49 PASS、最终50 PASS/零skip及其覆盖代码；核验7份source、7份evidence、17份cached primary的长度/SHA，共31项全部一致，并定点核对CRI故障链、FlexVolume和fsnotify实现。确认 retained image manifest包含新helper所需 `_ctypes`、`resource`、libffi，Docker接口保留stdout换行。未重跑suite、执行Docker/inotify探针或修改checkout/index/HEAD。

- **Spec：本轮controller批准的诊断/恢复代码范围 PASS；原bootstrap验收 NOT ADDRESSED。Quality：PASS，无新增Critical/Important breakage。Fix round：Findings remain open——持续EMFILE与真实Ready/CRI验收仍开放。** 后续仅可由controller执行必要fixed recovery并读取当前helper诊断；本结论不授权自动bootstrap，不重置round上限，不将Task3标记完成。
