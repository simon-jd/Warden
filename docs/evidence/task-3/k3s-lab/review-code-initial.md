### Spec Compliance

- ❌ Issues found：路径漂移后的现场保留、真实预期 warning 证据保留、完整 startup warning/error 检查尚未满足；见下列 3 项 Important。
- ⚠️ capability-bearing readiness、实际 cgroup/CNI/config/identity 与资源峰值仍需后续 controller live gate；本轮不要求提前启动，也不据此判缺陷。证据明确列出未执行范围：`docs/evidence/task-3/k3s-lab/verification.json:46`。

### Strengths

- 固定外层资源、capless/live 模式分离、精确镜像 ID 和完整归属标签均有明确实现：`scripts/k3s_lab.py:31`。
- 材料选择排除 wrapper、BusyBox 和模块加载 applet；归档解析拒绝 traversal、重复项、危险类型和超额展开：`scripts/k3s_lab.py:61`、`scripts/k3s_lab_materials.py:41`。
- 六项 sysctl 值与 `/proc/sys` 只读状态同时验证，配置启用 `protectKernelDefaults`：`scripts/k3s_lab_init.py:43`、`scripts/k3s_lab_init.py:56`。
- 原始 Popen、owned cgroup 和 session 交由既有 cleanup owner 收尾，并要求独立 inner marker：`scripts/k3s_lab_init.py:189`、`scripts/k3s_lab_init.py:246`、`scripts/k3s_lab.py:88`。
- SHA 绑定 capless evidence 清楚区分实际版本检查与未执行的 tenant/conformance；最终 smoke 显示精确对象删除和 exit 0：`docs/evidence/task-3/k3s-lab/capless-smoke.txt:8`、`:18`、`:43`。

### Issues

#### Critical (Must Fix)

- 无。

#### Important (Should Fix)

1. **路径漂移检查晚于 destructive cleanup，且检测失败后仍删除 image。**  
   `scripts/k3s_lab.py:106`、`:294`、`:295`、`:302`：`execute()` 成功时先删除 container，返回后才通过 `postflight()` 验证 session anchor；若此时发现目录被改名或替换，`image_session()` 的 `finally` 仍删除 image。charge 虽保留，承诺保留的 container/image 现场已经消失。应在允许 container/image 删除前验证仍持有的 anchor，并让漂移失败阻止后续对象删除；增加覆盖整个 `image_session` 删除顺序的路径替换测试。当前 `scripts/test_k3s_lab.py:136` 仅直接测试 `verify_anchor()`，未覆盖此顺序。

2. **成功执行会销毁真实预期 warning，只留下合成、去重后的 code。**  
   `scripts/k3s_lab_init.py:99`、`:113`、`:235`、`:242`、`:246`：`warning_codes()` 丢弃原始行及出现次数，归档仅写 `expected_startup_denials`，随后 cleanup 删除包含原始日志的 root。因而后续 live 即使成功，也无法提供裁定要求的可安全归档的真实预期 warning。应在严格验证完整格式后保留实际观察到的安全原始行或其精确安全片段，并测试额外字段、秘密前缀和非 allowlist 文本不会被导出；不能仅靠事后 code 重建证据。

3. **warning gate 漏掉独立 containerd 日志。**  
   `scripts/k3s_lab_init.py:232`、`:235`：目前只读取 `root/private.log`。所选 k3s 默认将 containerd 日志写入 `root/agent/containerd/containerd.log`；未启用 debug 时，containerd stdout/stderr 完全写入该文件。因此 containerd 的 unexpected warning/error 可以绕过检查，最终被清理删除。应对固定启动涉及的独立日志进行有界私有检查，并测试“主日志干净、containerd 日志含 unexpected warning/error”必须失败。源码依据：[固定版本日志路径](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/pkg/agent/config/config.go#L527)、[固定版本日志重定向](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/pkg/agent/containerd/containerd.go#L56)。

#### Minor (Nice to Have)

- `docs/evidence/task-3/k3s-lab/tests.txt:32`、`:39`：最终回归输出混有预期 guard refusal 与 synthetic conformance 文本。它们不是测试失败或真实 conformance，但按模板属于输出噪音；后续可在相应测试内部捕获并断言，保持最终输出清晰。历史失败记录已明确标注，不作为最终 SHA 失败处理。

### Assessment

**Task quality: Needs fixes**

**Reasoning:** 固定入口、材料选择和资源边界具备良好基础，但当前删除顺序及日志验收不足以可信进入下一步 live gate。上述问题均可在不启动 capability profile、不放宽主机边界的情况下修复和验证。

- 检查：按 source/safety/evidence 有限 pass 阅读 package；大型 manifest 对全部 674 条文件记录进行结构检查。源码 hunk 无截断，未单独重读 changed files，未运行测试或 smoke。
- 定点检查：`runtime_lab_paths.py:53` 排除 subprocess FD 路径误用；`runtime_lab_runner.py:63` 核查 cleanup 接口；所选 [base template](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/pkg/agent/templates/templates.go#L206) 与 [flannel 条件配置](https://github.com/k3s-io/k3s/blob/v1.36.5%2Bk3s1/pkg/executor/embed/embed.go#L151) 排除已怀疑的 CNI table 重复问题；独立日志漏检的源码核查见 Important 3。
