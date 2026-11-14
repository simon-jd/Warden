- **路径漂移检查晚于删除且失败后仍删除 image** — ADDRESSED。`scripts/k3s_lab.py:106` 在 container 删除前调用 gate；`:276` 将验证失败设为 sticky；`:312` 的 finally 与 image 删除前再次验证。`scripts/test_k3s_lab.py:150` 覆盖两模式、三个真实路径替换时点及 charge 保留。
- **成功执行丢失真实预期 warning** — ADDRESSED。`scripts/k3s_lab_init.py:100` 对完整安全格式做 fullmatch，保留实际原行、顺序和重复；`:145` 附带固定 source；`:310` 写入成功证据。新增测试覆盖秘密前缀、额外字段和未知文本拒绝。
- **warning gate 漏掉独立 containerd 日志** — ADDRESSED。`scripts/k3s_lab_init.py:115` 固定两条日志路径；`:120` 使用 no-follow、regular-file、非阻塞和有界读取；`:145` 执行合计 32MB gate，缺失及 rotated history 均拒绝。
- **预期 guard refusal 与 synthetic conformance 输出噪音** — ADDRESSED。`scripts/test_runtime_lab_docker.py:59` 捕获实际 subprocess/stdout，原 guard 继续执行；`:106`、`:242` 等断言预期输出。最终 raw covering output 干净。

### New Breakage in the Fix Diff

- None。`scripts/k3s_lab_init.py:157` 的失败 snapshot 使用 exact session、exclusive 0600、固定来源和总量上限；`:177` 的 finally 保证 snapshot 读取或复制异常仍调用独立 cleanup；`scripts/runtime_lab_runner.py:63` 确认 kill、original Popen reap 独立执行，失败不 handback。

### Out-of-Scope Observations

- None。

### Checks

- 核对 raw covering-tests 31＋17＋5 和 final-focused 15：54 distinct、无 SKIP；未重跑测试、ABI、smoke 或 live。
- package 首次工具输出截断；仅分段补读缺失 package 区间，未重建 git diff。一次 focused unchanged 接口检查覆盖 postflight/anchor 与 cleanup/session 契约；未修改文件、index 或 HEAD。

### Verdict

- **Fix round:** All findings addressed, no new Critical/Important breakage。
