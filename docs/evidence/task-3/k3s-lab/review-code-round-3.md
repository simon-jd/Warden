- **NRI/default kubeconfig EROFS — ADDRESSED（代码层）**。scripts/k3s_lab_init.py:39 禁用未使用的 NRI，:73 校验生成配置；scripts/k3s_lab.py:83 固定 /etc/rancher/k3s → /run/k3s-client，scripts/k3s_lab_init.py:341 独占创建 0700 目标。与 pinned k3s kubeconfig 实现 https://raw.githubusercontent.com/k3s-io/k3s/v1.36.5%2Bk3s1/pkg/server/server.go 相符；未增加 host bind、capability 或全局可写路径。

- **bounded adopted-child reap 与安全阶段诊断 — ADDRESSED**。scripts/k3s_lab_init.py:346 在五秒期限内等待并 reap，超时保持失败；:326 仅输出固定阶段、分类及受限数字 errno，:466 将 cleanup、reap、kernel postflight 纳入成功门槛。测试覆盖延迟 adopted grandchild、超时及异常秘密不外泄。

- **fixed recovery 身份、形状、预算、journal 与清理顺序 — ADDRESSED（代码层）**。scripts/k3s_lab_recover.py:30 固定 retained image、唯一 RO/rprivate bind、两项 capability 和资源上限；:164 核对原 scene、停止状态、scope、charge 与归属。scripts/k3s_lab_recovery_init.py:41 在 remount 前要求精确三个 root-owned 0600、nlink1、定长 regular files、无 extras、分配量≤33MB；:66 后才 remount、复核并经 held FD 删除。host :126 全额计算 outstanding、所有 owned images 与 helper reserve；:189 在 create 前持久化独占 journal，失答不释放 charge；:208 按 helper→原容器→原镜像删除，:215 普通 fresh guard 通过后才释放 charge。scripts/test_k3s_lab_recovery.py:130 覆盖失答、命令漂移、helper 失败、未知 absence、删除失败及顺序。

- **whole-main tar pathname drift — ADDRESSED**。scripts/k3s_lab.py:398 引入完整成功 gate，:400 保存原 archive inode，:406 核对 held directory 与 archive 身份后才通过 FD unlink；失败保留 archive。scripts/test_k3s_lab.py:216 覆盖 whole-main 中替换目录，确认原 archive、替换文件及失败对象均保留。

- **exact startup warning gate 与安全输出 — ADDRESSED（代码层）**。scripts/k3s_lab_init.py:108 对四类模板执行完整匹配、正确日志来源、路径、时间窗及次数限制；:361、:454 要求最终 API/Node Ready 后才接受启动瞬态。旧 safe denial 保留实际行，新模板仅导出实际安全片段和逐行 SHA256。scripts/test_k3s_lab_init.py:217 覆盖 secret 前后缀、错误来源/路径/error、越界时间及超量重复；历史分类未冒充 Ready 证据。

- **New Breakage：None。** 未发现本次 fix 引入的 Critical、Important 或 Minor 问题。

- **Out-of-Scope：None。** 真实 recovery、fresh bootstrap Ready、driver、guest、conformance 与 100 次启动仍未验证，不属于本轮代码复审通过声明。

- **Checks**：已核对 verification-tests.txt:1 的 53 PASS/零 skip，以及 final-recovery-focused.txt:1 的 7 PASS；历史 RED 与最终结果区分明确。未重跑 suite，未操作原 scene、Docker 对象、working tree、index 或 HEAD。

- **Spec verdict：PASS（代码层）。Quality verdict：PASS。Fix round verdict：All findings addressed, no new Critical/Important breakage。**
