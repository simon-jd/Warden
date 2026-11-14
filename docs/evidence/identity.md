# 身份验收证据（Task 6）

计划（[2-warden-security-plan.md](../../2-warden-security-plan.md) Task 6 的手工验证）要求记录到 `docs/evidence/identity.md`。实际的说明写在 [docs/identity.md](../identity.md)：应用注册、真实 Entra 令牌打 Warden 的结果、分配和取消分配的时间、SCIM 为什么不做（用户 2026-11-11 决定，最终）。

原始记录都在 [task-6/](task-6/)：

- [entra-oidc-live-20261110-run1.json](task-6/entra-oidc-live-20261110-run1.json)、[run2](task-6/entra-oidc-live-20261110-run2.json)、[过期令牌](task-6/entra-oidc-expired-20261110-run1.json)、[取消分配](task-6/entra-unassign-20261110-run1.json)
- [第一次分配](task-6/entra-assign-20261110.txt)、[建过和删掉的对象](task-6/entra-objects-20261110.txt)、[SCIM 只读检查](task-6/entra-scim-probe-20261110.txt)
- [这些运行记录的源码到底是什么](task-6/entra-provenance-20261112.txt)
- 回收站永久删除：[task-14/entra-recycle-bin-purge-20261112.txt](task-14/entra-recycle-bin-purge-20261112.txt)

结论一句话：OIDC 通过；“在 IdP 里取消分配，控制面同步变化”没有达到——取消分配后 Entra 不再签发新令牌，但已签发的令牌在 Warden 上一直有效到 `exp`，只有 SCIM 停用能立刻拒绝，而 Entra 的 SCIM 开通不做。
