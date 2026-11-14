# 固定旧cache维护：180秒超时，未完成

源7be15fa、固定入口SHA`f608dc714b79dcc4f3c4c2071ba6dd561c88eec10c45fc905820ec447d8a1ede`经独立source/执行计划审查后，仅实际执行一次。[controller intent](controller-cache-execute-intent-20261025.json)、[原始日志](controller-cache-execute-20261025.log)、[执行结果](controller-cache-execute-result-20261025.json)完整保留。

UTC10:02:24.874869至10:05:24.909528，180.025779秒；达到墙钟上限后只向本次拥有的进程组发送SIGTERM，原始子进程等待返回`-15`。source没有fork/服务/Go/Docker调用，没有后台子任务或容器产生。没有durable completed receipt，维护未完成，不把CLI终止或锁释放当成清理成功。

[独立只读metadata审计](controller-cache-timeout-audit-20261025.json)于UTC10:07:50通过：260个目录均已收紧，22,422个普通文件全部存在，其中18,900个已收紧、3,522个仍为原权限；派生文件/执行目录均无删除。所有现存普通文件的inode/owner/size/mtime一致，没有未知项或别名；只读元数据检查不等于重新读取/证明文件body。私有intent4,573,737B，SHA`cbc9e3aad72189cf1a048ee1a30270ea43dce2925823563c283fecd3dcf65e5e`；原位置保留，禁止删除或覆盖来重试。

三份兄弟cache完整元数据摘要匹配（当前firecracker-code、go-mod、warden-lab），原22项scene metadata和全部journal/Q未变，own objects0、六sysctls匹配。普通完整guard：R4,199,899,136B＋Q5GB=9,199,899,136B，通过；新增标准3GB仍未准入，未创建/释放新charge。原Q5GB不释放，原Gate退休未知继续保留。

`controller-cache-postflight-command-20261025.py`是超时前准备的条件成功postcheck草稿，**未执行**；其要求exit0，当前不满足。它不是本次成功证据。实际失败后只运行timeout audit，未重试维护或回退权限。

Ruling: 原单次维护机会在此终止；保留intent及部分收紧状态，后续cache继续操作必须另有具体checkpoint兼容源码/计划及独立review，不能重跑现入口或增加本次deadline来猜测继续 — 当前事实只证明停在权限阶段且没有unlink，不能证明后续删除或fsync完成 — 错误处理会误删状态，因此不接受空列表或终止信号作为完成。PG/material及新3GB资源流水线保持未准入。

Ruling: 继续独立authn/JWKS业务源码及已批准的固定`identity-unit`受界Go单元TDD，原代码profile使用`.cache/firecracker-code`，不写这个旧cache；每次仍须原ordinary guard/锁/Q和source manifest — 原进程已知终止、无Docker/authority pending且全项目可读，旧维护部分权限不阻断独立代码 — 若错误则code门禁拒绝，不能扩大为PG/cache重试许可。此前“失败不进入下一次actual”限定本次维护及依赖其容量的material/PG链，不撤回原独立业务代码授权。

完整Task6仍OPEN，cache source层PASS与实际维护失败分别记录。Task6原review fix计数已使用1/5，不因后续业务子层重置。Task3/4原五轮/Q和真实验收缺口、Task5真实42格、Azure预算及无宿主/发布许可均保持；Goal继续active，不是暂停或项目完成。
