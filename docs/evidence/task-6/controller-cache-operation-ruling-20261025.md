# Controller单次固定旧cache维护准入

仅此操作，依据 [独立source/执行计划复审PASS](review-cache-substage-round-1.md)、[范围裁定](cache-maintenance-scope-ruling-20261025.md)和[真实只读preflight](controller-cache-preflight-20261025.json)。此为controller操作裁定，非第二身份审批、真人审查或Task6验收。

2026-10-25T09:59:13Z preflight以普通UID/EUID/GID1000完成：真实祖先和已有锁dev66307/ino54563251/0600/单链接通过；固定go-build root UID/GID1000/0775；两receipt均不存在。六项固定source摘要及三份cachedGo1.26.10格式source摘要吻合，未执行Go。旧go.sh明确把本项目目录映射到workspace并指定该GOCACHE；旧调用均终态，当前实现者/审查者均已交回、无本项目服务或Go writer，controller独占维护窗口，不以flock本身证明无writer。

普通完整项目R4,195,131,392B＋原Q5GB＋96MB维护余量=9,291,131,392B<12GB，常驻含1GB host allowance<16GB；own containers/images0、六sysctls匹配、原22项scene metadata/全部journal和原退休未知/Q均保留。新增标准3GB若现在计入会达12,195,131,392B，尚未准入；清理只是为其创造可能，不是已证明后续容量。

Ruling: 在source/真实anchor/receipt缺席、fresh普通guard＋96MB及无writer条件仍成立时，批准普通UID1000对已审查source7be15fa执行**一次** `python3 -B scripts/identity_cache.py` — 精确固定旧派生缓存可重建，完整只读白名单、durable intent、持FD权限收紧及strict重验已审查 — 错误或未知结果保留所有intent/部分状态并停止此操作，不回退权限、不删除receipt、不换root、不盲重试，不触碰任何原现场或其他缓存/authority。

controller须在启动前再次验证六个sourcehash、旧root身份、receipt缺席及完整fresh guard；记录不可覆盖的controller intent、命令、源码前后hash、退出/超时、duration和受界输出。最多180秒，超时只终止本次拥有的进程组并等待，仍记未知/未完成，不当作安全清理。该脚本自己重新取得原项目锁并完整检查所有条目；不因已有规划计数绕过验证。

完成须另做只读postcheck：exit0＋durable result completed，源hash不变，旧root/256 buckets/metadata保留且派生产物消失，兄弟cache元数据摘要、原scene/全部journal/Q不变，自有对象0、六sysctls匹配；普通完整guard含Q5GB和新增标准3GB重新执行且通过，才可说后续3GB有预算余量。这里只前瞻评估，不创建/释放charge，不启动Go/material/PG/身份/云/GPU/VM。那些仍按原裁定另步实施与review。

任何失败/模糊状态只读调查，不进入下一次actual。维护成功也不代表原Gate/Popen/pidfd退休、Task3/4真实验收、Task5矩阵、Task6业务/SQL/IdP或整体Goal完成。原Q5GB不释放，原轮次和发布/宿主限制保持。
