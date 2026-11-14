# 固定旧 cache checkpoint 续接：源码阶段裁定（2026-10-25）

依据为[实现者完整提案](cache-continuation-proposal.md)及原[实际超时记录](cache-operation-20261025.md)。这是 controller 对 D1–D4 的裁定，只授权源码、生成的私有 fixture、冻结后独立安全审查；**不授权读取真实私有 intent、写真实 checkpoint、chmod/fsync/unlink 真实旧 cache 或启动续接**。后续实际只读捕获和维护分别准入。原180秒操作已终止失败，不延长、不重跑、不改旧 journal。Task6整体与Goal仍OPEN，原fix1/5不重置。

D1：批准实现仅适配已钉住旧 source/intent/已知wait=-15 的新固定一次入口，原入口和generic trust保持字节不变。真实准入必须独立验证全部22,682项仍存在、原稳定字段一致、连续前19,160项为target（260目录＋18,900文件）、余3,522项original且含ctime与旧fingerprint完全相同；prefix仅mode/ctime允许上述已知变化。任何非前缀、增缺、别名、大小/mtime/identity/权限或suffixctime异常即拒绝，没有任意混合状态fallback。只复用旧strict CachePlan扫描/recheck/remove，不设置旧tightened状态绕过。所有目标重新fsync，target项不重复chmod；新durable ready及strict复查在任何unlink之前。旧cache数据body仍不可读，元数据等同不构成内容真实性证明。

D2：批准在源码中实现未来controller调用的固定只读metadata捕获功能和校验，但本阶段不能运行于真实cache。未来必须先通过独立source/执行计划review，再由controller另行批准一次捕获：只读固定旧intent、固定长度4,573,737及SHA cbc9e3aad72189cf1a048ee1a30270ea43dce2925823563c283fecd3dcf65e5e（<=32MB），nofollow/0600/UIDGID1000/nlink1/同设备/读前后FD与path一致；严格schema、唯一relative及完整layout重新验证。新checkpoint最大16,000,000B，包含新实际完整fingerprint+blocks、顺序/prefix、parents/lock/source/旧公开终态hash与writer依据。禁止生成或提交真实journal body至Git；controller只发布长度/SHA/聚合结果。现有审计不被追认为prefix或fsync证明。

尚不存在的checkpoint不能事先硬编码hash。生产入口必须通过固定、无路径或环境参数的controller批准记录取得预期SHA/长度/绑定值；记录在已review源码冻结后由controller独占创建并本地提交，实际recorder再钉住其字节hash和源hash。可实现固定公开路径 `docs/evidence/task-6/cache-continuation-checkpoint-approval-20261025.json` 的严格有界schema（<=64KiB、nofollow/UID1000/regular/singlelink/受信祖先），没有该记录就failclosed；记录只含metadata摘要，不是私有body。当前不能创建此真实批准记录或默认允许值。批准记录与checkpoint在writer-free窗口必须不可变，执行时仍完整live匹配；不能自行刷新它们或由旧模式推导授权。这延续受信worktree/同UID无writer假设，不声称抵御恶意同UID替换。若需要不同固定绑定机制，先交具体proposal，不添加可配置retry/path/selector。

D3：同意四个新固定私有名字及提案durable状态机的源码设计：`identity-cache-continuation-v1-checkpoint.json`、`identity-cache-continuation-v1-intent.json`、`identity-cache-continuation-v1-ready.json`、`identity-cache-continuation-v1-result.json`。后三项各<=65,536B，0600/exclusive/nofollow/file+parentfsync，任何既存项（含partial/symlink）拒绝；旧intent只读、旧result保持不存在。公开recorder一次launch-intent须在child之前持久化，early-interruption也没有盲重启。总新时间盒最多600秒（590运行+5TERM+5KILL/wait），仅本次仍持有的child/group可signal，未知终态保留pending且不能并发postguard。旧PID不能再signal。输出<=1MiB、<=60秒稀疏进度，无逐项持久progress或body输出。96,000,000B维护headroom、全部既有charge/Q/ownimage/完整R、12e9磁盘、16e9内存及原1GB host allowance保持；不新增canonical charge、不放宽FD/bytes/parallel度。以上时间/资源是未来实际方案上限，不是本次执行许可。

D4：未来实际捕获和维护均需新的controller writer-free窗口、普通UID1000可信祖先/原锁identity、source/public历史/oldintent/oldresult事实、完整普通资源guard及原scene22/Q/六sysctls/ownobjects。所有已知项目命令须terminal；legacy go.sh不遵循锁，因此锁本身不证明无writer。新三兄弟完整metadata摘要取在同一锁内；firecracker-code采用获授权crypto运行后的新baseline，并用已知receipts解释变化，不要求回到旧10:07摘要；其他兄弟核实既有事实。新操作前后该新baseline必须相同。未取得wall-clock连续性证明，本裁定不使用ctime执行窗口来推断作者，不编造容差；严格prefix/稳定字段/suffixctime/新checkpoint/writer依据均不能省略。原scene/Q/owner退休未知及所有历史不变。任何失败仍只允许已知terminal后的只读审计/普通guard；成功必须exit0+durable新result+独立postflight，之后才单独评估新标准3GB，不能当场启动PG/material/SQL或释放Q。

实现/验证范围：仅两个新Python文件、必要的新精确执行计划/fixtures证据。旧engine/sharedguard/recovery/accounting/crypto文件不变。可以按本项目既有native Python私有fixture方式做有界TDD，生成树/显式测试注入，绝不把真实intent复制进测试。每次完整prospective source hash manifests；body snapshots仅新/相对dispatch BASE改变的文件，保留所有既有证据，不反向删副本。纯fixture wrapper设wall<=45秒/CPU<=30秒/地址空间<=512MiB/单文件<=32MiB；不启动Go/Docker/服务/网络或子agent。先源码commit、唯一冻结cover、再独立审查，测试仅新fixture模块，不重跑旧26或旧suite。失败fsync/chmod/unlink与ready-before-unlink门禁必须以生成fixture验证，不能替旧路径未运行的Minor背书。

Ruling: 采用精确连续前缀+新不可变checkpoint的源码方案，实际分阶段另准入 — 已知进程终止和全部文件存在支持一个可验证的受界方案，但旧汇总不足以授权删除 — 若判断错误，最先代价是新的源码/fixture返工或实际preflight拒绝；没有隐含的第二次维护或更宽数据目标。无host k3s/iptables、VM、GPU、Azure/身份mutation、push/发布许可。

## 冻结覆盖自审：recorder完整wall门禁（2026-10-25）

实现者报告产品源码已冻结 `93051e37849f6bfeb8416ef3883f65034f6dff09`、唯一首份冻结cover44PASS/145源码hash一致，但其runner的finally先取消45秒SIGALRM才写postmanifest/receipt。CPU/AS/FSIZE限制仍在，报告称实际timed phase均不足2秒；这些事实不把未被wall覆盖的收尾追认为受限。

Ruling: 45秒要求覆盖整个新fixture recorder，包括prospective setup和post-source/receipt/最终固定输出。只准新的更正run wrapper把alarm保留至全部收尾完成后再取消；真实超时按failure/unknown保留已有artifacts，不补造成功或改旧wrapper。产品源码93051保持冻结，额外一次仅新fixture模块的更正frozen cover因这个实际harness变更而必要；新独立目录保存完整前后145hash/changed-only snapshots/wrapper/命令输出时长，旧44PASS及所有旧失败逐字保留。不得重跑旧suite或真实cache，不能因此放宽限额。若裁定错误代价是一次有限重复fixture覆盖，不产生数据或外部资源变更。此为实现者自审修正，未消费独立review新一轮；原Task6 fix1/5保持。源码与执行计划仍须后续独立安全审查。
