# Task6 方案裁定：代码与有限TDD，真实外部身份操作仍未准入

原始[proposal](controller-proposal.md)完整保留。以下批准的是独立本地代码/测试准备，不是Task6或Goal完成，也不授权Azure/Entra对象创建、取实际token、Terraform apply、公开端点、发布或新VM。原现场、journal、Q5GB、Task3/4五轮和所有预算保持。

1. **接口与持久权威：批准。** 保留原authn.Verify(raw)并增加不同名称的VerifyContext；独立TenantAdapter满足现有tenant.Verifier。每次普通API请求由已验签的issuer/subject查持久active用户和tenant，只返回存储的TenantID。保留现有策略、run归属、scheduler、幂等与审计边界。SCIM字段、邮箱、externalId、oid均不自动当作sub或自助绑定权威；先SCIM创建，再由受信离线操作显式绑定。失绑定/停用/DB错误401，不新增HTTP bootstrap。已授权请求可在原10秒deadline内结束；提交停用后开始的鉴权立即拒绝，60秒要求保持。
2. **SCIM管理凭证：批准独立本地短租约，将24小时收窄为至多1小时。** 256bit随机、只存SHA256、限定一个tenant、可独立撤销、SQL侧校验到期和tenant状态。它不是云凭证，不赋予run API或身份绑定/tenant创建权限。实际离线凭证签发仍在独立操作门禁后；隔离测试可生成明确测试凭证。私有0600独占文件和持久intent先于SQL commit；确定rollback才可撤除新secret文件，commit结果未知必须保留文件/intent及credential ID并拒绝盲目重签，不能把不确定commit当rollback。token/secret不放argv、stdout、Git或证据，绑定真实token时只用受界私有输入。此短租约选择避免长期管理密钥；代价是实际连接器须轮换，未证明自动IdP接线。
3. **JWT/JWKS：批准所述严格单issuer/custom-audience/delegated-scope与stdlib RS256方案及有界传输、10分钟TTL、过期不接受旧key。** admitted未知kid立即发起或加入refresh；对额外刷新用2/sec、burst2和32waiter上限，过载拒绝而不接受未知/stale token。共享in-flight不重复耗费新fetch准入；取消调用者不取消其他人的有界fetch。过载可能暂时拒绝合法新key，这是明确可见的可用性代价，不宣称无限立即刷新。原named tests及精确TTL/失败边界、coalescing/压力/取消测试必须保留。
4. **PG测试形态：采用proposal最终的UID1000:1000＋两个最小只读账户fixture。** 不放宽共享trusted_directory以接受0770；fixture是项目内新建的最小passwd/group，不读取或复制宿主账户。只准固定cached PG image和Go/toolchain，不pull或安装；PG声明的VOLUME被显式512MiB tmpfs覆盖，无匿名volume。PG768MB memory=swap/CPU1/PIDs64/私有namespace/netnone/ROroot/capless/NNP，Go保持2GB固定形态；只共享精确0700 socket子目录，禁TCP/host port/host网络。单独material模式核实实际固定binary版本、路径和UID查找；网络源Dockerfile不当作缓存层实测。PG数据RAM内，只证明真实SQL/连接与应用重开，不声称断电持久性。
5. **资源预留保持已有格式：新增测试操作使用现有3,000,000,000B charge，原Q5GB不动。** 新3GB保守包含Go cache增长、PG的2×Size+64MB、tmpfs的额外保守磁盘计入、材料/overlay/log/metadata；每步仍算完整当前R＋全部未释放charge＋实际ownimage并防重复遗漏。proposal的浮点例子不是准入。未知create/start/cleanup outcome不得因空列表/CLI退出/单个ID而结清，保留状态/charge且阻止后续actual；只有已知终态、自有对象消失、host数据/FD核验及含Q5＋新3GB的普通完整guard通过后，才结清新3GB。不得修改旧charge金额/schema或旧恢复模块来迁就新profile。

现有四个指定cache的只读`du -s -B1`规划观测为：旧`.cache/go-build`1,972,539,392B，当前`.cache/firecracker-code`548,540,416B，模块/工具链`.cache/go-mod`772,935,680B，原现场等`.cache/warden-lab`713,883,648B。不是操作准入。旧go-build来自已停用的旧Go入口，是可重建派生产物；当前受界profile使用另一个cache。

Ruling: 允许实现并审查一个仅清理旧go-build内已确认Go管理条目的固定FD入口，以便已有3GB预留可适配12GB。只可在普通UID1000、既有项目锁、无并发writer下，对固定cache锚点/所有待删目录与普通文件做nofollow、dev/ino/owner/mode/nlink和已知Go cache形态检查，持FD/重查后unlink已知派生条目；拒绝未知项、别名/硬链、异常owner/布局。不得递归删除任意目录或接受path参数，不碰firecracker-code、go-mod、warden-lab、任何原root/journal/证据/源码。先检查固定工具链源码的cache格式；若无法确定条目就保留并停止该清理，不猜。清理只记录元数据/计数/字节，不读文件body、不启动Docker/Go/服务；先源代码/fixture回归/安全审查，控制器才做一次实际清理。其代价是以后需离线重新编译旧对象；模块/工具链/所有证据保留。清理后重新实测R，3GB预留不适配仍不启动PG。

执行顺序：

- 现在允许业务源码、严格crypto/handler单元TDD，以及新固定identity harness/cache入口的代码＋host Python无副作用fixture回归。Go单元测试只能在既有受界profile上新增唯一固定`identity-unit`目标`./controlplane/internal/authn`，保持所有边界，不运行PG；不得用旧go.sh/test-postgres入口或host Go。
- 新harness限定`material/unit/sql/cover`及上述固定cache入口，没有任意命令、路径、regex或container selector；使用现有项目锁与精确labels/检查。PG、material、cache清理**实际执行前**，必须冻结相关源码/测试/报告并由独立review检查这段source＋execution-plan。允许将business crypto单元代码一起冻结，但审查须明确SQL/realIdP尚未实测。控制器之后按顺序单独核定清理、普通guard/新3GB、material及PG/SQL，不能直接跨步。
- 业务层SCIM/SQL、main实际composition、审计/迁移与operator CLI按proposal最小范围实现。scope和代码支持的本地测试不冒充实际Entra/IdP。Terraform仅源码，选固定已核验provider，不init/apply/取token。不要把Free用户provisioning笼统写成P1；具体本租户能力仍需证据。
- 所有后续RED/GREEN/cover均记录运行前后完整源码manifest，真实setup/compile/行为失败分别记录。源码先提交，最终一次有限selected-controlplane covering在冻结commit上运行；受影响失败/修改可有必要定点回归，不重复未改runtime/SQL旧suite。原Task6四个named tests与真实SQL/HTTP撤销必须实际通过才能接受对应层；真实Entra/assignment与全Goal仍单列。

上述裁定的共同理由是已有普通guard可用，身份功能可独立进展，同时避免长期管理凭证、猜测身份映射或扩张资源/权限。若材料或预算/审查失败，保留事实和未完成项，继续独立可做部分；没有新的外部身份/宿主权限许可。
