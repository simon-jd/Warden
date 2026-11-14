# 固定旧 Go cache 的权限收紧裁定

此文件补充 [Task6 原裁定](controller-rulings.md)，仅批准源码、纯 fixture 回归及独立审查。没有批准实际 chmod、unlink、Docker/Go/PG 启动或新身份操作。

实现者只读元数据检查发现 `.cache/go-build` 根目录为 UID1000、0775，部分普通项为0664，执行缓存目录为0755；现有 shared `trusted_directory` 正确拒绝组可写目录。不能为这批旧派生产物放宽共享验证函数或其他 profile。

Ruling: 允许固定入口先收紧这个旧 cache 的权限，再按原严格规则清理 — 它是当前项目旧 Go 入口留下、可离线重建的派生产物，收紧权限使既有标准3GB预留有机会适配原12GB上限，而不改 Q5GB — 若布局或身份不符，停止并保留；错误最多造成旧对象重编译或部分权限已收紧，不得删除原现场、证据或身份权威。

实现必须满足：

- 只从受信项目及 `.cache` 父目录 FD 锚定固定 `go-build`，不接受路径参数；实际操作是普通 UID/GID1000，在既有项目锁内，controller 核实没有并发 writer。
- 先完整只读预检固定 Go cache 格式；所有待处理项须 nofollow、同设备、正确 owner/group、单链接普通文件或确定目录、已知名称和布局。目录仅接受已观测0755/0775，普通项仅0644/0664，已确认的执行项仅0755。未知类型、模式、owner、别名、硬链、替换或布局均在 mutation 前拒绝。
- 持久记录 permission-tightening intent 和原/新元数据后，持 FD 重核 dev/ino/type/nlink/owner/mode，再用 `fchmod` 收紧：目录0700、普通项0600、确认的执行项0700。不可增加权限、改 owner、跟随链接，或触碰其他缓存/源码/现场/journal/证据。
- 收紧后继续使用原严格身份和布局验证；任何 unlink 前再次验证完整白名单及无替换。不能把 permission intent 当成已完成清理。
- 失败保留已收紧状态和真实阶段记录，绝不自动回退为组可写、重置 operation 或猜测继续。没有文件 body 读取，不启动 Go、Docker 或服务。
- 增加纯 fixture：generic 路径继续拒绝组可写；仅固定锚定模式可收紧；未知 owner/mode/layout 在 mutation 前拒绝；替换和失败闭合。所有 RED/GREEN/cover 前后完整源码 manifest 按原裁定记录。

冻结源码、fixture 证据和精确 execution plan，经过一次独立 scoped 安全/source review 后，controller 才另行按 fresh guard 核定一次实际操作。实际清理后重新测整个项目加全部 charge；若标准3GB仍不适配，就不启动 PG。Task6业务/SQL尚未实现，Task3/4原上限、原 Q、Goal未完成和所有发布限制不变。
