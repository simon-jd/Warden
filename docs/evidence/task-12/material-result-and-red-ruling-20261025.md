# Task12 一次材料操作：通过，语义测试另行准入

初稿8136B全文核对发现未执行的缩进错误及逻辑展开量遗漏块开销；原作者只改两处。最终8593B全文读取73cf17，按实际父目录集合和4KiB文件取整核算两个展开副本。报告/18-pin lock固定，caller和lock在执行期间冻结，无新控制器。

fresh fc4ec9 normal0：R4450807808+Q5000000000+新增134217728=9585025536B≤12GB；MemAvailable86505500672B，常驻预留10GB含旧UNKNOWN9GB；新namespace不存在，嵌入Python AST与lock SHA通过。下载参数16MiB已包含在新增峰值中，未再重复加入磁盘总额。

唯一实际4f177a/session96700→6f9eac known exit0；e15a95只读取/公开保留本次五个owned文件。18个非yanked wheel与版本JSON、精确bytes、SHA、ABI、Requires-Dist及zip路径/类型/CRC均由caller逐一核对后，才在项目内全新site离线hash lock安装。metadata615133B，wheel2996767B，逻辑展开10423506B，4KiB展开估算11706368B，保守峰值52190460B。

实际work/head均0，cleanup1；postflight15609856B，完整材料树统计15613952B/544项，tmp不存在。原wheels/metadata/site保留供后续转换使用，没有再安装或运行额外version/smoke测试。子进程umask仅限定新子进程，不是宿主配置修改；原件权限未放宽。

源码作者只获必要的新site发布源码定向静态读取权限（≤24KiB），用于核对确切release API。下一步先交首个≤4096B固定RED caller，root全文读取/单独fresh资源门禁后才能执行；当前没有测试、Docker/backend、云或后续capture许可。

安装通过仅关闭本地依赖材料前置。32条规则/64fixture、转换适配器、coverage仍待真实语义RED与覆盖/独立审查；真实OpenSearch和上游可信审计缺口继续OPEN。原Task11通过部分不重跑/BP不重试，原Task6耗尽额度/Task16旧UNKNOWN/Q现场保持，Goal ACTIVE。
