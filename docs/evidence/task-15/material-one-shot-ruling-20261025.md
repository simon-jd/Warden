# Task15 单次材料准入

root `c28687` 全文读8007B修订body及说明；无umask/删除失败N，UID1000、nofollow目录FD、新N0700、私有O_EXCL文件、AS1GiB/CPU45/FSIZE256MiB/CORE0/NOFILE64及89+1秒整体边界已落实。原公开8162B draft及8007B稿保持未执行。

root只作三行兼容修正并完整核对差异 `11d291`：移除冗余路径chmod（已有新N私有mkdir及FD fchmod）；两个tar遍历同样忽略合法根目录项`.`/`./`，其余路径/链接/展开上限检查不放宽。初次文本提取 `27dad6` 因缩进匹配断言失败，在任何文件创建/材料操作前停下；修正匹配后创建8075B最终body SHA256 `1cc27db635c2bf5eef49b7e3a377d8e591d1d85c78adbd294d1f1bf30e0e1047`。这是同一个未执行首caller的静态修改，不是新尝试或额度重置，无新控制器。

正常native审批下仅准一次literal `/usr/bin/timeout --signal=TERM --kill-after=1s 89s /usr/bin/python3 -I -B .superpowers/sdd/2-warden-security-plan/task-15-material-admitted.py.txt`，cwd Warden。先未改azure_guard fresh `additional=5419430400` / `service-memory=10073741824` / `download=0` known0；body随后核UID/父路径/MemAvailable/新N独占及文件系统余量。Q5GB额外加完整新增400MiB，旧UNKNOWN9GB不释放、不扫PID/RSS/scene。

仅固定官方TLS/API metadata、三release asset哈希校验及≤256MiB安全展开。新N是 `.superpowers/sdd/2-warden-security-plan/.task15-cli-v1.19.2-material-20261025`，失败/超时/未知保留材料及短status（若能写）；没有自动重跑/阈值搜索或清理旧目录。bundle只校验官方API digest，不宣称密码验证。成功后root先读报告/成员元数据与实际工具事件；不执行解包文件/--version/Go/Kyverno/test/scan/sign/publish/服务或云，也不授SOURCE。

`c12feb`另核固定command.go的182/184行summary含Pass+Skip、187行按Fail判断错误；这是静态汇总逻辑，不证明意外Skip能满足预期拒绝，更不证明验签。后续真实每rule结果仍须检查。全Task15/Goal OPEN active，旧Task额度/Q/现场/宿主发布限制保持。
