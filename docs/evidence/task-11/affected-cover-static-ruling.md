# Task11 受影响正向覆盖静态裁定

ROOT 全文读取最初完整 driver/config/sh（cce6ae），复读修正后 22285B driver（f7dbb9），再读取最终 producer 等待段（62c6bf，driver22965B，config1274B，sh271B）；全文读取7761B `task-11-cover-run-command.txt`（c00219）和README。此次静态准备尚无正向测试或背压运行，不是独立接受审查。

执行前已纠正初始连接读取时限/本次连接跟踪和关闭、CPU软信号留证与父子预算、生产者固定窗口、ACK跨边界留痕、stdin关闭，以及固定10ms等待造成的约100/s吞吐上限。最终等待按quota真实到期时间及本次stdin可写就绪进行，不以忙等或延长负载凑结果。普通Task11首次运行前的源码纠正没有使用Task6旧轮次或有限六目标额度。

准入命令文本所列顺序的一次冻结受影响覆盖：九个固定TOML golden、独立agent静态validate、独立aggregator静态validate、一次本机背压。每一stage前分别取得同native UID1000 fresh预算及对应内存/新路径检查的known normal0；前序已知通过才进下一stage。完整请求、返回、poll、原始有界输出及所有失败/缺失须保留。必要的pinned `validate --help`已运行并留证，不重复。

golden/validate各50秒TERM+10秒强制清理；BP外层160+20=180秒，driver工作截止START+150、清理截止START+170。父CPU15soft/20hard（仅为唯一fork继承在出生前保留hard140），child120，合计不扩140；AS1GB+3GB、输出分别512KiB、metrics2MiB及其它既定限额不变。producer只能在原10+100秒内写入，后续仅drain；欠额最终FAIL。通过须同时有32320唯一ID对账missing0、固定60秒ACK禁发窗口的实际留痕，以及至少1秒连续写入阻塞与实际260000000B以上occupancy对齐。目标值、单次EAGAIN和缺失counter均不能充当通过证据。

Q5000000000B未释放，remaining_new2137167168B已含六个buffer各268435488+67108864B、工具padding及其余既定峰值；fresh R+Q+remaining≤12000000000B。resident保守旧UNKNOWN9GB+新增4GB=13GB且MemAvailable≥5GB。仅本次owned Popen/socket/thread，未知终态或资源/超时失败即停止本批、保留现场，不阈值搜索、不用旧数值PID清理。计时从原实际进程开始，tool yield不是deadline，物理不可中断IO不伪称已获硬保证。

普通配置/源码错误可保留后按原Task11 TDD纠正并声明受影响的新freeze；不重复已通过且未变的覆盖。尚不接受Task11组件，须完整交回报告及准确BASE..HEAD包后独立Spec+Quality审查。真实collectors/云/集群/OpenSearch/告警执行仍OPEN；Task6 actual CLOSED、旧SIX失败停止、Task16未验证dirty和旧native UNKNOWN不变。ROOT本记录暂不入实现者提交。

运行中协调补充：27项golden b48c73 known0之后，ROOT发现BP清理阶段capture仍可能置truncated而最终未再次判失败。首次BP执行前仅增加最后截断FAIL检查，7a5d54读取确认；driver新freeze23085B（作者061463记录，SHA1828e0d8fd488c86dd93b023d5c6975166e3010b4cddbf23bf54eadcfa8db025）。此修改只影响BP，已通过且未变的golden不重跑，agent/aggregator验证亦不受影响。BP单次准入改为此精确版本，其余命令/限额/停止条件不变。这是静态修正，不记成一次已执行的BP或新的Task6轮次。
