# Task9 logger 修正唯一实际诊断：已消费并停止

本次只执行协调文件 `COORDINATOR-TASK9-LOGGER-CORRECTION-20261026.json` 的新增一次额度。Task15 原作者已安全交回；c79a01 全文读取 12312B 最终 caller（SHA256 `68c82e12362296db7193bfbafe8613378d8dbcecf9b561c0921efd4152ac0f31`）、精确 2056B diff、说明和 freeze。2d02aa fresh 重新核实仅 logger option 与全新 namespace/name 三处替换、原 F/M/12 源码未变、namespace 不存在。总预留 11,349,343,232B / 12,000,000,000B，含 Q5GB、四外部 tmp 保守131072B、持续 logger hold2097152B、完整新1254803968B、Task15旧CODE524288B和独立publication1048576B；常驻预留14.5GB /16GB。没有 pull、Go、测试、产品或宿主修改。

sole actual182576 known0，原正常审批路径，无新自动拒绝；receipt elapsed0.886秒，完整日志/State/cleanup已回收。这里只是 `DIAGNOSTIC_RECEIPT_COMPLETE`，PG 未 ready、退出1，不能记为业务 RED/PASS。31ce6e 全文读12事件、24 raw共3017B，未截断。State 显示 exited / Running=false / Pid=0 / ExitCode=1 / OOMKilled=false / Error为空。

## 直接证据与因果边界

本次日志依次记录 initdb 选择 `posix`，自动默认 max_connections100/shared_buffers128MB，进入 bootstrap，随后 FATAL 无法把 POSIX共享内存段扩展至1048576B，错误 `No space left on device`；后续 PANIC/Aborted 并移除未完成 PGDATA。这是本次已观察的启动失败原因，发生在最终 postgres 的 `dynamic_shared_memory_type=mmap` 等参数生效前。不是容器内存 OOM，也不是 logger 再次拒绝。socket 的 chmod Operation not permitted 警告先出现，但进程继续进入 bootstrap，本次没有证据支持把它当致命根因或另加权限修复。

原业务 b 使用同一 initdb/1MiB shm 配置、在 readiness前退出，本次证据与其现象一致；**原b没有保存其启动日志，不能追溯声称直接证明了原b的全部原因**。当前结论是本次 initdb POSIX shm失败已知，原b精确原因仍未直接观察。

[PostgreSQL initdb 官方文档](https://www.postgresql.org/docs/current/app-initdb.html)说明 `--set name=value` 会在初始化期间强制参数，并写入生成的配置；[资源参数文档](https://www.postgresql.org/docs/current/runtime-config-resource.html)说明 DSM mmap 使用数据目录中的映射文件。[Docker 官方 Postgres entrypoint 源码](https://raw.githubusercontent.com/docker-library/postgres/master/docker-entrypoint.sh)将 POSTGRES_INITDB_ARGS 传给 initdb，最终服务器参数在后续启动使用。以上为当前官方文本，尚未把固定镜像内 entrypoint/版本与上游源码逐字绑定。

## 最小未应用提案与停止点

`pg-initdb-mmap-UNAPPLIED.diff.txt` 只增加容器环境值 `POSTGRES_INITDB_ARGS=--set=dynamic_shared_memory_type=mmap`，把既有最终服务器的 mmap 选择延伸到初始化阶段；不放大 shm、data/tmp、内存或时间上限，不改非 root/只读/网络none/无端口/capdrop。该候选直接针对真实失败阶段，**未应用、未执行、未声称会通过**。下次实际前仍须确认固定镜像 initdb/entrypoint 支持该参数、初始化数据盘容量/边界及全新 caller 门禁。本 diff 的输入是已消费 caller，仅用于审阅，不可直接执行或修改旧证据；未来 namespace/name/CID/owner 必须全新且重新证明不存在。没有第三次诊断或业务测试许可。

实际 CID `76a50d91d24bcb5ac0754ceb01896504acce85944bc3e80f093ebbfd04c2d8a4`，owner `f0cd72248dd966d3a831d1f84cdb35a3`。捕获前、清理前都核对CID/name/label；rm-fv known0，最终精确 name absence rc1/stdout换行/指定 No such container，所有自有CLI组known收尾。原新 namespace86016B与全部raw/CID/status/events及native请求/结果保留；持续外部logger2097152B不释放。旧FIRST_RED2/2、旧diag1/1永久SPENT，本新增logger修正1/1也SPENT，总诊断2/2。旧Task16 UNKNOWN9GB、Q5GB、全部旧额度/失败/现场不变。Goal active，Task9及整个项目未完成。
