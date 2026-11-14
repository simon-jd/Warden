# Task9 首 RED 总2/2 STOP：自有 PostgreSQL 在 readiness 前退出

原Task9第一次a absence解析失败保留；第二次fresh dc1619 known0：R5041319936+6748814336=11790134272B<=12GB，MemAvailable94212042752B，old9GB+new6.5GB预留不变。root0f45b5全文读唯一新body12367B，只改新b名称和stdout精确空/换行，原source/material/freeze未变。

sole a9ad3e/session18994→e88bf0→c1c3d2 known2，30.243秒，UNKNOWN:RuntimeError:pg_not_ready。没有Go run或测试，不是业务RED，不勾Task9测试/运行/实现。4eb0b4读取106009B events输出截断，不能称全文展示；d19d43逐项解析全部236事件、展示全部7种唯一精确事件及次数，并原样保留[完整events](first-red-actual-b-20261026/events.json)、472个raw/27185B、status、native请求结果和新caller。

唯一剩余实际阻塞：固定本机image、本次非root/只读/无网络/受限PG配置下，容器在最终readiness前退出；当前没有启动日志/State，因此退出根因未确定。先两次exec rc1无输出，后227次同一CID not running；不能将其解释成Go业务失败或仅一个PID1名字差异。原caller log-driver none未保存PG启动诊断，不以猜测改内存/shm/数据盘/阈值或版本。

清理已证实：仅PG被run，owner label前后一致；第235事件rm -f -v known0；第236事件精确名No such container/rc1，所有CLI均有结果且status cli_group_cleanup_known=true。Go名仅初始absence，无run。本次新自有容器已不存在；不把这写成旧Task16 native quiescence，旧UNKNOWN9GB/Q5GB仍保留。原a namespace9359360B、b10448896B及其旧字节/模式保持，后续由R计入；四Task15/tmp额外保守128KiB不释放。

附[未应用最小诊断差异](task9-pg-startup-diagnostics-UNAPPLIED.diff.txt)：仅PG有限local日志1MiB、保存已创建CID、精确not-running时提前结束轮询、退出前有界读取该自有PG的State/尾部日志。无阈值/资源扩大、产品修改、fixture/CLI版本替代或宿主操作；差异不能直接执行，因为仍指向已消费b名字，未来必须新的明确额度/新不存在namespace及全部原门禁。本差异只解决诊断缺失，不声称修复启动根因。当前不准apply、任何第三次实际、sizing/probe或新循环。

Task9此首RED实际总2/2关闭，五SOURCE仅未验证scaffold/测试/迁移，留工作区；不提交或称实现完成，不恢复任何Task6/15/16旧轮次。SOURCE/index回root，作者已停止。Task15单次readiness已交回并本地提交66832d8，不再修订其已交原件。Goal active、整个项目未完成；后续转原计划可独立推进项，不从新阶段名复活此测试材料额度。
