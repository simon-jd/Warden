# Task9 第一次实际：首 absence 解析失败，原件保留

fresh b0e46e known0：R5032681472+Q5000000000+held131072+完整new1748683264=11781495808B，MemAvailable94354677760B、newN不存在。sole b640b4 known2，0.069秒，STOP UNKNOWN:RuntimeError:container_not_proven_absent；不记业务RED。root8b8777全文读status265B/events287B/stdout1B/stderr78B。

唯一CLI为inspect新名warden-task9-red-20261025-a-pg，rc1，stdout精确一个换行，stderr是含该精确名的No such container错误。原caller要求stdout空，故门禁拒绝；不是Docker存在该容器，也不是自动审批拒绝。status记owned_names_attempted=[]、cli_group_cleanup_known=true，尚无container run/PG/Go/test。旧Task16 native仍UNKNOWN，不能因本次CLI已清理宣称旧quiescence。

原N .cache/task9-first-red-20261025-a保留9359360B（现计入R），所有原件字节/模式不改，不重放旧namespace。仅交同一作者一次最小caller修正准备：允许inspect stdout精确空或换行，rc1及精确name-specific错误不变；除此只改全新N b和两个b名。禁止strip/一般stdout放宽、阈值/版本/镜像探测、改源/冻结/M、控制器或重复已过测试。新body另存，旧body/失败保持。

root全文受影响diff/完整新body、fresh全部原门禁后，可独立准第2次且最后一次本Task9首RED实际；目前未准新actual。若仍不是预期业务RED，STOP给精确剩余阻塞，不自扩额度。此为原Task9普通首caller语法适配，不复活Task6/15/16任何耗尽轮次，不改host/网络/预算/Q/9GBreserve。Task9/整个Goal仍未完成，Goal active。
