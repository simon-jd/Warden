- **1. Swap 拒绝与 NoSwap 保证 — ADDRESSED。** scripts/k3s_lab_init.py:69 设置 failSwapOn=false、显式 NoSwap；:74 通过 private cgroup held parent FD，以 nofollow、nonblocking、有界读取严格要求 0\n。:475、:559、:576 分别覆盖 session 创建前、成功输出前及最终 postflight；未改 shared bootstrap、宿主 swap 或资源上限。

- **2. 第三次固定场景恢复 — ADDRESSED。** scripts/k3s_lab_recover.py:21、scripts/k3s_lab_recovery_init.py:15 固定新 CID/image/labels/目录身份及124/0/55203B三文件。原有RO握手、精确shape/blocks检查后remount、两capability profile、全额预算、exclusive durable journal和失答保留链继续适配新场景，见scripts/k3s_lab_recovery_init.py:41、scripts/k3s_lab_recover.py:136、:201。

- **3. 新 tar 身份与回收顺序 — ADDRESSED。** scripts/k3s_lab_recover.py:32 校验固定dev/inode/UID/mode/nlink/size，:181起持有archive FD，:204 journal记录身份。:222起依次确认helper、原容器、镜像移除；:229 ordinary guard成功后才重核parent/FD/pathname、dirFD unlink、目录fsync，最后durable release charge。漂移、未知、普通guard失败不提前删除；unlink后fsync失败仍保留charge。

- **4. Exact startup gate、UTC 窗口及 namespace 恢复证明 — ADDRESSED。** scripts/k3s_lab_init.py:121、:138、:176 固定32 API enums、severity/caller/source、次数和完整模板；klog日期须唯一落入有界UTC startup window，:513固定进程TZ=UTC。:454验证两个固定namespace的exact name、非空UID、Active、无deletionTimestamp；:552最终Ready后所得证明集合才传入gate。输出仅安全fragment/hash，swap与cancellation错误仍拒绝。

- **New Breakage：None。** 未发现本轮diff新增的Critical、Important或Minor问题。

- **Out-of-Scope Observations：None。**

- **Checks：** 核对报告命令与最终输出，verification-tests.txt:49为44 tests、OK、零skips；RED和中间fixture失败未被当作最终GREEN。对照修改后的行为测试、恢复生命周期顺序和相关接口；核验20份缓存pinned primary-source的长度/SHA，并定点核对swap与新增日志模板。未重跑suite、未执行Docker/恢复/启动操作，checkout/index/HEAD未修改。

- **Spec：PASS；Quality：PASS；Fix round：全部四项ADDRESSED，无新增Critical/Important breakage。** 此结论限代码阶段；真实新recovery、Ready/cgroup、guest/conformance和100次测量仍未验证，Task3整体保持OPEN。
