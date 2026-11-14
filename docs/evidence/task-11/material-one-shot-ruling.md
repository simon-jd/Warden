# Task11 固定工具材料包的一次准入

root已全文读最终8149B material-once-command.sh.txt，SHA25643f9fee6fe1f07994afa70c562d7b1ef4f8430ebdaebcac53a6ea6c611e58742；其ignored原稿由作者交回、停止编辑，public副本逐字保存。原inert draft未运行、未改。当前仅root拥有SOURCE/Git/index与实际调用权。

允许一次下载指定Vector0.45.0 musl包、按已取得publisher SHA256校验并回读已存archive、拒绝不安全tar成员/超50MB archive/超200MB解包/多余entry或非x86_64 ELF，然后只执行该唯一[V,--version]。不安装全局工具、不运行test/服务/collector、不连接Azure/OpenSearch/旧缓存/现场、不修改Task6/16源码。只有正常0、publisher equality、已知唯一child终态、原始version输出经root读取后才可接受材料兼容性；不是Task11实现/云日志或整个Goal验收。

调用使用native ordinaryUID1000、project cwd、exec env-i固定PATH/LANG/LC/T11_R_BYTES，HOME/umask不改。GNU timeout TERM80+KILL10，总90秒；单Python-I-S-B owner在最早MONO后60/65/74秒设置更保守work/version/cleanup检查。父CPU55/AS soft1GB-hard3GB/FSIZE200MB/NOFILE128/core0，唯一child CPU3/AS3GB/FSIZE每stream512KiB。实际out/err独占文件在本次私有0700树内，失败前保留路径与partial长度；owner持原Popen/可用pidfd，在同绝对截止剩余量内TERM/wait/KILL/reap。任何非零/未知/超时即停止此材料batch，不重跑/搜索参数/删除unknown树或凭历史PID重发；对不可中断IO不做物理退出保证。90秒不包含工具调度队列，yield不是deadline；Task6原所有期限不变。

最终预算增加明确20MiB工具inode/directory/文件padding预留，new_peak=2387167168B；原2366195648+20971520。脚本内部较小预算检查不是最终准入authority，root外部fresh R+Q5000000000+new_peak≤12000000000才可运行，archive已含、不重复加download。resident预留oldunknown9GB+parent/driver1GB+Vector3GB=13GB≤16GB，fresh MemAvailable≥5GB；不是RSS实测。下一个最终guard必须与actual同native环境执行并保存原始返回，不复用旧R。

前置事实见material-preconditions-20261025.json：默认sandbox的/与/home为65534映射，第一次只读gate断言失败、无材料执行；定向stat保留原值。相同条件在实际native profile46f1af正常，二者owner0/项目父目录1000，模式非group/world-writable，无symlink，新固定.cache/task11-material-once-0.45.0不存在，hard ceilings支持所需limits，MemAvailable85070327808。没有放宽owner条件，也没有自动审批拒绝。实际包同样使用native profile；默认sandbox快照不替代它。

以上native元数据加随后fresh final budget通过，root即可立即执行这一固定包一次，无需真人内部审批。通过不自动执行RED/源码或后续步骤；要另行按原Task11 TDD/材料路径与资源准入。Task6失败额度（5/5、material1/1、六目标cover/review各1/1）保持，不因工具材料有进展而恢复actual；Task16 dirty/oldnative UNKNOWN/Q5GBreleasedfalse/scene22、Azure6及保护RG、GPU锁/宿主隔离/禁止公开发布不变。
