# Task15 首个inert材料命令：尚未准入

root `f84d0e` 全文读取8162B [首draft](task-15-material-preparation.md)。它实际新建于公开docs，而不是所要求的ignored路径；其“仅写此ignored文件”一句不实。没有产品/Git/index变更，root保留该公开原稿作为本次静态证据，不删改旧字节。原稿未执行，没有材料尝试、下载或进程。

三项必须在执行前修正：移除os.umask，不更改host umask；落实原新1GiB内存预留对应的明确进程限额（AS1GiB、CPU45秒、FSIZE256MiB、CORE0、NOFILE64，whole90含收尾保持）；删除失败时shutil.rmtree(N)，失败/未知须保留新N和已得原件，正常失败写简短status、不记录授权头或临时签名URL。仅本项目全新N、UID1000和控制的非symlink父路径应在首次写前核定。无child/发布包执行，不需要新进程组控制框架。

仅原作者准备新的body-only inert `.superpowers/sdd/2-warden-security-plan/task-15-material-command.py.txt`，≤8192B，短说明可另写ignored文件。不再写新公开提案，不重写原draft。新增限额、私有创建与失败留存只落实原边界，不扩材料内容、资源、功能或新元控制器。root全文及fresh门禁通过后另准一次实际；当前actual仍关闭。SOURCE/Git/index归root，原Task15/Goal OPEN active，所有旧额度/Q/现场/UNKNOWN与宿主发布限制保持。
