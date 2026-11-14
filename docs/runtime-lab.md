# runc 专用 lab runner

2026-10-23。本机Docker入口已独立审查，33项Python测试、capless ABI smoke及首次七项真实guest conformance全部通过，无SKIP；[实测证据](evidence/task-2/lab-live/README.md)。每次仍须先资源preflight并保持下列固定受信probe边界，[API→真实runc及完整退休协议也已实机验收通过](evidence/task-2/api-runtime/live/README.md)。home-ubuntu 是本宿主环境别名，实际Docker Name/hostname为 `postedism-ubuntu-system-selfuse`。不使用既有共享containerd，也不创建Azure资源。

## 专用 Docker 入口（优先）

`runtime_lab_docker.py` 为固定probe构建一次性scratch镜像，随后运行并按精确ID回收镜像和容器。不下载基础镜像、不产生build cache，也不依赖其他项目镜像。宿主Ubuntu26.04的Python3.14.4、containerd/ctr/shim2.4.2、runc1.5.2、libseccomp2.6.0及ELF依赖一起复制；不混用Ubuntu24.04的libc。每个输入文件SHA256写入本次`manifest.json`，实际镜像ID和标签写入`identity.json`；运行时再次拒绝runtime版本不匹配。首次capless smoke中rootfs文件合计约191.4MB；最终SHA绑定记录见`docs/evidence/task-2/lab-wrapper/`。

普通项目用户先准备缓存和可信文件权限；只修改本项目目录，runner不会自动修复权限：

```bash
# 已有build产物可直接使用；需要重新编译时先做资源检查。
python3 -B scripts/azure_guard.py preflight --additional-bytes 3000000000 --service-memory-bytes 4000000000 --download-bytes 0
scripts/build-runtime-lab.sh
chmod go-w . .cache .cache/warden-lab scripts
chmod go-w scripts/runtime_lab_{docker,docker_init,runner,paths}.py
python3 -B scripts/runtime_lab_docker.py smoke --other-service-memory-bytes 0
python3 -B -m unittest discover -s scripts -p 'test_runtime_lab*.py'
```

`0`只适用于已核实没有其他Warden常驻服务的本次环境。后续必须填其他所有服务的内存上限合计；wrapper再加自身4,000,000,000 bytes，交给16GB guard。每次打包前还预留3,000,000,000 bytes，覆盖tar、导入content与snapshot、内层daemon数据和Docker日志；已存在的Warden镜像另外按每个唯一ID的`2*Size+64MB`保守计入项目外占用。已有Warden容器则拒绝，需先核对其内存/磁盘；项目内已用空间由guard实测。下载固定0；本机guard不访问Azure。该预留是固定probe的容量估算，不是文件系统quota，异常/被中断的Docker导入可能留下daemon content store待GC数据，不能以image ID消失证明所有字节已物理回收，禁止因此全局prune。每次import前在本次session持久化并fsync `charge.json`的3GB outstanding charge；导入失败/响应不确定/清理失败时保留。后续preflight累加所有未释放charge，因此反复失败会耗尽24GB门槛，不能重新使用同一份预留。只有明确成功导入且image按精确ID删除并确认不存在才原子写released=true；这是对象生命周期的语义释放，不代表content store已物理GC。没有自动抹除失败charge的命令，恢复须审查现场后处理。

smoke以UID/GID65534、drop ALL、Docker默认AppArmor/seccomp运行，**没有任何host bind**，只验证版本及ABI，不运行guest。两个模式均固定本机`unix:///var/run/docker.sock`，清空继承Docker环境并核对daemon hostname/cgroup-v2/rootful；不改变context。整个外层设置memory=4GB、memory-swap=4GB（无额外swap）、pids=512、CPU=2、私有PID/mount/IPC/network/cgroup namespace、只读根、NNP、network=none、日志10MB×2、`/tmp`和`/run`各64MiB tmpfs。PID/mount namespace使用Docker私有默认值，cgroup与IPC显式private。

live一致性运行：

```bash
python3 -B scripts/runtime_lab_docker.py run --other-service-memory-bytes 0 \
  > docs/evidence/task-2/lab-conformance.txt 2>&1
```

live只bind本项目新建0700 `docker-<session>`目录到镜像的`.cache/warden-lab`，源码、Python入口和编译输入均已复制到只读镜像；不挂源码工作树、Docker socket、home、根目录、host cgroup树、GPU或磁盘设备。镜像入口只接受固定`smoke/run`，不透传用户command。所有host输入保留owner/mode/no-follow校验；容器内runtime必须root-owned regular且不可group/other写。原native runner的fd锚定session、可信artifact和独立daemon身份校验继续使用。

live建议cap profile为drop ALL后增加 `CHOWN,DAC_OVERRIDE,FOWNER,SETGID,SETUID,SETPCAP,SYS_CHROOT,MKNOD,KILL,SYS_ADMIN,NET_ADMIN`，外层AppArmor/seccomp为unconfined；**没有`--privileged`；该固定probe profile已实测通过**。SYS_ADMIN用于私有cgroup2/overlay/proc等mount、namespace和runc设备BPF操作；NET_ADMIN用于runc初始化guest私有loopback，不提供宿主network namespace或veth。其他caps用于解包所有权、切换UID/GID、设备节点、chroot和信号。默认Docker策略阻止所需mount/namespace路径，因此此profile已独立安全审查；SYS_ADMIN/BPF和外层LSM放宽扩大宿主内核暴露，不能把它作为任意不可信外层root代码的安全边界。guest自身仍由原driver强制non-root、drop ALL、NNP、default-deny seccomp、只读rootfs与network none，不更改任何expected断言。

bootstrap要求自己是PID1/root，cgroup namespace不同于宿主传入的inode，`/proc/self/cgroup`精确为`0::/`；随后在私有namespace重新挂载cgroup2（不把host bind remount为rw），再次检查mount root为`/`、memory/pids/CPU硬限额及root只含PID1。只有全部通过才创建自己的bootstrap leaf、移入PID1、开启自己root的cpu/memory/pids controllers。绝不修改外层硬限额或host父controllers；原native16GB lab子树始终受实际外层4GB约束。

容器与镜像都带`project=warden,owner=warden-lab,session=<随机128bit>,ttl=<UTC+1h>`。wrapper持有项目锁；SIGINT/SIGTERM与失败进入finally，先给owned容器20秒正常终止、保存Docker输出，再精确ID force-rm兜底并查询确认不存在。创建/导入响应丢失时，只按本次完整随机标签恢复ID并再次核验owner；未知查询错误不会当作不存在，unowned对象绝不删除。镜像同样只删除核验过的精确ID；不prune、不删volume、不修改daemon/systemd/sudo。TTL只是恢复元数据，不是后台reaper。SIGKILL/断电/daemon故障须显式检查本次identity.json，不得清理其他会话对象。

Docker路径在内层daemon reap、subtree空和data清理均成功后，仅通过session fd及两个已验证regular、单link、0600文件fd，把本次`containerd.toml`/`containerd.log`和session目录交回调用者UID；先交文件、最后交目录，不递归chown，也不跟随被替换的路径。存在未知entry、非空/未验证状态、symlink或hardlink则保留原ownership并报错；这种故障现场仍会让下一次普通用户预算扫描fail closed，需显式恢复，不能当作可读成功输出。

外层消失只证明最后一道回收，不能替代内层runtime.Kill验收。本次live已保存七项无SKIP输出、pids.events/peak、OOM与timeout空树、task/snapshot清理、独立daemon身份和退出回收证据；API→runtime调度验收另一步，Task2尚未完成。

## egress 模式（Task 10，`make test-egress-runc`）

- 和 `run` 一样起专用 lab 容器，区别只有三点：
  - 不是 `--network=none`，而是接到出口 lab 自己建的 `--internal` 沙箱网络（名字必须是 `warden-egress-<8位hex>-sbx`，标签 `warden.test=task10`，子网与参数一致），固定 IP `.3`；
  - 额外 bind Envoy 配置目录（必须是本项目 `.cache` 下的真实目录）到 `/opt/warden/egress`，lab 里的 `EgressController` 直接改真实 Envoy 的 LDS；
  - 多加 `SYS_PTRACE`：runc init 按路径加入 netns 时会把自己设成 non-dumpable，runc 随后要打开它的 `/proc/<pid>/ns/mnt`，没有这个 capability 会 `permission denied`（实测）。宿主上的 runc 本来就是完整 root。沙箱本身仍是 0 capability。
- lab 镜像多打包了宿主的 `/usr/bin/ip`（iproute2）。
- 每个 `Network: allowlist` 的 run：driver 用 `ip netns add` 建 `warden-<run>`，在 lab 的 eth0 上建 ipvlan（L2、`private`，同一父接口的沙箱互相不通）放进去，只配调度器分配的地址，不加任何路由；进程环境里有 `HTTPS_PROXY/HTTP_PROXY`。run 结束、cgroup 为空后删 netns。

## 原native入口前置条件（保留，非本阶段执行方式）

- amd64 Linux、cgroup v2，父级 `cgroup.subtree_control` 已有 cpu、memory、pids；runner 不修改父级 controller。
- containerd 2.4.2、runc 1.5.2（libseccomp 支持）、containerd-shim-runc-v2、ctr、timeout、Python3.11+（支持dir_fd的symlink-resistant shutil.rmtree）、项目 Go wrapper；内核须提供pids.events和pids.peak。
- 运行者有 root 权限，只为新建 `/sys/fs/cgroup/warden-lab` 及其中的 run/service cgroup。当前 `sudo -n true` 不可用；没有据此修改 sudo 或系统服务。
- `/sys/fs/cgroup/warden-lab`不得已存在；lab base中预存的root/state/io、containerd.toml/log/socket（含dangling symlink）均拒绝，由操作员检查和显式恢复。
- project、cache、lab目录及所有祖先必须由root或显式可信operator UID拥有，不得group/other writable（root sticky临时目录例外）。所有目录组件均O_NOFOLLOW；构建产物须regular、可信owner且不可group/other写。当前项目默认775需要由普通项目用户先执行`chmod go-w . .cache .cache/warden-lab`，runner不会替你修改现有权限。
- 可用磁盘预计 <2.5 GB（本项目当前 cache 约1.5 GB），guest OCI <15 MB，专用 daemon/state <0.5 GB。Warden 总上限24 GB。runner 限 daemon 1 GiB，lab subtree 16 GB；还须由控制器合计其他Warden常驻服务内存。

## 原native构建与真实运行

在Warden根目录，以普通用户构建。构建不会执行guest、不访问containerd：

```bash
scripts/build-runtime-lab.sh
file .cache/warden-lab/warden-probe .cache/warden-lab/runc.test
cat .cache/warden-lab/image-digest
```

上述probe和test均为静态amd64 ELF；OCI archive由Python构建，包含guest和只读测试文件，镜像没有shell或基础发行版。批准的专用lab有root能力时执行：

```bash
sudo env WARDEN_LAB_ACK=dedicated-warden-lab scripts/run-runtime-lab.sh \
  > docs/evidence/task-2/lab-conformance.txt 2>&1
```

脚本经`python3 -B`启动（不写__pycache__），创建独占0700 `.cache/warden-lab/session-<random>`；配置/log使用O_EXCL|O_NOFOLLOW以0600新建，root/state/io也独占新建。全部daemon路径通过session目录fd的/proc入口锚定，避免父路径被改名后root写出项目。namespace为`warden-lab`。只向此daemon导入probe OCI，使用manifest裸digest进行执行并核验image target，不拉取镜像、不查询共享daemon。脚本不会修改systemd服务、root cgroup controller或现有daemon配置。

退出finally杀掉本次创建的整个lab cgroup和其拥有的daemon PID，验证`populated 0`再删除自身cgroup及daemon数据；目录fd锚定清理、symlink-resistant rmtree且仅操作本次session创建对象。probe/digest保留；本次session的配置和日志保留为root-owned0600，需有root读取权限。SIGTERM/SIGINT转为异常进入finally；SIGKILL/断电仍需显式恢复。失败cleanup会显著报错，保留现场供操作员检查，不能将失败运行写成通过。异常断电后不得直接复用残留环境；调度器应在独占持久claim后调用`Driver.Reap(ctx,runID)`并把中断记录为失败。

## 共用七项行为

`conformance.Run(t, runtime)`供runc/gVisor/Firecracker共用。通过需要全部七项真实guest输出、exit信息及subtree清理结论，且没有skip：

- ForkBombCappedByPids：guest使用amd64裸fork，让children仅执行pause，避免Go线程数扭曲测试；至少16个child后观察真实EAGAIN；driver另外采集目标cgroup的pids.events max增量>0及pids.peak==32，排除首次fork EAGAIN或其他资源压力假通过。pause syscall明确允许，child在kernel阻塞而不是EPERM忙循环。
- RootfsReadOnly：对镜像中mode0666文件写入，必须返回EROFS。
- NoNetworkByDefault：仅loopback，向基准测试地址198.18.0.1的本地route lookup返回ENETUNREACH，不发送第三方流量。
- RunsAsNonRoot：真实guest UID/GID非0。
- TimeoutKillsProcessGroup：父子进程保持运行，driver独立超时后cgroup.kill；整个subtree populated=0。
- MemoryLimitOOMKilled：mmap并触碰页面直到真实OOM；核验host cgroup memory.events oom_kill计数，而非仅看137退出码。
- SeccompBlocksMountAndPtrace：真实filter mode2，mount及PTRACE_TRACEME均EPERM；unit测试另外检验default-deny policy与危险syscall不在allow规则。

本机不带 `WARDEN_LAB_ACK=dedicated-warden-lab` 时，七项逐项显示`NOT EXECUTED`与SKIP。

## Runtime与后续集成边界

Driver Config必须由部署代码传入ExpectedDaemonPID（自己的child进程PID）和TrustedOwnerUID；每次gRPC dial/reconnect拒绝socket/父组件symlink、核验目录owner/mode与socket类型，并以SO_PEERCRED核验peer PID/UID，路径名字包含warden-lab不再充当专用daemon证明。root runner从自己创建的Popen取得PID，并向test进程传WARDEN_LAB_DAEMON_PID/OWNER_UID；sudo使用SUDO_UID作为可信operator，专用Docker入口需显式WARDEN_LAB_OWNER_UID。

Spec的RunID必须为`[A-Z2-7]{26}`，容器/快照/cgroup ID为`warden-<runID>`。默认网络none；allowlist在出口代理落地前拒绝启动。rootfs只读、UID/GID65534、drop all caps、NNP、独立namespace、seccomp、cgroup限额均由driver再次强制。

Handle的Wait caller取消不会取消运行者自己的timeout/cleanup；自然退出也杀剩余子进程。日志最多保存stdout/stderr合计前1MiB，溢出立即丢弃；Exit.LogsTruncated和DroppedLogBytes提供机器可读不完整标识。仅snapshot读取，当前进程崩溃会丢日志。收尾先等FIFO EOF，1秒内未完成才Cancel/Close并返回明确截断错误；退出事件到达不会提前取消尾部复制。删除task/snapshot失败返回错误，不伪报成功。

**控制面与后续验收**：持久claim/恢复、存储tenant重新授权、runc registry、状态/审计/日志持久化和GET logs已在[core阶段](evidence/task-2/scheduler/README.md)实现并单独审查。新增[真实HTTP集成fixture与原节点退休协议](api-runtime-lab.md)已完成代码阶段；capless私有PG通过，完整API→runc与两阶段quiescence仍待独立代码审查及后续live验收。生产main没有OIDC验证器，继续fail closed；本文件不表示Task2完成。

## 官方依据

- [containerd 2.4.2 release](https://github.com/containerd/containerd/releases/tag/v2.4.2)
- [containerd Go client getting started](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)：cgroup.events populated覆盖后代树，空父cgroup.procs不足以证明清理。

- [Docker run](https://docs.docker.com/reference/cli/docker/container/run/)：私有cgroup namespace、capabilities、resource limits与只读根选项。
- [runc 1.5.2 private network转换](https://github.com/opencontainers/runc/blob/v1.5.2/libcontainer/specconv/spec_linux.go) 与 [loopback初始化](https://github.com/opencontainers/runc/blob/v1.5.2/libcontainer/network_linux.go)：新guest network namespace的lo LinkSetUp路径，是NET_ADMIN需求依据；不是实机通过证据。
