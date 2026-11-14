# 第四次失败场景恢复及当前helper资源诊断

source30ac350，执行HEAD6975515。独立末轮审查只接受必要fixed recovery与诊断代码，原Ready/CRI EMFILE仍OPEN。本次原始输出recovery-third.txt：exit0、3.63s、host maxRSS40,560KiB，未下载/import/启动k3s。

fresh conservative budget项目3,525,320,704B＋outstanding6,000,000,000B＋all-owned imagecharge1,434,749,826B＋helper64,000,000B＝11,024,070,530B≤12GB/services320MB≤16GB。唯一retainedimage、two-cap256MB/32tasks/1CPU，ROshape核验后一次self资源探针，再按既定顺序清理。

已严格验证的当前helper诊断为UID0、nofile soft1024/hard524288、fd_entries7、inotify_result opened/errno0；FD已立即关闭。这些仅描述本次helper，没有原K3s进程FD/limit或UIDquota使用量，不能证明原EMFILE原因或后续K3s有足够容量，不授权再次bootstrap。

独立postflight recovery-third-postflight.json：原outer DEV66307/INO56143028/UID1000/0700与publicidentity/manifest字节不变；privatechild/tarabsent，helper377a6ef4608d4c983a76c1e44bb0e8d874eab0a757b32716004e1bc6cf2fa889、oldCID9a22e3c…、image2504a55c…均exactinspect absent。完整own --all lists与outstanding0，ordinary fullguardPASS，项目3,028,709,376B，六sysctl匹配。journal/complete+diag在JSON中。

6GBcharge仅objects→ordinaryguard→heldtar重核unlink/fsync→durablerelease后归零。不是原Popen/GoGate退休/Ready/guest/conformance/Task3完成。到达原bootstrap5轮上限，不继续同入口盲目重试；保留结构限制并推进独立Task4本机KVM/专用guestkernel可行性。Azure承诺估算0，无Azure/GPU或宿主配置改动。
