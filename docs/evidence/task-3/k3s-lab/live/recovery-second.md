# 第三次失败场景固定恢复实测

source6f52f54、执行HEADae6ac6f，round4独立复审通过后由controller执行固定恢复。原始公开输出recovery-second.txt：exit0、4.62s、host maxRSS42,480KiB，无下载/新imageimport/k3s启动。

fresh预算：项目3,523,575,808B＋outstanding6,000,000,000B＋全部ownedimagecharge1,434,739,404B＋helper64,000,000B＝11,022,315,212B≤12GB，服务320MB≤16GB。helper使用固定两cap/256MB/32tasks/1CPU、原session唯一初始RO/rprivate bind，exact新三文件/child身份后清理。

独立postflight recovery-second-postflight.json确认原outer DEV66307/INO56011098/UID1000/0700不变，原publicidentity/manifest字节不变，privatechild与tar均不存在。helper d59ceba0f2a63fd172925586d12cea7baaa9ea3b3b52e9be4d29e0c78a7d4668、oldCID57a48b46…、image53914c90…精确inspect absent；完整owned --all containers/images空，outstanding0、charge releasedtrue。ordinary完整guard通过，项目3,026,972,672B、六protected sysctls匹配。journal/complete及固定tar身份归档在JSON。

按reviewed代码objects→ordinaryguard→heldtar重核/dirFDunlink/fsync→durablerelease顺序完成。该成功仅证明本停止场景回收，不证明原Popen/GoGate退休、NoSwap真实startup、nodeReady或Task3完成。下一步单独freshbootstrap。Azure承诺估算0，无Azure/GPU变更。
