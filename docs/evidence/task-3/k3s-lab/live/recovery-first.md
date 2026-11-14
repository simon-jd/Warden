# 第二次失败场景的固定恢复实测

源码e91e9addbf85c4314630d32dd8f62bb607fe84e3；执行HEAD322f7a4，round3独立复审通过后由controller运行固定命令。`recovery-first.txt` 为原始公开输出，exit0/3.75s，host maximum RSS42,396KiB。未下载、导入或启动k3s。

完整预算为项目3,025,076,224B＋原6,000,000,000B预留＋全部owned image charge1,434,733,588B＋helper64,000,000B＝10,523,809,812B≤12GB；服务预算320MB≤16GB。只复用原镜像，helper两项capability/256MB/32tasks/1CPU，原scene唯一RO/rprivate bind和身份检查后清理三个固定私有文件。

controller独立postflight见 `recovery-first-postflight.json`：原outer DEV66307/INO55586536/UID1000/0700不变，公开identity/manifest字节不变，原privatechild已不存在；helper cc53c48d66de68b06baff8039d245e99192f6de6659f99cdea7c2d9cd4bbc82f、原CID37b95dd4…、原imagea2bd74a…均精确inspect absent。完整带标签--all images/containers为空，ordinary full guard通过，outstanding0、charge releasedtrue，项目3,025,088,512B，六项protected sysctl匹配。

恢复代码只有依次确认helper→原container→原image移除和普通guard通过后才释放charge。journal/complete与执行预算归档于postflight JSON。该成功只证明固定停止场景已回收，不是原始Popen/GoGate退休、节点Ready、tenant/conformance或Task3完成。Azure承诺估算仍0，无Azure/GPU动作。下一步单独fresh bootstrap并生成新input manifest。
