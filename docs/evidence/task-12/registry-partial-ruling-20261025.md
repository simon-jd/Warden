# Task12 候选镜像：部分元数据，原调用FAILED

fresh fb5fe7 normal0；唯一只读调用9f2649/session91889→621fd6 known exit1，phase=config/redirect refused，实际5请求、读取body8062B。匿名token只在内存，未保存或打印，未GET layer/pull/接触Docker daemon/启动容器。原失败namespace和原件保留，不重试。

bd2653仅读取并公开保留失败前原始index/amd64 manifest及failure，未重新请求网络。tag digest `sha256:72fe2fc84be8295906b8efca020b46c58ed45c8da60cd9b8b49e1991e38e89a4`；index声明linux/amd64 manifest `sha256:7ad3c515e43fb1642ddf2181dfd03402e42e85a16030e098ed1f3fc1404d7e89`，7层压缩总1028720640B。config预期6445B、digest `sha256:731779f1c50424e38335b0af191058642a4964a2b2c62175ebcc8d5734fee13a`；config原文未收到，因此不能声称已验证其os/arch或完整镜像材料。

精确当前阻塞：固定no-redirect reader拒绝config GET的CDN重定向；没有保存Location，不能杜撰或盲目放宽host。最小未应用差异是先保留3xx状态/Location authority（不保存带签名query、不转发Bearer），经root核对后仅对config允许一个有界HTTPS重定向，按既定6445B/SHA校验；不扩大到layer、不改旧失败reader或terminal。该差异当前未执行，也未准入新的调用。

即便config取得，expanded layers、压缩/展开重叠、daemon/writable/data/log峰值仍UNKNOWN。压缩总量既不证明R+Q+全峰值能fit12GB，也不证明永远无法fit。真实OpenSearch原验收保持OPEN；当前作者只推进已经准入的独立本地组件，不扩大为镜像/宿主操作或metadata循环。所有原额度、Q/现场/UNKNOWN与发布限制不变。
