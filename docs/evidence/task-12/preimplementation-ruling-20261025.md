# Task12 实现前裁定（2026-10-25）

当前 BASE 为 `1b2eba62003560852b734fe0508176aa3509e61f`。原 Task11 R1 的 I1/I2 已修复并独立复核通过；BP 的 I3/I4/I5 仍 OPEN，不准重试。原 Task12 的 8186 字节提案只是一份静态提案，尚未授予源码、依赖安装或 OpenSearch 执行权限。

Ruling: 先核对规则语义与必要材料，再准入可验证的源码批次。读取 MITRE、pySigma/backend 与 OpenSearch 官方资料，修正缺少事实支持的技术标签，明确依赖和镜像未知项；不能把未取得的元数据当作永久物理阻塞。若判断错误，代价是重新设计规则或材料方案，不是追认一次未经准入的执行。

当前生产字段约束：Azure `api.operation` 保留原大小写；Tetragon `process.name` 和父进程名称是完整路径，仅包含 exec 事件；Kubernetes 附加字段仅在原始记录提供且未超过 2048 字节时保留。规则的大小写、路径与缺失字段语义必须与实际转换/查询兼容。Warden 真实审计缺少可信原始时间、操作者和来源，特权 Pod 也缺少稳定的有界投影，均不能用合成 fixture 宣称真实覆盖。

原 Task12 的真实 testcontainers → OpenSearch → pySigma 查询验收保留。独立的规则解析、转换、fixture 合约与 tag 矩阵只能按各自实际证据记录，不能取代后端或真实攻击验收。任何后续实际调用都需精确 caller、fresh 资源门禁与本会话 root 准入。

原 Task6 耗尽额度、Task16 未验证源码及旧 native UNKNOWN、Q=5000000000 字节、现场保留、磁盘 12 GB、常驻内存 16 GB、云预算及禁止公开发布边界不变。未修改宿主 k3s/iptables、旧失败文件或旧进程。Task12 和整个 Goal 仍未完成。

静态收敛文档 12274B 已全文读取，原提案与收敛文档分别原样保留。一次固定 PyPI JSON 读取 d2fc42 normal0 共收到38010B，三个版本均未 yanked；OpenSearch backend2.0.3 的发布依赖实际是 `pysigma>=1.0.0,<2.0.0` 与 `pysigma-backend-elasticsearch>=2.0.0`，wheel16940B/原bcb90... SHA。Core1.5.1 wheel171485B，ES2.1.1 wheel42529B；精确SHA/URL/依赖见完整实际工具事件。此处消除了网页读取不可用造成的三个根包元数据缺口，未下载wheel、安装或导入发布包。

下一步仅准备一次本机Python3.14的有界pip dry-run解析caller，明确允许缺少PEP658时的wheel材料获取，禁止sdist/build/install。发布依赖的传递闭包、ABI wheel和实际总大小尚未取得，不能批准安装；镜像与后端准入仍独立关闭。SOURCE和Git/index继续归root。
