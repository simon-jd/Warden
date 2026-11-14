# Task5 独立纯分类层的后续准入

这份裁定只准许在当前B实现者交回工作区后，启动Task5原任务中的纯分类/fixture层；当前没有执行或通过相关测试。真实语料、镜像、runner/CLI接线及42格矩阵均未验收，不因此勾选Task5。

Ruling: 普通完整资源检查已在保留Q5GB下实测通过，故后续可以用原受界代码测试形态实现纯分类层；Task3/4未就绪不阻止这项不构造真实driver的独立代码工作。只能依据既定分类裁定处理完整、身份一致、明确目标及退出/日志/清理已知的fixture，未知/失败/marker不足不算blocked。误判的代价是分类层返工，不能用fixture填补实际运行时验收。

允许复用既有固定代码测试harness，新增唯一固定matrix-code模式和字面Go目标`./attacks/matrix`；保持UID1000、capless、network none、只读源码、固定cached Go1.26.10、2GB memory=swap/CPU2/PIDs256及全部既有边界，计入额外1GB host allowance。没有任意命令、路径或正则输入；不执行shell/攻击、加载真实Runtime、连接daemon里的tenant或构建guest。不引入新依赖、不安装下载。每次测试前仍须全项目＋Q＋自有镜像＋512MB allowance通过12GB，内存总额≤16GB。

先真实RED/GREEN，源码先提交，最终已提交源码做一次有限覆盖，再归档证据；独立spec/quality审查仍必需。所有测试数据标明fixture/子agent来源，不冒充真人或真实隔离结果。原现场、所有协调证据、Q、五轮上限和不push/发布限制保持。此裁定不释放Q、不授权新VM或宿主k3s/iptables修改。
