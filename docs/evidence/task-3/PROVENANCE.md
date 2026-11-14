# Binding substep：基线说明

原报告与manifest保持SHA绑定时的历史字节；其中“full base SHA在manifest”的措辞不准确。正确关系如下：

| 含义 | 提交 |
|---|---|
| 控制器派发BASE | c0ae3a0 |
| 其后插入的控制器文档提交、也是源码提交的直接parent | 2dc90459cb924c6ee78040460de72ec2950a8b8a |
| 实现源码 | f232b0d5e833e1060afa5df2533b2421ee714e2c |
| SHA绑定证据 | 88813cd |
| 独立审查完整范围 | c0ae3a0..88813cd |

2dc9045仅修改docs/STATUS.md与docs/evidence/plan-review.md。审查包包含全部三次提交，无实现差异遗漏。[控制器23个哈希核验](controller-verification.json)与[审查原文](review-binding.md)共同解释这一差别；原[报告副本](report.md)与scratch报告逐字一致，不改写原始SHA证据。

另外，五项原有runc socket测试失败祖先尚未定位；它们在gate调用前失败。完整suite未通过，不能将focused17和真实PG26写成全套通过。后续单独定位实际拒绝组件，保持目录信任检查不放宽。
