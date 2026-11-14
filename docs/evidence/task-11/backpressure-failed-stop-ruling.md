# Task11 唯一背压运行失败后的停止裁定

ROOT全文读取19033B最终报告和原始失败输出，并定向读取metrics417/418。唯一实际ea8359/session34528→80abc5 known exit1；本次Vector child_return0、peer_joinedtrue。stage0/disk/bp_http采样为buffer_byte_size=-16616、buffer_events=-1，前序峰值134207432低于原260000000判据。失败时accepted31077/received31076；差1不是最终丢失证明，未完成32320对账也不是零丢失证明。负值成因未证实，不能直接归因某个Vector内部缺陷。

本批停止，不钳制负数、改阈值、延长突发/drain、换版本或重试。三个driver/config/sh工作区文件保持原字节和0664模式，精确inert副本已提交为证据。27golden和两次独立静态validate的PASS保留，整个Task11的10x验收仍OPEN。

精确剩余阻塞：唯一实际没有产出满足原条件的可采信“高占用＋对齐连续阻塞＋32320完整ID”证据。指标含负值，失败分支未留完整phase_counts、ACK区间和seen位图；现有数据不能补造这些历史事实。SOURCE337faf6只提交18个已验证mapping/static文件，EVIDENCE0beb321保留完整失败。独立审查尚未结束，此处不接受整个组件或任务。

最小未应用诊断差异：在既有failure emit中增加下列有界字段，既有成功谓词全部不改。它不能将旧运行修成PASS，也不授权再次执行。

```python
# Unapplied extra keyword arguments in the existing failure emit:
stalls=stalls[-64:], phase_counts=phase_counts,
attempted_events=attempted, actual_write_bytes=write_bytes,
received_bitmap_hex=seen.hex(), buffer_allocated_peak=max_allocated,
ack_window_violation=state['ack_window_violation'],
last_ack_before_interval=state['last_ack_before_interval'],
first_ack_after_interval=state['first_ack_after_interval'],
discard_series_seen=bool(counter)
```

固定32320B位图编码为64640字符，加64条末尾区间和固定计数仍须在原输出上限内。若今后考虑恢复，须先解释原指标/填充证据缺口、独立复核准确差异并按原资源/时限fresh准入；本说明不自动授予重试。当前不应用差异或执行更多背压实验，转原Task12的独立只读规则/依赖方案，无SOURCE/安装/容器或云权限。

原Task6五轮与额外material/六目标失败额度、actual CLOSED、Task16工作区和旧native UNKNOWN、Q5GB/现场、Azure6美元/磁盘12GB/内存16GB/宿主隔离/禁公开发布全部保持。新证据保留，Goal active、未完成。
