# Scheduler first-review fixes

Implementation `ea41312035b38207f6e2aa3215a5e8d104178a7e` addresses both Important findings in [the independent first review](../review-initial.md). The late reader now has an explicit cleanup ownership handoff. A new real-PG regression actually materializes a resource after the initial absent Reap, then recovers it through new gate/worker instances while preserving creation uncertainty.

[Full fix report](report.md) documents the change, deterministic RED→GREEN, delayed-creation behavior and remaining boundaries. [Verification manifest](verification.json) records source SHA, commands and log hashes. Normal and race suites pass 55 top-level entries / 68 including subcases, no SKIP; vet and exact PG fixture cleanup pass.

This round is ready for independent re-review, not Task 2 acceptance. The candidate-window Minor remains deferred; actual API→runc and original-daemon quiescence/reconciliation remain required integration work. Production auth remains fail closed.
