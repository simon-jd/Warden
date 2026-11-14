# Task 13 metrics component implementation report

## Status and scope

Task 13 and the overall Goal remain **OPEN**. This batch implements the required bounded detection metrics component and its supplied normal-window annotation helper. It does not supply real emulation, detector integration, continuous normal-operation coverage, or seven-day ground truth. No detection-coverage.md artifact or attack runner was created. Independent Spec and Quality review remain for root after this handback; this self-review does not replace them.

The implementation subagent read the exact Task 13 brief first at .superpowers/sdd/2-warden-security-plan/task-13-brief.md and then docs/evidence/task-13/metrics-implementation-ruling.md. There was no whole-plan/history crawl. Root explicitly handed off scoped source/Git/index ownership at BASE **31074496b5ba320a86466f07b838c57359444dd0**. Source commit is **8b6555c5e191877d81660a675242af7319d141cf**, subject **detect: correlate emulation events and detection latency**. The original whole-Task13 commit subject remains reserved.

This report is append-only from its initial creation and has an exact public mirror at docs/evidence/task-13/metrics-substage-report.md. The separate evidence commit follows the source commit. Evidence-commit identity is reported in the final handback, avoiding a self-referential report hash.

## Exact source files and interfaces

Only five source/test/fixture files were added:

- detect/report/detection_metrics.py: import-safe stdlib module, exact timestamp parser, validation, correlation/metrics computation, normal-window helper, bounded JSONL reader, argparse CLI.
- detect/report/test_detection_metrics.py: 15 focused pure-stdlib unittest methods with bounded data tables and owned temporary files.
- detect/report/fixtures/metrics/executions.jsonl: three synthetic successful executions with three distinct technique IDs.
- detect/report/fixtures/metrics/alerts.jsonl: two synthetic explicitly correlated alerts.
- detect/report/fixtures/metrics/README.md: full record/output semantics, bounds, CLI example and honest synthetic-fixture labels.

Public functions: compute_metrics(executions, alerts, observed_until, *, normal_alerts=None, normal_start=None, normal_end=None); normal_window_metrics(alerts=None, start=None, end=None); read_jsonl(path); timestamp_ns(value); main(argv=None). MetricsError subclasses ValueError. No package/dependency files changed.

CLI requires --executions, --alerts and --observed-until, with optional --normal-alerts/--normal-start/--normal-end supplied together. Paths are explicit; there is no stdin/default path discovery/network behavior. Invalid data returns 2, emits a concise stderr error and prints no partial report; argparse retains its ordinary syntax-error behavior. Successful output is deterministic JSON.

## Implemented decisions

Execution dictionaries require exactly execution_id, run_id, technique_id, executed_at, outcome. Outcomes are exactly succeeded/failed/skipped. Alert dictionaries require exactly alert_id, execution_id, rule_id, alerted_at. All IDs are nonblank UTF-8 strings of at most 256 bytes. Technique validation is ASCII syntax Tdddd or Tdddd.ddd, without catalog authenticity claims. Non-string IDs, malformed dates, missing/unknown fields, nonfinite values and unknown outcomes are errors.

Every identity includes every original record field. Identical repeated IDs deduplicate; conflicting duplicates error, including changes to run, technique, outcome, time spelling or alert rule/correlation/time. No input is mutated. Explicit execution_id correlation is required; unknown executions and alerts earlier than their execution error. No date/technique proximity guesses are made.

RFC3339 timestamps have Z or a numeric offset and 0–9 fractional digits. Lowercase t/z are accepted per RFC3339. Integer nanoseconds normalize offsets exactly; no float conversion is used in timestamp arithmetic. Report timestamp origin is explicitly 0001-01-01T00:00:00Z. UTC dates outside years 1–9999, invalid dates/times, naive dates, excessive fractional digits and leap seconds error. The explicit observed-until cutoff is required; no clock is read. All supplied execution/alert timestamps must be at or before it.

Only successful executions enter the execution detection denominator; only techniques with at least one successful execution enter the unique-technique denominator. Both rates retain numerator and denominator. Each successful execution uses its earliest correlated alert, with alert ID breaking equal-time ties deterministically. Additional unique alerts do not multiply detections/latency samples. Failed/skipped rows have no successful detection or latency; their alert count is exposed separately. Technique rows include successful/detected/failed/skipped counts, detected flag and minimum successful latency. Execution rows expose observation duration and not_detected_by_cutoff status; undetected outcomes are right-censored, never permanent misses.

p50/p95 use nearest rank ceil(p*n) over first latencies of detected successful executions only. Zero latency is valid. Empty percentiles/rates are null with sample counts/denominators; missing detections never supply zero latency. Output ordering is stable across input order.

Normal annotations require exactly alert_id, rule_id, alerted_at, disposition, with dispositions false_positive/true_positive/unreviewed. Full identical records deduplicate and conflicts error. All annotations must fall in explicit [start,end), with start < end. Output separately counts each disposition and reports exact span and whether it reaches seven days. It always states coverage_verified=false and that supplied endpoints/labels require external validation for continuous coverage and ground truth. Absent input is unavailable, with no invented false-positive zero. Normal windows are separately supplied and do not inherit the emulation cutoff.

Reader bounds apply before JSON decode: each regular file <=16 MiB, each nonempty record <=65,536 bytes excluding its LF delimiter, each input <=100,000 records before deduplication. readline is capped at record limit+2 to distinguish the optional LF and overlong records. Regular-file checks reject symlinks/directories/special files; open uses O_NOFOLLOW/O_NONBLOCK and the opened descriptor is checked again. Bytes and record count are bounded while reading as well as using the initial file-size check. Blank lines, invalid UTF-8, trailing JSON content, duplicate object keys (including nested objects), nonfinite constants/overflowed numbers, and non-object JSONL records are rejected. There is no new trust/provenance loader or external authentication assertion.

## TDD, freeze and verification

The initial importable/compilable skeleton performed no I/O and returned {}. The real test_metrics_on_fixture assertion expected execution rate numerator=2, denominator=3 and rate=2/3; it failed with AssertionError, exit 1. This was genuine business-assertion RED, separate from the earlier missing-directory setup diagnostic.

Implementation and full tables were then written. Initial source freeze recorded module SHA256 f5531dab33b4f76a761ddda223863e21161764afa56ebbb29192b2fe6fc16cbd and test SHA256 77db8032af4a8cf425026f96d2270e15c98a89f00aac4716aa4fc89c3834d28d. The first post-freeze 15-test suite returned exit 1: the reader accepted a deeply nested JSON array, while the reader test required an object record. The other 14 methods passed. This was an ordinary behavior failure, not infrastructure or an unknown live handle.

The affected reader was corrected to reject non-object JSONL records. Decode was also made explicit about finite float numbers, with a 1e999 test case. Source/tests were frozen again before the final affected suite. That final run passed all 15 methods in 0.003 seconds, exit 0, with no session ID and no polling. There were no automatic approval rejections, timeout/kill events, unexpected infrastructure failures, live-handle unknowns or repeat tests after this pass. No source/test/fixture files changed after the final freeze.

Exact final source freeze SHA256:

| New file | SHA256 |
| --- | --- |
| detect/report/detection_metrics.py | cb47d4bfee84572e13fae778500999889edac6909db5b4f29eea520dcfab1ee3 |
| detect/report/test_detection_metrics.py | 6c214419a6fea1ab1db1421461030dc08a9132c4bcd2085d3437bb7cdc8378cb |
| detect/report/fixtures/metrics/README.md | ac4cd62ad753de5d11e9d7eee092b7ae9080fff6868fe29014181c52f32200bc |
| detect/report/fixtures/metrics/executions.jsonl | d860670353d77f0dee374a28f7c8bc768f498403eb0e083b382bd61b7d127549 |
| detect/report/fixtures/metrics/alerts.jsonl | 606af9f7c388d628050824aaa5036b7b4b011917f113e6aecfe13c280ec6119b |

Every actual test command used clean env, fixed project cwd, /bin/bash with login=false/tty=false, CPU20 seconds, address space262144KiB, FSIZE2048KiB, timeout TERM45s/kill-after3s and /usr/bin/python3 -B -m unittest discover -s detect/report -p test_detection_metrics.py -v. UID was verified as1000 before the tests. require_escalated, initial yield1000 and max_output_tokens6000 were used as authorized. Original tool requests were stored before await; full original returned objects and actual combined stdout/stderr are retained. The tool exposed only a combined output field, not separate stdout/stderr streams. No metadata wrapper, child terminal, recorder process or workaround was executed.

The 15 methods cover required fixture rates2/3 and exact2s/9s latencies; dedup and input-order/no-mutation behavior; all execution identity fields and alert conflicts; failed/skipped denominators; unknown/missing correlation and negative latency; future/naive/invalid/overflowing timestamps; offset/nanosecond arithmetic; empty/zero-latency/cutoff censor cases; 20-sample nearest-rank p50/p95 and technique minimum; strict field/type/UTF-8-byte ID/technique tables; normal dispositions/duplicates/window endpoints/seven-day threshold/unavailable behavior; strict JSONL/actual record-byte boundary; caps/regular-file/symlink behavior; and in-process deterministic/error/normal CLI paths.

To stay below the fixed2MiB FSIZE bound, only file-byte/count constants are temporarily lowered inside two boundary tests using unittest.mock.patch.object; actual small regular files and real reader/computation branches run. No function/output behavior is mocked. Tests assert the actual16MiB/100000 constants. The record-byte test uses the real65536-byte limit. The suite does not allocate a16MiB on-disk file or100000-record dataset, and makes no claim that it did.

## Raw evidence and all failures

docs/evidence/task-13/metrics-tool-evidence.json retains complete exposed test/freeze request/return objects, the importable RED skeleton text, the setup failure, and both freeze identities. docs/evidence/task-13/metrics-git-tool-evidence.json retains exact source staging/commit request/returns. The appendix below repeats full test/freeze request/return values so this report is self-contained.

## Source/index hygiene and self-review

Source staging named only the five new paths explicitly. git diff --cached --check passed; staged names/stat showed only those five paths (544 inserted lines). The source commit contains exactly them. Evidence staging is likewise restricted to the new Task13 report/raw-evidence paths. The private plan report is mirrored exactly in the public report; neither edits any historical report.

Existing scripts/firecracker_code.py and vuln/ were never written, formatted, reset, staged or executed. No old-file hash inventory was taken. Only hashes of this tiny new source scope were taken. A read-only current diff showed the existing literal vuln-unit extension in the script. No action was taken to verify those unrelated Task16 files.

While this subagent held scoped source/index ownership, root independently created docs/evidence/azure-budget/reaper-task13-start-20261025.json and added five coordination-only lines in docs/COORDINATOR-SIX-MODE-METADATA-20261025.txt. Root acknowledged these as its own out-of-scope work and explicitly updated handoff to permit these two extra unstaged paths. Neither is staged by this subagent. Task16 paths remain unstaged. No six-mode work was performed here.

Self-review found no unresolved implementation failure after the ordinary reader correction. Meaningful limitations remain: user-supplied data has no authenticated provenance; technique IDs are syntactic; metrics cannot validate an emulator/detector; normal annotation labels/endpoints do not verify coverage or ground truth; original Task13 runtime/normal-evidence acceptance is still outstanding. Root must independently review BASE..HEAD after reading this full report. No subagents or reviewer children were spawned by this implementation subagent.

No Go, Docker, emulator, cloud, network, service, proc scan, private/cache scene, attack, GPU, Task6 implementation, Task16 execution, terminal recovery or resource-threshold workaround occurred. Existing native descendant unknowns and all earlier gate/terminal/eligibility constraints remain unchanged. Azure budget/own-RG/TTL/protected-RG, disk/resident/GPU and publication/no-sudo constraints remain intact. No source publication/push or destructive response occurred.

## Remaining original Task13 acceptance

Real authorized emulation across the required platforms/corpus, detector integration, genuine detection-rate/latency reporting from those runs, and seven days of verified normal-operation false-positive evidence remain open. Stratus/Atomic/Task5 execution dependencies remain unimplemented/unaccepted here. This synthetic fixture suite cannot substitute for them. Whole Task13 and the Goal remain OPEN.

## Exact test/freeze tool appendix

### task13_red

```json
{
  "request": {
    "cmd": "env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /bin/bash --noprofile --norc -c 'ulimit -t 20; ulimit -v 262144; ulimit -f 2048; exec timeout --signal=TERM --kill-after=3s 45s /usr/bin/python3 -B -m unittest discover -s detect/report -p test_detection_metrics.py -v'",
    "workdir": "/home/postedism/Desktop/Warden",
    "shell": "/bin/bash",
    "login": false,
    "tty": false,
    "sandbox_permissions": "require_escalated",
    "justification": "Run the authorized Task13 bounded pure-stdlib fixture RED test as UID 1000.",
    "yield_time_ms": 1000,
    "max_output_tokens": 6000
  },
  "return": {
    "chunk_id": "376d11",
    "wall_time_seconds": 0.000012346,
    "exit_code": 1,
    "original_token_count": 225,
    "output": "test_metrics_on_fixture (test_detection_metrics.MetricsTests.test_metrics_on_fixture) ... FAIL\n\n======================================================================\nFAIL: test_metrics_on_fixture (test_detection_metrics.MetricsTests.test_metrics_on_fixture)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/postedism/Desktop/Warden/detect/report/test_detection_metrics.py\", line 18, in test_metrics_on_fixture\n    self.assertEqual(report.get(\"execution_detection\"), {\"numerator\": 2, \"denominator\": 3, \"rate\": 2 / 3})\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: None != {'numerator': 2, 'denominator': 3, 'rate': 0.6666666666666666}\n\n----------------------------------------------------------------------\nRan 1 test in 0.000s\n\nFAILED (failures=1)\n"
  }
}
```

### task13_green

```json
{
  "request": {
    "cmd": "env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /bin/bash --noprofile --norc -c 'ulimit -t 20; ulimit -v 262144; ulimit -f 2048; exec timeout --signal=TERM --kill-after=3s 45s /usr/bin/python3 -B -m unittest discover -s detect/report -p test_detection_metrics.py -v'",
    "workdir": "/home/postedism/Desktop/Warden",
    "shell": "/bin/bash",
    "login": false,
    "tty": false,
    "sandbox_permissions": "require_escalated",
    "justification": "Run the authorized Task13 bounded pure-stdlib tests against the frozen metrics source as UID 1000.",
    "yield_time_ms": 1000,
    "max_output_tokens": 6000
  },
  "return": {
    "chunk_id": "4dac25",
    "wall_time_seconds": 0.000008233,
    "exit_code": 1,
    "original_token_count": 799,
    "output": "test_cli_in_process_deterministic_json_and_no_partial_output (test_detection_metrics.MetricsTests.test_cli_in_process_deterministic_json_and_no_partial_output) ... ok\ntest_conflicting_id_includes_every_execution_field (test_detection_metrics.MetricsTests.test_conflicting_id_includes_every_execution_field) ... ok\ntest_correlation_is_mandatory_and_nonnegative (test_detection_metrics.MetricsTests.test_correlation_is_mandatory_and_nonnegative) ... ok\ntest_empty_zero_latency_and_censor_at_cutoff (test_detection_metrics.MetricsTests.test_empty_zero_latency_and_censor_at_cutoff) ... ok\ntest_failed_skipped_and_repeated_techniques (test_detection_metrics.MetricsTests.test_failed_skipped_and_repeated_techniques) ... ok\ntest_ingestion_file_and_count_caps_with_owned_small_files (test_detection_metrics.MetricsTests.test_ingestion_file_and_count_caps_with_owned_small_files) ... ok\ntest_invalid_normal_annotations_window_and_options (test_detection_metrics.MetricsTests.test_invalid_normal_annotations_window_and_options) ... ok\ntest_invalid_timestamps (test_detection_metrics.MetricsTests.test_invalid_timestamps) ... ok\ntest_jsonl_strict_decoding_and_real_record_byte_bound (test_detection_metrics.MetricsTests.test_jsonl_strict_decoding_and_real_record_byte_bound) ... \n  test_jsonl_strict_decoding_and_real_record_byte_bound (test_detection_metrics.MetricsTests.test_jsonl_strict_decoding_and_real_record_byte_bound) (payload=b'[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[') ... FAIL\ntest_metrics_on_fixture (test_detection_metrics.MetricsTests.test_metrics_on_fixture) ... ok\ntest_nearest_rank_and_technique_minimum (test_detection_metrics.MetricsTests.test_nearest_rank_and_technique_minimum) ... ok\ntest_normal_annotations_deduplicate_without_claiming_coverage (test_detection_metrics.MetricsTests.test_normal_annotations_deduplicate_without_claiming_coverage) ... ok\ntest_offsets_and_nanoseconds_without_float_rounding (test_detection_metrics.MetricsTests.test_offsets_and_nanoseconds_without_float_rounding) ... ok\ntest_order_deduplication_no_mutation_and_first_alert (test_detection_metrics.MetricsTests.test_order_deduplication_no_mutation_and_first_alert) ... ok\ntest_strict_record_fields_types_ids_and_techniques (test_detection_metrics.MetricsTests.test_strict_record_fields_types_ids_and_techniques) ... ok\n\n======================================================================\nFAIL: test_jsonl_strict_decoding_and_real_record_byte_bound (test_detection_metrics.MetricsTests.test_jsonl_strict_decoding_and_real_record_byte_bound) (payload=b'[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[')\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/postedism/Desktop/Warden/detect/report/test_detection_metrics.py\", line 164, in test_jsonl_strict_decoding_and_real_record_byte_bound\n    with self.subTest(payload=payload[:50]), self.assertRaises(metrics.MetricsError):\n                                             ~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: MetricsError not raised\n\n----------------------------------------------------------------------\nRan 15 tests in 0.004s\n\nFAILED (failures=1)\n"
  }
}
```

### task13_freeze

```json
{
  "request": {
    "cmd": "sha256sum detect/report/detection_metrics.py detect/report/test_detection_metrics.py detect/report/fixtures/metrics/README.md detect/report/fixtures/metrics/executions.jsonl detect/report/fixtures/metrics/alerts.jsonl",
    "max_output_tokens": 6000
  },
  "return": {
    "chunk_id": "657a55",
    "wall_time_seconds": 0.00001348,
    "exit_code": 0,
    "original_token_count": 135,
    "output": "cb47d4bfee84572e13fae778500999889edac6909db5b4f29eea520dcfab1ee3  detect/report/detection_metrics.py\n6c214419a6fea1ab1db1421461030dc08a9132c4bcd2085d3437bb7cdc8378cb  detect/report/test_detection_metrics.py\nac4cd62ad753de5d11e9d7eee092b7ae9080fff6868fe29014181c52f32200bc  detect/report/fixtures/metrics/README.md\nd860670353d77f0dee374a28f7c8bc768f498403eb0e083b382bd61b7d127549  detect/report/fixtures/metrics/executions.jsonl\n606af9f7c388d628050824aaa5036b7b4b011917f113e6aecfe13c280ec6119b  detect/report/fixtures/metrics/alerts.jsonl\n"
  }
}
```

### task13_final_green

```json
{
  "request": {
    "cmd": "env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /bin/bash --noprofile --norc -c 'ulimit -t 20; ulimit -v 262144; ulimit -f 2048; exec timeout --signal=TERM --kill-after=3s 45s /usr/bin/python3 -B -m unittest discover -s detect/report -p test_detection_metrics.py -v'",
    "workdir": "/home/postedism/Desktop/Warden",
    "shell": "/bin/bash",
    "login": false,
    "tty": false,
    "sandbox_permissions": "require_escalated",
    "justification": "Run the authorized affected Task13 stdlib suite after ordinary ingestion behavior fixes and renewed source freeze, as UID 1000.",
    "yield_time_ms": 1000,
    "max_output_tokens": 6000
  },
  "return": {
    "chunk_id": "fda152",
    "wall_time_seconds": 0.000008796,
    "exit_code": 0,
    "original_token_count": 552,
    "output": "test_cli_in_process_deterministic_json_and_no_partial_output (test_detection_metrics.MetricsTests.test_cli_in_process_deterministic_json_and_no_partial_output) ... ok\ntest_conflicting_id_includes_every_execution_field (test_detection_metrics.MetricsTests.test_conflicting_id_includes_every_execution_field) ... ok\ntest_correlation_is_mandatory_and_nonnegative (test_detection_metrics.MetricsTests.test_correlation_is_mandatory_and_nonnegative) ... ok\ntest_empty_zero_latency_and_censor_at_cutoff (test_detection_metrics.MetricsTests.test_empty_zero_latency_and_censor_at_cutoff) ... ok\ntest_failed_skipped_and_repeated_techniques (test_detection_metrics.MetricsTests.test_failed_skipped_and_repeated_techniques) ... ok\ntest_ingestion_file_and_count_caps_with_owned_small_files (test_detection_metrics.MetricsTests.test_ingestion_file_and_count_caps_with_owned_small_files) ... ok\ntest_invalid_normal_annotations_window_and_options (test_detection_metrics.MetricsTests.test_invalid_normal_annotations_window_and_options) ... ok\ntest_invalid_timestamps (test_detection_metrics.MetricsTests.test_invalid_timestamps) ... ok\ntest_jsonl_strict_decoding_and_real_record_byte_bound (test_detection_metrics.MetricsTests.test_jsonl_strict_decoding_and_real_record_byte_bound) ... ok\ntest_metrics_on_fixture (test_detection_metrics.MetricsTests.test_metrics_on_fixture) ... ok\ntest_nearest_rank_and_technique_minimum (test_detection_metrics.MetricsTests.test_nearest_rank_and_technique_minimum) ... ok\ntest_normal_annotations_deduplicate_without_claiming_coverage (test_detection_metrics.MetricsTests.test_normal_annotations_deduplicate_without_claiming_coverage) ... ok\ntest_offsets_and_nanoseconds_without_float_rounding (test_detection_metrics.MetricsTests.test_offsets_and_nanoseconds_without_float_rounding) ... ok\ntest_order_deduplication_no_mutation_and_first_alert (test_detection_metrics.MetricsTests.test_order_deduplication_no_mutation_and_first_alert) ... ok\ntest_strict_record_fields_types_ids_and_techniques (test_detection_metrics.MetricsTests.test_strict_record_fields_types_ids_and_techniques) ... ok\n\n----------------------------------------------------------------------\nRan 15 tests in 0.003s\n\nOK\n"
  }
}
```

## Append-only authoring correction

The Handoff detail addition used an insufficiently specific code-fence anchor and was inserted after the earlier setup-output fence rather than at end of file. All original report content was preserved; nothing was removed. This correction is appended at the end. The optional-path diagnostic output string in that addition uses literal escaped line breaks; the original tool output used newline bytes, so interpret those \\n sequences as newlines. Original retained test/freeze/source-Git request/return objects are unchanged and preserve their actual output strings.
