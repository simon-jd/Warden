"""Pure stdlib tests; all fixtures are synthetic inputs."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from detect.report import detection_metrics as metrics


FIXTURES = Path(__file__).parent / "fixtures" / "metrics"
CUTOFF = "2026-01-01T00:01:00Z"


def execution(execution_id="e", technique_id="T1001", outcome="succeeded", executed_at="2026-01-01T00:00:00Z"):
    return dict(execution_id=execution_id, run_id="synthetic-run", technique_id=technique_id,
                outcome=outcome, executed_at=executed_at)


def alert(alert_id="a", execution_id="e", alerted_at="2026-01-01T00:00:02Z"):
    return dict(alert_id=alert_id, execution_id=execution_id, rule_id="synthetic-rule", alerted_at=alerted_at)


def normal(alert_id="n", alerted_at="2026-01-01T00:00:00Z", disposition="false_positive"):
    return dict(alert_id=alert_id, rule_id="synthetic-rule", alerted_at=alerted_at, disposition=disposition)


class MetricsTests(unittest.TestCase):
    def test_metrics_on_fixture(self):
        executions = [json.loads(line) for line in (FIXTURES / "executions.jsonl").read_text().splitlines()]
        alerts = [json.loads(line) for line in (FIXTURES / "alerts.jsonl").read_text().splitlines()]
        report = metrics.compute_metrics(executions, alerts, "2026-01-01T00:01:00Z")
        self.assertEqual(report.get("execution_detection"), {"numerator": 2, "denominator": 3, "rate": 2 / 3})
        self.assertEqual(report["technique_detection"], {"numerator": 2, "denominator": 3, "rate": 2 / 3})
        self.assertEqual([row["latency_ns"] for row in report["executions"]], [2_000_000_000, 9_000_000_000, None])
        self.assertEqual(report["latency_ns"], {"sample_count": 2, "method": "nearest-rank", "p50": 2_000_000_000, "p95": 9_000_000_000})

    def test_order_deduplication_no_mutation_and_first_alert(self):
        executions = [execution("z"), execution(), execution()]
        alerts = [alert("late", alerted_at="2026-01-01T00:00:05Z"), alert(), alert()]
        original = deepcopy((executions, alerts))
        report = metrics.compute_metrics(executions, alerts, CUTOFF)
        self.assertEqual(report, metrics.compute_metrics(executions[::-1], alerts[::-1], CUTOFF))
        self.assertEqual((executions, alerts), original)
        self.assertEqual((report["execution_count"], report["alert_count"]), (2, 2))
        self.assertEqual(report["executions"][0]["latency_ns"], 2_000_000_000)
        self.assertEqual(report["executions"][0]["alert_ids"], ["a", "late"])
        self.assertEqual(report["latency_ns"]["sample_count"], 1)

    def test_conflicting_id_includes_every_execution_field(self):
        for field, changed in (("run_id", "other"), ("technique_id", "T1002"), ("outcome", "failed"),
                               ("executed_at", "2026-01-01T00:00:01Z")):
            with self.subTest(field=field), self.assertRaises(metrics.MetricsError):
                metrics.compute_metrics([execution(), dict(execution(), **{field: changed})], [], CUTOFF)
        for changed in (dict(alert(), rule_id="other"), dict(alert(), execution_id="other"),
                        dict(alert(), alerted_at="2026-01-01T00:00:03Z")):
            with self.subTest(alert=changed), self.assertRaises(metrics.MetricsError):
                metrics.compute_metrics([execution()], [alert(), changed], CUTOFF)

    def test_failed_skipped_and_repeated_techniques(self):
        executions = [execution(), execution("e2"), execution("f", "T1002", "failed"), execution("s", "T1003", "skipped")]
        report = metrics.compute_metrics(executions, [alert(), alert("af", "f"), alert("as", "s")], CUTOFF)
        self.assertEqual(report["execution_detection"], dict(numerator=1, denominator=2, rate=0.5))
        self.assertEqual(report["technique_detection"], dict(numerator=1, denominator=1, rate=1.0))
        self.assertEqual(report["alerts_on_failed_or_skipped_executions"], 2)
        self.assertEqual([r["detected"] for r in report["executions"]], [True, False, None, None])
        self.assertEqual(report["techniques"][0]["successful_executions"], 2)

    def test_correlation_is_mandatory_and_nonnegative(self):
        for bad in (alert(execution_id="unknown"), alert(alerted_at="2025-12-31T23:59:59Z"),
                    {key: value for key, value in alert().items() if key != "execution_id"}):
            with self.subTest(alert=bad), self.assertRaises(metrics.MetricsError):
                metrics.compute_metrics([execution()], [bad], CUTOFF)

    def test_invalid_timestamps(self):
        invalid = ["2026-01-01T00:00:00", "2026-02-30T00:00:00Z", "2026-01-01T00:00:60Z",
                   "2026-01-01T24:00:00Z", "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+00:60",
                   "0000-01-01T00:00:00Z", "0001-01-01T00:00:00+00:01", "9999-12-31T23:59:59-00:01",
                   "2026-01-01T00:00:00.1234567890Z", "2026-01-01T00:00:00.Z", 1, True, None]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(metrics.MetricsError):
                metrics.timestamp_ns(value)
        for executions, alerts in (([execution(executed_at="2026-01-01T00:02:00Z")], []),
                                   ([execution()], [alert(alerted_at="2026-01-01T00:02:00Z")])):
            with self.subTest(future=(executions, alerts)), self.assertRaises(metrics.MetricsError):
                metrics.compute_metrics(executions, alerts, CUTOFF)

    def test_offsets_and_nanoseconds_without_float_rounding(self):
        start = "2026-01-01T01:00:00.123456789+01:00"
        end = "2025-12-31T19:00:00.123456790-05:00"
        self.assertEqual(metrics.timestamp_ns(start), metrics.timestamp_ns("2026-01-01T00:00:00.123456789Z"))
        report = metrics.compute_metrics([execution(executed_at=start)], [alert(alerted_at=end)], CUTOFF)
        self.assertEqual(report["executions"][0]["latency_ns"], 1)
        self.assertEqual(metrics.timestamp_ns("0001-01-01T00:00:00Z"), 0)

    def test_empty_zero_latency_and_censor_at_cutoff(self):
        report = metrics.compute_metrics([], [], CUTOFF)
        self.assertEqual(report["execution_detection"], dict(numerator=0, denominator=0, rate=None))
        self.assertEqual(report["technique_detection"], report["execution_detection"])
        self.assertIsNone(report["latency_ns"]["p50"])
        self.assertIsNone(report["latency_ns"]["p95"])
        report = metrics.compute_metrics([execution(executed_at=CUTOFF)], [alert(alerted_at=CUTOFF)], CUTOFF)
        self.assertEqual(report["latency_ns"]["p95"], 0)
        report = metrics.compute_metrics([execution(executed_at=CUTOFF)], [], CUTOFF)
        row = report["executions"][0]
        self.assertEqual((row["status"], row["observation_duration_ns"], row["latency_ns"]), ("not_detected_by_cutoff", 0, None))

    def test_nearest_rank_and_technique_minimum(self):
        executions = [execution(str(i)) for i in range(1, 21)]
        alerts = [alert(str(i), str(i), "2026-01-01T00:00:%02dZ" % i) for i in range(1, 21)]
        report = metrics.compute_metrics(executions, alerts, CUTOFF)
        self.assertEqual((report["latency_ns"]["p50"], report["latency_ns"]["p95"]), (10_000_000_000, 19_000_000_000))
        self.assertEqual(report["techniques"][0]["minimum_latency_ns"], 1_000_000_000)

    def test_strict_record_fields_types_ids_and_techniques(self):
        invalid = [[], dict(execution(), extra=1), dict(execution(), run_id=1), dict(execution(), run_id=True),
                   dict(execution(), run_id=""), dict(execution(), run_id=" "), dict(execution(), run_id="é" * 129),
                   dict(execution(), run_id="\ud800"), dict(execution(), technique_id="T100"),
                   dict(execution(), technique_id="T1000.01"), dict(execution(), technique_id="T１０００"),
                   dict(execution(), outcome="success"), dict(execution(), outcome=[]), dict(execution(), executed_at=float("inf"))]
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(metrics.MetricsError):
                metrics.compute_metrics([record], [], CUTOFF)
        self.assertEqual(metrics.compute_metrics([dict(execution(), run_id="é" * 128)], [], CUTOFF)["execution_count"], 1)

    def test_normal_annotations_deduplicate_without_claiming_coverage(self):
        records = [normal(), normal(), normal("tp", disposition="true_positive"), normal("u", disposition="unreviewed")]
        report = metrics.compute_metrics([], [], CUTOFF, normal_alerts=records,
                                         normal_start="2026-01-01T00:00:00Z", normal_end="2026-01-08T00:00:00Z")
        window = report["normal_window"]
        self.assertEqual(window["counts"], dict(false_positive=1, true_positive=1, unreviewed=1))
        self.assertEqual(window["alert_count"], 3)
        self.assertTrue(window["span_at_least_seven_days"])
        self.assertFalse(window["coverage_verified"])
        self.assertIn("external validation", window["limitation"])
        self.assertFalse(metrics.normal_window_metrics([], "2026-01-01T00:00:00Z", "2026-01-07T23:59:59.999999999Z")["span_at_least_seven_days"])
        unavailable = metrics.normal_window_metrics()
        self.assertFalse(unavailable["available"])
        self.assertNotIn("counts", unavailable)

    def test_invalid_normal_annotations_window_and_options(self):
        start, end = "2026-01-01T00:00:00Z", "2026-01-08T00:00:00Z"
        for records in ([normal(alerted_at=end)], [normal(alerted_at="2025-12-31T23:59:59Z")],
                        [normal(), normal(disposition="true_positive")], [normal(disposition="unknown")],
                        [dict(normal(), rule_id=1)], [dict(normal(), extra=1)]):
            with self.subTest(records=records), self.assertRaises(metrics.MetricsError):
                metrics.normal_window_metrics(records, start, end)
        for args in (([], None, end), (None, start, end), ([], start, None), ([], end, start), ([], start, start)):
            with self.subTest(args=args), self.assertRaises(metrics.MetricsError):
                metrics.normal_window_metrics(*args)

    def test_jsonl_strict_decoding_and_real_record_byte_bound(self):
        invalid = [b"\n", b" \n", b"{} {}\n", b"{\"a\":1,\"a\":2}\n", b"{\"a\":{\"b\":1,\"b\":2}}\n",
                   b"{\"a\":NaN}\n", b"{\"a\":Infinity}\n", b"{\"a\":-Infinity}\n", b"{\"a\":1e999}\n", b"\xff\n",
                   b"{}\n\n", b"[" * 1200 + b"]" * 1200, b" " * (metrics.MAX_RECORD_BYTES + 1)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.jsonl"
            for payload in invalid:
                path.write_bytes(payload)
                with self.subTest(payload=payload[:50]), self.assertRaises(metrics.MetricsError):
                    metrics.read_jsonl(path)
            path.write_bytes(b"{}" + b" " * (metrics.MAX_RECORD_BYTES - 2) + b"\n")
            self.assertEqual(metrics.read_jsonl(path), [{}])
            path.write_bytes(b"{}")
            self.assertEqual(metrics.read_jsonl(path), [{}])
            path.write_bytes(b"")
            self.assertEqual(metrics.read_jsonl(path), [])

    def test_ingestion_file_and_count_caps_with_owned_small_files(self):
        # Lower only constants to exercise the real read branches under FSIZE 2MiB.
        self.assertEqual((metrics.MAX_FILE_BYTES, metrics.MAX_RECORDS), (256 * 1024 * 1024, 1000000))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.jsonl"
            path.write_bytes(b"{}\n{}\n")
            with patch.object(metrics, "MAX_FILE_BYTES", 5), self.assertRaises(metrics.MetricsError):
                metrics.read_jsonl(path)
            with patch.object(metrics, "MAX_RECORDS", 1), self.assertRaises(metrics.MetricsError):
                metrics.read_jsonl(path)
            with patch.object(metrics, "MAX_RECORDS", 1), self.assertRaises(metrics.MetricsError):
                metrics.compute_metrics([execution(), execution("e2")], [], CUTOFF)
            link = Path(directory) / "link"
            link.symlink_to(path)
            for invalid in (link, Path(directory), Path(directory) / "missing"):
                with self.subTest(path=invalid), self.assertRaises(metrics.MetricsError):
                    metrics.read_jsonl(invalid)

    def test_cli_in_process_deterministic_json_and_no_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            executions, alerts, normals = (path / name for name in ("executions.jsonl", "alerts.jsonl", "normal.jsonl"))
            executions.write_text(json.dumps(execution()) + "\n", encoding="utf-8")
            alerts.write_text(json.dumps(alert()) + "\n", encoding="utf-8")
            normals.write_text(json.dumps(normal()) + "\n", encoding="utf-8")
            argv = ["--executions", str(executions), "--alerts", str(alerts), "--observed-until", CUTOFF]
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                result = metrics.main(argv)
            self.assertEqual((result, err.getvalue()), (0, ""))
            self.assertEqual(json.loads(out.getvalue()), metrics.compute_metrics([execution()], [alert()], CUTOFF))
            self.assertEqual(out.getvalue(), json.dumps(json.loads(out.getvalue()), sort_keys=True, separators=(",", ":")) + "\n")
            normal_options = ["--normal-alerts", str(normals), "--normal-start", "2026-01-01T00:00:00Z", "--normal-end", "2026-01-08T00:00:00Z"]
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(metrics.main(argv + normal_options), 0)
            self.assertEqual(json.loads(out.getvalue())["normal_window"]["counts"]["false_positive"], 1)
            for suffix in (["--normal-start", CUTOFF], ["--normal-alerts", str(normals)],
                           ["--normal-end", CUTOFF], normal_options[:-1] + ["bad"]):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    result = metrics.main(argv + suffix)
                self.assertEqual(result, 2)
                self.assertEqual(out.getvalue(), "")
                self.assertTrue(err.getvalue().startswith("error: "))
            alerts.write_text('{"alert_id":"a","alert_id":"b"}\n', encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                result = metrics.main(argv)
            self.assertEqual((result, out.getvalue()), (2, ""))
            self.assertIn("duplicate", err.getvalue())


if __name__ == "__main__":
    unittest.main()
