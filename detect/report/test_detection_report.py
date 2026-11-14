"""Tests for the detection coverage page, on the synthetic metrics fixtures."""

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

from detect.report import detection_metrics as metrics
from detect.report import detection_report as report


FIXTURES = Path(__file__).parent / "fixtures" / "metrics"
CUTOFF = "2026-01-01T00:01:00Z"


def fixture_report(**normal):
    return metrics.compute_metrics(metrics.read_jsonl(str(FIXTURES / "executions.jsonl")),
                                   metrics.read_jsonl(str(FIXTURES / "alerts.jsonl")), CUTOFF, **normal)


class DetectionReportTests(unittest.TestCase):
    def test_fixture_page(self):
        page = report.render(fixture_report())
        for line in ("| Successful executions | 2 | 3 | 66.7% |",
                     "| Techniques with a successful execution | 2 | 3 | 66.7% |",
                     "p50 2.000 s, p95 9.000 s.",
                     "No normal-operation window was supplied, so there is no false-positive count.",
                     "Observed until 2026-01-01T00:01:00.000000Z"):
            self.assertIn(line, page)
        self.assertEqual(page.count("\n| `"), 3)

    def test_normal_window(self):
        normal = [{"alert_id": "n1", "rule_id": "r", "alerted_at": "2026-01-02T00:00:00Z", "disposition": "false_positive"},
                  {"alert_id": "n2", "rule_id": "r", "alerted_at": "2026-01-03T00:00:00Z", "disposition": "unreviewed"}]
        page = report.render(metrics.compute_metrics([], [], "2026-01-09T00:00:00Z", normal_alerts=normal,
                                                     normal_start="2026-01-01T00:00:00Z", normal_end="2026-01-08T00:00:00Z"))
        self.assertIn("(7.00 days; at least seven days)", page)
        self.assertIn("| 1 | 0 | 1 | 2 |", page)
        self.assertIn("No successful execution was detected", page)
        self.assertIn("| Successful executions | 0 | 0 | – |", page)

    def test_scope_notes(self):
        notes = ["One successful execution (n=1).", "Rule map: every stock rule."]
        page = report.render(fixture_report(), notes)
        self.assertIn("## Scope\n\n- One successful execution (n=1).\n- Rule map: every stock rule.\n", page)
        self.assertLess(page.index("## Scope"), page.index("## Detection rate"))
        self.assertNotIn("## Scope", report.render(fixture_report()))
        with self.assertRaises(report.ReportError):
            report.render(fixture_report(), [" "])
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "metrics.json", Path(tmp) / "page.md"
            source.write_text(json.dumps(fixture_report()))
            argv = ["--metrics", str(source), "--out", str(out)]
            for note in notes:
                argv += ["--note", note]
            self.assertEqual(report.main(argv), 0)
            self.assertEqual(out.read_text(), report.render(fixture_report(), notes))

    def test_rejects_other_input(self):
        for bad in ({}, [], {**fixture_report(), "scope": "other"}):
            with self.assertRaises(report.ReportError):
                report.render(bad)

    def test_cli_writes_the_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "metrics.json", Path(tmp) / "page.md"
            source.write_text(json.dumps(fixture_report()))
            self.assertEqual(report.main(["--metrics", str(source), "--out", str(out)]), 0)
            self.assertEqual(out.read_text(), report.render(fixture_report()))
            source.write_text("{")
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(report.main(["--metrics", str(source), "--out", str(out)]), 2)
            self.assertIn("error:", err.getvalue())
            self.assertEqual(out.read_text(), report.render(fixture_report()))


if __name__ == "__main__":
    unittest.main()
