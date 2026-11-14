"""Render docs/evidence/detection-coverage.md from a detection_metrics.py report.

    python3 -B detect/report/detection_metrics.py --executions E --alerts A \\
        --observed-until T [--normal-alerts N --normal-start S --normal-end X] > metrics.json
    python3 -B detect/report/detection_report.py --metrics metrics.json \\
        --out docs/evidence/detection-coverage.md [--note TEXT ...]

The page states the detection rate, time to detect (p50/p95), the
false-positive count over the normal-operation window, and the per-technique
and per-execution rows behind them. It adds no numbers of its own. Each
--note becomes a line of a Scope section above the rate: what the cohort
is and is not (its size, the rule map, the runtimes covered), as the person
running it states it.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import tempfile

_ORIGIN = datetime(1, 1, 1, tzinfo=timezone.utc)
_REQUIRED = ("scope", "observed_until_ns", "execution_count", "alert_count", "execution_detection",
             "technique_detection", "latency_ns", "executions", "techniques", "normal_window", "limitations")


class ReportError(ValueError):
    """The input is not a detection_metrics.py report."""


def _time(ns):
    return (_ORIGIN + timedelta(microseconds=ns // 1000)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _seconds(ns):
    return "–" if ns is None else f"{ns / 1e9:.3f}"


def _rate(rate):
    if not rate["denominator"]:
        return f"| {rate['numerator']} | {rate['denominator']} | – |"
    return f"| {rate['numerator']} | {rate['denominator']} | {100 * rate['numerator'] / rate['denominator']:.1f}% |"


def _cell(value):
    text = "–" if value is None or value == "" else str(value)
    return " ".join(text.replace("|", "\\|").split())


def render(report, notes=()):
    """Return the markdown page for one metrics report, with optional scope notes."""
    if any(not isinstance(note, str) or not note.strip() for note in notes):
        raise ReportError("a scope note must be nonblank text")
    if not isinstance(report, dict) or any(key not in report for key in _REQUIRED):
        raise ReportError("not a detection_metrics.py report")
    if report["scope"] != "provided-cohort":
        raise ReportError("unexpected report scope " + repr(report["scope"]))
    latency, normal = report["latency_ns"], report["normal_window"]
    lines = [
        "# Detection coverage",
        "",
        f"Observed until {_time(report['observed_until_ns'])}: {report['execution_count']} executions, "
        f"{report['alert_count']} alerts.",
        "",
    ]
    if notes:
        lines += ["## Scope", ""] + [f"- {_cell(note)}" for note in notes] + [""]
    lines += [
        "## Detection rate",
        "",
        "| Measure | Detected | Of | Rate |",
        "|---|---|---|---|",
        "| Successful executions " + _rate(report["execution_detection"]),
        "| Techniques with a successful execution " + _rate(report["technique_detection"]),
        "",
        f"Alerts on failed or skipped executions: {report.get('alerts_on_failed_or_skipped_executions', 0)}.",
        "",
        "## Time to detect",
        "",
    ]
    if latency["sample_count"]:
        lines.append(f"Over the {latency['sample_count']} detected successful executions ({latency['method']}): "
                     f"p50 {_seconds(latency['p50'])} s, p95 {_seconds(latency['p95'])} s.")
    else:
        lines.append("No successful execution was detected, so there is no time to detect.")
    lines += ["", "## False positives in normal operation", ""]
    if normal.get("available"):
        counts = normal["counts"]
        days = normal["span_ns"] / 86400e9
        lines += [
            f"Window {_time(normal['start_ns'])} to {_time(normal['end_ns'])} ({days:.2f} days; "
            f"{'at least' if normal['span_at_least_seven_days'] else 'shorter than'} seven days).",
            "",
            "| False positives | True positives | Unreviewed | Alerts |",
            "|---|---|---|---|",
            f"| {counts['false_positive']} | {counts['true_positive']} | {counts['unreviewed']} | {normal['alert_count']} |",
        ]
    else:
        lines.append("No normal-operation window was supplied, so there is no false-positive count.")
    lines += ["", "## Per technique", "",
              "| Technique | Successful | Detected | Failed | Skipped | Fastest detection (s) |",
              "|---|---|---|---|---|---|"]
    for row in report["techniques"]:
        lines.append(f"| {_cell(row['technique_id'])} | {row['successful_executions']} | {row['detected_executions']} | "
                     f"{row['failed_executions']} | {row['skipped_executions']} | {_seconds(row['minimum_latency_ns'])} |")
    lines += ["", "## Per execution", "",
              "| Execution | Run | Technique | Outcome | Status | Executed (UTC) | Time to detect (s) | First alert |",
              "|---|---|---|---|---|---|---|---|"]
    for row in report["executions"]:
        lines.append(f"| `{_cell(row['execution_id'])}` | {_cell(row['run_id'])} | {_cell(row['technique_id'])} | "
                     f"{row['outcome']} | {row['status']} | {_time(row['executed_at_ns'])} | "
                     f"{_seconds(row['latency_ns'])} | {_cell(row['first_alert_id'])} |")
    lines += ["", "## Limits", ""]
    lines += [f"- {_cell(text)}" for text in report["limitations"]]
    if normal.get("limitation"):
        lines.append(f"- {_cell(normal['limitation'])}")
    return "\n".join(lines) + "\n"


def _write(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--metrics", required=True, help="detection_metrics.py JSON report, or - for stdin")
    parser.add_argument("--out", help="markdown file to write (default stdout)")
    parser.add_argument("--note", action="append", default=[], help="a line of the page's Scope section; repeat")
    args = parser.parse_args(argv)
    try:
        if args.metrics == "-":
            report = json.load(sys.stdin)
        else:
            with open(args.metrics, encoding="utf-8") as handle:
                report = json.load(handle)
        text = render(report, args.note)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    if args.out:
        _write(args.out, text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
