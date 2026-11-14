"""Bounded, exact metrics for an explicitly correlated supplied cohort.

Importing this stdlib-only module performs no I/O. Timestamps are represented as
integer nanoseconds since 0001-01-01T00:00:00Z, including in the JSON report.
"""

import argparse
from datetime import date
import json
import math
import os
import re
import stat
import sys


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 65536
MAX_RECORDS = 100000
SECOND = 1_000_000_000
DAY = 86400 * SECOND
SEVEN_DAYS = 7 * DAY
_TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?([Zz]|[+-][0-9]{2}:[0-9]{2})\Z")
_TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
_EXECUTION_FIELDS = {"execution_id", "run_id", "technique_id", "executed_at", "outcome"}
_ALERT_FIELDS = {"alert_id", "execution_id", "rule_id", "alerted_at"}
_NORMAL_FIELDS = {"alert_id", "rule_id", "alerted_at", "disposition"}


class MetricsError(ValueError):
    """Invalid supplied data, with no successful partial report."""


def timestamp_ns(value):
    """Parse RFC3339 without floating-point rounding or host-clock access."""
    if not isinstance(value, str):
        raise MetricsError("timestamp must be a string")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise MetricsError("timestamp must be RFC3339 with an explicit offset")
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    if hour > 23 or minute > 59 or second > 59:
        raise MetricsError("invalid timestamp time or leap second")
    try:
        ordinal = date(year, month, day).toordinal() - 1
    except ValueError as exc:
        raise MetricsError("invalid timestamp date") from exc
    fraction = int((match[7] or "").ljust(9, "0"))
    zone = match[8]
    offset = 0
    if zone.upper() != "Z":
        offset_hour, offset_minute = int(zone[1:3]), int(zone[4:6])
        if offset_hour > 23 or offset_minute > 59:
            raise MetricsError("invalid timestamp offset")
        offset = (offset_hour * 3600 + offset_minute * 60) * (1 if zone[0] == "+" else -1)
    result = ordinal * DAY + (hour * 3600 + minute * 60 + second - offset) * SECOND + fraction
    if not 0 <= result < date.max.toordinal() * DAY:
        raise MetricsError("UTC timestamp is outside representable dates")
    return result


def _id(value):
    if not isinstance(value, str) or not value.strip():
        raise MetricsError("IDs must be nonblank strings")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise MetricsError("IDs must be valid UTF-8") from exc
    if size > 256:
        raise MetricsError("ID exceeds 256 UTF-8 bytes")


def _events(records, fields, identity, time_field, cutoff):
    events = {}
    for count, record in enumerate(records, 1):
        if count > MAX_RECORDS:
            raise MetricsError("record count exceeds limit")
        if not isinstance(record, dict) or set(record) != fields:
            raise MetricsError("record has missing or unknown fields")
        for key, value in record.items():
            if key.endswith("_id"):
                _id(value)
        stamp = timestamp_ns(record[time_field])
        if stamp > cutoff:
            raise MetricsError("event is after observed-until cutoff")
        if "outcome" in fields and record["outcome"] not in ("succeeded", "failed", "skipped"):
            raise MetricsError("invalid execution outcome")
        if "technique_id" in fields and _TECHNIQUE.fullmatch(record["technique_id"]) is None:
            raise MetricsError("invalid ATT&CK technique ID")
        if "disposition" in fields and record["disposition"] not in ("false_positive", "true_positive", "unreviewed"):
            raise MetricsError("invalid normal-alert disposition")
        event_id = record[identity]
        if event_id in events and events[event_id][0] != record:
            raise MetricsError("conflicting duplicate event ID")
        events[event_id] = (dict(record), stamp)
    return events


def _rate(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None}


def normal_window_metrics(alerts=None, start=None, end=None):
    """Count supplied annotations; endpoints cannot verify source coverage."""
    if alerts is None and start is None and end is None:
        return {"available": False, "coverage_verified": False,
                "limitation": "Normal-operation data unavailable; no false-positive count inferred."}
    if alerts is None or start is None or end is None:
        raise MetricsError("normal alerts, start and end must be supplied together")
    start_ns, end_ns = timestamp_ns(start), timestamp_ns(end)
    if start_ns >= end_ns:
        raise MetricsError("normal window must have start before end")
    events = _events(alerts, _NORMAL_FIELDS, "alert_id", "alerted_at", end_ns)
    counts = dict.fromkeys(("false_positive", "true_positive", "unreviewed"), 0)
    for record, stamp in events.values():
        if not start_ns <= stamp < end_ns:
            raise MetricsError("normal alert outside [start,end)")
        counts[record["disposition"]] += 1
    return {"available": True, "start_ns": start_ns, "end_ns": end_ns,
            "span_ns": end_ns - start_ns, "span_at_least_seven_days": end_ns - start_ns >= SEVEN_DAYS,
            "counts": counts, "alert_count": len(events), "coverage_verified": False,
            "limitation": "Supplied endpoints and annotations do not prove continuous source coverage or true ground truth; external validation required."}


def compute_metrics(executions, alerts, observed_until, *, normal_alerts=None,
                    normal_start=None, normal_end=None):
    """Compute earliest explicit correlations; do not mutate caller records.

    Exact duplicate IDs deduplicate across all fields. Conflicting IDs, unknown
    correlations and pre-execution alerts fail the entire supplied cohort.
    """
    cutoff = timestamp_ns(observed_until)
    execution_map = _events(executions, _EXECUTION_FIELDS, "execution_id", "executed_at", cutoff)
    alert_map = _events(alerts, _ALERT_FIELDS, "alert_id", "alerted_at", cutoff)
    correlated = {key: [] for key in execution_map}
    for alert_id, (record, stamp) in alert_map.items():
        execution_id = record["execution_id"]
        if execution_id not in execution_map:
            raise MetricsError("alert references unknown execution_id")
        if stamp < execution_map[execution_id][1]:
            raise MetricsError("alert precedes execution")
        correlated[execution_id].append((stamp, alert_id))
    details, techniques, latencies = [], {}, []
    succeeded = detected = unsuccessful_alerts = 0
    for execution_id in sorted(execution_map):
        record, stamp = execution_map[execution_id]
        matches = sorted(correlated[execution_id])
        eligible = record["outcome"] == "succeeded"
        latency = matches[0][0] - stamp if eligible and matches else None
        row = {"execution_id": execution_id, "run_id": record["run_id"],
               "technique_id": record["technique_id"], "outcome": record["outcome"],
               "executed_at_ns": stamp, "observation_duration_ns": cutoff - stamp,
               "eligible": eligible, "detected": bool(matches) if eligible else None,
               "status": ("detected" if matches else "not_detected_by_cutoff") if eligible else "excluded_outcome",
               "latency_ns": latency, "first_alert_id": matches[0][1] if matches else None,
               "alert_ids": [alert_id for _, alert_id in matches]}
        details.append(row)
        technique = techniques.setdefault(record["technique_id"], {
            "technique_id": record["technique_id"], "successful_executions": 0,
            "detected_executions": 0, "failed_executions": 0, "skipped_executions": 0,
            "detected": False, "minimum_latency_ns": None})
        if eligible:
            succeeded += 1
            technique["successful_executions"] += 1
            if latency is not None:
                detected += 1
                technique["detected_executions"] += 1
                technique["detected"] = True
                previous = technique["minimum_latency_ns"]
                technique["minimum_latency_ns"] = latency if previous is None else min(previous, latency)
                latencies.append(latency)
        else:
            technique[record["outcome"] + "_executions"] += 1
            unsuccessful_alerts += len(matches)
    latencies.sort()
    count = len(latencies)
    successful_techniques = [row for row in techniques.values() if row["successful_executions"]]
    return {"scope": "provided-cohort", "timestamp_origin": "0001-01-01T00:00:00Z",
            "observed_until_ns": cutoff, "execution_count": len(execution_map), "alert_count": len(alert_map),
            "execution_detection": _rate(detected, succeeded),
            "technique_detection": _rate(sum(row["detected"] for row in successful_techniques), len(successful_techniques)),
            "latency_ns": {"sample_count": count, "method": "nearest-rank",
                           "p50": latencies[(50 * count + 99) // 100 - 1] if count else None,
                           "p95": latencies[(95 * count + 99) // 100 - 1] if count else None},
            "executions": details, "techniques": [techniques[key] for key in sorted(techniques)],
            "alerts_on_failed_or_skipped_executions": unsuccessful_alerts,
            "normal_window": normal_window_metrics(normal_alerts, normal_start, normal_end),
            "limitations": ["Analysis of supplied cohort only; no provider provenance or authentication is asserted.",
                            "Undetected executions are right-censored at the supplied cutoff, not permanent misses.",
                            "Fixture or supplied data does not establish real emulation, integration or deployment coverage."]}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MetricsError("duplicate JSON object key")
        result[key] = value
    return result


def _constant(value):
    raise MetricsError("nonfinite JSON value")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise MetricsError("nonfinite JSON number")
    return result


def read_jsonl(path):
    """Read explicit regular files, bounding bytes before decoding each record.

    A record's byte cap excludes its LF delimiter. Blank lines are invalid.
    Symlinks and special files are rejected; no path discovery is performed.
    """
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise MetricsError("input must be a regular file, not a symlink or special file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise MetricsError("input must be a regular file")
            if info.st_size > MAX_FILE_BYTES:
                raise MetricsError("file exceeds byte limit")
            records, total = [], 0
            while True:
                line = stream.readline(MAX_RECORD_BYTES + 2)
                if not line:
                    break
                total += len(line)
                if total > MAX_FILE_BYTES:
                    raise MetricsError("file exceeds byte limit")
                record = line[:-1] if line.endswith(b"\n") else line
                if len(record) > MAX_RECORD_BYTES:
                    raise MetricsError("record exceeds byte limit")
                if not record.strip():
                    raise MetricsError("blank JSONL record")
                if len(records) >= MAX_RECORDS:
                    raise MetricsError("record count exceeds limit")
                decoded = json.loads(record.decode("utf-8"), object_pairs_hook=_object,
                                     parse_constant=_constant, parse_float=_finite_float)
                if not isinstance(decoded, dict):
                    raise MetricsError("JSONL record must be an object")
                records.append(decoded)
            return records
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, MetricsError):
            raise
        raise MetricsError("cannot read valid bounded JSONL input") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executions", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--observed-until", required=True)
    parser.add_argument("--normal-alerts")
    parser.add_argument("--normal-start")
    parser.add_argument("--normal-end")
    args = parser.parse_args(argv)
    try:
        normal_options = (args.normal_alerts, args.normal_start, args.normal_end)
        if any(value is not None for value in normal_options) and not all(value is not None for value in normal_options):
            raise MetricsError("normal options must be supplied together")
        report = compute_metrics(read_jsonl(args.executions), read_jsonl(args.alerts), args.observed_until,
                                 normal_alerts=read_jsonl(args.normal_alerts) if args.normal_alerts is not None else None,
                                 normal_start=args.normal_start, normal_end=args.normal_end)
        output = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except MetricsError as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
