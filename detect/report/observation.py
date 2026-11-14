"""Account for supplied normal-operation source coverage, never inferred uptime.

A ledger is an operator-reviewed collector export, not authenticated evidence.
Use explicit source lists and wall-clock windows; idle time is not observation.
"""
import argparse
import json
import sys
try:
    from .detection_metrics import (DAY, MetricsError, normal_window_metrics, read_jsonl, timestamp_ns)
except ImportError:
    from detection_metrics import (DAY, MetricsError, normal_window_metrics, read_jsonl, timestamp_ns)

FIELDS = {'source_id', 'start', 'end', 'healthy', 'event_count', 'workload_count', 'dropped_events', 'receipt'}


def account(intervals, alerts, required_sources, start, end, observed_until):
    beginning, ending, cutoff = map(timestamp_ns, (start, end, observed_until))
    if not beginning < ending <= cutoff:
        raise MetricsError('observation must have start < end <= observed-until')
    if (not isinstance(required_sources, list) or not required_sources or
            any(not isinstance(source, str) or not source.strip() for source in required_sources) or
            len(set(required_sources)) != len(required_sources)):
        raise MetricsError('explicit nonempty unique required source IDs required')
    normal = normal_window_metrics(alerts, start, end)
    spans = {source: [] for source in required_sources}
    rejected = {source: 0 for source in required_sources}
    for interval in intervals:
        if not isinstance(interval, dict) or set(interval) != FIELDS:
            raise MetricsError('coverage interval has missing or unknown fields')
        source = interval['source_id']
        if source not in spans:
            raise MetricsError('coverage interval references undeclared source')
        left, right = map(timestamp_ns, (interval['start'], interval['end']))
        if not left < right <= cutoff:
            raise MetricsError('coverage interval must have start < end <= observed-until')
        if type(interval['healthy']) is not bool:
            raise MetricsError('coverage health must be boolean')
        for key in ('event_count', 'workload_count', 'dropped_events'):
            if type(interval[key]) is not int or interval[key] < 0:
                raise MetricsError('coverage counters must be nonnegative integers')
        if not isinstance(interval['receipt'], str) or not interval['receipt'].strip():
            raise MetricsError('collector receipt reference required')
        active = (interval['healthy'] and interval['event_count'] > 0 and
                  interval['workload_count'] > 0 and interval['dropped_events'] == 0)
        if not active and max(left, beginning) < min(right, ending):
            rejected[source] += 1
        elif max(left, beginning) < min(right, ending):
            spans[source].append((max(left, beginning), min(right, ending)))
    sources = {}
    for source in required_sources:
        covered, previous = 0, beginning
        for left, right in sorted(spans[source]):
            covered += max(0, right - max(left, previous))
            previous = max(previous, right)
        sources[source] = {'covered_ns': covered, 'gap_ns': ending - beginning - covered,
                           'rejected_intervals': rejected[source],
                           'active_continuous_coverage': covered == ending - beginning and rejected[source] == 0}
    eligible = (ending - beginning >= 7 * DAY and
                all(row['active_continuous_coverage'] for row in sources.values()) and
                normal['counts']['unreviewed'] == 0)
    return {'scope': 'supplied-collector-ledger', 'start': start, 'end': end,
            'observed_until': observed_until, 'span_ns': ending - beginning, 'sources': sources,
            'eligible_seven_day_window': eligible, 'coverage_verified': False,
            'false_positive_count': normal['counts']['false_positive'] if eligible else None,
            'reviewed_counts': normal['counts'], 'alert_count': normal['alert_count'],
            'limitations': ['Ledger counters, source coverage and reviewer dispositions require external validation.',
                            'Unhealthy, dropped, missing or idle intervals do not establish active observation.',
                            'A null false_positive_count means unavailable or incomplete; it must not be reported as zero.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coverage', required=True, help='collector coverage intervals JSONL')
    parser.add_argument('--normal-alerts', required=True, help='reviewed normal alerts JSONL')
    parser.add_argument('--source', action='append', required=True, help='required source; repeat for every source')
    parser.add_argument('--start', required=True)
    parser.add_argument('--end', required=True)
    parser.add_argument('--observed-until', required=True)
    args = parser.parse_args(argv)
    try:
        result = account(read_jsonl(args.coverage), read_jsonl(args.normal_alerts), args.source,
                         args.start, args.end, args.observed_until)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
