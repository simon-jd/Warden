from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

try:
    from detect.report import observation
except ImportError:
    try:
        import observation
    except ImportError:
        observation = None

START = '2026-11-01T00:00:00Z'
END = '2026-11-08T00:00:00Z'


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(observation, 'Observation accounting missing')

    def intervals(self):
        return [{'source_id': 'falco', 'start': START, 'end': END, 'healthy': True,
                 'event_count': 42, 'workload_count': 1, 'dropped_events': 0,
                 'receipt': 'collector-log-sha256:reviewed'}]

    def report(self, intervals=None, alerts=None, sources=None, end=END):
        return observation.account(intervals if intervals is not None else self.intervals(),
                                   alerts or [], sources or ['falco'], START, end, END)

    def test_no_telemetry_cannot_be_zero_false_positives(self):
        result = self.report(intervals=[])
        self.assertIsNone(result['false_positive_count'])
        self.assertFalse(result['eligible_seven_day_window'])
        self.assertEqual(result['sources']['falco']['covered_ns'], 0)

    def test_idle_dropped_and_unhealthy_cannot_be_zero(self):
        for key, value in [('event_count', 0), ('workload_count', 0), ('healthy', False), ('dropped_events', 1)]:
            intervals = self.intervals()
            intervals[0][key] = value
            with self.subTest(key=key):
                self.assertIsNone(self.report(intervals=intervals)['false_positive_count'])

    def test_healthy_active_coverage_can_count_reviewed_false_positives(self):
        alerts = [{'alert_id': 'a', 'rule_id': 'rule', 'alerted_at': START, 'disposition': 'false_positive'}]
        result = self.report(alerts=alerts)
        self.assertTrue(result['eligible_seven_day_window'])
        self.assertEqual(result['false_positive_count'], 1)
        self.assertFalse(result['coverage_verified'])

    def test_unreviewed_or_short_window_makes_count_unknown(self):
        alerts = [{'alert_id': 'a', 'rule_id': 'rule', 'alerted_at': START, 'disposition': 'unreviewed'}]
        self.assertIsNone(self.report(alerts=alerts)['false_positive_count'])
        self.assertIsNone(self.report(end='2026-11-02T00:00:00Z')['false_positive_count'])

    def test_coverage_is_union_per_required_source_not_sum(self):
        intervals = self.intervals() * 2
        intervals[0] = dict(intervals[0], end='2026-11-04T00:00:00Z')
        intervals[1] = dict(intervals[1], start='2026-11-05T00:00:00Z')
        result = self.report(intervals=intervals)
        self.assertIsNone(result['false_positive_count'])
        self.assertEqual(result['sources']['falco']['gap_ns'], 86400 * 10**9)
        self.assertIsNone(self.report(sources=['falco', 'k8s-audit'])['false_positive_count'])

    def test_conflicting_alerts_bad_counts_and_future_end_fail(self):
        intervals = self.intervals()
        intervals[0]['event_count'] = -1
        with self.assertRaises(ValueError):
            self.report(intervals=intervals)
        alerts = [{'alert_id': 'a', 'rule_id': 'rule', 'alerted_at': START, 'disposition': 'false_positive'},
                  {'alert_id': 'a', 'rule_id': 'rule', 'alerted_at': START, 'disposition': 'true_positive'}]
        with self.assertRaises(ValueError):
            self.report(alerts=alerts)
        with self.assertRaises(ValueError):
            self.report(end='2026-11-09T00:00:00Z')

class RejectedCoverageTests(unittest.TestCase):
    def test_unhealthy_overlap_blocks_complete_claim(self):
        ledger = ObservationTests().intervals()
        ledger.append(dict(ledger[0], start='2026-11-04T00:00:00Z', end='2026-11-04T01:00:00Z', healthy=False))
        result = observation.account(ledger, [], ['falco'], START, END, END)
        self.assertIsNone(result['false_positive_count'])
        self.assertFalse(result['eligible_seven_day_window'])


if __name__ == '__main__':
    unittest.main()
