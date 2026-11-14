"""detect/falco/review.py: group kept alerts by signature, apply a person's dispositions.

Synthetic alerts. The tool must never decide a disposition itself: what no
mapping names stays unreviewed.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    from detect.falco import review
except ImportError:
    review = None
try:
    from detect.report import observation
except ImportError:
    observation = None


def alert(n, rule, proc, cid='a' * 12, t='2026-11-20T01:00:00Z'):
    return {'time': t, 'rule': rule, 'priority': 'Notice', 'source': 'syscall', 'output': 'x %d' % n,
            'output_fields': {'container.id': cid, 'proc.name': proc, 'evt.num': n}}


def digest(evt):
    return hashlib.sha256(json.dumps(evt, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def scoping(evt, klass):
    return {'raw_event_sha256': digest(evt), 'time': evt['time'], 'rule': evt['rule'], 'class': klass}


def kept():
    alerts = [alert(i, 'PTRACE attached to process', 'gvisor_sentry', 'b' * 12) for i in range(5)]
    alerts += [alert(10 + i, 'Drop and execute new binary in container', 'kubectl', 'c' * 12) for i in range(3)]
    alerts += [alert(20, 'PTRACE anti-debug attempt', 'warden-probe')]
    classes = ['sandbox'] * 5 + ['node'] * 3 + ['sandbox']
    return alerts, [scoping(a, k) for a, k in zip(alerts, classes)]


class Base(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(review, 'detect/falco/review.py missing')


class GroupTest(Base):
    def test_groups_by_rule_process_and_class_with_counts(self):
        alerts, scopes = kept()
        groups = review.groups(alerts, scopes)
        self.assertEqual([(g['rule'], g['process'], g['class'], g['count']) for g in groups], [
            ('Drop and execute new binary in container', 'kubectl', 'node', 3),
            ('PTRACE anti-debug attempt', 'warden-probe', 'sandbox', 1),
            ('PTRACE attached to process', 'gvisor_sentry', 'sandbox', 5)])

    def test_the_template_decides_nothing(self):
        alerts, scopes = kept()
        self.assertEqual({t['disposition'] for t in review.template(review.groups(alerts, scopes))}, {'unreviewed'})

    def test_an_alert_without_a_scoping_record_is_its_own_class(self):
        alerts, scopes = kept()
        self.assertIn(('PTRACE anti-debug attempt', 'warden-probe', 'unknown'),
                      [(g['rule'], g['process'], g['class']) for g in review.groups(alerts, scopes[:-1])])


class ApplyTest(Base):
    def mapping(self):
        return [{'rule': 'PTRACE attached to process', 'process': 'gvisor_sentry', 'class': 'sandbox', 'disposition': 'false_positive'},
                {'rule': 'PTRACE anti-debug attempt', 'process': 'warden-probe', 'class': 'sandbox', 'disposition': 'true_positive'}]

    def test_mapped_groups_get_the_persons_disposition_and_the_rest_stay_unreviewed(self):
        alerts, scopes = kept()
        rows, report = review.apply(alerts, scopes, self.mapping())
        self.assertEqual(len(rows), 9)
        self.assertEqual({tuple(sorted(r)) for r in rows}, {('alert_id', 'alerted_at', 'disposition', 'rule_id')})
        by = {}
        for r in rows:
            by.setdefault(r['rule_id'], set()).add(r['disposition'])
        self.assertEqual(by, {'PTRACE attached to process': {'false_positive'}, 'PTRACE anti-debug attempt': {'true_positive'},
                              'Drop and execute new binary in container': {'unreviewed'}})
        self.assertEqual(rows[0]['alert_id'], 'falco-' + digest(alerts[0]))
        self.assertEqual((report['false_positive'], report['true_positive'], report['unreviewed']), (5, 1, 3))
        self.assertEqual({(g['rule'], g['false_positive']) for g in report['groups']},
                         {('PTRACE attached to process', 5), ('PTRACE anti-debug attempt', 0), ('Drop and execute new binary in container', 0)})
        self.assertEqual(report['unmatched_mappings'], [])

    def test_no_mapping_means_everything_unreviewed(self):
        alerts, scopes = kept()
        rows, report = review.apply(alerts, scopes, [])
        self.assertEqual({r['disposition'] for r in rows}, {'unreviewed'})
        self.assertEqual(report['unreviewed'], 9)

    def test_bad_mappings_fail(self):
        alerts, scopes = kept()
        for bad in ([dict(self.mapping()[0], disposition='benign')], [dict(self.mapping()[0], note='x')],
                    [self.mapping()[0], dict(self.mapping()[0], disposition='true_positive')], [{'rule': 'x'}]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                review.apply(alerts, scopes, bad)

    def test_a_mapping_that_matches_nothing_is_reported(self):
        alerts, scopes = kept()
        extra = {'rule': 'Terminal shell in container', 'process': 'sh', 'class': 'sandbox', 'disposition': 'false_positive'}
        _, report = review.apply(alerts, scopes, self.mapping() + [extra])
        self.assertEqual(report['unmatched_mappings'], [extra])

    def test_window_limits_the_alerts(self):
        alerts, scopes = kept()
        late = alert(99, 'PTRACE anti-debug attempt', 'warden-probe', t='2026-11-28T00:00:00Z')
        rows, _ = review.apply(alerts + [late], scopes + [scoping(late, 'sandbox')], [], start='2026-11-20T00:00:00Z',
                               end='2026-11-27T00:00:00Z')
        self.assertEqual(len(rows), 9)

    def test_output_feeds_observation(self):
        if observation is None:
            self.skipTest('detect/report/observation.py missing')
        alerts, scopes = kept()
        rows, _ = review.apply(alerts, scopes, self.mapping() + [
            {'rule': 'Drop and execute new binary in container', 'process': 'kubectl', 'class': 'node', 'disposition': 'false_positive'}])
        coverage = [{'source_id': 'falco-host', 'start': '2026-11-20T00:00:00Z', 'end': '2026-11-27T00:00:00Z', 'healthy': True,
                     'event_count': 1, 'workload_count': 1, 'dropped_events': 0, 'receipt': 'synthetic'}]
        result = observation.account(coverage, rows, ['falco-host'], '2026-11-20T00:00:00Z', '2026-11-27T00:00:00Z',
                                     '2026-11-27T00:00:00Z')
        self.assertEqual(result['false_positive_count'], 8)


class CommandTest(Base):
    def test_groups_then_apply(self):
        alerts, scopes = kept()
        with tempfile.TemporaryDirectory() as d:
            a, s = Path(d, 'alerts.jsonl'), Path(d, 'scoping.jsonl')
            a.write_text(''.join(json.dumps(x) + '\n' for x in alerts))
            s.write_text(''.join(json.dumps(x) + '\n' for x in scopes))
            run = lambda *args: subprocess.run([sys.executable, '-I', '-B', review.__file__, *args], capture_output=True, text=True)
            r = run('groups', '--alerts', str(a), '--scoping', str(s), '--out', os.path.join(d, 'groups.jsonl'),
                    '--template', os.path.join(d, 'map.jsonl'))
            self.assertEqual(r.returncode, 0, r.stderr)
            template = [json.loads(x) for x in Path(d, 'map.jsonl').read_text().splitlines()]
            self.assertEqual(len(template), 3)
            template[0]['disposition'] = 'false_positive'
            Path(d, 'map.jsonl').write_text(''.join(json.dumps(x) + '\n' for x in template))
            r = run('apply', '--alerts', str(a), '--scoping', str(s), '--map', os.path.join(d, 'map.jsonl'),
                    '--out', os.path.join(d, 'normal.jsonl'), '--report', os.path.join(d, 'report.json'))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(Path(d, 'report.json').read_text())['false_positive'], 3)
            again = run('apply', '--alerts', str(a), '--scoping', str(s), '--map', os.path.join(d, 'map.jsonl'),
                        '--out', os.path.join(d, 'normal.jsonl'), '--report', os.path.join(d, 'report.json'))
            self.assertNotEqual(again.returncode, 0, 'existing outputs are not overwritten')


if __name__ == '__main__':
    unittest.main()
