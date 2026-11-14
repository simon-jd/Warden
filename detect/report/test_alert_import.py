import unittest
try:
    from detect.report import alert_import
except ImportError:
    try:
        import alert_import
    except ImportError:
        alert_import = None

START = '2026-11-13T00:00:00Z'
END = '2026-11-13T00:01:00Z'


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(alert_import, 'real alert importer missing')

    def binding(self):
        return {'run_id': 'run-1', 'execution_id': 'exec-1', 'container_id': 'a' * 64,
                'start': START, 'end': END}

    def event(self):
        return {'time': '2026-11-13T00:00:02Z', 'rule': 'Terminal shell in container',
                'priority': 'Notice', 'output_fields': {'container.id': 'a' * 12},
                'output': 'real collector output'}

    def test_falco_alert_requires_matching_trusted_container_binding(self):
        rows, provenance = alert_import.from_falco([self.event()], [self.binding()], {'exec-1': {'Terminal shell in container'}})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['execution_id'], 'exec-1')
        self.assertEqual(rows[0]['alerted_at'], self.event()['time'])
        self.assertEqual(provenance[0]['source'], 'falco-json')
        self.assertEqual(set(rows[0]), {'execution_id', 'alert_id', 'rule_id', 'alerted_at'})
        event = self.event()
        event['output_fields']['container.id'] = 'b' * 12
        self.assertEqual(alert_import.from_falco([event], [self.binding()], {'exec-1': {'Terminal shell in container'}})[0], [])

    def test_empty_input_produces_empty_alerts_no_synthetic_detection(self):
        self.assertEqual(alert_import.from_falco([], [self.binding()], {'exec-1': {'Terminal shell in container'}}), ([], []))

    def test_ambiguous_short_ids_and_pre_execution_events_are_not_correlated(self):
        other = dict(self.binding(), execution_id='exec-2', run_id='run-2', container_id='a' * 12 + 'b' * 52)
        with self.assertRaises(ValueError):
            alert_import.from_falco([self.event()], [self.binding(), other], {'exec-1': {'Terminal shell in container'}, 'exec-2': {'Terminal shell in container'}})
        event = self.event()
        event['time'] = '2026-11-12T23:59:59Z'
        self.assertEqual(alert_import.from_falco([event], [self.binding()], {'exec-1': {'Terminal shell in container'}})[0], [])

    def test_deduplication_and_invalid_raw_event(self):
        rows, _ = alert_import.from_falco([self.event(), self.event()], [self.binding()], {'exec-1': {'Terminal shell in container'}})
        self.assertEqual(len(rows), 1)
        with self.assertRaises(ValueError):
            alert_import.from_falco([{'rule': 'malformed'}], [self.binding()], {'exec-1': {'Terminal shell in container'}})


    def test_unrelated_rule_in_bound_container_is_not_attack_detection(self):
        event = self.event()
        event['rule'] = 'Unrelated background warning'
        alerts, _ = alert_import.from_falco([event], [self.binding()], {'exec-1': {'Terminal shell in container'}})
        self.assertEqual(alerts, [])
