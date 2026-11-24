"""detect/report/audit_alert_import.py on synthetic k8saudit alerts and run records."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    from detect.report import audit_alert_import as importer
    from detect.report import detection_metrics
except ImportError:
    importer = detection_metrics = None

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'audit-import'
UUID_A, UUID_B = '0d7c1e52-7a43-4b5e-9a0f-3c1b2d4e5f60', '9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f'
START, END = '2026-11-14T18:00:00.000000Z', '2026-11-14T18:00:10.000000Z'
EXEC = 'Attach/Exec Pod'
SA = 'K8s Serviceaccount Created'


def event(rule=EXEC, time='2026-11-14T18:00:02.500000000Z', namespace='warden-smoke-1', label='<NA>', legacy=None, **extra):
    """legacy: the warden_run_id label, if it differs from warden.dev/run."""
    fields = {'ka.target.namespace': namespace, importer.LABEL_FIELDS[0]: label,
              importer.LABEL_FIELDS[1]: label if legacy is None else legacy, 'ka.auditid': 'a-1',
              'ka.useragent': 'kubectl/v1.36.5', 'ka.user.name': 'kubernetes-admin', **extra}
    return {'time': time, 'rule': rule, 'priority': 'Notice', 'source': 'k8s_audit', 'output': 'stock output text',
            'output_fields': fields, 'tags': ['k8s'], 'hostname': 'falco'}


def run(**changes):
    record = {'execution_id': 'exec-1', 'run_id': 'smoke-0123', 'namespaces': ['warden-smoke-1'], 'start': START, 'end': END}
    record.update(changes)
    return record


RULES = {'exec-1': {EXEC, SA}, 'exec-2': {EXEC, SA}}


class MatchTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importer, 'audit importer missing')

    def test_namespace_match_inside_the_window(self):
        alerts, provenance = importer.from_k8saudit([event()], [run()], RULES)
        self.assertEqual(alerts, [{'alert_id': alerts[0]['alert_id'], 'execution_id': 'exec-1', 'rule_id': EXEC,
                                   'alerted_at': '2026-11-14T18:00:02.500000000Z'}])
        self.assertEqual(provenance[0]['matched_by'], ['namespace'])
        self.assertEqual(provenance[0]['label'], None)
        self.assertEqual(provenance[0]['source'], 'falco-k8saudit-json')

    def test_label_match_in_any_namespace(self):
        alerts, provenance = importer.from_k8saudit([event(SA, namespace='elsewhere', label='smoke-0123')], [run()], RULES)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(provenance[0]['matched_by'], ['label'])
        both = importer.from_k8saudit([event(SA, label='smoke-0123')], [run()], RULES)[1]
        self.assertEqual(both[0]['matched_by'], ['label', 'namespace'])
        for label, legacy in (('smoke-0123', '<NA>'), ('<NA>', 'smoke-0123')):
            with self.subTest(label=label, legacy=legacy):
                got = importer.from_k8saudit([event(SA, namespace='elsewhere', label=label, legacy=legacy)], [run()], RULES)[1]
                self.assertEqual(got[0]['matched_by'], ['label'])
                self.assertEqual(got[0]['label'], 'smoke-0123')

    def test_the_label_fields_are_the_wrappers_keys(self):
        self.assertEqual(importer.LABEL_FIELDS, ('jevt.value[/requestObject/metadata/labels/warden.dev~1run]',
                                                 'jevt.value[/requestObject/metadata/labels/warden_run_id]'))

    def test_outside_the_window_or_another_namespace_or_label_is_not_attributed(self):
        for alert in (event(time='2026-11-14T17:59:59.999999999Z'), event(time='2026-11-14T18:00:10.000000001Z'),
                      event(namespace='warden-smoke-2'), event(namespace='<NA>', label='smoke-9999'),
                      event(namespace='', label='')):
            with self.subTest(alert=alert['time'] + str(alert['output_fields'])):
                self.assertEqual(importer.from_k8saudit([alert], [run()], RULES), ([], []))

    def test_window_bounds_are_inclusive(self):
        for stamp in (START, END):
            self.assertEqual(len(importer.from_k8saudit([event(time=stamp)], [run()], RULES)[0]), 1)

    def test_rules_outside_the_reviewed_map_are_left_out(self):
        self.assertEqual(importer.from_k8saudit([event('K8s Namespace Created')], [run()], RULES), ([], []))

    def test_an_alert_two_runs_claim_fails_the_import(self):
        other = run(execution_id='exec-2', run_id='smoke-4567')
        with self.assertRaisesRegex(ValueError, 'more than one run'):
            importer.from_k8saudit([event(label='smoke-4567')], [run(), other], RULES)

    def test_duplicates_collapse_and_ids_match_the_container_importer(self):
        alerts, _ = importer.from_k8saudit([event(), event()], [run()], RULES)
        self.assertEqual(len(alerts), 1)
        canonical = json.dumps(event(), sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        import hashlib
        self.assertEqual(alerts[0]['alert_id'], 'falco-' + hashlib.sha256(canonical.encode()).hexdigest())

    def test_alerts_without_the_appended_fields_or_of_another_source_fail_closed(self):
        bare = event()
        del bare['output_fields'][importer.LABEL_FIELDS[0]]
        with self.assertRaisesRegex(ValueError, 'appends'):
            importer.from_k8saudit([bare], [run()], RULES)
        syscall = dict(event(), source='syscall')
        with self.assertRaisesRegex(ValueError, 'k8s_audit'):
            importer.from_k8saudit([syscall], [run()], RULES)
        with self.assertRaises(ValueError):
            importer.from_k8saudit([{'rule': 'x'}], [run()], RULES)

    def test_run_records_are_checked(self):
        bad = [dict(run(), extra=1), {k: v for k, v in run().items() if k != 'namespaces'}, run(namespaces=['kube-system']),
               run(namespaces=['default']), run(namespaces=['Not_A_Namespace']), run(namespaces='warden-smoke-1'),
               run(namespaces=['a', 'a']), run(run_id='has space'), run(start=END, end=START), run(start='2026-11-14 18:00'),
               run(execution_id='')]
        for record in bad:
            with self.subTest(record=record), self.assertRaises(ValueError):
                importer.from_k8saudit([], [record], RULES)
        with self.assertRaisesRegex(ValueError, 'duplicate run_id'):
            importer.from_k8saudit([], [run(), run(execution_id='exec-2')], RULES)
        self.assertEqual(importer.from_k8saudit([], [run(namespaces=[])], RULES), ([], []))
        with self.assertRaisesRegex(ValueError, 'rule map'):
            importer.from_k8saudit([event()], [run()], {})

    def test_output_is_what_detection_metrics_reads(self):
        alerts, _ = importer.from_k8saudit([event()], [run()], RULES)
        executions = [{'execution_id': 'exec-1', 'run_id': 'smoke-0123', 'technique_id': 'T1609',
                       'executed_at': START, 'outcome': 'succeeded'}]
        report = detection_metrics.compute_metrics(executions, alerts, '2026-11-14T18:01:00Z')
        self.assertEqual(report['execution_detection']['numerator'], 1)
        self.assertEqual(report['latency_ns']['p50'], 2_500_000_000)


class ReceiptTest(unittest.TestCase):
    def receipt(self, **changes):
        record = {'source': 'official-stratus-red-team', 'technique': 'k8s.privilege-escalation.privileged-pod',
                  'run_id': 'stratus-' + 'a' * 24, 'execution_id': 'stratus-' + 'a' * 24, 'started_at': START,
                  'finished_at': END, 'returncode': 0, 'cleanup_returncode': 0, 'namespace': 'warden-lab',
                  'pod_image': 'busybox@sha256:' + 'b' * 64}
        record.update(changes)
        return record

    def test_a_wrapper_receipt_is_a_run_record(self):
        self.assertEqual(importer.from_receipt(self.receipt()),
                         {'execution_id': 'stratus-' + 'a' * 24, 'run_id': 'stratus-' + 'a' * 24, 'namespaces': ['warden-lab'],
                          'start': START, 'end': END})
        record = importer.from_receipt(self.receipt())
        rules = {record['execution_id']: {EXEC}}
        alerts, provenance = importer.from_k8saudit([event(namespace='warden-lab')], [record], rules)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(provenance[0]['matched_by'], ['namespace'])

    def test_a_receipt_file_on_one_or_several_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            for indent in (None, 1):
                path = Path(tmp) / ('r%s.json' % indent)
                path.write_text(json.dumps(self.receipt(), indent=indent) + '\n')
                self.assertEqual(importer.read_receipt(str(path))['namespaces'], ['warden-lab'])
            (Path(tmp) / 'bad.json').write_text('{"run_id": ')
            with self.assertRaises(ValueError):
                importer.read_receipt(str(Path(tmp) / 'bad.json'))

    def test_bad_receipts(self):
        for receipt in (self.receipt(execution_id='other'), {k: v for k, v in self.receipt().items() if k != 'namespace'},
                        self.receipt(namespace=['warden-lab']), self.receipt(namespace='kube-system')):
            with self.subTest(receipt=receipt), self.assertRaises(ValueError):
                importer.runs_of([importer.from_receipt(receipt)])


class CorrelationTest(unittest.TestCase):
    """The fixtures: three receipts, nine alerts (fixtures/audit-import/README.md)."""

    def setUp(self):
        self.assertIsNotNone(importer)
        self.records = [importer.read_receipt(str(FIXTURES / name)) for name in ('receipt-a.json', 'receipt-b.json', 'receipt-c.json')]
        self.alerts = detection_metrics.read_jsonl(str(FIXTURES / 'alerts.jsonl'))
        rules = {r['rule'] for r in self.alerts}
        self.rules = {r['execution_id']: rules for r in self.records}

    def test_fixture_attribution(self):
        alerts, provenance = importer.from_k8saudit(self.alerts, self.records, self.rules)
        got = sorted((p['raw_event']['output_fields']['ka.auditid'], p['run_id'][-1], tuple(p['matched_by'])) for p in provenance)
        self.assertEqual(got, [('audit-1', 'a', ('correlation_id',)), ('audit-2', 'a', ('correlation_id',)),
                               ('audit-3', 'a', ('correlation_id',)), ('audit-4', 'b', ('correlation_id', 'namespace')),
                               ('audit-5', 'b', ('namespace',)), ('audit-7', 'c', ('label', 'namespace'))])
        self.assertEqual(len(alerts), 6)
        self.assertEqual(self.records[0]['correlation_id'], UUID_A)
        self.assertNotIn('correlation_id', self.records[2])

    def test_correlation_id_outranks_another_runs_namespace(self):
        a = dict(self.records[0], start='2026-11-14T18:00:00Z', end='2026-11-14T18:05:00Z', namespaces=[])
        c = dict(self.records[2], start='2026-11-14T18:00:00Z', end='2026-11-14T18:05:00Z')
        alert = dict(self.alerts[5], time='2026-11-14T18:01:10Z')  # warden-lab (c's namespace), a's User-Agent
        _, provenance = importer.from_k8saudit([alert], [a, c], self.rules)
        self.assertEqual((provenance[0]['run_id'], provenance[0]['matched_by']), (a['run_id'], ['correlation_id']))

    def test_conflicts_fail_the_import(self):
        a = dict(self.records[0], start='2026-11-14T18:00:00Z', end='2026-11-14T18:05:00Z')
        c = dict(self.records[2], start='2026-11-14T18:00:00Z', end='2026-11-14T18:05:00Z')
        labelled = json.loads(json.dumps(self.alerts[0]))
        for field in importer.LABEL_FIELDS:
            labelled['output_fields'][field] = c['run_id']
        with self.assertRaisesRegex(ValueError, 'different runs'):
            importer.from_k8saudit([labelled], [a, c], self.rules)
        both = json.loads(json.dumps(self.alerts[0]))
        both['output_fields']['ka.useragent'] = 'stratus-red-team_%s stratus-red-team_%s' % (UUID_A, UUID_B)
        b = dict(self.records[1], start='2026-11-14T18:00:00Z', end='2026-11-14T18:05:00Z')
        with self.assertRaisesRegex(ValueError, 'more than one run'):
            importer.from_k8saudit([both], [a, b], self.rules)

    def test_the_correlation_id_must_be_stratus_s_token(self):
        a = self.records[0]
        def agent(value):
            alert = json.loads(json.dumps(self.alerts[0]))  # cluster-scoped, inside a's window
            alert['output_fields']['ka.useragent'] = value
            return importer.from_k8saudit([alert], [a], self.rules)[1]
        for value in ('stratus-red-team_' + UUID_A, 'HashiCorp/1.0 Terraform/1.3.10 stratus-red-team_' + UUID_A,
                      '(stratus-red-team_%s)' % UUID_A, 'stratus-red-team_%s; other/1.0' % UUID_A):
            with self.subTest(value=value):
                self.assertEqual([p['matched_by'] for p in agent(value)], [['correlation_id']])
        for value in (UUID_A, 'kubectl/v1.36.5 ' + UUID_A, 'ff' + UUID_A + 'ff', 'stratus-red-team_' + UUID_A + 'ff',
                      'stratus-red-team_' + UUID_A + '-0', 'x-stratus-red-team_' + UUID_A, 'xstratus-red-team_' + UUID_A,
                      'stratus-red-team_' + UUID_A.upper(), 'stratus-red-team-' + UUID_A, '<NA>'):
            with self.subTest(value=value):
                self.assertEqual(agent(value), [], 'not the token, or not delimited')

    def test_correlation_ids_are_checked(self):
        for value in (UUID_A.upper(), 'stratus-' + 'a' * 24, UUID_A[:-1], 7, ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                importer.runs_of([dict(self.records[0], correlation_id=value)])
        with self.assertRaisesRegex(ValueError, 'duplicate correlation_id'):
            importer.runs_of([self.records[0], dict(self.records[1], correlation_id=UUID_A)])
        bare = json.loads(json.dumps(self.alerts[0]))
        del bare['output_fields']['ka.useragent']
        with self.assertRaisesRegex(ValueError, 'appends'):
            importer.from_k8saudit([bare], self.records, self.rules)

    def test_receipts_through_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'rules.jsonl').write_text(''.join(json.dumps({'execution_id': e, 'rule_id': r}) + '\n'
                                                   for e, rules in self.rules.items() for r in sorted(rules)))
            argv = [sys.executable, '-E', '-s', '-B', '-m', 'detect.report.audit_alert_import',
                    '--falco', str(FIXTURES / 'alerts.jsonl'), '--expected-rules', str(d / 'rules.jsonl'),
                    '--out', str(d / 'out.jsonl'), '--provenance', str(d / 'prov.jsonl')]
            for name in ('receipt-a.json', 'receipt-b.json', 'receipt-c.json'):
                argv += ['--receipt', str(FIXTURES / name)]
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['imported_alerts'], 6)


class CLITest(unittest.TestCase):
    def test_writes_new_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'alerts.jsonl').write_text(json.dumps(event()) + '\n')
            (d / 'runs.jsonl').write_text(json.dumps(run()) + '\n')
            (d / 'rules.jsonl').write_text(json.dumps({'execution_id': 'exec-1', 'rule_id': EXEC}) + '\n')
            argv = [sys.executable, '-E', '-s', '-B', '-m', 'detect.report.audit_alert_import', '--falco', str(d / 'alerts.jsonl'),
                    '--runs', str(d / 'runs.jsonl'), '--expected-rules', str(d / 'rules.jsonl'),
                    '--out', str(d / 'out.jsonl'), '--provenance', str(d / 'prov.jsonl')]
            env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
            first = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, env=env)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(json.loads(first.stdout)['imported_alerts'], 1)
            again = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, env=env)
            self.assertEqual(again.returncode, 2)
            self.assertIn('existing evidence', again.stderr)
            receipt = {'run_id': 'smoke-0123', 'execution_id': 'exec-1', 'started_at': START, 'finished_at': END,
                       'namespace': 'warden-smoke-1'}
            (d / 'receipt.json').write_text(json.dumps(receipt) + '\n')
            argv2 = [x for x in argv if x not in ('--runs', str(d / 'runs.jsonl'))]
            argv2 = [x.replace('out.jsonl', 'out2.jsonl').replace('prov.jsonl', 'prov2.jsonl') for x in argv2]
            receipt_run = subprocess.run(argv2 + ['--receipt', str(d / 'receipt.json')], cwd=ROOT, capture_output=True,
                                         text=True, env=env)
            self.assertEqual(receipt_run.returncode, 2, 'receipt run_id and execution_id differ')
            receipt['execution_id'] = 'smoke-0123'
            (d / 'receipt.json').write_text(json.dumps(receipt) + '\n')
            (d / 'rules.jsonl').write_text(json.dumps({'execution_id': 'smoke-0123', 'rule_id': EXEC}) + '\n')
            receipt_run = subprocess.run(argv2 + ['--receipt', str(d / 'receipt.json')], cwd=ROOT, capture_output=True,
                                         text=True, env=env)
            self.assertEqual(receipt_run.returncode, 0, receipt_run.stderr)
            self.assertEqual(json.loads(receipt_run.stdout)['imported_alerts'], 1)


if __name__ == '__main__':
    unittest.main()
