"""Convert real k8saudit Falco alerts using the runs' audit run records.

    python3 -B detect/report/audit_alert_import.py --falco ALERTS \\
        (--receipt RUN/receipt.json ... | --runs AUDIT-RUNS) \\
        --expected-rules RULES --out NEW-ALERTS --provenance NEW-PROVENANCE

ALERTS is the k8saudit instance's alerts.jsonl as its collector kept it
(detect/falco/audit_collector.py): Falco JSON events of the k8s_audit source,
with the fields detect/falco/falco-k8saudit.yaml appends to output_fields.
Each run comes from the receipt.json attacks/stratus/emulate.py writes per
run (--receipt, repeated: run_id = execution_id, started_at, finished_at,
namespace, and correlation_id if the receipt has it), or from a run-record
file (--runs; the contract is in docs/falco-detector.md and
detect/README.md), one record per execution:

    {"execution_id": "...", "run_id": "...", "namespaces": ["..."],
     "start": "<RFC3339>", "end": "<RFC3339>", "correlation_id": "<UUID>"}

correlation_id is optional. A receipt becomes {"namespaces": [namespace],
"start": started_at, "end": finished_at, "correlation_id": ...}. An alert
belongs to a run if its event time (Falco's `time`, the audit event's
stageTimestamp) is inside [start, end] and one of:

* correlation ID: the request's User-Agent has the token
  stratus-red-team_<correlation_id> (delimited: the start, the end, or a
  character that cannot be part of it; the UUID alone, or inside a longer
  string, is no match). Stratus sends it with every API request, so
  this also attributes cluster-scoped and kube-system requests and lists
  across all namespaces. It wins over a namespace match of another run; an
  alert whose User-Agent names a run outside that run's window is not
  attributed at all;
* label: a run label of the request body (warden.dev/run or warden_run_id)
  equals the run's run_id;
* namespace: the request's target namespace is one of the run's namespaces.
  This match ignores who made the request, so the namespace must hold
  nothing of an earlier run when a run starts (scripts/kind_lab.sh
  check-empty --audit): a kubelet or controller request about an earlier
  run's leftovers would count for the later run.

The namespaces Kubernetes and kind create for themselves are refused in a
record: the system's own requests there would be attributed to the run. An
alert two runs claim (by correlation ID, label or namespace, the namespace
being outranked by a correlation ID), or a record that is malformed, fails
the whole import. RULES is the reviewed execution-to-rule map (as for
alert_import.py); alerts of other rules are left out. The output is the
format detection_metrics.py reads, the same as alert_import.py's, with
provenance (which key matched, the raw event).

The correlation ID must be the UUID the wrapper gave Stratus in
STRATUS_RED_TEAM_CORRELATION_ID: Stratus v2.38.0 accepts only a UUID there
(v2/pkg/stratus/runner/runner.go resolveCorrelationID) and replaces anything
else with a random UUID it records nowhere. A run without a correlation_id
(the wrapper at dd79f39 passed its run ID and recorded none; 795c5db passes
and records a UUID) has its requests outside warden-lab without a run label
not attributed.

This is temporal association within a run's own correlation ID, label or
namespace, not proof that the run caused the alert. No match does not prove
detector coverage.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
try:
    from .detection_metrics import MetricsError, read_jsonl, timestamp_ns
    from .alert_import import write_new_jsonl
except ImportError:
    from detection_metrics import MetricsError, read_jsonl, timestamp_ns
    from alert_import import write_new_jsonl

RUN_FIELDS = {'execution_id', 'run_id', 'namespaces', 'start', 'end'}
OPTIONAL_RUN_FIELDS = {'correlation_id'}
CORRELATION_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
USER_AGENT_FIELD = 'ka.useragent'
# Stratus's User-Agent token (v2/pkg/stratus/useragent): stratus-red-team_<UUID>,
# alone or appended to another agent (Terraform's provider), so delimited by
# the start, the end, or a character that cannot be part of the token.
STRATUS_TOKEN = re.compile(r'(?<![A-Za-z0-9_.-])stratus-red-team_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
                           r'(?![A-Za-z0-9_.-])')
MAX_RECEIPT_BYTES = 1 << 20
RECEIPT_FIELDS = ('run_id', 'execution_id', 'started_at', 'finished_at', 'namespace')
# The run labels attacks/stratus/emulate.py puts on the pods it configures,
# both with the run ID as value, as falco-k8saudit.yaml appends them (a JSON
# pointer: "/" in a key is written ~1).
RUN_LABELS = ('warden.dev/run', 'warden_run_id')
LABEL_FIELDS = tuple('jevt.value[/requestObject/metadata/labels/%s]' % key.replace('~', '~0').replace('/', '~1')
                     for key in RUN_LABELS)
NAMESPACE_FIELD = 'ka.target.namespace'
# Namespaces of the cluster itself (and kind's storage provisioner).
SHARED_NAMESPACES = frozenset({'default', 'kube-system', 'kube-public', 'kube-node-lease', 'local-path-storage'})
LABEL_VALUE = re.compile(r'[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?')
NAMESPACE = re.compile(r'[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?')
ABSENT = (None, '', '<NA>')


def from_receipt(receipt):
    """The run record of one attacks/stratus/emulate.py receipt.json."""
    if not isinstance(receipt, dict) or any(key not in receipt for key in RECEIPT_FIELDS):
        raise MetricsError('Stratus receipt lacks %s' % ', '.join(RECEIPT_FIELDS))
    if receipt['run_id'] != receipt['execution_id']:
        raise MetricsError('Stratus receipt run_id and execution_id differ')
    if not isinstance(receipt['namespace'], str):
        raise MetricsError('Stratus receipt namespace must be a name')
    record = {'execution_id': receipt['execution_id'], 'run_id': receipt['run_id'], 'namespaces': [receipt['namespace']],
              'start': receipt['started_at'], 'end': receipt['finished_at']}
    if 'correlation_id' in receipt:
        record['correlation_id'] = receipt['correlation_id']
    return record


def read_receipt(path):
    """One receipt.json: a JSON object (the wrapper writes it on one line), at most 1 MiB."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise MetricsError('receipt must be a regular file, not a symlink or special file')
        with open(path, 'rb') as source:
            data = source.read(MAX_RECEIPT_BYTES + 1)
        if len(data) > MAX_RECEIPT_BYTES:
            raise MetricsError('receipt exceeds byte limit')
        return from_receipt(json.loads(data.decode('utf-8')))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, MetricsError):
            raise
        raise MetricsError('cannot read a valid receipt') from exc


def runs_of(records):
    runs, seen, correlations = [], set(), set()
    for record in records:
        if not isinstance(record, dict) or not RUN_FIELDS <= set(record) <= RUN_FIELDS | OPTIONAL_RUN_FIELDS:
            raise MetricsError('audit run record has missing or unknown fields')
        if 'correlation_id' in record:
            if not isinstance(record['correlation_id'], str) or not CORRELATION_ID.fullmatch(record['correlation_id']):
                raise MetricsError('correlation_id must be a lowercase canonical UUID (what Stratus puts in its User-Agent)')
            if record['correlation_id'] in correlations:
                raise MetricsError('duplicate correlation_id in audit run records')
            correlations.add(record['correlation_id'])
        for key in ('execution_id', 'run_id', 'start', 'end'):
            if not isinstance(record[key], str) or not record[key].strip():
                raise MetricsError('audit run record fields must be nonblank strings')
        if not LABEL_VALUE.fullmatch(record['run_id']):
            raise MetricsError('run_id must be a Kubernetes label value (it is the warden_run_id label)')
        if record['run_id'] in seen:
            raise MetricsError('duplicate run_id in audit run records')
        seen.add(record['run_id'])
        namespaces = record['namespaces']
        if not isinstance(namespaces, list) or len(set(map(str, namespaces))) != len(namespaces):
            raise MetricsError('namespaces must be a list of distinct names')
        for name in namespaces:
            if not isinstance(name, str) or not NAMESPACE.fullmatch(name):
                raise MetricsError('invalid namespace name in audit run record')
            if name in SHARED_NAMESPACES:
                raise MetricsError('namespace %s is the cluster\'s own; it cannot identify a run' % name)
        start, end = timestamp_ns(record['start']), timestamp_ns(record['end'])
        if start >= end:
            raise MetricsError('audit run start must precede end')
        runs.append((record, frozenset(namespaces), start, end))
    return runs


def from_k8saudit(events, records, expected_rules):
    if not isinstance(expected_rules, dict) or not expected_rules:
        raise MetricsError('reviewed execution-to-rule map required')
    runs = runs_of(records)
    alerts, provenance = {}, {}
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get('rule'), str) or not event['rule'].strip():
            raise MetricsError('real Falco event requires a nonblank rule')
        stamp = timestamp_ns(event.get('time'))
        fields = event.get('output_fields')
        if not isinstance(fields, dict):
            raise MetricsError('real Falco event requires output_fields')
        if event.get('source') != 'k8s_audit':
            raise MetricsError('not an alert of the k8s_audit source')
        appended = LABEL_FIELDS + (NAMESPACE_FIELD, USER_AGENT_FIELD)
        if any(key not in fields for key in appended):
            raise MetricsError('alert lacks the fields falco-k8saudit.yaml appends (%s)' % ', '.join(appended))
        labels = {fields[key] for key in LABEL_FIELDS} - set(ABSENT)
        namespace = fields[NAMESPACE_FIELD]
        agent = fields[USER_AGENT_FIELD]
        tokens = set(STRATUS_TOKEN.findall(agent)) if isinstance(agent, str) and agent not in ABSENT else set()
        label = sorted(labels)[0] if len(labels) == 1 else (sorted(labels) or None)
        named = [run for run in runs if run[0].get('correlation_id') in tokens]
        if len(named) > 1:
            raise MetricsError('k8saudit alert names more than one run\'s correlation ID')
        inside = [run for run in runs if run[2] <= stamp <= run[3]]
        if named and named[0] not in inside:
            continue  # a run's own request, outside its window: no other run's
        by_label = [run for run in inside if run[0]['run_id'] in labels]
        by_namespace = [run for run in inside if namespace not in ABSENT and namespace in run[1]]
        if named:
            chosen = named[0]
            if any(run is not chosen for run in by_label):
                raise MetricsError('k8saudit alert\'s correlation ID and run label name different runs')
            keys = ['correlation_id'] + (['label'] if chosen in by_label else []) + \
                   (['namespace'] if chosen in by_namespace else [])
        else:
            candidates = {id(run): run for run in by_label + by_namespace}
            if len(candidates) > 1:
                raise MetricsError('k8saudit alert matches more than one run')
            if not candidates:
                continue
            chosen = next(iter(candidates.values()))
            keys = (['label'] if chosen in by_label else []) + (['namespace'] if chosen in by_namespace else [])
        record = chosen[0]
        rules = expected_rules.get(record['execution_id'])
        if not isinstance(rules, (set, frozenset)) or not rules or not all(isinstance(r, str) and r.strip() for r in rules):
            raise MetricsError('reviewed rules missing for execution')
        if event['rule'] not in rules:
            continue
        canonical = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
        alert_id = 'falco-' + hashlib.sha256(canonical.encode()).hexdigest()
        alerts[alert_id] = {'alert_id': alert_id, 'execution_id': record['execution_id'],
                            'rule_id': event['rule'], 'alerted_at': event['time']}
        provenance[alert_id] = {'alert_id': alert_id, 'source': 'falco-k8saudit-json', 'run_id': record['run_id'],
                                'matched_by': keys, 'label': label, 'user_agent': fields.get(USER_AGENT_FIELD),
                                'namespace': None if namespace in ABSENT else namespace,
                                'audit_id': fields.get('ka.auditid'), 'raw_event_sha256': alert_id.removeprefix('falco-'),
                                'raw_event': event,
                                'limitation': 'Temporal association within the run\'s correlation ID, label or namespace; '
                                              'run records and alert input require external validation.'}
    return [alerts[k] for k in sorted(alerts)], [provenance[k] for k in sorted(provenance)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--falco', required=True, help="the k8saudit collector's alerts.jsonl, unaltered")
    parser.add_argument('--receipt', action='append', default=[], help="a run's receipt.json from attacks/stratus/emulate.py; repeat")
    parser.add_argument('--runs', help='audit run records JSONL (one per execution)')
    parser.add_argument('--expected-rules', required=True, help='reviewed JSONL execution_id/rule_id pairs')
    parser.add_argument('--out', required=True, help='new metrics-format alerts JSONL')
    parser.add_argument('--provenance', required=True, help='new source records JSONL')
    args = parser.parse_args(argv)
    try:
        rules = {}
        for item in read_jsonl(args.expected_rules):
            if not isinstance(item, dict) or set(item) != {'execution_id', 'rule_id'} or \
                    not all(isinstance(v, str) and v.strip() for v in item.values()):
                raise MetricsError('invalid reviewed rule mapping')
            rules.setdefault(item['execution_id'], set()).add(item['rule_id'])
        if not args.receipt and not args.runs:
            raise MetricsError('--receipt or --runs required')
        records = [read_receipt(path) for path in args.receipt] + (read_jsonl(args.runs) if args.runs else [])
        alerts, provenance = from_k8saudit(read_jsonl(args.falco), records, rules)
        if os.path.lexists(args.out) or os.path.lexists(args.provenance) or \
                os.path.abspath(args.out) == os.path.abspath(args.provenance):
            raise MetricsError('distinct new output paths required; existing evidence will not be overwritten')
        write_new_jsonl(args.provenance, provenance)
        write_new_jsonl(args.out, alerts)
        print(json.dumps({'imported_alerts': len(alerts), 'source': 'supplied-falco-k8saudit-json',
                          'limitation': 'No matches does not prove detector or collector coverage.'}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
