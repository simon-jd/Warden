"""Convert real Falco JSON alerts using explicit trusted container bindings.

Raw audit entries, successful commands, expected signals and empty streams are
never converted into detections. Original records remain in provenance JSONL.
"""
import argparse
import hashlib
import json
import os
import re
import sys
try:
    from .detection_metrics import MetricsError, read_jsonl, timestamp_ns
except ImportError:
    from detection_metrics import MetricsError, read_jsonl, timestamp_ns

BINDING_FIELDS = {'execution_id', 'run_id', 'container_id', 'start', 'end'}


def from_falco(events, bindings, expected_rules):
    if not isinstance(expected_rules, dict) or not expected_rules:
        raise MetricsError("reviewed execution-to-rule map required")
    trusted = []
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != BINDING_FIELDS:
            raise MetricsError('binding has missing or unknown fields')
        if not all(isinstance(binding[key], str) and binding[key].strip() for key in BINDING_FIELDS):
            raise MetricsError('binding fields must be nonblank strings')
        if not re.fullmatch('[a-f0-9]{64}', binding['container_id']):
            raise MetricsError('trusted full container ID required')
        start, end = map(timestamp_ns, (binding['start'], binding['end']))
        if start >= end:
            raise MetricsError('binding start must precede end')
        trusted.append((binding, start, end))
    alerts, provenance = {}, {}
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get('rule'), str) or not event['rule'].strip():
            raise MetricsError('real Falco event requires a nonblank rule')
        stamp = timestamp_ns(event.get('time'))
        fields = event.get('output_fields')
        if not isinstance(fields, dict):
            raise MetricsError('real Falco event requires output_fields')
        container_id = fields.get('container.id')
        # Events unrelated to a container are retained by the collector, but
        # cannot be mapped to a container-bound emulation execution.
        if container_id in (None, '', '<NA>', 'host'):
            continue
        if not isinstance(container_id, str) or not re.fullmatch('[a-f0-9]{12,64}', container_id):
            raise MetricsError('invalid Falco container identity')
        matches = [(binding, start, end) for binding, start, end in trusted
                   if binding['container_id'].startswith(container_id) and start <= stamp <= end]
        unique = {(binding['execution_id'], binding['run_id'], binding['container_id']) for binding, _, _ in matches}
        if len(unique) > 1:
            raise MetricsError('Falco container identity has ambiguous execution binding')
        if not matches:
            continue
        binding = matches[0][0]
        rules = expected_rules.get(binding['execution_id'])
        if not isinstance(rules, (set, frozenset)) or not rules or not all(isinstance(rule, str) and rule.strip() for rule in rules):
            raise MetricsError('reviewed rules missing for execution')
        if event['rule'] not in rules:
            continue
        canonical = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
        alert_id = 'falco-' + hashlib.sha256(canonical.encode()).hexdigest()
        alerts[alert_id] = {'alert_id': alert_id, 'execution_id': binding['execution_id'],
                            'rule_id': event['rule'], 'alerted_at': event['time']}
        provenance[alert_id] = {'alert_id': alert_id, 'source': 'falco-json',
                                'run_id': binding['run_id'], 'container_id': binding['container_id'],
                                'raw_event_sha256': alert_id.removeprefix('falco-'), 'raw_event': event,
                                'limitation': 'Input and trusted binding provenance require external validation.'}
    return ([alerts[key] for key in sorted(alerts)], [provenance[key] for key in sorted(provenance)])


def write_new_jsonl(path, rows):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        for row in rows:
            output.write(json.dumps(row, sort_keys=True, allow_nan=False) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--falco', required=True, help='unaltered real Falco JSONL export')
    parser.add_argument('--bindings', required=True, help='trusted collector container/run bindings JSONL')
    parser.add_argument('--expected-rules', required=True, help='reviewed JSONL execution_id/rule_id pairs')
    parser.add_argument('--out', required=True, help='new metrics-format alerts JSONL')
    parser.add_argument('--provenance', required=True, help='new source records JSONL')
    args = parser.parse_args(argv)
    try:
        rules = {}
        for item in read_jsonl(args.expected_rules):
            if not isinstance(item, dict) or set(item) != {'execution_id', 'rule_id'} or not all(isinstance(v, str) and v.strip() for v in item.values()):
                raise MetricsError('invalid reviewed rule mapping')
            rules.setdefault(item['execution_id'], set()).add(item['rule_id'])
        alerts, provenance = from_falco(read_jsonl(args.falco), read_jsonl(args.bindings), rules)
        if os.path.lexists(args.out) or os.path.lexists(args.provenance) or os.path.abspath(args.out) == os.path.abspath(args.provenance):
            raise MetricsError('distinct new output paths required; existing evidence will not be overwritten')
        write_new_jsonl(args.provenance, provenance)
        write_new_jsonl(args.out, alerts)
        print(json.dumps({'imported_alerts': len(alerts), 'source': 'supplied-falco-json',
                          'limitation': 'No matches does not prove detector or collector coverage.'}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
