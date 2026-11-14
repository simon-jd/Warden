#!/usr/bin/env python3
"""Bulk review of kept Falco alerts: group them, then apply a person's dispositions.

    review.py groups --alerts A.jsonl --scoping S.jsonl [...] --out groups.jsonl [--template map.jsonl]
    review.py apply  --alerts A.jsonl --scoping S.jsonl [...] --map map.jsonl --out normal-alerts.jsonl
                     --report report.json [--start T --end T]

The stock rules stay untuned, so Warden's own labs raise alerts every hour
(docs/falco-detector.md). A group is a reviewed signature: the rule, the
process name (proc.name) and the container class the collector gave the
alert (sandbox: a Warden run; node: the k3s node; lab: other lab
containers; unknown: no scoping record), with its count and first and last
time. --template writes one mapping line per group with disposition
"unreviewed": it is a form for a person, not a decision.

The map is written by a person: one JSON object per line with exactly rule,
process, class and disposition (false_positive, true_positive or unreviewed).
apply gives every alert of a mapped group that disposition and every other
alert "unreviewed": this tool never decides one itself. The output has
observation.py's and detection_metrics.py's normal-alert fields (alert_id,
rule_id, alerted_at, disposition); alert_id is alert_import.py's
falco-<sha256 of the canonical event>. The report gives the counts per group
and disposition, false positives per group, and the mappings that matched no
group. Existing outputs are never overwritten.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import sys

DISPOSITIONS = ('false_positive', 'true_positive', 'unreviewed')
MAP_FIELDS = {'rule', 'process', 'class', 'disposition'}
_TS = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?(Z|z|[+-][0-9]{2}:[0-9]{2})')
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def ns(value):
    match = _TS.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError('timestamp with an explicit offset required: %r' % (value,))
    zone = '+00:00' if match[3] in ('Z', 'z') else match[3]
    seconds = (datetime.fromisoformat(match[1] + zone) - EPOCH) // timedelta(seconds=1)
    return seconds * 1_000_000_000 + int((match[2] or '0')[:9].ljust(9, '0'))


def digest(event):
    text = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(text.encode()).hexdigest()


def signature(event, classes):
    process = (event.get('output_fields') or {}).get('proc.name')
    return event['rule'], process if isinstance(process, str) else '<none>', classes.get(digest(event), 'unknown')


def class_index(scopings):
    return {s['raw_event_sha256']: s.get('class') or 'unknown' for s in scopings if 'raw_event_sha256' in s}


def unique(alerts):
    """Alerts by alert_id; an exact duplicate raw event is one alert."""
    seen = {}
    for event in alerts:
        seen.setdefault(digest(event), event)
    return seen


def groups(alerts, scopings):
    classes, out = class_index(scopings), {}
    for event in unique(alerts).values():
        key = signature(event, classes)
        g = out.setdefault(key, {'rule': key[0], 'process': key[1], 'class': key[2], 'count': 0,
                                 'first': event['time'], 'last': event['time']})
        g['count'] += 1
        g['first'] = min(g['first'], event['time'], key=ns)
        g['last'] = max(g['last'], event['time'], key=ns)
    return [out[k] for k in sorted(out)]


def template(found):
    return [{'rule': g['rule'], 'process': g['process'], 'class': g['class'], 'disposition': 'unreviewed'} for g in found]


def read_map(entries):
    mapping = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != MAP_FIELDS:
            raise ValueError('a map line needs exactly rule, process, class and disposition: %r' % (entry,))
        if entry['disposition'] not in DISPOSITIONS or not all(isinstance(entry[k], str) and entry[k] for k in MAP_FIELDS):
            raise ValueError('invalid map line: %r' % (entry,))
        key = (entry['rule'], entry['process'], entry['class'])
        if key in mapping and mapping[key] != entry['disposition']:
            raise ValueError('conflicting dispositions for %r' % (key,))
        mapping[key] = entry['disposition']
    return mapping


def apply(alerts, scopings, entries, start=None, end=None):
    mapping = read_map(entries)
    classes = class_index(scopings)
    lo = ns(start) if start else None
    hi = ns(end) if end else None
    rows, per_group = [], {}
    for alert_id, event in unique(alerts).items():
        t = ns(event['time'])
        if (lo is not None and t < lo) or (hi is not None and t >= hi):
            continue
        key = signature(event, classes)
        disposition = mapping.get(key, 'unreviewed')
        rows.append({'alert_id': 'falco-' + alert_id, 'rule_id': event['rule'], 'alerted_at': event['time'],
                     'disposition': disposition})
        g = per_group.setdefault(key, dict({'rule': key[0], 'process': key[1], 'class': key[2], 'count': 0,
                                            'disposition': disposition}, **dict.fromkeys(DISPOSITIONS, 0)))
        g['count'] += 1
        g[disposition] += 1
    totals = {d: sum(g[d] for g in per_group.values()) for d in DISPOSITIONS}
    unmatched = [{'rule': k[0], 'process': k[1], 'class': k[2], 'disposition': v} for k, v in sorted(mapping.items())
                 if k not in per_group]
    report = dict(totals, alerts=len(rows), groups=[per_group[k] for k in sorted(per_group)], unmatched_mappings=unmatched,
                  limitation='Dispositions are the reviewer\'s; unmapped groups stay unreviewed.')
    return rows, report


def read_jsonl(paths):
    rows = []
    for path in paths:
        with open(path) as source:
            rows += [json.loads(line) for line in source if line.strip()]
    return rows


def write_new(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(text)


def jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('groups', 'apply'))
    parser.add_argument('--alerts', action='append', required=True, help="a collector's alerts.jsonl; repeat")
    parser.add_argument('--scoping', action='append', default=[], help='its scoping.jsonl; repeat')
    parser.add_argument('--out', required=True)
    parser.add_argument('--template')
    parser.add_argument('--map')
    parser.add_argument('--report')
    parser.add_argument('--start')
    parser.add_argument('--end')
    args = parser.parse_args(argv)
    try:
        for path in (args.out, args.template, args.report):
            if path and os.path.lexists(path):
                raise ValueError('will not overwrite ' + path)
        alerts, scopings = read_jsonl(args.alerts), read_jsonl(args.scoping)
        if args.command == 'groups':
            found = groups(alerts, scopings)
            write_new(args.out, jsonl(found))
            if args.template:
                write_new(args.template, jsonl(template(found)))
            print(json.dumps({'groups': len(found), 'alerts': sum(g['count'] for g in found)}))
        else:
            if not args.map or not args.report:
                raise ValueError('apply needs --map and --report')
            rows, report = apply(alerts, scopings, read_jsonl([args.map]), args.start, args.end)
            write_new(args.out, jsonl(rows))
            write_new(args.report, json.dumps(report, indent=1, sort_keys=True) + '\n')
            print(json.dumps({k: report[k] for k in ('alerts',) + DISPOSITIONS}))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('error: %s' % error, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
