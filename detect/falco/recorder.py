#!/usr/bin/env python3
"""Coverage intervals for detect/report/observation.py, from what a collector kept.

Inputs are one Falco instance's files from detect/falco/collector.py
(heartbeats.jsonl, health.jsonl) and the benign workload's workloads.jsonl
(detect/falco/benign.py). The window [--start, --end) is cut into --period
slices (one hour: one benign hour each; the last slice may be shorter), and
each record is one slice exactly: its end is the next record's start, the
first starts at --start and the last ends at --end. The window should start
at the collector's first healthy point (first_healthy_point: the first
heartbeat after Falco's first counting metrics snapshot), and the collector
should keep beating past --end (the seven-day stop comes 15 minutes later).

A slice is substantiated by the heartbeats that bracket it: the last one at
or before its start and the first one at or after its end. It is healthy
only if both exist and, over all heartbeats between them:
* none are more than --max-gap seconds apart, all saw the Falco container
  running, with one StartedAt and RestartCount and no OOM kill (Docker's
  view), all come from one collector start, and the collector's
  collector_errors and collector_restarts did not grow (an error or a restart
  may have cost an alert even when nothing was counted as dropped);
* every Falco metrics snapshot used has the event and drop counters
  (scap.n_evts and scap.n_drops; the gVisor engine's falco.n_evts and
  falco.n_drops) and they all have the same falco.start_ts (no restart);
* with --snapshot-gap (the host instance, whose modern eBPF engine reports all
  the time), snapshots are never more than that many seconds apart from the
  last one at or before the start to the slice's end.

event_count is Falco's event counter delta: the last snapshot at or before
the end minus the last at or before the start (counting from 0 when there is
none yet, or after a restart). dropped_events adds Falco's own drop counters
(scap.n_drops, falco.outputs_queue_num_drops, falco.n_drops_full_threadtable),
its "syscall event drop" notices, and the collector's dropped_unresolved,
dropped_error, dropped_overflow and dropped_malformed: an alert the collector
could not place may have been a Warden alert. workload_count is the number of
complete benign hours in the slice: successful workloads of every --runtime
that started and ended inside it, the fewest of any one runtime (the hourly
workload must succeed on runc and on gVisor). The explain file lists the
counts per runtime. The receipt names the sha256 of the exact input lines
each record used.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import sys

METRICS_RULE = 'Falco internal: metrics snapshot'
DROP_KEYS = ('scap.n_drops', 'falco.outputs_queue_num_drops', 'falco.n_drops_full_threadtable')
COLLECTOR_DROPS = ('dropped_unresolved', 'dropped_error', 'dropped_overflow', 'dropped_malformed')
# Any increase makes the slice unhealthy: an error may have cost an alert even
# when nothing was counted as dropped, a restart what was pending.
COLLECTOR_TROUBLE = ('collector_errors', 'collector_restarts')
FIELDS = ('source_id', 'start', 'end', 'healthy', 'event_count', 'workload_count', 'dropped_events', 'receipt')
_TS = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?(Z|z|[+-][0-9]{2}:[0-9]{2})')
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def ns(value):
    """RFC3339 with an explicit offset and any number of fraction digits ->
    integer nanoseconds since the epoch."""
    match = _TS.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError('timestamp with an explicit offset required: %r' % (value,))
    zone = '+00:00' if match[3] in ('Z', 'z') else match[3]
    seconds = (datetime.fromisoformat(match[1] + zone) - EPOCH) // timedelta(seconds=1)
    return seconds * 1_000_000_000 + int((match[2] or '0')[:9].ljust(9, '0'))


def sha(lines):
    digest = hashlib.sha256()
    for line in lines:
        digest.update(line.rstrip(b'\n') + b'\n')
    return digest.hexdigest()


def latest(items, limit):
    """The last (t, ...) item with t <= limit, or None."""
    found = None
    for item in items:
        if item[0] <= limit:
            found = item
        else:
            break
    return found


def has_counters(fields):
    return ('scap.n_evts' in fields and 'scap.n_drops' in fields) or ('falco.n_evts' in fields and 'falco.n_drops' in fields)


def counters(snapshot):
    """(falco.start_ts, events, drops). The modern eBPF engine names its
    counters scap.*; Falco 0.43.1's gVisor engine falco.n_evts/falco.n_drops."""
    fields = snapshot['output_fields']
    if 'scap.n_evts' in fields:
        events, keys = fields['scap.n_evts'], DROP_KEYS
    else:
        events, keys = fields.get('falco.n_evts'), ('falco.n_drops',) + DROP_KEYS[1:]
    return fields.get('falco.start_ts'), events, sum(int(fields.get(k) or 0) for k in keys)


def chain_delta(chain):
    """Sum of counter increases along successive snapshots; a new start_ts
    starts again from zero."""
    events = drops = 0
    previous = None
    for snapshot in chain:
        start_ts, n_evts, n_drops = counters(snapshot)
        if previous is not None and previous[0] == start_ts:
            events += max(0, n_evts - previous[1])
            drops += max(0, n_drops - previous[2])
        else:
            events += n_evts
            drops += n_drops
        previous = (start_ts, n_evts, n_drops)
    return events, drops


def fmt(value_ns):
    seconds, fraction = divmod(value_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + '.%09dZ' % fraction


def counting(snapshot):
    fields = snapshot['output_fields']
    events = fields.get('scap.n_evts', fields.get('falco.n_evts'))
    return isinstance(events, int) and events > 0


def first_healthy_point(heartbeats, health):
    """The first heartbeat, with Falco running, at or after Falco's first
    metrics snapshot that shows it counting events; None if there is none yet."""
    snaps = sorted(ns(r['time']) for _, r in health if r.get('rule') == METRICS_RULE and counting(r))
    if not snaps:
        return None
    for t, _, r in sorted((ns(r['time']), raw, r) for raw, r in heartbeats):
        if t >= snaps[0] and (r.get('falco') or {}).get('running') is True:
            return r['time']
    return None


def intervals(heartbeats, health, workloads, *, source_id, runtimes, start, end, period=3600, max_gap=90,
              snapshot_gap=None, explain=None):
    """heartbeats and health are [(raw line, record)]; workloads are records."""
    beats = sorted((ns(r['time']), raw, r) for raw, r in heartbeats)
    snaps, notices = [], []
    for raw, r in health:
        if r.get('rule') == METRICS_RULE:
            snaps.append((ns(r['time']), raw, r))
        elif 'event drop' in r.get('rule', ''):
            notices.append((ns(r['time']), raw, r))
    snaps.sort(key=lambda x: x[0])
    notices.sort(key=lambda x: x[0])
    period_ns, gap_ns = int(period * 1e9), int(max_gap * 1e9)
    snap_gap_ns = None if snapshot_gap is None else int(snapshot_gap * 1e9)
    first, stop = ns(start), ns(end)
    if not first < stop:
        raise ValueError('--start must precede --end')
    bounds = list(range(first, stop, period_ns)) + [stop]
    out = []
    for w0, w1 in zip(bounds, bounds[1:]):
        reasons = []
        a = latest(beats, w0)
        b = next((x for x in beats if x[0] >= w1), None)
        if a is None:
            reasons.append('no heartbeat at or before the start')
        if b is None:
            reasons.append('no heartbeat at or after the end')
        lo = a[0] if a else w0
        hi = b[0] if b else w1
        span = [x for x in beats if lo <= x[0] <= hi]
        if any(right[0] - left[0] > gap_ns for left, right in zip(span, span[1:])):
            reasons.append('heartbeat gap over %ss' % max_gap)
        states = [x[2].get('falco') or {} for x in span]
        if not all(st.get('running') is True and st.get('oom_killed') is False for st in states):
            reasons.append('Falco container not running, or OOM-killed')
        if len({st.get('started_at') for st in states}) > 1 or len({st.get('restart_count') for st in states}) > 1:
            reasons.append('Falco container restarted')
        if len({x[2].get('collector_started_at') for x in span}) > 1:
            reasons.append('collector restarted')
        base = latest(snaps, w0)
        inside = [x for x in snaps if w0 < x[0] <= w1]
        used = ([base] if base else []) + inside
        if not all(has_counters(x[2]['output_fields']) for x in used):
            reasons.append('metrics snapshot without event and drop counters')
            events, drops = 0, 0
        else:
            events, drops = chain_delta([x[2] for x in used])
            if base:
                base_start, base_evts, base_drops = counters(base[2])
                events, drops = events - base_evts, drops - base_drops
                if any(counters(x[2])[0] != base_start for x in inside):
                    reasons.append('Falco restarted (falco.start_ts changed)')
            elif len({counters(x[2])[0] for x in inside}) > 1:
                reasons.append('Falco restarted (falco.start_ts changed)')
        if snap_gap_ns is not None:
            times = ([base[0]] if base else [w0]) + [x[0] for x in inside] + [w1]
            if base is None or any(right - left > snap_gap_ns for left, right in zip(times, times[1:])):
                reasons.append('metrics snapshot gap over %ss' % snapshot_gap)
        drops += sum(1 for x in notices if w0 < x[0] <= w1)
        if span:
            first_counts, last_counts = span[0][2].get('counts') or {}, span[-1][2].get('counts') or {}
            drops += sum(max(0, int(last_counts.get(key, 0)) - int(first_counts.get(key, 0))) for key in COLLECTOR_DROPS)
            for key in COLLECTOR_TROUBLE:
                grew = int(last_counts.get(key, 0)) - int(first_counts.get(key, 0))
                if grew:
                    reasons.append('%s (%d)' % (key.replace('_', ' '), grew))
        done = [w for w in workloads if w.get('runtime') in runtimes and w.get('ok') is True
                and w0 <= ns(w['start']) and ns(w['end']) <= w1]
        per_runtime = {runtime: sum(1 for w in done if w['runtime'] == runtime) for runtime in runtimes}
        receipt = 'heartbeats n=%d sha256:%s; falco-metrics n=%d sha256:%s; drop-notices n=%d; workloads n=%d (%s) sha256:%s' % (
            len(span), sha(x[1] for x in span), len(used), sha(x[1] for x in used),
            sum(1 for x in notices if w0 < x[0] <= w1), len(done), ' '.join('%s=%d' % kv for kv in per_runtime.items()),
            sha(json.dumps(w, sort_keys=True).encode() for w in done))
        record = {'source_id': source_id, 'start': start if w0 == first else fmt(w0), 'end': end if w1 == stop else fmt(w1),
                  'healthy': not reasons, 'event_count': max(0, int(events)), 'workload_count': min(per_runtime.values()),
                  'dropped_events': max(0, int(drops)), 'receipt': receipt}
        out.append(record)
        if explain is not None:
            explain.append({'start': record['start'], 'end': record['end'], 'reasons': reasons, 'workloads': per_runtime})
    return out


def read(paths):
    rows = []
    for path in paths:
        with open(path, 'rb') as source:
            for line in source:
                if line.strip():
                    rows.append((line.rstrip(b'\n'), json.loads(line)))
    return rows


def write_new(path, rows):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        for row in rows:
            out.write(json.dumps(row, sort_keys=True) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--heartbeats', action='append', required=True)
    parser.add_argument('--health', action='append', required=True)
    parser.add_argument('--workloads', action='append', default=[])
    parser.add_argument('--source-id', required=True)
    parser.add_argument('--runtime', action='append', required=True, choices=('runc', 'gvisor'),
                        help="the workloads this source covers; repeat (the host instance: runc and gvisor)")
    parser.add_argument('--start', required=True)
    parser.add_argument('--end', required=True)
    parser.add_argument('--period', type=float, default=3600)
    parser.add_argument('--max-gap', type=float, default=90)
    parser.add_argument('--snapshot-gap', type=float)
    parser.add_argument('--out', required=True)
    parser.add_argument('--explain')
    args = parser.parse_args(argv)
    try:
        for path in (args.out, args.explain):
            if path and os.path.lexists(path):
                raise ValueError('will not overwrite ' + path)
        explain = [] if args.explain else None
        rows = intervals(read(args.heartbeats), read(args.health), [r for _, r in read(args.workloads)],
                         source_id=args.source_id, runtimes=tuple(args.runtime), start=args.start, end=args.end,
                         period=args.period, max_gap=args.max_gap, snapshot_gap=args.snapshot_gap, explain=explain)
        write_new(args.out, rows)
        if explain is not None:
            write_new(args.explain, explain)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('error: %s' % error, file=sys.stderr)
        return 2
    print(json.dumps({'records': len(rows), 'healthy': sum(r['healthy'] for r in rows), 'source_id': args.source_id}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
