#!/usr/bin/env python3
"""Feed the kind audit lab's API audit log to the k8saudit Falco instance; keep its alerts.

    audit_collector.py --audit-log LOG --audit-fifo IN --fifo OUT --fifo-gid GID \\
        --out DIR --falco-container NAME

The k8saudit instance (docs/falco-detector.md) has no network and no
capabilities, so it neither receives the API server's audit webhook nor
reads the API server's files itself. This collector does both ends:

* feed: follows LOG, the audit log kube-apiserver appends to in the kind node
  (scripts/kind_lab.sh up --audit bind-mounts it from the worktree, owned by
  this user), from its size when the collector starts, and writes every
  complete line into the FIFO IN, which the k8saudit plugin reads as a plain
  file. A line is forwarded only whole; a partial line waits for its newline.
  A line of 64 KiB or more (with its newline) is not forwarded: the plugin's
  reader stops at its first longer line, which would end the source. It is
  counted (audit_oversize) and its auditID, stage and length go to
  oversize.jsonl. feed.jsonl records each forwarded line: auditID, stage,
  stageTimestamp, offset, length and fed_at, when its write into IN
  returned. A log that shrinks or is replaced counts audit_truncations and is
  followed from its start.
* reader: reads Falco's file_output from the FIFO OUT, as collector.py does
  (opened read-write, so a writer closing it after each alert is no EOF),
  and stamps each line when it is read (read_at).

Every line Falco writes is one of:
* an alert of the k8s_audit source: alerts.jsonl, byte for byte as Falco
  wrote it, and arrivals.jsonl: its canonical SHA256 (the digest
  alert_import.py and audit_alert_import.py give it), rule, event time,
  read_at, and written_at, after alerts.jsonl was flushed. Every alert is
  kept: this instance reads only the lab's audit log, so there is no other
  project's alert to drop;
* Falco's own events (source internal: the metrics snapshots): health.jsonl;
* anything else: counted (dropped_malformed, dropped_other_source).

heartbeats.jsonl gets one record every --heartbeat seconds and at once on
SIGUSR1: the Falco container's state from Docker, the counters and the feed's
position. If Falco stops reading IN, the feed's next write fails: that is
counted once (feed_reader_gone, with the time) and the feed stops, as it
does at every down; a reader gone before the window's cutoff is a gap.

coverage() turns these files into health records in the ledger's format
(recorder.py's FIELDS) for source falco-k8saudit; see its docstring for
what makes a slice healthy. The seven-day window does not read them: its
only source is falco-host. Standard library only, and collector.py's FIFO
and Docker helpers.
"""
import argparse
import hashlib
import json
import os
import queue
import signal
import stat
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collector  # noqa: E402  (this directory, made explicit: the unit runs python3 -I)
import recorder  # noqa: E402

SOURCE_ID = 'falco-k8saudit'
# Counters whose growth inside a slice is a dropped or unforwarded line.
DROPS = ('dropped_malformed', 'dropped_other_source', 'dropped_overflow', 'audit_oversize', 'audit_truncations')
TROUBLE = ('collector_errors', 'collector_restarts', 'feed_reader_gone')
# How far Falco's event count may trail the lines fed before a snapshot.
FALCO_LAG_NS = 2_000_000_000
STAMP_SLACK_NS = 100_000_000
# The plugin reads IN with bufio.Scanner's default buffer (64 KiB): a token
# must fit in it with room for its newline.
FORWARD_LIMIT = 64 * 1024 - 1
MAX_LINE = collector.MAX_LINE
COUNTERS = ('received', 'alerts', 'health_events', 'duplicates', 'dropped_malformed', 'dropped_other_source',
            'dropped_overflow', 'collector_errors', 'collector_restarts', 'audit_lines_fed', 'audit_bytes_fed',
            'audit_oversize', 'audit_unparsed', 'audit_truncations', 'feed_reader_gone')


def audit_fields(line):
    """auditID, stage and stageTimestamp of one audit log line (None if it is not an audit event)."""
    try:
        event = json.loads(line)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(event, dict):
        return None
    return {'audit_id': event.get('auditID'), 'stage': event.get('stage'), 'stage_timestamp': event.get('stageTimestamp')}


def classify(raw):
    """'alert', 'health', 'other' or 'malformed', and the event."""
    try:
        event = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return 'malformed', None
    if (not isinstance(event, dict) or not isinstance(event.get('rule'), str) or not isinstance(event.get('time'), str)
            or not isinstance(event.get('output_fields'), dict)):
        return 'malformed', None
    if event.get('source') == 'internal' or event['rule'].startswith('Falco internal:'):
        return 'health', event
    if event.get('source') == 'k8s_audit':
        return 'alert', event
    return 'other', event


class Counts:
    def __init__(self):
        self.values = dict.fromkeys(COUNTERS, 0)
        self.lock = threading.Lock()

    def count(self, name, n=1):
        with self.lock:
            self.values[name] += n

    def snapshot(self):
        with self.lock:
            return dict(self.values)


class Feed:
    """Follow the audit log and write its complete lines into the plugin's FIFO."""

    def __init__(self, log_path, fifo_path, sink, counts, clock_ns=time.time_ns, poll=0.01, sleep=time.sleep):
        self.log_path, self.fifo_path, self.sink, self.counts = log_path, fifo_path, sink, counts
        self.clock_ns, self.poll, self.sleep = clock_ns, poll, sleep
        self.log = os.open(log_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(self.log)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError('the audit log is not a regular file: ' + log_path)
        self.inode = (info.st_dev, info.st_ino)
        # From the log's size now: what the API server wrote before is not fed.
        self.start_offset = self.offset = info.st_size
        os.lseek(self.log, self.offset, os.SEEK_SET)
        self.buffer, self.fifo, self.alive, self.reader_gone_at = b'', None, False, None

    def position(self):
        try:
            size = os.stat(self.log_path).st_size
        except OSError:
            size = None
        return {'path': self.log_path, 'start_offset': self.start_offset, 'offset': self.offset,
                'buffered': len(self.buffer), 'size': size, 'fifo_open': self.fifo is not None, 'alive': self.alive,
                'reader_gone_at': self.reader_gone_at}

    def open_fifo(self):
        # Blocks until Falco opens the FIFO for reading.
        self.fifo = os.open(self.fifo_path, os.O_WRONLY | os.O_CLOEXEC)

    def write(self, data):
        view = memoryview(data)
        while view:
            view = view[os.write(self.fifo, view):]

    def forward(self, line, offset):
        """One complete line (without its newline) at offset in the log."""
        if len(line) + 1 > FORWARD_LIMIT:
            self.counts.count('audit_oversize')
            fields = audit_fields(line) or {}
            self.sink.write('oversize.jsonl', {**fields, 'offset': offset, 'bytes': len(line) + 1,
                                               'seen_at': collector.now_rfc3339(self.clock_ns())})
            return
        fields = audit_fields(line)
        if fields is None:
            self.counts.count('audit_unparsed')
            fields = {}
        self.write(line + b'\n')
        self.counts.count('audit_lines_fed')
        self.counts.count('audit_bytes_fed', len(line) + 1)
        self.sink.write('feed.jsonl', {**fields, 'offset': offset, 'bytes': len(line) + 1,
                                       'fed_at': collector.now_rfc3339(self.clock_ns())})

    def reopen_if_replaced(self):
        try:
            info = os.stat(self.log_path)
        except OSError:
            return
        current = os.fstat(self.log)
        if (info.st_dev, info.st_ino) != self.inode or current.st_size < self.offset:
            self.counts.count('audit_truncations')
            os.close(self.log)
            self.log = os.open(self.log_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            info = os.fstat(self.log)
            self.inode, self.offset, self.buffer = (info.st_dev, info.st_ino), 0, b''

    def step(self):
        """Read what the log has now and forward its complete lines; False if there was nothing."""
        self.reopen_if_replaced()
        chunk = os.read(self.log, 1 << 20)
        if not chunk:
            return False
        base = self.offset - len(self.buffer)
        self.offset += len(chunk)
        self.buffer += chunk
        start = 0
        while True:
            newline = self.buffer.find(b'\n', start)
            if newline < 0:
                break
            line = self.buffer[start:newline]
            if line.strip():
                self.forward(line, base + start)
            start = newline + 1
        self.buffer = self.buffer[start:]
        if len(self.buffer) > MAX_LINE:  # a line longer than any audit event: counted, never forwarded
            self.counts.count('audit_oversize')
            self.sink.write('oversize.jsonl', {'offset': self.offset - len(self.buffer), 'bytes': len(self.buffer),
                                               'seen_at': collector.now_rfc3339(self.clock_ns()), 'unterminated': True})
            self.buffer = b''
        return True

    def run(self, stop):
        try:
            self.open_fifo()
            self.alive = True
            while not stop.is_set():
                if not self.step():
                    self.sleep(self.poll)
        except BrokenPipeError:
            self.counts.count('feed_reader_gone')
            self.reader_gone_at = collector.now_rfc3339(self.clock_ns())
        except Exception as error:  # noqa: BLE001 -- counted; the heartbeat shows the feed stopped
            self.counts.count('collector_errors')
            print('audit feed failed: %s' % type(error).__name__, file=sys.stderr, flush=True)
        finally:
            self.alive = False


def read_stamped(fd, out, stop, counts, clock_ns=time.time_ns):
    """Falco's output lines, each with the time it was read."""
    buffer, skipping = b'', False
    while not stop.is_set():
        chunk = os.read(fd, 1 << 16)
        if not chunk:
            continue
        read_at = clock_ns()
        buffer += chunk
        while True:
            newline = buffer.find(b'\n')
            if newline < 0:
                if len(buffer) > MAX_LINE:
                    buffer, skipping = b'', True
                break
            line, buffer = buffer[:newline], buffer[newline + 1:]
            if skipping:
                skipping = False
                counts.count('received')
                counts.count('dropped_malformed')
                continue
            if line.strip():
                try:
                    out.put_nowait((line, read_at))
                except queue.Full:
                    counts.count('received')
                    counts.count('dropped_overflow')


class Keeper:
    """Writes what Falco sent: alerts (with their arrival), health events."""

    def __init__(self, sink, counts, clock_ns=time.time_ns):
        self.sink, self.counts, self.clock_ns = sink, counts, clock_ns
        self.kept = {'alerts': set(), 'health': set()}

    def load_kept(self, out):
        for line in collector._lines(os.path.join(out, 'alerts.jsonl')):
            try:
                self.kept['alerts'].add(collector.canonical_sha256(json.loads(line)))
            except ValueError:
                pass
        for line in collector._lines(os.path.join(out, 'health.jsonl')):
            self.kept['health'].add(hashlib.sha256(line.rstrip(b'\n')).hexdigest())

    def feed(self, raw, read_at):
        self.counts.count('received')
        kind, event = classify(raw)
        if kind == 'malformed':
            self.counts.count('dropped_malformed')
        elif kind == 'other':
            self.counts.count('dropped_other_source')
        elif kind == 'health':
            digest = hashlib.sha256(raw.rstrip(b'\n')).hexdigest()
            if digest not in self.kept['health']:
                self.sink.write('health.jsonl', raw)
                self.kept['health'].add(digest)
                self.counts.count('health_events')
        else:
            digest = collector.canonical_sha256(event)
            if digest in self.kept['alerts']:
                self.counts.count('duplicates')
                return
            self.sink.write('alerts.jsonl', raw)
            written_at = self.clock_ns()
            self.kept['alerts'].add(digest)
            self.sink.write('arrivals.jsonl', {'raw_event_sha256': digest, 'rule': event['rule'], 'time': event['time'],
                                               'read_at': collector.now_rfc3339(read_at),
                                               'written_at': collector.now_rfc3339(written_at)})
            self.counts.count('alerts')


def coverage(heartbeats, health, feed_rows, *, start, end, period=3600, max_gap=90, snapshot_gap=150, explain=None):
    """Health records of the k8saudit instance, one per slice of [start, end].

    heartbeats and health are [(raw line, record)], feed_rows the records of
    feed.jsonl. A slice is healthy only if heartbeats bracket it and are never
    more than max_gap seconds apart, all saw the same running Falco container
    (no restart, no OOM kill) and one collector start with the feed alive and
    its FIFO open, collector_errors, collector_restarts and feed_reader_gone
    did not grow, metrics snapshots are never more than snapshot_gap seconds
    apart, and at every snapshot in it Falco's event count (falco.num_evts)
    is at most the lines fed by then (0.1 s slack for the stamp) and at least
    the lines fed two seconds earlier: no line lost, none waiting longer. event_count is the lines fed
    in the slice; dropped_events the growth of the drop counters (DROPS) plus
    falco.outputs_queue_num_drops; workload_count is 0 (no benign workload).
    """
    beats = sorted((recorder.ns(r['time']), raw, r) for raw, r in heartbeats)
    snaps = sorted((recorder.ns(r['time']), raw, r) for raw, r in health if r.get('rule') == recorder.METRICS_RULE)
    fed = sorted(recorder.ns(r['fed_at']) for r in feed_rows)

    def fed_by(t):
        lo, hi = 0, len(fed)
        while lo < hi:
            mid = (lo + hi) // 2
            if fed[mid] <= t:
                lo = mid + 1
            else:
                hi = mid
        return lo

    first, stop = recorder.ns(start), recorder.ns(end)
    if not first < stop:
        raise ValueError('start must precede end')
    period_ns, gap_ns, snap_gap_ns = int(period * 1e9), int(max_gap * 1e9), int(snapshot_gap * 1e9)
    bounds = list(range(first, stop, period_ns)) + [stop]
    out = []
    for w0, w1 in zip(bounds, bounds[1:]):
        reasons = []
        a = recorder.latest(beats, w0)
        b = next((x for x in beats if x[0] >= w1), None)
        if a is None:
            reasons.append('no heartbeat at or before the start')
        if b is None:
            reasons.append('no heartbeat at or after the end')
        lo, hi = (a[0] if a else w0), (b[0] if b else w1)
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
        if not all((x[2].get('feed') or {}).get('alive') is True and (x[2].get('feed') or {}).get('fifo_open') is True
                   for x in span):
            reasons.append('feed not writing into the open FIFO')
        drops = 0
        if span:
            c0, c1 = span[0][2].get('counts') or {}, span[-1][2].get('counts') or {}
            drops += sum(max(0, int(c1.get(k, 0)) - int(c0.get(k, 0))) for k in DROPS)
            for key in TROUBLE:
                grew = int(c1.get(key, 0)) - int(c0.get(key, 0))
                if grew:
                    reasons.append('%s (%d)' % (key.replace('_', ' '), grew))
        base = recorder.latest(snaps, w0)
        inside = [x for x in snaps if w0 < x[0] <= w1]
        times = ([base[0]] if base else [w0]) + [x[0] for x in inside] + [w1]
        if base is None or any(right - left > snap_gap_ns for left, right in zip(times, times[1:])):
            reasons.append('metrics snapshot gap over %ss' % snapshot_gap)
        used = ([base] if base else []) + inside
        queue_drops = [int((x[2]['output_fields'] or {}).get('falco.outputs_queue_num_drops') or 0) for x in used]
        if len(queue_drops) > 1:
            drops += max(0, queue_drops[-1] - queue_drops[0])
        elif queue_drops:
            drops += queue_drops[0]
        for t, _, snap in inside:
            events = (snap.get('output_fields') or {}).get('falco.num_evts')
            if not isinstance(events, int):
                reasons.append('metrics snapshot without falco.num_evts')
                break
            # fed_at is stamped just after the write returns, so a line Falco
            # counted may carry a stamp a little after the snapshot.
            if not fed_by(t - FALCO_LAG_NS) <= events <= fed_by(t + STAMP_SLACK_NS):
                reasons.append('Falco counted %d events at %s against %d lines fed by then (%d two seconds before)' % (
                    events, snap['time'], fed_by(t + STAMP_SLACK_NS), fed_by(t - FALCO_LAG_NS)))
        events = fed_by(w1) - fed_by(w0)
        receipt = 'heartbeats n=%d sha256:%s; falco-metrics n=%d sha256:%s; feed lines n=%d' % (
            len(span), recorder.sha(x[1] for x in span), len(used), recorder.sha(x[1] for x in used), events)
        record = {'source_id': SOURCE_ID, 'start': start if w0 == first else recorder.fmt(w0),
                  'end': end if w1 == stop else recorder.fmt(w1), 'healthy': not reasons, 'event_count': events,
                  'workload_count': 0, 'dropped_events': drops, 'receipt': receipt}
        out.append(record)
        if explain is not None:
            explain.append({'start': record['start'], 'end': record['end'], 'reasons': reasons})
    return out


def make_fifo(path, gid, mode):
    """Create (or reuse) a FIFO of this user's, group gid, without ACLs."""
    try:
        os.mkfifo(path, 0o600)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISFIFO(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError('not our FIFO: ' + path)
    collector.drop_acl(path)
    os.chown(path, -1, gid, follow_symlinks=False)
    os.chmod(path, mode)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--audit-log', required=True, help="the kind audit lab's API audit log")
    parser.add_argument('--audit-fifo', required=True, help='FIFO the k8saudit plugin reads')
    parser.add_argument('--fifo', required=True, help="FIFO Falco's file_output writes")
    parser.add_argument('--fifo-gid', type=int, required=True, help='group the Falco container opens both FIFOs as')
    parser.add_argument('--out', required=True, help='private directory for the JSONL files')
    parser.add_argument('--falco-container', required=True)
    parser.add_argument('--docker-socket', default='/var/run/docker.sock')
    parser.add_argument('--heartbeat', type=float, default=30.0)
    parser.add_argument('--poll', type=float, default=0.01, help='seconds between reads of the audit log when it has nothing new')
    args = parser.parse_args(argv)
    stop, flush = threading.Event(), threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGUSR1, lambda *_: flush.set())
    restarts = collector.previous_starts(args.out)
    sink = collector.Sink(args.out)
    counts = Counts()
    counts.count('collector_restarts', restarts)
    keeper = Keeper(sink, counts)
    keeper.load_kept(args.out)
    docker = collector.DockerAPI(args.docker_socket)
    # Falco writes OUT (group write) and reads IN (group read).
    make_fifo(args.audit_fifo, args.fifo_gid, 0o640)
    fd = collector.open_fifo(args.fifo, args.fifo_gid)
    feed = Feed(args.audit_log, args.audit_fifo, sink, counts, poll=args.poll)
    started = collector.now_rfc3339()
    lines = queue.Queue(maxsize=200000)
    reader = threading.Thread(target=read_stamped, args=(fd, lines, stop, counts), daemon=True)
    feeder = threading.Thread(target=feed.run, args=(stop,), daemon=True)
    reader.start()
    feeder.start()
    print('audit collector: feeding %s from byte %d into %s, reading %s, writing %s (start %d)' % (
        args.audit_log, feed.start_offset, args.audit_fifo, args.fifo, args.out, restarts), flush=True)

    def heartbeat():
        sink.write('heartbeats.jsonl', {'time': collector.now_rfc3339(), 'instance': 'k8saudit', 'collector_started_at': started,
                                        'falco': collector.falco_state(docker, args.falco_container),
                                        'counts': counts.snapshot(), 'feed': feed.position()})
        sink.sync()

    next_beat, status = time.monotonic(), 0
    while True:
        try:
            raw, read_at = lines.get(timeout=0.2)
            keeper.feed(raw, read_at)
        except queue.Empty:
            pass
        except Exception as error:  # noqa: BLE001 -- counted, never fatal
            counts.count('collector_errors')
            print('audit collector step failed: %s' % type(error).__name__, file=sys.stderr, flush=True)
        if flush.is_set() or time.monotonic() >= next_beat:
            flush.clear()
            try:
                heartbeat()
            except Exception as error:  # noqa: BLE001
                counts.count('collector_errors')
                print('heartbeat failed: %s' % type(error).__name__, file=sys.stderr, flush=True)
            next_beat = time.monotonic() + args.heartbeat
        if stop.is_set() and lines.empty():
            break
        if not reader.is_alive():
            print('audit collector: the FIFO reader stopped', file=sys.stderr, flush=True)
            status = 1
            break
    try:
        heartbeat()
    except Exception as error:  # noqa: BLE001
        print('final heartbeat failed: %s' % type(error).__name__, file=sys.stderr, flush=True)
    print('audit collector: stopped, %s' % json.dumps(counts.snapshot(), sort_keys=True), flush=True)
    sink.close()
    return status


if __name__ == '__main__':
    sys.exit(main())
