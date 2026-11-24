"""detect/falco/audit_collector.py: the audit log feed, what it keeps of
Falco's output, and the health records. Synthetic files and pipes only."""
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest

try:
    from detect.falco import audit_collector as ac
    from detect.falco import collector
except ImportError:
    ac = collector = None


def audit_line(audit_id, stage='ResponseComplete', size=None):
    record = {'kind': 'Event', 'apiVersion': 'audit.k8s.io/v1', 'auditID': audit_id, 'stage': stage,
              'stageTimestamp': '2026-11-14T18:00:00.000001Z'}
    line = json.dumps(record, separators=(',', ':')).encode()
    if size is not None:
        record['pad'] = 'x' * (size - len(line) - 9)
        line = json.dumps(record, separators=(',', ':')).encode()
    return line


class Base(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(ac, 'detect/falco/audit_collector.py missing')
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.d = Path(self.dir.name)
        self.sink = collector.Sink(str(self.d / 'out'))
        self.addCleanup(self.sink.close)
        self.counts = ac.Counts()

    def rows(self, name):
        path = self.d / 'out' / name
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class FeedTest(Base):
    def feed(self, initial=b''):
        log = self.d / 'audit.log'
        log.write_bytes(initial)
        feed = ac.Feed(str(log), str(self.d / 'unused.fifo'), self.sink, self.counts, clock_ns=lambda: 1_794_680_000_000_000_000)
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        feed.fifo = write_end
        self.addCleanup(lambda: os.close(feed.fifo))
        return feed, log, read_end

    def test_starts_at_the_end_and_forwards_only_whole_lines(self):
        feed, log, out = self.feed(audit_line('before') + b'\n')
        self.assertFalse(feed.step(), 'what was in the log at start is not fed')
        with open(log, 'ab') as w:
            w.write(audit_line('one') + b'\n' + audit_line('two')[:20])
        self.assertTrue(feed.step())
        self.assertEqual(os.read(out, 1 << 16), audit_line('one') + b'\n')
        with open(log, 'ab') as w:
            w.write(audit_line('two')[20:] + b'\n')
        feed.step()
        self.assertEqual(os.read(out, 1 << 16), audit_line('two') + b'\n')
        fed = self.rows('feed.jsonl')
        self.assertEqual([r['audit_id'] for r in fed], ['one', 'two'])
        self.assertEqual(fed[0]['offset'], len(audit_line('before')) + 1)
        self.assertEqual(fed[1]['offset'], fed[0]['offset'] + fed[0]['bytes'])
        snap = self.counts.snapshot()
        self.assertEqual((snap['audit_lines_fed'], snap['audit_bytes_fed']), (2, fed[0]['bytes'] + fed[1]['bytes']))

    def test_a_line_the_plugin_could_not_read_is_counted_not_forwarded(self):
        feed, log, out = self.feed()
        with open(log, 'ab') as w:
            w.write(audit_line('big', size=ac.FORWARD_LIMIT) + b'\n' + audit_line('fits', size=ac.FORWARD_LIMIT - 1) + b'\n')
        feed.step()
        self.assertEqual(self.counts.snapshot()['audit_oversize'], 1)
        self.assertEqual(self.rows('oversize.jsonl')[0]['audit_id'], 'big')
        data = b''
        while len(data) < ac.FORWARD_LIMIT:
            data += os.read(out, 1 << 17)
        self.assertEqual(data, audit_line('fits', size=ac.FORWARD_LIMIT - 1) + b'\n')
        self.assertEqual(len(data), ac.FORWARD_LIMIT)

    def test_unparsed_lines_are_forwarded_and_counted(self):
        feed, log, out = self.feed()
        with open(log, 'ab') as w:
            w.write(b'not json\n\n')
        feed.step()
        self.assertEqual(os.read(out, 100), b'not json\n')
        self.assertEqual(self.counts.snapshot()['audit_unparsed'], 1)

    def test_a_truncated_or_replaced_log_is_counted_and_followed_from_its_start(self):
        feed, log, out = self.feed(audit_line('old') + b'\n')
        log.write_bytes(b'')
        log.write_bytes(audit_line('n') + b'\n')
        feed.step()
        self.assertEqual(self.counts.snapshot()['audit_truncations'], 1)
        self.assertEqual(os.read(out, 1 << 16), audit_line('n') + b'\n')
        replacement = self.d / 'new.log'
        replacement.write_bytes(audit_line('r') + b'\n')
        os.replace(replacement, log)
        feed.step()
        self.assertEqual(self.counts.snapshot()['audit_truncations'], 2)
        self.assertEqual(os.read(out, 1 << 16), audit_line('r') + b'\n')

    def test_a_reader_that_goes_is_counted_once_and_stops_the_feed(self):
        feed, log, out = self.feed()
        read_end, write_end = os.pipe()
        os.close(read_end)
        os.close(feed.fifo)
        feed.fifo = write_end  # its read end is closed: Falco has gone
        feed.open_fifo = lambda: None
        with open(log, 'ab') as w:
            w.write(audit_line('x') + b'\n')
        stop = threading.Event()
        feed.run(stop)
        self.assertEqual(self.counts.snapshot()['feed_reader_gone'], 1)
        self.assertFalse(feed.alive)
        self.assertIsNotNone(feed.reader_gone_at)


class KeeperTest(Base):
    def alert(self, rule='Attach/Exec Pod'):
        return json.dumps({'time': '2026-11-14T18:00:01.000000000Z', 'rule': rule, 'source': 'k8s_audit',
                           'output_fields': {'ka.auditid': 'a'}, 'output': 'x', 'priority': 'Notice'}).encode()

    def test_alerts_health_and_the_rest(self):
        keeper = ac.Keeper(self.sink, self.counts, clock_ns=lambda: 1_794_680_400_000_000_000)
        snapshot = json.dumps({'time': '2026-11-14T18:00:00Z', 'rule': 'Falco internal: metrics snapshot', 'source': 'internal',
                               'output_fields': {'falco.num_evts': 3}}).encode()
        other = json.dumps({'time': '2026-11-14T18:00:00Z', 'rule': 'x', 'source': 'syscall', 'output_fields': {}}).encode()
        for raw in (self.alert(), self.alert(), snapshot, other, b'{"rule": 1}', b'garbage'):
            keeper.feed(raw, 1_794_680_399_000_000_000)
        self.assertEqual((self.d / 'out/alerts.jsonl').read_bytes(), self.alert() + b'\n', 'kept byte for byte, once')
        arrival = self.rows('arrivals.jsonl')
        self.assertEqual(len(arrival), 1)
        self.assertEqual(arrival[0]['raw_event_sha256'], collector.canonical_sha256(json.loads(self.alert())))
        self.assertEqual(arrival[0]['read_at'], '2026-11-14T18:19:59.000000000Z')
        self.assertEqual(arrival[0]['written_at'], '2026-11-14T18:20:00.000000000Z')
        self.assertEqual(len(self.rows('health.jsonl')), 1)
        counts = self.counts.snapshot()
        self.assertEqual((counts['received'], counts['alerts'], counts['duplicates'], counts['health_events'],
                          counts['dropped_other_source'], counts['dropped_malformed']), (6, 1, 1, 1, 1, 2))

    def test_after_a_restart_kept_alerts_are_not_written_again(self):
        ac.Keeper(self.sink, self.counts).feed(self.alert(), 0)
        keeper = ac.Keeper(self.sink, ac.Counts())
        keeper.load_kept(str(self.d / 'out'))
        keeper.feed(self.alert(), 0)
        self.assertEqual(len(self.rows('alerts.jsonl')), 1)
        self.assertEqual(keeper.counts.snapshot()['duplicates'], 1)


def beat(t, started='2026-11-14T17:59:00Z', running=True, alive=True, counts=None):
    record = {'time': t, 'collector_started_at': 'c1',
              'falco': {'running': running, 'oom_killed': False, 'started_at': started, 'restart_count': 0},
              'feed': {'alive': alive, 'fifo_open': True}, 'counts': counts or {}}
    return (json.dumps(record).encode(), record)


def snap(t, events, drops=0):
    record = {'time': t, 'rule': 'Falco internal: metrics snapshot', 'source': 'internal',
              'output_fields': {'falco.num_evts': events, 'falco.outputs_queue_num_drops': drops}}
    return (json.dumps(record).encode(), record)


def fed(*times):
    return [{'fed_at': t} for t in times]


class CoverageTest(unittest.TestCase):
    START, END = '2026-11-14T18:00:00Z', '2026-11-14T18:02:00Z'

    def setUp(self):
        self.assertIsNotNone(ac)
        self.beats = [beat('2026-11-14T17:59:50Z'), beat('2026-11-14T18:00:30Z'), beat('2026-11-14T18:01:10Z'),
                      beat('2026-11-14T18:01:50Z'), beat('2026-11-14T18:02:05Z')]
        self.snaps = [snap('2026-11-14T17:59:55Z', 0), snap('2026-11-14T18:00:55Z', 2), snap('2026-11-14T18:01:55Z', 3)]
        self.fed = fed('2026-11-14T18:00:10Z', '2026-11-14T18:00:20Z', '2026-11-14T18:01:20Z')

    def records(self, **kw):
        explain = []
        out = ac.coverage(kw.get('beats', self.beats), kw.get('snaps', self.snaps), kw.get('fed', self.fed),
                          start=self.START, end=self.END, explain=explain)
        return out, explain

    def test_a_healthy_window(self):
        out, explain = self.records()
        self.assertEqual(len(out), 1)
        self.assertEqual(explain[0]['reasons'], [])
        self.assertTrue(out[0]['healthy'])
        self.assertEqual((out[0]['event_count'], out[0]['dropped_events'], out[0]['workload_count']), (3, 0, 0))
        self.assertEqual(out[0]['source_id'], 'falco-k8saudit')
        self.assertEqual(sorted(out[0]), sorted(ac.recorder.FIELDS))

    def test_falco_behind_or_ahead_of_the_feed_is_unhealthy(self):
        for events in (1, 4):
            snaps = self.snaps[:1] + [snap('2026-11-14T18:00:55Z', events)] + self.snaps[2:]
            with self.subTest(events=events):
                out, explain = self.records(snaps=snaps)
                self.assertFalse(out[0]['healthy'])
                self.assertIn('Falco counted', ' '.join(explain[0]['reasons']))

    def test_gaps_restarts_dead_feed_and_drops(self):
        cases = {
            'heartbeat gap': self.beats[:1] + self.beats[3:],
            'restarted': self.beats[:2] + [beat('2026-11-14T18:01:10Z', started='2026-11-14T18:01:00Z')] + self.beats[3:],
            'not running': self.beats[:2] + [beat('2026-11-14T18:01:10Z', running=False)] + self.beats[3:],
            'feed not writing': self.beats[:2] + [beat('2026-11-14T18:01:10Z', alive=False)] + self.beats[3:],
            'no heartbeat at or after': self.beats[:-1],
        }
        for reason, beats in cases.items():
            with self.subTest(reason=reason):
                out, explain = self.records(beats=beats)
                self.assertFalse(out[0]['healthy'])
                self.assertIn(reason, ' '.join(explain[0]['reasons']))
        grown = self.beats[:-1] + [beat('2026-11-14T18:02:05Z', counts={'audit_oversize': 1, 'collector_errors': 2})]
        out, explain = self.records(beats=grown)
        self.assertEqual(out[0]['dropped_events'], 1)
        self.assertIn('collector errors (2)', explain[0]['reasons'])
        out, explain = self.records(snaps=self.snaps[:1] + [snap('2026-11-14T18:00:55Z', 2, drops=4), snap('2026-11-14T18:01:55Z', 3, drops=4)])
        self.assertEqual(out[0]['dropped_events'], 4)
        out, explain = self.records(snaps=[])
        self.assertIn('metrics snapshot gap over 150s', explain[0]['reasons'])


class FifoTest(Base):
    def test_fifo_modes_without_acls(self):
        path = self.d / 'audit.fifo'
        ac.make_fifo(str(path), os.getgid(), 0o640)
        info = os.lstat(path)
        self.assertTrue(stat.S_ISFIFO(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o640)
        self.assertEqual(info.st_gid, os.getgid())
        regular = self.d / 'regular'
        regular.write_text('')
        with self.assertRaisesRegex(RuntimeError, 'not our FIFO'):
            ac.make_fifo(str(regular), os.getgid(), 0o640)


if __name__ == '__main__':
    unittest.main()
