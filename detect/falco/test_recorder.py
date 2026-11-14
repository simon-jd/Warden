"""detect/falco/recorder.py: collector heartbeats and Falco's own metrics ->
the coverage intervals detect/report/observation.py accepts.

The heartbeats, snapshots and workloads here are synthetic: they test the
arithmetic, the health rules and that a complete week can be eligible, not a
real seven-day window.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

try:
    from detect.falco import recorder
except ImportError:
    recorder = None
try:
    from detect.report import observation
except ImportError:
    observation = None

# The window starts at a heartbeat: the one the collector writes right after
# Falco's first counting metrics snapshot (detector.py seven-day-start).
T0 = datetime(2026, 11, 20, 0, 0, 30, 250000, tzinfo=timezone.utc)
FIELDS = {'source_id', 'start', 'end', 'healthy', 'event_count', 'workload_count', 'dropped_events', 'receipt'}


def stamp(t):
    return t.strftime('%Y-%m-%dT%H:%M:%S') + '.%09dZ' % (t.microsecond * 1000)


def parse(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


def beat(t, started='2026-11-20T00:00:00Z', running=True, oom=False, restarts=0, collector='2026-11-20T00:00:05Z', **counts):
    c = {'received': 0, 'warden_alerts': 0, 'health_events': 0, 'dropped_host': 0, 'dropped_other_container': 0,
         'dropped_unresolved': 0, 'dropped_malformed': 0, 'dropped_overflow': 0, 'dropped_error': 0, 'collector_errors': 0,
         'collector_restarts': 0, 'pending': 0}
    c.update(counts)
    return {'time': stamp(t), 'instance': 'host', 'collector_started_at': collector,
            'falco': {'exists': True, 'running': running, 'started_at': started, 'restart_count': restarts,
                      'oom_killed': oom, 'exit_code': 0, 'image': 'sha256:' + 'f' * 64}, 'counts': c}


def snap(t, n_evts, n_drops=0, start_ts=1000, queue_drops=0):
    return {'time': stamp(t), 'rule': 'Falco internal: metrics snapshot', 'source': 'internal', 'priority': 'Informational',
            'output': 'Falco metrics snapshot', 'output_fields': {
                'scap.n_evts': n_evts, 'scap.n_drops': n_drops, 'falco.start_ts': start_ts,
                'falco.outputs_queue_num_drops': queue_drops, 'falco.n_drops_full_threadtable': 0}}


def workload(t, runtime='runc', ok=True, minutes=2):
    return {'workload_id': 'w-' + stamp(t), 'runtime': runtime, 'start': stamp(t), 'end': stamp(t + timedelta(minutes=minutes)),
            'ok': ok, 'exit_code': 0 if ok else 1}


def week(hours=168, events_per_snap=100, runtimes=('runc', 'gvisor')):
    """Heartbeats every 30 s from the window start to 15 minutes past its end
    (the stop comes then), a snapshot every 60 s from 20 s before the start,
    and each hour's benign runs from minute 2."""
    end = T0 + timedelta(hours=hours, minutes=15)
    beats, t = [], T0
    while t <= end:
        beats.append(beat(t))
        t += timedelta(seconds=30)
    snaps, t, n = [], T0 - timedelta(seconds=20), 0
    while t <= end:
        n += events_per_snap
        snaps.append(snap(t, n))
        t += timedelta(seconds=60)
    works = [workload(T0 + timedelta(hours=h, minutes=2 + 3 * i), runtime)
             for h in range(hours) for i, runtime in enumerate(runtimes)]
    return beats, snaps, works


def lines(records):
    return [(json.dumps(r).encode(), r) for r in records]


def without(records, start, minutes):
    return [r for r in records if not start <= parse(r['time']) < start + timedelta(minutes=minutes)]


class Base(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(recorder, 'detect/falco/recorder.py missing')

    def run_recorder(self, beats, snaps, works, hours=168, snapshot_gap=150, runtimes=('runc', 'gvisor'), start=T0):
        return recorder.intervals(lines(beats), lines(snaps), works, source_id='falco-host', runtimes=runtimes,
                                  start=stamp(start), end=stamp(T0 + timedelta(hours=hours)), period=3600,
                                  max_gap=90, snapshot_gap=snapshot_gap)


class IntervalTest(Base):
    def test_records_are_the_slices_exactly_and_contiguous(self):
        beats, snaps, works = week(hours=3)
        recs = self.run_recorder(beats, snaps, works, hours=3)
        self.assertEqual([(r['start'], r['end']) for r in recs],
                         [(stamp(T0 + timedelta(hours=h)), stamp(T0 + timedelta(hours=h + 1))) for h in range(3)])
        for r in recs:
            self.assertEqual(set(r), FIELDS)
            self.assertTrue(r['healthy'], r)
            self.assertEqual((r['workload_count'], r['dropped_events']), (1, 0), 'one complete benign hour: runc and gVisor')
            self.assertIn('sha256:', r['receipt'])

    def test_the_last_record_ends_exactly_at_a_short_windows_end(self):
        beats, snaps, works = week(hours=2)
        recs = recorder.intervals(lines(beats), lines(snaps), works, source_id='falco-host', runtimes=('runc',),
                                  start=stamp(T0), end=stamp(T0 + timedelta(minutes=90)), period=3600, max_gap=90,
                                  snapshot_gap=150)
        self.assertEqual([r['end'] for r in recs], [stamp(T0 + timedelta(hours=1)), stamp(T0 + timedelta(minutes=90))])

    def test_event_count_is_the_counter_delta(self):
        beats, snaps, works = week(hours=1, events_per_snap=10)
        self.assertEqual(self.run_recorder(beats, snaps, works, hours=1)[0]['event_count'], 600)

    def test_a_drop_anywhere_in_the_hour_is_counted(self):
        beats, snaps, works = week(hours=2)
        for s in snaps[70:]:
            s['output_fields']['scap.n_drops'] = 3
        for s in snaps[80:]:
            s['output_fields']['falco.outputs_queue_num_drops'] = 2
        self.assertEqual([r['dropped_events'] for r in self.run_recorder(beats, snaps, works, hours=2)], [0, 5])

    def test_collector_drops_that_may_hide_an_alert_are_drops(self):
        for key in ('dropped_unresolved', 'dropped_error'):
            with self.subTest(key=key):
                beats, snaps, works = week(hours=1)
                for b in beats[60:]:
                    b['counts'][key] = 1
                self.assertEqual(self.run_recorder(beats, snaps, works, hours=1)[0]['dropped_events'], 1)

    def test_collector_errors_or_restarts_make_the_hour_unhealthy(self):
        # An error may have cost an alert even when nothing was counted as
        # dropped; a restart may have lost what was pending.
        for key in ('collector_errors', 'collector_restarts'):
            with self.subTest(key=key):
                beats, snaps, works = week(hours=2)
                for b in beats[150:]:
                    b['counts'][key] = 1
                explain = []
                recs = recorder.intervals(lines(beats), lines(snaps), works, source_id='falco-host', runtimes=('runc', 'gvisor'),
                                          start=stamp(T0), end=stamp(T0 + timedelta(hours=2)), period=3600, max_gap=90,
                                          snapshot_gap=150, explain=explain)
                self.assertEqual([r['healthy'] for r in recs], [True, False])
                self.assertTrue(any(key.replace('_', ' ') in reason for reason in explain[1]['reasons']), explain[1])

    def test_internal_drop_notices_are_drops(self):
        beats, snaps, works = week(hours=1)
        notice = {'time': stamp(T0 + timedelta(minutes=30)), 'rule': 'Falco internal: syscall event drop',
                  'source': 'internal', 'output_fields': {'n_drops': 1}}
        self.assertGreaterEqual(self.run_recorder(beats, snaps + [notice], works, hours=1)[0]['dropped_events'], 1)

    def test_heartbeat_gap_makes_the_hour_unhealthy(self):
        beats, snaps, works = week(hours=2)
        beats = without(beats, T0 + timedelta(hours=1, minutes=20), 3)
        self.assertEqual([r['healthy'] for r in self.run_recorder(beats, snaps, works, hours=2)], [True, False])

    def test_missing_falco_snapshots_make_the_host_hour_unhealthy(self):
        beats, snaps, works = week(hours=2)
        snaps = without(snaps, T0 + timedelta(minutes=10), 5)
        self.assertEqual([r['healthy'] for r in self.run_recorder(beats, snaps, works, hours=2)], [False, True])

    def test_without_a_snapshot_rule_heartbeats_alone_carry_liveness(self):
        beats, _, works = week(hours=2)
        snaps = [snap(T0 - timedelta(seconds=5), 100), snap(T0 + timedelta(minutes=3), 5000),
                 snap(T0 + timedelta(hours=1, minutes=3), 9000)]
        recs = self.run_recorder(beats, snaps, works, hours=2, snapshot_gap=None)
        self.assertEqual([(r['healthy'], r['event_count']) for r in recs], [(True, 4900), (True, 4000)])

    def test_gvisor_engine_counters_have_falco_names(self):
        beats, _, works = week(hours=1)
        snaps = []
        for minute, n in ((-1, 100), (3, 700), (4, 900)):
            s = snap(T0 + timedelta(minutes=minute), 0)
            fields = s['output_fields']
            del fields['scap.n_evts'], fields['scap.n_drops']
            fields.update({'falco.n_evts': n, 'falco.n_drops': 0, 'scap.engine_name': 'gvisor'})
            snaps.append(s)
        rec = self.run_recorder(beats, snaps, works, hours=1, snapshot_gap=None)[0]
        self.assertEqual((rec['healthy'], rec['event_count']), (True, 800))

    def test_falco_or_collector_restart_or_stop_is_unhealthy(self):
        for change in ({'started': '2026-11-20T00:30:00Z'}, {'running': False}, {'oom': True}, {'restarts': 1},
                       {'collector': '2026-11-20T00:31:00Z'}):
            with self.subTest(change=change):
                beats, snaps, works = week(hours=1)
                beats[40] = beat(parse(beats[40]['time']), **change)
                self.assertFalse(self.run_recorder(beats, snaps, works, hours=1)[0]['healthy'])

    def test_counter_reset_counts_from_the_restart(self):
        beats, snaps, works = week(hours=1, events_per_snap=10)
        for i, s in enumerate(snaps[30:], 1):
            s['output_fields'].update({'scap.n_evts': 10 * i, 'falco.start_ts': 2000})
        rec = self.run_recorder(beats, snaps, works, hours=1)[0]
        self.assertFalse(rec['healthy'])
        self.assertGreater(rec['event_count'], 0)

    def test_an_hour_needs_a_successful_run_on_every_runtime(self):
        beats, snaps, _ = week(hours=3)
        works = [workload(T0 + timedelta(minutes=2), ok=False), workload(T0 + timedelta(minutes=5), runtime='gvisor'),
                 workload(T0 + timedelta(hours=1, minutes=2)), workload(T0 + timedelta(hours=1, minutes=5), runtime='firecracker'),
                 workload(T0 + timedelta(hours=2, minutes=2)), workload(T0 + timedelta(hours=2, minutes=5), runtime='gvisor')]
        explain = []
        recs = recorder.intervals(lines(beats), lines(snaps), works, source_id='falco-host', runtimes=('runc', 'gvisor'),
                                  start=stamp(T0), end=stamp(T0 + timedelta(hours=3)), period=3600, max_gap=90,
                                  snapshot_gap=150, explain=explain)
        self.assertEqual([r['workload_count'] for r in recs], [0, 0, 1])
        self.assertEqual([e['workloads'] for e in explain], [{'runc': 0, 'gvisor': 1}, {'runc': 1, 'gvisor': 0},
                                                             {'runc': 1, 'gvisor': 1}])
        self.assertEqual([r['workload_count'] for r in self.run_recorder(beats, snaps, works, hours=3, runtimes=('runc',))], [0, 1, 1])

    def test_snapshot_without_counters_is_unhealthy(self):
        beats, snaps, works = week(hours=1)
        del snaps[20]['output_fields']['scap.n_drops']
        self.assertFalse(self.run_recorder(beats, snaps, works, hours=1)[0]['healthy'])

    def test_a_slice_nothing_substantiates_is_an_unhealthy_record(self):
        # Before the first heartbeat, or after the last one, a slice cannot
        # be covered; the record says so instead of shrinking.
        beats, snaps, works = week(hours=2)
        early = self.run_recorder(beats, snaps, works, hours=2, start=T0 - timedelta(seconds=10))
        self.assertEqual(early[0]['start'], stamp(T0 - timedelta(seconds=10)))
        self.assertFalse(early[0]['healthy'])
        cut = [b for b in beats if parse(b['time']) < T0 + timedelta(hours=2)]
        self.assertEqual([r['healthy'] for r in self.run_recorder(cut, snaps, works, hours=2)], [True, False])


class WindowStartTest(Base):
    def test_first_heartbeat_after_the_first_counting_snapshot(self):
        beats = [beat(T0 - timedelta(seconds=40)), beat(T0 - timedelta(seconds=10)), beat(T0)]
        snaps = [snap(T0 - timedelta(seconds=30), 0), snap(T0 - timedelta(seconds=5), 12)]
        self.assertEqual(recorder.first_healthy_point(lines(beats), lines(snaps)), stamp(T0))
        self.assertIsNone(recorder.first_healthy_point(lines(beats[:2]), lines(snaps)))


class ObservationTest(Base):
    def setUp(self):
        super().setUp()
        self.assertIsNotNone(observation, 'detect/report/observation.py missing')

    def account(self, recs):
        end = stamp(T0 + timedelta(days=7))
        return observation.account(recs, [], ['falco-host'], stamp(T0), end, end)

    def test_a_complete_healthy_week_is_eligible(self):
        beats, snaps, works = week()
        recs = self.run_recorder(beats, snaps, works)
        self.assertEqual(len(recs), 168)
        self.assertEqual((recs[0]['start'], recs[-1]['end']), (stamp(T0), stamp(T0 + timedelta(days=7))))
        result = self.account(recs)
        self.assertEqual(result['sources']['falco-host']['gap_ns'], 0)
        self.assertTrue(result['eligible_seven_day_window'], result['sources'])
        self.assertEqual(result['false_positive_count'], 0)
        self.assertFalse(result['coverage_verified'])

    def test_a_real_gap_makes_the_week_ineligible(self):
        beats, snaps, works = week()
        beats = without(beats, T0 + timedelta(hours=50, minutes=10), 10)
        result = self.account(self.run_recorder(beats, snaps, works))
        self.assertFalse(result['eligible_seven_day_window'])
        self.assertIsNone(result['false_positive_count'])
        self.assertEqual(result['sources']['falco-host']['rejected_intervals'], 1)

    def test_an_hour_without_a_workload_makes_it_ineligible(self):
        beats, snaps, works = week()
        works = [w for w in works if not parse(w['start']).strftime('%m-%dT%H') == (T0 + timedelta(hours=99)).strftime('%m-%dT%H')]
        self.assertFalse(self.account(self.run_recorder(beats, snaps, works))['eligible_seven_day_window'])

    def test_an_hour_whose_gvisor_run_failed_makes_it_ineligible(self):
        beats, snaps, works = week()
        hour = (T0 + timedelta(hours=120)).strftime('%m-%dT%H')
        for w in works:
            if w['runtime'] == 'gvisor' and parse(w['start']).strftime('%m-%dT%H') == hour:
                w['ok'] = False
        self.assertFalse(self.account(self.run_recorder(beats, snaps, works))['eligible_seven_day_window'])


class CommandTest(Base):
    def test_cli_writes_new_files_only(self):
        beats, snaps, works = week(hours=2)
        with tempfile.TemporaryDirectory() as d:
            paths = {}
            for name, records in (('heartbeats', beats), ('health', snaps), ('workloads', works)):
                paths[name] = os.path.join(d, name + '.jsonl')
                Path(paths[name]).write_text(''.join(json.dumps(r) + '\n' for r in records))
            out, explain = os.path.join(d, 'coverage.jsonl'), os.path.join(d, 'explain.jsonl')
            cmd = [sys.executable, '-I', '-B', recorder.__file__, '--heartbeats', paths['heartbeats'], '--health', paths['health'],
                   '--workloads', paths['workloads'], '--source-id', 'falco-host', '--runtime', 'runc', '--runtime', 'gvisor',
                   '--start', stamp(T0), '--end', stamp(T0 + timedelta(hours=2)), '--snapshot-gap', '150',
                   '--out', out, '--explain', explain]
            r = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            recs = [json.loads(x) for x in Path(out).read_text().splitlines()]
            self.assertEqual([x['workload_count'] for x in recs], [1, 1])
            self.assertEqual(len(Path(explain).read_text().splitlines()), 2)
            again = subprocess.run(cmd, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0, 'an existing output must not be overwritten')


if __name__ == '__main__':
    unittest.main()
