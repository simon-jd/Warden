"""Vector disk-buffer backpressure under a 10x burst (Review Focus #4).

Live test, opt-in with WARDEN_LIVE_VECTOR=1 (`make test-vector-live`). It starts
Vector, feeds synthetic events with unique IDs and receives them on an owned
loopback HTTP peer. BP_SOURCE picks the source:

  stdin        detect/tests/backpressure.toml. Vector 0.45.0's stdin source keeps
               reading the pipe and holds the burst in memory, so the sender is
               never blocked (FAIL on the block assertion; nothing is lost).
  http_server  detect/tests/backpressure-http.toml, acknowledgements on: a full
               disk buffer leaves the POST unanswered, i.e. real backpressure.
  vector       two Vector processes, the production agent -> aggregator hop:
               backpressure-agent.toml (http_server -> `vector` sink
               agent_forward, disk buffer) and backpressure-aggregator.toml
               (`vector` source -> os_api, disk buffer). A throwaway Prometheus
               container (warden-bp-prom-*) scrapes both and loads
               detect/vector/buffer-alerts.yml. BP_WHEN_FULL=drop_newest makes
               the agent buffer drop instead of block: then the pass condition
               is that every lost ID is counted as discarded and
               WardenVectorBufferDiscarded fires (see verdict()).

Phases:

  baseline  BASE_RATE ev/s for BASE_SECONDS, peer healthy
  burst     10 x BASE_RATE ev/s for BURST_EVENTS, peer answering 503 (stalled)
            until the sender has been blocked for RELEASE_AFTER_BLOCK seconds,
            i.e. the 256 MiB disk buffer is full and backpressure reached stdin
  drain     peer healthy until every ID has arrived or DRAIN_SECONDS pass

Pass: zero IDs lost (duplicates are allowed; delivery is at-least-once), zero
buffer/component discards, and the sender was actually blocked. Result JSON
goes to $BP_OUT when set. Vector 0.45.0 can report negative disk-buffer gauges
(acknowledgement accounting races); they are counted, not treated as fatal.
"""
import datetime
import http.client
import http.server
import json
import os
import select
import socket
import subprocess
import tempfile
import threading
import time
import tomllib
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / 'detect/tests/backpressure.toml'
LINE_BYTES = 16384
BASE_RATE = 20
BASE_SECONDS = 10
BURST_FACTOR = 10
BURST_EVENTS = 24000          # 375 MiB offered: more than the 256 MiB buffer
RELEASE_AFTER_BLOCK = 3.0
BURST_MAX_SECONDS = 150
DRAIN_SECONDS = 120
DRAIN_IDLE_SECONDS = 20


CONFIGS = {'stdin': [CONFIG], 'http_server': [REPO / 'detect/tests/backpressure-http.toml'],
           # agent first, aggregator second
           'vector': [REPO / 'detect/tests/backpressure-agent.toml', REPO / 'detect/tests/backpressure-aggregator.toml']}
ALERT_RULES = REPO / 'detect/vector/buffer-alerts.yml'
ALERT_NAME = 'WardenVectorBufferDiscarded'
GAP_ALERT = 'WardenVectorAgentForwardGap'
PROM_IMAGE = 'prom/prometheus:v3.14.0'
ALERT_WAIT_SECONDS = 90


# BP_INPUTS=6: the production agent's six inputs, each with its own sender.
INPUT_NAMES = ('aks', 'azure', 'k3s', 'tetragon', 'vnet', 'warden')
AGENT_6 = REPO / 'detect/tests/backpressure-agent-6.toml'
ID_STRIDE = 10_000_000  # input k sends IDs k*ID_STRIDE, k*ID_STRIDE+1, ...


def configs_for(source, inputs=1):
    if source not in CONFIGS:
        raise ValueError('BP_SOURCE must be one of %s' % sorted(CONFIGS))
    if inputs == len(INPUT_NAMES):
        return [AGENT_6] + CONFIGS[source][1:]
    return list(CONFIGS[source])


def inputs_for(source, value):
    """BP_INPUTS: 1 (default) or 6, and 6 only for the two-hop config."""
    n = int(value) if value and value.isdigit() else (1 if not value else None)
    if n not in (1, len(INPUT_NAMES)):
        raise ValueError('BP_INPUTS must be 1 or %d' % len(INPUT_NAMES))
    if n != 1 and source != 'vector':
        raise ValueError('BP_INPUTS=%d needs BP_SOURCE=vector' % n)
    return n


def series_peak(series):
    """Largest value of a Prometheus.range() series, or None."""
    values = [v for _, v in series.get('values', [])]
    return max(values) if values else None


def when_full_for(source, value):
    """BP_WHEN_FULL: only the two-hop config takes it; default block."""
    value = value or 'block'
    if value not in ('block', 'drop_newest'):
        raise ValueError('BP_WHEN_FULL must be block or drop_newest')
    if value != 'block' and source != 'vector':
        raise ValueError('BP_WHEN_FULL=%s needs BP_SOURCE=vector' % value)
    return value


def prometheus_config(targets):
    """Scrape config for the throwaway Prometheus; rules are the production file."""
    return ('global:\n  scrape_interval: 1s\n  evaluation_interval: 1s\n'
            'rule_files:\n  - /etc/prometheus/rules/buffer-alerts.yml\n'
            'scrape_configs:\n  - job_name: warden-vector\n    static_configs:\n'
            '      - targets: [%s]\n' % ', '.join("'%s'" % t for t in targets))


def parse_rfc3339(s):
    """Seconds since the epoch for Prometheus/Vector UTC timestamps (ns precision dropped to us)."""
    s = s.rstrip('Z')
    if '.' in s:
        head, frac = s.split('.', 1)
        s = head + '.' + frac[:6]
        fmt = '%Y-%m-%dT%H:%M:%S.%f'
    else:
        fmt = '%Y-%m-%dT%H:%M:%S'
    return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc).timestamp()


def firing_alerts(body, name):
    out = []
    for a in body.get('data', {}).get('alerts', []):
        if a.get('labels', {}).get('alertname') == name and a.get('state') == 'firing':
            out.append({'component_id': a['labels'].get('component_id'), 'active_at': parse_rfc3339(a['activeAt']),
                        'value': a.get('value')})
    return out


def first_positive(lines, name):
    """Epoch time of the first sample of counter `name` above zero, or None."""
    best = None
    for raw in lines:
        if not raw.strip():
            continue
        m = json.loads(raw)
        if m.get('name') == name and m.get('counter', {}).get('value', 0) > 0 and 'timestamp' in m:
            t = parse_rfc3339(m['timestamp'])
            best = t if best is None else min(best, t)
    return best


def first_near_peak(lines, name, component, fraction):
    """Epoch time gauge `name` of `component` first reached fraction x its peak."""
    pts = []
    for raw in lines:
        if not raw.strip():
            continue
        m = json.loads(raw)
        if m.get('name') == name and 'gauge' in m and (m.get('tags') or {}).get('component_id') == component:
            pts.append((parse_rfc3339(m['timestamp']), m['gauge']['value']))
    if not pts:
        return None
    peak = max(v for _, v in pts)
    return min(t for t, v in pts if v >= fraction * peak)


def verdict(result, when_full):
    """List of failed expectations (empty = pass).

    block:       nothing lost, nothing discarded, the sender was blocked, no alert.
    drop_newest: events were discarded, every lost ID is covered by the discard
                 counter (no silent loss) and WardenVectorBufferDiscarded fired."""
    r, m, s = result['reconcile'], result['metrics'], result['sender']
    firing = result.get('alert', {}).get('firing', [])
    gap_firing = result.get('alert', {}).get('gap_firing', [])
    bad = []
    if r['unexpected_ids']:
        bad.append('unexpected ids received')
    if when_full == 'block':
        if r['lost']:
            bad.append('%d events lost under backpressure' % r['lost'])
        if m['buffer_discarded_events_total'] or m['component_discarded_events_total']:
            bad.append('events discarded with when_full=block')
        if s['longest_block_s'] < RELEASE_AFTER_BLOCK:
            bad.append('buffer never filled: backpressure did not reach the source')
        if firing:
            bad.append('discard alert fired without discards')
        if gap_firing:
            bad.append('%s fired without loss' % GAP_ALERT)
    else:
        discarded = m['buffer_discarded_events_total']
        if not discarded:
            bad.append('nothing was discarded: the buffer never overflowed')
        if r['lost'] > discarded:
            bad.append('%d lost but only %d counted as discarded' % (r['lost'], discarded))
        if not firing:
            bad.append('%s did not fire' % ALERT_NAME)
        if not gap_firing:
            bad.append('%s did not fire' % GAP_ALERT)
    return bad


def event_line(n, phase):
    """One JSON event, exactly LINE_BYTES long including the newline."""
    base = {'id': n, 'phase': phase, 'pad': ''}
    pad = LINE_BYTES - len(json.dumps(base, separators=(',', ':'))) - 1
    base['pad'] = 'p' * pad
    b = json.dumps(base, separators=(',', ':')).encode() + b'\n'
    assert len(b) == LINE_BYTES
    return b


def reconcile(ids, received_counts):
    """ids: the IDs the sender got acknowledged; received_counts: id -> deliveries."""
    ids = set(ids)
    unique = sum(1 for i in ids if received_counts.get(i, 0) > 0)
    return {'sent': len(ids), 'received_unique': unique, 'lost': len(ids) - unique,
            'duplicates': sum(c - 1 for c in received_counts.values() if c > 1),
            'unexpected_ids': sum(1 for i in received_counts if i not in ids)}


def summarize_metrics(lines, component=None):
    """Peak/min of the gauges and last value of the discard counters
    (only samples tagged component_id=component when given)."""
    out = {'samples': 0, 'buffer_byte_size_max': None, 'buffer_byte_size_min': None,
           'buffer_events_max': None, 'negative_gauge_samples': 0,
           'buffer_discarded_events_total': 0.0, 'component_discarded_events_total': 0.0}
    for raw in lines:
        if not raw.strip():
            continue
        m = json.loads(raw)
        if component is not None and (m.get('tags') or {}).get('component_id') != component:
            continue
        name = m['name']
        if 'gauge' in m:
            v = m['gauge']['value']
            out['samples'] += 1
            if v < 0:
                out['negative_gauge_samples'] += 1
            key = name + '_max'
            if key in out:
                out[key] = v if out[key] is None else max(out[key], v)
            if name == 'buffer_byte_size':
                lo = out['buffer_byte_size_min']
                out['buffer_byte_size_min'] = v if lo is None else min(lo, v)
        elif 'counter' in m and name in out:
            out[name] = max(out[name], m['counter']['value'])
    return out


def counter_series(lines):
    """'name{k=v,...}' -> highest value, for every counter sample."""
    out = {}
    for raw in lines:
        if not raw.strip():
            continue
        m = json.loads(raw)
        if 'counter' not in m:
            continue
        tags = m.get('tags') or {}
        key = '%s{%s}' % (m['name'], ','.join('%s=%s' % kv for kv in sorted(tags.items())))
        out[key] = max(out.get(key, 0.0), m['counter']['value'])
    return out


class HelpersTest(unittest.TestCase):
    def test_event_line_is_fixed_size_and_parseable(self):
        for n in (0, 7, 23999):
            b = event_line(n, 'burst')
            self.assertEqual(len(b), LINE_BYTES)
            self.assertEqual(json.loads(b)['id'], n)

    def test_reconcile_counts_loss_duplicates_and_strays(self):
        r = reconcile(range(5), {0: 1, 1: 2, 3: 1, 9: 1})
        self.assertEqual(r, {'sent': 5, 'received_unique': 3, 'lost': 2, 'duplicates': 1, 'unexpected_ids': 1})
        # Disjoint per-input ID ranges, as MultiSender sends them.
        r = reconcile([0, 1, ID_STRIDE, ID_STRIDE + 1], {0: 1, 1: 1, ID_STRIDE: 1, 2: 1})
        self.assertEqual(r, {'sent': 4, 'received_unique': 3, 'lost': 1, 'duplicates': 0, 'unexpected_ids': 1})

    def test_inputs_choice(self):
        self.assertEqual(inputs_for('vector', None), 1)
        self.assertEqual(inputs_for('vector', '6'), 6)
        for source, value in (('vector', '2'), ('vector', 'x'), ('http_server', '6'), ('stdin', '6')):
            with self.assertRaises(ValueError):
                inputs_for(source, value)
        self.assertEqual(configs_for('vector', 6)[1], configs_for('vector')[1])
        self.assertNotEqual(configs_for('vector', 6)[0], configs_for('vector')[0])

    def test_six_input_agent_matches_the_production_inputs(self):
        agent = tomllib.loads(configs_for('vector', 6)[0].read_text())
        one = tomllib.loads(configs_for('vector')[0].read_text())
        prod = tomllib.loads((REPO / 'detect/vector/agent.toml').read_text())
        self.assertEqual(sorted(agent['sinks']['agent_forward']['inputs']), sorted(prod['sinks']['agent_forward']['inputs']))
        self.assertEqual(agent['sinks']['agent_forward'], {**one['sinks']['agent_forward'], 'inputs': agent['sinks']['agent_forward']['inputs']})
        for name in INPUT_NAMES:
            self.assertEqual(agent['transforms']['label_' + name]['source'], prod['transforms']['label_' + name]['source'])
            self.assertEqual(agent['transforms']['label_' + name]['inputs'], ['spool_' + name])
            src = agent['sources']['spool_' + name]
            self.assertEqual(src['address'], '${BP_LISTEN_%s}' % name.upper())
            self.assertEqual({k: v for k, v in src.items() if k != 'address'},
                             {k: v for k, v in one['sources']['spool_warden'].items() if k != 'address'})
        self.assertEqual(agent['sinks']['metrics_export'], one['sinks']['metrics_export'])

    def test_multi_sender_splits_target_and_ids(self):
        class Stub:
            def __init__(self, offset):
                self.offset, self.target, self.sent, self.pending, self.blocked_since = offset, 0, 0, False, None
                self.longest_block, self.blocked_total, self.errors = 0.0, 0.0, 0
            def pump(self, target, phase, now):
                self.target = max(self.target, target)
            def current_block(self, now):
                return 0.0
            def sent_ids(self):
                return range(self.offset, self.offset + self.sent)
        m = MultiSender([Stub(k * ID_STRIDE) for k in range(6)])
        m.pump(20, 'baseline', 0)
        self.assertEqual([s.target for s in m.senders], [4, 4, 3, 3, 3, 3])
        for s in m.senders:
            s.sent = s.target
        self.assertEqual(m.sent, 20)
        self.assertEqual(sorted(m.sent_ids())[:5], [0, 1, 2, 3, ID_STRIDE])
        self.assertEqual(len(list(m.sent_ids())), 20)
        m.senders[3].blocked_since, m.senders[3].pending = 5.0, True
        self.assertTrue(m.pending)
        self.assertEqual(m.blocked_since, 5.0)

    def test_peak_of_a_range_series(self):
        self.assertEqual(series_peak({'values': [[1, 3.0], [2, 833.0], [3, -1.0]]}), 833.0)
        self.assertIsNone(series_peak({'values': []}))
        self.assertIsNone(series_peak({'error': 'x'}))

    def test_source_selects_config(self):
        self.assertEqual(configs_for('stdin'), [CONFIG])
        http_cfg = configs_for('http_server')[0].read_text()
        self.assertIn('type = "http_server"', http_cfg)
        self.assertIn('acknowledgements.enabled = true', http_cfg.split('[sinks.bp_http]')[0])
        with self.assertRaises(ValueError):
            configs_for('kafka')

    def test_vector_source_uses_the_production_hop(self):
        agent, aggregator = (tomllib.loads(p.read_text()) for p in configs_for('vector'))
        prod_agent = tomllib.loads((REPO / 'detect/vector/agent.toml').read_text())
        prod_agg = tomllib.loads((REPO / 'detect/vector/aggregator.toml').read_text())
        fwd, prod_fwd = agent['sinks']['agent_forward'], prod_agent['sinks']['agent_forward']
        self.assertEqual(fwd['type'], 'vector')
        self.assertEqual(fwd['acknowledgements'], prod_fwd['acknowledgements'])
        self.assertEqual({k: v for k, v in fwd['buffer'].items() if k != 'when_full'},
                         {k: v for k, v in prod_fwd['buffer'].items() if k != 'when_full'})
        self.assertEqual(fwd['buffer']['when_full'], '${BP_WHEN_FULL}')
        # Same component names as production, so the production alert rules apply unchanged.
        self.assertEqual(fwd['inputs'], ['label_warden'])
        self.assertIn('label_warden', prod_fwd['inputs'])
        self.assertEqual(agent['transforms']['label_warden']['source'], prod_agent['transforms']['label_warden']['source'])
        self.assertEqual(agent['transforms']['label_warden']['inputs'], ['spool_warden'])
        self.assertEqual(agent['sources']['spool_warden']['type'], 'http_server')
        self.assertEqual(agent['sources']['spool_warden']['acknowledgements'], {'enabled': True})
        src, prod_src = aggregator['sources']['agent'], prod_agg['sources']['agent']
        self.assertEqual((src['type'], src['acknowledgements']), (prod_src['type'], prod_src['acknowledgements']))
        self.assertEqual(aggregator['sinks']['os_api']['buffer'], prod_agg['sinks']['os_api']['buffer'])
        self.assertEqual(aggregator['sinks']['os_api']['acknowledgements'], {'enabled': True})

    def test_when_full_choices(self):
        self.assertEqual(when_full_for('vector', ''), 'block')
        self.assertEqual(when_full_for('vector', 'drop_newest'), 'drop_newest')
        self.assertEqual(when_full_for('http_server', ''), 'block')
        with self.assertRaises(ValueError):
            when_full_for('vector', 'drop_oldest')
        with self.assertRaises(ValueError):
            when_full_for('stdin', 'drop_newest')  # only the two-hop config is parameterized

    def test_prometheus_config_scrapes_both_hops_and_loads_production_rules(self):
        cfg = prometheus_config(['127.0.0.1:1001', '127.0.0.1:1002'])
        self.assertIn("targets: ['127.0.0.1:1001', '127.0.0.1:1002']", cfg)
        self.assertIn('scrape_interval: 1s', cfg)
        self.assertIn('evaluation_interval: 1s', cfg)
        self.assertIn('- /etc/prometheus/rules/buffer-alerts.yml', cfg)
        self.assertIn('WardenVectorBufferDiscarded', ALERT_RULES.read_text())

    def test_gap_alert_covers_every_production_agent_input(self):
        rules = ALERT_RULES.read_text()
        self.assertIn('alert: %s' % GAP_ALERT, rules)
        expr = rules.split('alert: %s' % GAP_ALERT, 1)[1].split('expr:', 1)[1].splitlines()[0]
        self.assertIn('vector_buffer_received_events_total{component_id="agent_forward"}', expr)
        prod_agent = tomllib.loads((REPO / 'detect/vector/agent.toml').read_text())
        labels = sorted(i.removeprefix('label_') for i in prod_agent['sinks']['agent_forward']['inputs'])
        self.assertIn('vector_component_sent_events_total{component_id=~"^label_(%s)$"}' % '|'.join(labels), expr)
        self.assertIn('[5m]', expr)
        self.assertIn('> 2000', expr)

    def test_firing_alerts_are_picked_by_name_and_state(self):
        body = {'status': 'success', 'data': {'alerts': [
            {'labels': {'alertname': 'WardenVectorBufferDiscarded', 'component_id': 'agent_forward'},
             'state': 'firing', 'activeAt': '2026-10-27T12:00:05.5Z', 'value': '3.2e+03'},
            {'labels': {'alertname': 'WardenVectorBufferDiscarded', 'component_id': 'os_api'},
             'state': 'pending', 'activeAt': '2026-10-27T12:00:06Z', 'value': '1e+00'},
            {'labels': {'alertname': 'Other'}, 'state': 'firing', 'activeAt': '2026-10-27T12:00:00Z'}]}}
        got = firing_alerts(body, 'WardenVectorBufferDiscarded')
        self.assertEqual([a['component_id'] for a in got], ['agent_forward'])
        self.assertAlmostEqual(got[0]['active_at'], parse_rfc3339('2026-10-27T12:00:05.5Z'))
        self.assertEqual(parse_rfc3339('1970-01-01T00:00:01.25Z'), 1.25)

    def test_summary_can_be_limited_to_one_component(self):
        lines = [json.dumps({'name': 'buffer_discarded_events_total', 'tags': {'component_id': c}, 'counter': {'value': v}})
                 for c, v in (('agent_forward', 3.0), ('fixture', 9.0))]
        self.assertEqual(summarize_metrics(lines)['buffer_discarded_events_total'], 9.0)
        self.assertEqual(summarize_metrics(lines, 'agent_forward')['buffer_discarded_events_total'], 3.0)

    def test_counter_series_keeps_every_tag_set(self):
        mk = lambda tags, v: json.dumps({'name': 'buffer_discarded_events_total', 'tags': tags, 'counter': {'value': v}})
        lines = [mk({'component_id': 'agent_forward', 'intentional': 'true'}, 5.0),
                 mk({'component_id': 'agent_forward', 'intentional': 'true'}, 7.0),
                 mk({'intentional': 'false'}, 1.0),
                 json.dumps({'name': 'buffer_events', 'tags': {}, 'gauge': {'value': 4.0}})]
        self.assertEqual(counter_series(lines), {
            'buffer_discarded_events_total{component_id=agent_forward,intentional=true}': 7.0,
            'buffer_discarded_events_total{intentional=false}': 1.0})

    def test_first_time_gauge_reaches_fraction_of_its_peak(self):
        tags = {'component_id': 'agent_forward'}
        lines = [json.dumps({'name': 'buffer_byte_size', 'tags': tags, 'gauge': {'value': v}, 'timestamp': ts})
                 for v, ts in ((10.0, '1970-01-01T00:00:01Z'), (99.5, '1970-01-01T00:00:02Z'),
                               (100.0, '1970-01-01T00:00:03Z'))]
        lines.append(json.dumps({'name': 'buffer_byte_size', 'tags': {'component_id': 'x'}, 'gauge': {'value': 500.0},
                                 'timestamp': '1970-01-01T00:00:00Z'}))
        self.assertEqual(first_near_peak(lines, 'buffer_byte_size', 'agent_forward', 0.99), 2.0)
        self.assertIsNone(first_near_peak([], 'buffer_byte_size', 'agent_forward', 0.99))

    def test_first_positive_counter_time(self):
        tags = {'component_id': 'agent_forward'}
        lines = [json.dumps({'name': 'buffer_discarded_events_total', 'tags': tags, 'counter': {'value': v},
                             'timestamp': ts}) for v, ts in
                 ((0.0, '1970-01-01T00:00:10Z'), (25.0, '1970-01-01T00:00:11.5Z'), (50.0, '1970-01-01T00:00:12Z'))]
        self.assertEqual(first_positive(lines, 'buffer_discarded_events_total'), 11.5)
        self.assertIsNone(first_positive(lines[:1], 'buffer_discarded_events_total'))

    def test_verdict_block_requires_no_loss_backpressure_and_no_alert(self):
        ok = {'reconcile': {'lost': 0, 'unexpected_ids': 0}, 'sender': {'longest_block_s': 4.0},
              'metrics': {'buffer_discarded_events_total': 0, 'component_discarded_events_total': 0},
              'alert': {'firing': [], 'gap_firing': []}}
        self.assertEqual(verdict(ok, 'block'), [])
        bad = json.loads(json.dumps(ok))
        bad['alert']['firing'] = [{'component_id': 'agent_forward'}]
        bad['alert']['gap_firing'] = [{'component_id': None}]
        bad['sender']['longest_block_s'] = 0.5
        self.assertEqual(len(verdict(bad, 'block')), 3)

    def test_verdict_drop_requires_counted_loss_and_alert(self):
        ok = {'reconcile': {'lost': 120, 'unexpected_ids': 0}, 'sender': {'longest_block_s': 0.1},
              'metrics': {'buffer_discarded_events_total': 120, 'component_discarded_events_total': 0},
              'alert': {'firing': [{'component_id': 'agent_forward'}], 'gap_firing': [{'component_id': None}]}}
        self.assertEqual(verdict(ok, 'drop_newest'), [])
        no_gap_alert = json.loads(json.dumps(ok))
        no_gap_alert['alert']['gap_firing'] = []
        self.assertEqual(len(verdict(no_gap_alert, 'drop_newest')), 1)
        uncounted = json.loads(json.dumps(ok))
        uncounted['metrics']['buffer_discarded_events_total'] = 100
        self.assertEqual(len(verdict(uncounted, 'drop_newest')), 1)
        silent = json.loads(json.dumps(ok))
        silent['alert']['firing'] = []
        self.assertEqual(len(verdict(silent, 'drop_newest')), 1)
        nothing = json.loads(json.dumps(ok))
        nothing['reconcile']['lost'] = nothing['metrics']['buffer_discarded_events_total'] = 0
        self.assertEqual(len(verdict(nothing, 'drop_newest')), 1)

    def test_http_sender_records_a_hanging_request_as_blocked(self):
        delay = 0.6

        class Slow(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                if self.server.slow.is_set():
                    time.sleep(delay)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_):
                pass

        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Slow)
        srv.slow = threading.Event()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        sender = HttpSender('http://127.0.0.1:%d/' % srv.server_address[1], batch=4)
        try:
            sender.pump(8, 'baseline', time.monotonic())
            deadline = time.monotonic() + 5
            while sender.sent < 8 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(sender.sent, 8)
            self.assertLess(sender.longest_block, delay / 2)
            srv.slow.set()
            sender.pump(12, 'burst', time.monotonic())
            time.sleep(delay / 2)
            self.assertGreater(sender.current_block(time.monotonic()), 0.0)
            while sender.sent < 12 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertGreaterEqual(sender.longest_block, delay * 0.9)
        finally:
            sender.close()
            srv.shutdown()

    def test_negative_gauges_are_counted_not_fatal(self):
        # Shape and values from the 2026-10-25 run that aborted on -16616.
        tags = {'component_id': 'bp_http'}
        lines = [json.dumps({'name': 'buffer_byte_size', 'tags': tags, 'gauge': {'value': v}}) for v in (134207432.0, -16616.0)]
        lines.append(json.dumps({'name': 'buffer_events', 'tags': tags, 'gauge': {'value': -1.0}}))
        lines.append(json.dumps({'name': 'buffer_discarded_events_total', 'tags': tags, 'counter': {'value': 0.0}}))
        s = summarize_metrics(lines)
        self.assertEqual(s['negative_gauge_samples'], 2)
        self.assertEqual(s['buffer_byte_size_max'], 134207432.0)
        self.assertEqual(s['buffer_byte_size_min'], -16616.0)
        self.assertEqual(s['buffer_discarded_events_total'], 0.0)


class Peer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), PeerHandler)
        self.lock = threading.Lock()
        self.counts = {}
        self.stalled = threading.Event()
        self.requests = {'ok': 0, 'rejected': 0}


class PeerHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        peer = self.server
        if peer.stalled.is_set():
            with peer.lock:
                peer.requests['rejected'] += 1
            self.send_response(503)
            self.end_headers()
            return
        ids = [json.loads(l)['id'] for l in body.splitlines() if l.strip()]
        with peer.lock:
            peer.requests['ok'] += 1
            for i in ids:
                peer.counts[i] = peer.counts.get(i, 0) + 1
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_):
        pass


class Sampler(threading.Thread):
    """Direct occupancy: bytes under the buffer data_dir and Vector's RSS.
    Vector's own gauge is not reliable enough to decide where events are held."""

    def __init__(self, data_dir, pid, t0):
        super().__init__(daemon=True)
        self.data_dir, self.pid, self.t0 = data_dir, pid, t0
        self.stop = threading.Event()
        self.series = []  # (t, disk_bytes, rss_bytes)

    def run(self):
        while not self.stop.wait(0.5):
            disk = 0
            for root, _dirs, files in os.walk(self.data_dir):
                for f in files:
                    try:
                        disk += os.stat(os.path.join(root, f)).st_size
                    except FileNotFoundError:
                        pass
            rss = 0
            try:
                for line in Path('/proc/%d/status' % self.pid).read_text().splitlines():
                    if line.startswith('VmRSS:'):
                        rss = int(line.split()[1]) * 1024
            except (FileNotFoundError, ProcessLookupError):
                pass
            self.series.append((round(time.monotonic() - self.t0, 2), disk, rss))

    def summary(self):
        s = self.series
        return {'samples': len(s), 'disk_bytes_max': max((d for _, d, _ in s), default=None),
                'rss_bytes_max': max((r for _, _, r in s), default=None),
                # every 10th sample keeps the shape without bloating the evidence
                'series_t_disk_rss': s[::10]}


class Prometheus:
    """Throwaway Prometheus container (warden-bp-prom-*) on the host network,
    bound to 127.0.0.1, scraping both Vector exporters with the production
    detect/vector/buffer-alerts.yml rules. Removed by remove()."""

    def __init__(self, work, targets):
        self.name = 'warden-bp-prom-' + os.urandom(4).hex()
        self.port = free_port()
        self.base = 'http://127.0.0.1:%d' % self.port
        self.cfg = work / 'prometheus.yml'
        self.cfg.write_text(prometheus_config(targets))
        self.cfg.chmod(0o644)
        self.targets = targets
        self.info = {'image': PROM_IMAGE, 'container': self.name, 'targets': targets}
        self.last_poll = 0.0
        self.started = time.time()
        self.gap_expr = None  # set once the rules are loaded

    def _get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return json.loads(r.read())

    def start(self):
        subprocess.run(['docker', 'run', '-d', '--name', self.name, '--label', 'project=warden',
                        '--network', 'host', '--memory', '512m', '--cpus', '1',
                        '-v', '%s:/etc/prometheus/prometheus.yml:ro' % self.cfg,
                        '-v', '%s:/etc/prometheus/rules/buffer-alerts.yml:ro' % ALERT_RULES,
                        PROM_IMAGE, '--config.file=/etc/prometheus/prometheus.yml',
                        '--storage.tsdb.path=/prometheus', '--web.listen-address=127.0.0.1:%d' % self.port],
                       check=True, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 60
        last = None
        while True:
            try:
                rules = self._get('/api/v1/rules')
                targets = self._get('/api/v1/targets')
                names = [r['name'] for g in rules['data']['groups'] for r in g['rules']]
                active = targets['data']['activeTargets']
                up = [t['scrapeUrl'] for t in active if t['health'] == 'up']
                if {ALERT_NAME, GAP_ALERT} <= set(names) and len(up) == len(self.targets):
                    self.info.update({'rules_loaded': names, 'targets_up': up})
                    self.started = time.time()
                    self.gap_expr = next(r['query'] for g in rules['data']['groups'] for r in g['rules']
                                         if r['name'] == GAP_ALERT)
                    return
                last = {'rules': names, 'targets': [(t['scrapeUrl'], t['health'], t.get('lastError')) for t in active]}
            except (OSError, ValueError, KeyError) as e:
                last = repr(e)
            if time.monotonic() > deadline:
                logs = subprocess.run(['docker', 'logs', '--tail', '20', self.name], capture_output=True, text=True)
                raise RuntimeError('prometheus not ready in 60 s: last=%r logs=%s' % (last, logs.stdout + logs.stderr))
            time.sleep(0.5)

    def poller(self, alert):
        def poll():
            now = time.monotonic()
            if now - self.last_poll < 1.0:
                return
            self.last_poll = now
            try:
                body = self._get('/api/v1/alerts')
            except (OSError, ValueError):
                alert['errors'] += 1
                return
            alert['polls'] += 1
            for key, name in (('', ALERT_NAME), ('gap_', GAP_ALERT)):
                got = firing_alerts(body, name)
                if got and not alert[key + 'firing']:
                    alert[key + 'firing'] = got
                    alert[key + 'first_seen'] = time.time()
        return poll

    def snapshot(self, query, key='final_series'):
        """Every series matching `query` as Prometheus saw it at the end."""
        try:
            body = self._get('/api/v1/query?query=' + urllib.parse.quote(query))
            self.info[key] = {
                '%s{%s}' % (r['metric'].get('__name__'), ','.join('%s=%s' % kv for kv in sorted(
                    (k, v) for k, v in r['metric'].items() if k != '__name__'))): r['value'][1]
                for r in body['data']['result']}
        except (OSError, ValueError, KeyError) as e:
            self.info[key] = repr(e)

    def range(self, expr, key):
        """`expr` at 1 s steps over the whole run: [[epoch, value], ...]."""
        try:
            q = urllib.parse.urlencode({'query': expr, 'start': '%.3f' % self.started,
                                        'end': '%.3f' % time.time(), 'step': '1'})
            res = self._get('/api/v1/query_range?' + q)['data']['result']
            self.info[key] = {'expr': expr, 'values': [[round(float(t), 3), float(v)] for t, v in res[0]['values']]
                              if res else []}
        except (OSError, ValueError, KeyError, IndexError) as e:
            self.info[key] = {'expr': expr, 'error': repr(e)}

    def remove(self):
        r = subprocess.run(['docker', 'rm', '-fv', self.name], capture_output=True, text=True)
        self.info['removed'] = r.returncode == 0


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_listening(addr, timeout):
    host, port = addr.rsplit(':', 1)
    deadline = time.monotonic() + timeout
    while True:
        try:
            socket.create_connection((host, int(port)), timeout=1).close()
            return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)


class Sender:
    """Paced non-blocking writer that records how long stdin was blocked."""

    def __init__(self, fd):
        self.fd = fd
        os.set_blocking(fd, False)
        self.pending = b''
        self.sent = 0
        self.blocked_since = None
        self.blocked_total = 0.0
        self.longest_block = 0.0

    def pump(self, target, phase, now):
        while True:
            if not self.pending:
                if self.sent >= target:
                    break
                self.pending = event_line(self.sent, phase)
                self.sent += 1
            try:
                n = os.write(self.fd, self.pending)
            except BlockingIOError:
                if self.blocked_since is None:
                    self.blocked_since = now
                return
            self.pending = self.pending[n:]
            if self.blocked_since is not None:
                self._unblock(now)

    def _unblock(self, now):
        d = now - self.blocked_since
        self.blocked_total += d
        self.longest_block = max(self.longest_block, d)
        self.blocked_since = None

    def current_block(self, now):
        return 0.0 if self.blocked_since is None else now - self.blocked_since

    def sent_ids(self):
        return range(self.sent)

    def wait_writable(self, timeout):
        select.select([], [self.fd], [], timeout)

    def close(self):
        pass


class HttpSender:
    """Same interface as Sender for an http_server source. One request at a
    time on a worker thread; an event counts as sent once its request got a
    2xx. "Blocked" is the time a request has been waiting for its answer."""

    def __init__(self, url, batch=25, id_offset=0):
        u = urllib.parse.urlsplit(url)
        self.host, self.port, self.path, self.batch = u.hostname, u.port, u.path or '/', batch
        self.id_offset = id_offset
        self.cv = threading.Condition()
        self.target, self.phase, self.sent = 0, 'baseline', 0
        self.inflight_since = None
        self.blocked_total = 0.0
        self.longest_block = 0.0
        self.errors = 0
        self.closed = False
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    @property
    def pending(self):
        with self.cv:
            return self.inflight_since is not None

    @property
    def blocked_since(self):
        with self.cv:
            return self.inflight_since

    def pump(self, target, phase, now):
        with self.cv:
            if target > self.target:
                self.target, self.phase = target, phase
                self.cv.notify()

    def current_block(self, now):
        with self.cv:
            return 0.0 if self.inflight_since is None else now - self.inflight_since

    def wait_writable(self, timeout):
        time.sleep(timeout)

    def _unblock(self, now):
        pass  # the worker accounts for each request when it returns

    def sent_ids(self):
        with self.cv:
            return range(self.id_offset, self.id_offset + self.sent)

    def close(self):
        with self.cv:
            self.closed = True
            self.cv.notify()


    def _run(self):
        conn = None
        while True:
            with self.cv:
                while not self.closed and self.sent >= self.target:
                    self.cv.wait()
                if self.closed:
                    break
                first, n, phase = self.sent, min(self.batch, self.target - self.sent), self.phase
                start = time.monotonic()
                self.inflight_since = start
            body = b''.join(event_line(self.id_offset + i, phase) for i in range(first, first + n))
            ok = False
            try:
                if conn is None:
                    conn = http.client.HTTPConnection(self.host, self.port, timeout=600)
                conn.request('POST', self.path, body, {'Content-Type': 'application/x-ndjson'})
                resp = conn.getresponse()
                resp.read()
                ok = 200 <= resp.status < 300
            except (OSError, http.client.HTTPException):
                if conn is not None:
                    conn.close()
                conn = None
            end = time.monotonic()
            with self.cv:
                d = end - start
                self.longest_block = max(self.longest_block, d)
                if d >= 1.0:
                    self.blocked_total += d
                self.inflight_since = None
                if ok:
                    self.sent += n
                else:
                    self.errors += 1
            if not ok:
                time.sleep(0.2)  # same IDs are resent
        if conn is not None:
            conn.close()


class MultiSender:
    """Fans one paced target out over several HttpSenders (one per agent
    input), each with its own ID range; reports like a single sender."""

    def __init__(self, senders):
        self.senders = senders

    def pump(self, target, phase, now):
        n = len(self.senders)
        for k, s in enumerate(self.senders):
            s.pump(target // n + (1 if k < target % n else 0), phase, now)

    @property
    def sent(self):
        return sum(s.sent for s in self.senders)

    @property
    def pending(self):
        return any(s.pending for s in self.senders)

    @property
    def blocked_since(self):
        times = [s.blocked_since for s in self.senders if s.blocked_since is not None]
        return min(times) if times else None

    @property
    def longest_block(self):
        return max(s.longest_block for s in self.senders)

    @property
    def blocked_total(self):
        return sum(s.blocked_total for s in self.senders)

    @property
    def errors(self):
        return sum(s.errors for s in self.senders)

    def current_block(self, now):
        return max(s.current_block(now) for s in self.senders)

    def sent_ids(self):
        return [i for s in self.senders for i in s.sent_ids()]

    def wait_writable(self, timeout):
        time.sleep(timeout)

    def _unblock(self, now):
        pass

    def close(self):
        for s in self.senders:
            s.close()


@unittest.skipUnless(os.environ.get('WARDEN_LIVE_VECTOR') == '1', 'live Vector test: run `make test-vector-live`')
class BackpressureLiveTest(unittest.TestCase):
    def test_10x_burst_into_stalled_sink_loses_nothing(self):
        vector = os.environ['VECTOR']
        source = os.environ.get('BP_SOURCE') or 'stdin'
        when_full = when_full_for(source, os.environ.get('BP_WHEN_FULL'))
        inputs = inputs_for(source, os.environ.get('BP_INPUTS'))
        loadavg_start = os.getloadavg()
        configs = configs_for(source, inputs)
        work = Path(tempfile.mkdtemp(prefix='warden-bp-'))
        data, metrics = work / 'data', work / 'metrics.ndjson'
        data.mkdir()
        peer = Peer()
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'BP_DATA': str(data), 'BP_METRICS': str(metrics),
               'BP_URI': 'http://127.0.0.1:%d/' % peer.server_address[1],
               # e.g. BP_VECTOR_LOG=warn,vector_buffers=debug shows intentional buffer drops
               'VECTOR_LOG': os.environ.get('BP_VECTOR_LOG') or 'warn'}
        if source != 'stdin':
            env['BP_LISTEN'] = '127.0.0.1:%d' % free_port()
        listens = [env.get('BP_LISTEN')]
        if inputs > 1:
            listens = []
            for name in INPUT_NAMES:
                env['BP_LISTEN_' + name.upper()] = '127.0.0.1:%d' % free_port()
                listens.append(env['BP_LISTEN_' + name.upper()])
        exports = []
        if source == 'vector':
            (work / 'data-agg').mkdir()
            exports = ['127.0.0.1:%d' % free_port(), '127.0.0.1:%d' % free_port()]
            env.update({'BP_DATA_AGG': str(work / 'data-agg'), 'BP_METRICS_AGG': str(work / 'metrics-agg.ndjson'),
                        'BP_AGG': '127.0.0.1:%d' % free_port(), 'BP_WHEN_FULL': when_full,
                        'BP_PROM_EXPORT': exports[0], 'BP_AGG_PROM_EXPORT': exports[1]})
        procs, samplers, prom = [], [], None
        timeline = {}
        alert = {'polls': 0, 'errors': 0, 'firing': [], 'first_seen': None, 'gap_firing': [], 'gap_first_seen': None}
        sender = None
        try:
            # Downstream first: the aggregator must listen before the agent sink connects.
            for name, cfg, ddir in reversed(list(zip(('agent', 'aggregator'), configs,
                                                     (data, work / 'data-agg')))):
                with open(work / ('vector-%s.stderr' % name), 'wb') as err:
                    p = subprocess.Popen([vector, '--config', str(cfg)],
                                         stdin=subprocess.PIPE if source == 'stdin' else subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=err, env=env)
                procs.insert(0, p)
                samplers.insert(0, Sampler(ddir, p.pid, time.monotonic()))
                if name == 'aggregator':
                    try:
                        wait_listening(env['BP_AGG'], 30)
                    except OSError:
                        raise RuntimeError('aggregator did not start: %s' % (
                            work / 'vector-aggregator.stderr').read_text(errors='replace')[-1500:])
            for s in samplers:
                s.start()
            if exports:
                prom = Prometheus(work, exports)
                prom.start()
            if source == 'stdin':
                sender = Sender(procs[0].stdin.fileno())
            elif inputs > 1:
                for addr in listens:
                    wait_listening(addr, 30)
                sender = MultiSender([HttpSender('http://%s/' % addr, id_offset=k * ID_STRIDE) for k, addr in enumerate(listens)])
            else:
                wait_listening(env['BP_LISTEN'], 30)
                sender = HttpSender('http://%s/' % env['BP_LISTEN'])
            poll = prom.poller(alert) if prom else None
            result = self._drive(sender, peer, timeline, poll)
            if prom and when_full != 'block' and not (alert['firing'] and alert['gap_firing']):
                w0 = time.monotonic()
                while not (alert['firing'] and alert['gap_firing']) and time.monotonic() - w0 < ALERT_WAIT_SECONDS:
                    poll()
                    time.sleep(1)
                timeline['extra_alert_wait'] = round(time.monotonic() - w0, 2)
        finally:
            if sender is not None:
                sender.close()
            for s in samplers:
                s.stop.set()
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(30)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
            if prom:
                prom.snapshot('{__name__=~"vector_.*(discard|drop).*"}')
                # Event counters on the data path, to see whether any of them reveals a loss.
                prom.snapshot('{__name__=~"vector_(component_received|component_sent|buffer_received|buffer_sent)'
                              '_events_total", component_id=~"spool_warden|label_warden|agent_forward|agent|os_api"}',
                              'final_flow')
                prom.range('sum(vector_component_sent_events_total{component_id=~"^label_.*"})'
                           ' - sum(vector_buffer_received_events_total{component_id="agent_forward"})', 'gap_raw')
                # The alert expression without its "> 100" comparison.
                if prom.gap_expr:
                    prom.range(prom.gap_expr.rsplit('>', 1)[0].strip(), 'gap_alert_value')
                prom.remove()
            peer.shutdown()

        def lines(p):
            return p.read_text().splitlines() if p.exists() else []
        result['occupancy'] = samplers[0].summary()
        if source == 'vector':
            result['metrics'] = summarize_metrics(lines(metrics), 'agent_forward')
            result['occupancy_aggregator'] = samplers[1].summary()
            result['metrics_aggregator'] = summarize_metrics(lines(work / 'metrics-agg.ndjson'), 'os_api')
            result['counter_series'] = {'agent': counter_series(lines(metrics)),
                                        'aggregator': counter_series(lines(work / 'metrics-agg.ndjson'))}
        else:
            result['metrics'] = summarize_metrics(lines(metrics))
        if source == 'vector':
            first = first_positive(lines(metrics), 'buffer_discarded_events_total')
            alert['first_discard_epoch'] = first
            if first is not None and alert['firing']:
                alert['discard_to_active_s'] = round(min(a['active_at'] for a in alert['firing']) - first, 3)
                alert['discard_to_seen_s'] = round(alert['first_seen'] - first, 3)
            # No discard counter to start the clock for the gap alert: measure from the
            # first time the agent buffer was within 1% of its peak (i.e. full).
            full = first_near_peak(lines(metrics), 'buffer_byte_size', 'agent_forward', 0.99)
            alert['agent_buffer_full_epoch'] = full
            if full is not None and alert['gap_firing']:
                alert['buffer_full_to_gap_active_s'] = round(min(a['active_at'] for a in alert['gap_firing']) - full, 3)
                alert['buffer_full_to_gap_seen_s'] = round(alert['gap_first_seen'] - full, 3)
            alert['prometheus'] = prom.info if prom else None
            result['alert'] = alert
        result['timeline_s'] = timeline
        result['source'] = source
        result['load'] = {'nproc': os.cpu_count(), 'loadavg_start': loadavg_start, 'loadavg_end': os.getloadavg()}
        result['config'] = {'line_bytes': LINE_BYTES, 'base_rate': BASE_RATE, 'burst_rate': BASE_RATE * BURST_FACTOR,
                            'burst_events': BURST_EVENTS, 'buffer_max_size': 268435488, 'when_full': when_full,
                            'hops': len(configs), 'inputs': inputs}
        if prom:
            # Calibration input for WardenVectorAgentForwardGap: the largest
            # in-flight gap Prometheus saw (raw and as the alert computes it).
            result['gap_peak'] = {'raw': series_peak(prom.info.get('gap_raw', {})),
                                  'alert_value': series_peak(prom.info.get('gap_alert_value', {}))}
        stderr = {p.name: p.read_text(errors='replace') for p in sorted(work.glob('vector-*.stderr'))}
        result['vector_stderr_tail'] = {k: v[-2000:] for k, v in stderr.items()}
        result['vector_log'] = env['VECTOR_LOG']
        result['vector_stderr_counts'] = {k: {m: v.count(m) for m in ('Events dropped.', 'Request timed out', 'Retrying')}
                                          for k, v in stderr.items()}
        result['vector_stderr_dropped_lines'] = {k: [l for l in v.splitlines() if 'Events dropped.' in l][:5]
                                                 for k, v in stderr.items()}
        result['scratch_bytes'] = sum(p.stat().st_size for p in work.rglob('*') if p.is_file())
        for p in sorted(work.rglob('*'), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
        work.rmdir()
        result['failures'] = verdict(result, when_full)
        out = os.environ.get('BP_OUT')
        if out:
            Path(out).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        occ = {k: v for k, v in result['occupancy'].items() if k != 'series_t_disk_rss'}
        print(json.dumps({'reconcile': result['reconcile'], 'sender': result['sender'],
                          'metrics': result['metrics'], 'occupancy': occ,
                          'alert': {k: v for k, v in alert.items() if k != 'prometheus'} if prom else None},
                         sort_keys=True))
        self.assertEqual(result['failures'], [])

    def _drive(self, sender, peer, timeline, poll=None):
        t0 = time.monotonic()
        # Baseline.
        while (now := time.monotonic()) - t0 < BASE_SECONDS:
            sender.pump(int((now - t0) * BASE_RATE), 'baseline', now)
            time.sleep(0.01)
        sender.pump(BASE_RATE * BASE_SECONDS, 'baseline', time.monotonic())
        base_sent = sender.sent
        # Burst into a stalled peer.
        peer.stalled.set()
        b0 = time.monotonic()
        timeline['burst_start'] = b0 - t0
        total = base_sent + BURST_EVENTS
        released = False
        while sender.sent < total or sender.pending:
            now = time.monotonic()
            if now - b0 > BURST_MAX_SECONDS:
                break
            target = min(total, base_sent + int((now - b0) * BASE_RATE * BURST_FACTOR))
            sender.pump(target, 'burst', now)
            if poll:
                poll()
            if not released and sender.current_block(now) >= RELEASE_AFTER_BLOCK:
                peer.stalled.clear()
                released = True
                timeline['release'] = now - t0
            if sender.blocked_since is not None:
                sender.wait_writable(0.05)
            else:
                time.sleep(0.005)
        if not released:
            peer.stalled.clear()
            timeline['release'] = time.monotonic() - t0
        if sender.blocked_since is not None:
            sender._unblock(time.monotonic())
        timeline['burst_end'] = time.monotonic() - t0
        # Drain: until every ID arrived, DRAIN_SECONDS passed, or nothing new
        # arrived for DRAIN_IDLE_SECONDS (dropped events never arrive).
        d0 = last_change = time.monotonic()
        last_seen = -1
        while (now := time.monotonic()) - d0 < DRAIN_SECONDS:
            with peer.lock:
                seen = len(peer.counts)
                done = all(peer.counts.get(i, 0) for i in sender.sent_ids())
            if done:
                break
            if seen != last_seen:
                last_seen, last_change = seen, now
            elif now - last_change > DRAIN_IDLE_SECONDS:
                timeline['drain_idle_stop'] = True
                break
            if poll:
                poll()
            time.sleep(0.5)
        timeline['drain_end'] = time.monotonic() - t0
        with peer.lock:
            counts = dict(peer.counts)
            requests = dict(peer.requests)
        return {'reconcile': reconcile(sender.sent_ids(), counts), 'peer_requests': requests,
                'released_by_block': released,
                'sender': {'sent': sender.sent, 'baseline_sent': base_sent, 'burst_sent': sender.sent - base_sent,
                           'blocked_total_s': round(sender.blocked_total, 3),
                           'longest_block_s': round(sender.longest_block, 3),
                           'http_errors': getattr(sender, 'errors', None)}}


if __name__ == '__main__':
    unittest.main()
