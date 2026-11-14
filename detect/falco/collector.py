#!/usr/bin/env python3
"""Keep the Falco alerts of Warden containers; only count everyone else's.

One collector reads one Falco instance (host or gvisor). Falco writes every
alert as one JSON line into a FIFO (file_output); a FIFO holds nothing on disk.
For each line the collector decides:

* Falco's own events (source "internal": metrics snapshots, drop notices)
  go to health.jsonl unchanged;
* an alert whose container.id is a Warden container goes to alerts.jsonl
  unchanged (the bytes Falco wrote), with the decision in scoping.jsonl;
* runsc's start-up signature in a Warden pod's sandbox ("PTRACE attached to
  process" from gvisor_sentry: the sentry attaching to its stubs, which every
  gVisor sandbox does) goes to platform-alerts.jsonl with class platform: kept
  and reviewable, never among the alerts scored against runs;
* an alert of a host process, of another project's container, of a container
  no resolver knows within --resolve-deadline seconds, and any line that is
  not a Falco JSON event, is counted and dropped. Nothing of it is written.

A line is never lost silently. If its lookup or a write fails it is kept
for the next pass and the error is counted (collector_errors); past
--resolve-deadline it is dropped and counted (dropped_unresolved, or
dropped_error after an error). Writes are idempotent per alert: an alert
already in alerts.jsonl (also from before a restart) is not written again.

A Warden container is a Docker container labelled project=warden (the label
every Warden lab container carries), or a container of a pod in the k3s
lab's namespace warden-lab with the label warden.dev/run. Docker is asked
through its socket (and, for a container that has already gone, the start
events this collector recorded), the lab through the API server named in its
kubeconfig. With --cgroup-root, an ID no API knows is also looked up as a
cgroup nested inside a running Warden container's: the k3s node's pod
sandboxes, where runsc's sentry runs. There the pod decides first (only a
warden-lab pod with warden.dev/run is Warden's; the smoke's control pod is
not, although it runs in the Warden node); a cgroup of the node in no pod is
the node's own infrastructure. Every kept alert gets a container class:
sandbox (a Warden run), node (the k3s node) or lab (other lab containers).

heartbeats.jsonl gets one record every --heartbeat seconds, and at once on
SIGUSR1: the Falco container's state from Docker and the counters so far.
An error in one step is counted (collector_errors) and the loop goes on; if
the reader dies the collector exits non-zero and systemd restarts it, and the
new start counts itself in collector_restarts. registry.jsonl
records Warden containers' lifetimes (Docker start/die events with
--watch-docker, k3s pod container states with --watch-k8s); bindings.py
turns them into trusted bindings. Standard library only.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import queue
import re
import signal
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone

MAX_LINE = 1 << 20
SHORT_ID = re.compile(r'[0-9a-f]{12,64}')
FULL_ID = re.compile(r'[0-9a-f]{64}')
NOT_A_CONTAINER = (None, '', 'host', '<NA>')
DOCKER_LABELS = ('project', 'owner', 'session', 'warden.dev/run')
WARDEN_NAMESPACE = 'warden-lab'
RUN_LABEL = 'warden.dev/run'
# dropped_other_container counts every other container's alert; of those,
# dropped_other_lab_owned are containers labelled owner=warden-lab without
# project=warden (the detector's own Falco containers, the smoke's control)
# and dropped_other_lab_pod are k3s lab pods outside warden-lab.
COUNTERS = ('received', 'warden_alerts', 'platform_alerts', 'health_events', 'duplicates', 'dropped_host',
            'dropped_other_container', 'dropped_other_lab_owned', 'dropped_other_lab_pod', 'dropped_unresolved',
            'dropped_error', 'dropped_malformed', 'dropped_overflow', 'collector_errors', 'collector_restarts')
# (rule, proc.name) of what every gVisor sandbox does at start, in its pod
# sandbox's cgroup: platform start-up, not an alert of the run.
PLATFORM_SIGNATURES = frozenset({('PTRACE attached to process', 'gvisor_sentry')})
NODE_NAME = 'warden-k3s-gvisor'
POD_DIR = re.compile(r'pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})')


def now_rfc3339(ns=None):
    ns = time.time_ns() if ns is None else ns
    seconds, fraction = divmod(ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + '.%09dZ' % fraction


def canonical_sha256(event):
    """The digest alert_import.py gives the same event (falco-<digest>)."""
    text = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(text.encode()).hexdigest()


def classify(raw):
    """(kind, event, container_id) for one line Falco wrote.

    kind is 'malformed', 'health' (Falco's own events), 'host' (no container)
    or 'container'.
    """
    try:
        event = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return 'malformed', None, None
    if not isinstance(event, dict) or not isinstance(event.get('rule'), str) or not isinstance(event.get('time'), str):
        return 'malformed', None, None
    fields = event.get('output_fields')
    if not isinstance(fields, dict):
        return 'malformed', None, None
    if event.get('source') == 'internal' or event['rule'].startswith('Falco internal:'):
        return 'health', event, None
    container_id = fields.get('container.id')
    if container_id in NOT_A_CONTAINER:
        return 'host', event, None
    if not isinstance(container_id, str) or not SHORT_ID.fullmatch(container_id):
        return 'malformed', None, None
    return 'container', event, container_id


class Decision:
    __slots__ = ('warden', 'resolver', 'full_id', 'run_id', 'detail', 'klass')

    def __init__(self, warden, resolver, full_id, run_id, detail, klass=None):
        self.warden, self.resolver, self.full_id, self.run_id, self.detail = warden, resolver, full_id, run_id, detail
        self.klass = klass


def labels_decision(full, labels, name, resolver):
    """A Docker container's decision from its labels and name."""
    if not FULL_ID.fullmatch(full or ''):
        return None
    detail = {k: labels[k] for k in DOCKER_LABELS if k in labels}
    detail['name'] = name
    warden = labels.get('project') == 'warden'
    run = labels.get(RUN_LABEL) or labels.get('session')
    klass = None
    if warden:
        klass = 'sandbox' if run else 'node' if name == NODE_NAME else 'lab'
    return Decision(warden, resolver, full, run, detail, klass)


def docker_decision(inspect):
    labels = (inspect.get('Config') or {}).get('Labels') or {}
    return labels_decision(inspect.get('Id', ''), labels, (inspect.get('Name') or '').lstrip('/'), 'docker')


def pod_containers(pod):
    """(full container ID, status) of every container of one pod object."""
    status = pod.get('status') or {}
    for key in ('initContainerStatuses', 'containerStatuses', 'ephemeralContainerStatuses'):
        for item in status.get(key) or []:
            cid = item.get('containerID') or ''
            if '://' in cid:
                cid = cid.split('://', 1)[1]
            if FULL_ID.fullmatch(cid):
                yield cid, item


def pod_decision(pod, full_id):
    meta = pod.get('metadata') or {}
    labels = meta.get('labels') or {}
    namespace = meta.get('namespace')
    warden = namespace == WARDEN_NAMESPACE and RUN_LABEL in labels
    detail = {'namespace': namespace, 'pod': meta.get('name')}
    if RUN_LABEL in labels:
        detail[RUN_LABEL] = labels[RUN_LABEL]
    return Decision(warden, 'k8s', full_id, labels.get(RUN_LABEL), detail, 'sandbox' if warden else None)


def sandbox_ids(cgroup_root, parents, uid):
    """The 64-hex cgroups directly in pod <uid>'s cgroup (its sandbox and
    containers), below any of the parent containers' scopes."""
    found, want = set(), uid.replace('_', '-')
    for top in cgroup_tops(cgroup_root, parents):
        for directory, dirs, _ in walk(top):
            match = POD_DIR.search(os.path.basename(directory))
            if match and match.group(1).replace('_', '-') == want:
                found.update(f for d in dirs for f in re.findall(r'[0-9a-f]{64}', d))
    return found


def cgroup_tops(cgroup_root, parents):
    for parent in parents:
        for top in (os.path.join(cgroup_root, 'system.slice', 'docker-%s.scope' % parent),
                    os.path.join(cgroup_root, 'docker', parent)):
            if os.path.isdir(top):
                yield top


def walk(top, depth=6):
    base = top.count(os.sep)
    for directory, dirs, files in os.walk(top):
        if directory.count(os.sep) - base >= depth:
            dirs[:] = []
        yield directory, dirs, files


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__('localhost', timeout=timeout)
        self.unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


class DockerAPI:
    def __init__(self, path='/var/run/docker.sock'):
        self.path = path

    def get(self, url, timeout=5):
        conn = UnixHTTPConnection(self.path, timeout)
        try:
            conn.request('GET', url)
            resp = conn.getresponse()
            body = resp.read(8 << 20)
            return resp.status, (json.loads(body) if resp.status == 200 else None)
        finally:
            conn.close()

    def inspect(self, ident):
        status, body = self.get('/containers/%s/json' % urllib.parse.quote(ident, safe=''))
        return body if status == 200 else None

    def running(self, labels):
        filters = {'label': ['%s=%s' % kv for kv in labels.items()]}
        status, body = self.get('/containers/json?filters=' + urllib.parse.quote(json.dumps(filters)))
        return [c['Id'] for c in body or []] if status == 200 else []

    def events(self, filters):
        """Yield Docker events until the stream ends."""
        conn = UnixHTTPConnection(self.path, timeout=None)
        try:
            conn.request('GET', '/events?filters=' + urllib.parse.quote(json.dumps(filters)))
            resp = conn.getresponse()
            if resp.status != 200:
                raise OSError('docker events: HTTP %d' % resp.status)
            while True:
                line = resp.readline(1 << 20)
                if not line:
                    return
                if line.strip():
                    yield json.loads(line)
        finally:
            conn.close()


def kubeconfig_fields(text):
    """server, CA, client certificate and key from a k3s kubeconfig."""
    out = {}
    for key in ('server', 'certificate-authority-data', 'client-certificate-data', 'client-key-data'):
        values = re.findall(r'^\s*' + re.escape(key) + r':\s*(\S+)\s*$', text, re.M)
        if len(values) != 1:
            raise ValueError('kubeconfig needs exactly one ' + key)
        out[key] = values[0]
    if not re.fullmatch(r'https://[0-9.]+:[0-9]+', out['server']):
        raise ValueError('kubeconfig server must be https://<address>:<port>')
    return out


class KubeAPI:
    """The k3s lab's API server, from its kubeconfig; reloaded when that file
    changes (every lab up writes a new one) and idle while it is missing."""

    def __init__(self, kubeconfig, private_dir):
        self.kubeconfig, self.private_dir = kubeconfig, private_dir
        self.identity, self.context, self.host, self.port = None, None, None, None

    def _load(self):
        try:
            info = os.stat(self.kubeconfig)
        except FileNotFoundError:
            self.identity = self.context = None
            return False
        identity = (info.st_ino, info.st_mtime_ns, info.st_size)
        if identity == self.identity:
            return self.context is not None
        with open(self.kubeconfig) as source:
            fields = kubeconfig_fields(source.read(1 << 20))
        os.makedirs(self.private_dir, mode=0o700, exist_ok=True)
        os.chmod(self.private_dir, 0o700)
        cert, key = os.path.join(self.private_dir, 'client.crt'), os.path.join(self.private_dir, 'client.key')
        for path, data in ((cert, fields['client-certificate-data']), (key, fields['client-key-data'])):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(base64.b64decode(data))
        context = ssl.create_default_context(cadata=base64.b64decode(fields['certificate-authority-data']).decode())
        context.load_cert_chain(cert, key)
        parsed = urllib.parse.urlsplit(fields['server'])
        self.context, self.host, self.port, self.identity = context, parsed.hostname, parsed.port, identity
        return True

    def get(self, url, timeout=5):
        if not self._load():
            return None
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=timeout)
        try:
            conn.request('GET', url)
            resp = conn.getresponse()
            body = resp.read(32 << 20)
            return json.loads(body) if resp.status == 200 else None
        finally:
            conn.close()

    def pods(self, namespace=None, selector=None):
        url = '/api/v1/namespaces/%s/pods' % namespace if namespace else '/api/v1/pods'
        if selector:
            url += '?labelSelector=' + urllib.parse.quote(selector)
        body = self.get(url)
        return None if body is None else body.get('items') or []

    def close(self):
        for name in ('client.crt', 'client.key'):
            try:
                os.unlink(os.path.join(self.private_dir, name))
            except FileNotFoundError:
                pass
        try:
            os.rmdir(self.private_dir)
        except OSError:
            pass


class Resolver:
    """Container ID (Falco's 12 characters, or more) -> Decision.

    Decisions are cached: a container ID never changes owner. None means no
    resolver knows the ID (yet)."""

    def __init__(self, docker=None, kube=None, clock=time.monotonic, kube_refresh=1.0, cgroup_root=None):
        self.docker, self.kube, self.clock, self.kube_refresh = docker, kube, clock, kube_refresh
        self.cgroup_root = cgroup_root
        self.cache, self.pods, self.pods_by_uid, self.pods_at = {}, {}, {}, None
        self.exited = {}  # full ID -> (labels, name), from Docker start events
        self.nested_seen = {}  # full ID -> (parent, pod uid or None): cgroups found once, kept after they go
        self.lock = threading.Lock()

    def remember_pod_cgroups(self, pod, ids, inside):
        """Cgroups of a pod that are none of its containers (its sandbox),
        found by the pod watch while they exist: the pod decides."""
        with self.lock:
            uid = (pod.get('metadata') or {}).get('uid')
            if uid:
                self.pods_by_uid[uid] = pod
            for full in ids:
                by_pod = pod_decision(pod, full)
                self.pods[full] = Decision(by_pod.warden, 'cgroup' if by_pod.warden else 'cgroup-pod', full, by_pod.run_id,
                                           dict(by_pod.detail, inside=inside), by_pod.klass)

    def remember_docker(self, record):
        if record.get('source') == 'docker' and FULL_ID.fullmatch(record.get('container_id', '')):
            with self.lock:
                self.exited[record['container_id']] = (record.get('labels') or {}, record.get('name') or '')

    def remember_pods(self, items):
        with self.lock:
            for pod in items:
                uid = (pod.get('metadata') or {}).get('uid')
                if uid:
                    self.pods_by_uid[uid] = pod
                for full, _ in pod_containers(pod):
                    self.pods[full] = pod_decision(pod, full)
            self.pods_at = self.clock()

    def _refresh_pods(self, force=False):
        if self.kube is None:
            return
        with self.lock:
            due = force or self.pods_at is None or self.clock() - self.pods_at >= self.kube_refresh
        if not due:
            return
        try:
            items = self.kube.pods()
        except (OSError, ValueError, http.client.HTTPException):
            items = None
        if items is not None:
            self.remember_pods(items)
        else:
            with self.lock:
                self.pods_at = self.clock()

    def _from_pods(self, short):
        return {full: d for full, d in self.pods.items() if full.startswith(short)}

    def _nested(self, short):
        """A cgroup named with this ID inside a running Warden container's:
        its pod decides first, else it is that container's."""
        if self.cgroup_root is None or self.docker is None:
            return {}
        try:
            parents = self.docker.running({'project': 'warden'})
        except OSError:
            return {}
        found = {}
        for parent in parents:
            for top in cgroup_tops(self.cgroup_root, [parent]):
                for directory, dirs, _ in walk(top):
                    for name in dirs:
                        for full in re.findall(r'[0-9a-f]{64}', name):
                            if full.startswith(short):
                                path = os.path.relpath(os.path.join(directory, name), top)
                                match = POD_DIR.search(path)
                                found[full] = (parent, match.group(1).replace('_', '-') if match else None)
        with self.lock:
            self.nested_seen.update(found)
            for full, seen in self.nested_seen.items():
                if full.startswith(short) and full not in found:
                    found[full] = seen  # its cgroup has gone since
        decisions = {}
        for full, (parent, uid) in found.items():
            inspect = self.docker.inspect(parent)
            owner = docker_decision(inspect) if inspect else None
            if owner is None or not owner.warden:
                continue
            inside = owner.detail.get('name')
            if uid:
                with self.lock:
                    pod = self.pods_by_uid.get(uid)
                if pod is None:
                    self._refresh_pods()
                    with self.lock:
                        pod = self.pods_by_uid.get(uid)
                if pod is None:
                    continue  # unknown pod: retried, then dropped as unresolved
                by_pod = pod_decision(pod, full)
                detail = dict(by_pod.detail, inside=inside)
                decisions[full] = Decision(by_pod.warden, 'cgroup' if by_pod.warden else 'cgroup-pod', full,
                                           by_pod.run_id, detail, 'sandbox' if by_pod.warden else None)
            else:
                decisions[full] = Decision(True, 'cgroup', full, owner.run_id, {'inside': inside, 'project': 'warden'},
                                           owner.klass)
        return decisions

    def resolve(self, short):
        with self.lock:
            if short in self.cache:
                return self.cache[short]
        found = {}
        if self.docker is not None:
            try:
                inspect = self.docker.inspect(short)
            except OSError:
                inspect = None
            decision = docker_decision(inspect) if inspect else None
            if decision is not None and decision.full_id.startswith(short):
                found[decision.full_id] = decision
        if not found:
            with self.lock:
                gone = {full: v for full, v in self.exited.items() if full.startswith(short)}
            for full, (labels, name) in gone.items():
                decision = labels_decision(full, labels, name, 'registry')
                if decision is not None:
                    found[full] = decision
        if self.kube is not None and not found:
            with self.lock:
                from_pods = self._from_pods(short)
            if not from_pods:
                self._refresh_pods()
                with self.lock:
                    from_pods = self._from_pods(short)
            found.update(from_pods)
        if not found:
            found = self._nested(short)
        if len(found) != 1:
            return None  # unknown, or the short ID is ambiguous
        decision = next(iter(found.values()))
        with self.lock:
            self.cache[short] = self.cache[decision.full_id] = decision
        return decision


class Sink:
    """Append-only JSONL files in one private directory."""

    def __init__(self, directory):
        self.directory = directory
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.files = {}
        self.lock = threading.Lock()

    def write(self, name, line):
        if isinstance(line, (dict, list)):
            line = json.dumps(line, sort_keys=True, separators=(',', ':')).encode()
        with self.lock:
            out = self.files.get(name)
            if out is None:
                fd = os.open(os.path.join(self.directory, name), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
                out = self.files[name] = os.fdopen(fd, 'ab')
            out.write(line.rstrip(b'\n') + b'\n')
            out.flush()

    def sync(self):
        with self.lock:
            for out in self.files.values():
                os.fsync(out.fileno())

    def close(self):
        with self.lock:
            for out in self.files.values():
                out.flush()
                os.fsync(out.fileno())
                out.close()
            self.files = {}


class Collector:
    def __init__(self, instance, sink, resolver, deadline=20.0, clock=time.monotonic):
        self.instance, self.sink, self.resolver, self.deadline, self.clock = instance, sink, resolver, deadline, clock
        self.counts = dict.fromkeys(COUNTERS, 0)
        self.pending = []  # (first seen, raw line, container id or None)
        self.waiting = set()  # container ids with pending alerts
        self.kept = {'alerts': set(), 'scoping': set(), 'health': set()}  # what is written, by digest
        self.lock = threading.Lock()

    def count(self, name, n=1):
        with self.lock:
            self.counts[name] += n

    def load_kept(self, out):
        """After a restart: what this directory already holds is not written again."""
        for name in ('alerts.jsonl', 'platform-alerts.jsonl'):
            for line in _lines(os.path.join(out, name)):
                try:
                    self.kept['alerts'].add(canonical_sha256(json.loads(line)))
                except ValueError:
                    pass
        for line in _lines(os.path.join(out, 'scoping.jsonl')):
            try:
                self.kept['scoping'].add(json.loads(line)['raw_event_sha256'])
            except (ValueError, KeyError):
                pass
        for line in _lines(os.path.join(out, 'health.jsonl')):
            self.kept['health'].add(hashlib.sha256(line.rstrip(b'\n')).hexdigest())

    def feed(self, raw):
        self.count('received')
        try:
            state, container_id = self._process(raw, {}, self.waiting)
        except Exception as error:  # noqa: BLE001 -- the line waits for the next pass
            self._error(error)
            state, container_id = 'error', None
        if state != 'done':
            self.pending.append((self.clock(), raw, container_id))
            if container_id:
                self.waiting.add(container_id)

    def tick(self, final=False):
        """Retry pending lines; past the deadline (or when final) they are
        dropped and counted. Each container is looked up once per pass."""
        now = self.clock()
        work, self.pending, decisions = self.pending, [], {}
        for first, raw, _ in work:
            try:
                state, container_id = self._process(raw, decisions)
            except Exception as error:  # noqa: BLE001
                self._error(error)
                state, container_id = 'error', None
            if state == 'done':
                continue
            if final or now - first >= self.deadline:
                self.count('dropped_unresolved' if state == 'unknown' else 'dropped_error')
            else:
                self.pending.append((first, raw, container_id))
        self.waiting = {cid for _, _, cid in self.pending if cid}

    def _error(self, error):
        self.count('collector_errors')
        print('collector: %s' % type(error).__name__, file=sys.stderr, flush=True)

    def _process(self, raw, decisions, waiting=frozenset()):
        """('done' | 'unknown' | 'error', container id). Write errors raise."""
        kind, event, container_id = classify(raw)
        if kind == 'malformed':
            self.count('dropped_malformed')
            return 'done', None
        if kind == 'health':
            digest = hashlib.sha256(raw.rstrip(b'\n')).hexdigest()
            if digest not in self.kept['health']:
                self.sink.write('health.jsonl', raw)
                self.kept['health'].add(digest)
                self.count('health_events')
            return 'done', None
        if kind == 'host':
            self.count('dropped_host')
            return 'done', None
        if container_id in waiting:
            return 'unknown', container_id  # its container is being looked up: wait with the others
        if container_id not in decisions:
            try:
                decisions[container_id] = self.resolver.resolve(container_id)
            except Exception as error:  # noqa: BLE001 -- e.g. a Docker HTTP error or socket timeout
                self._error(error)
                decisions[container_id] = ERROR
        decision = decisions[container_id]
        if decision is ERROR:
            return 'error', container_id
        if decision is None:
            return 'unknown', container_id
        self._apply(raw, event, container_id, decision)
        return 'done', container_id

    def _apply(self, raw, event, container_id, decision):
        if not decision.warden:
            self.count('dropped_other_container')
            if decision.resolver in ('k8s', 'cgroup-pod'):
                self.count('dropped_other_lab_pod')
            elif decision.detail.get('owner') == 'warden-lab':
                self.count('dropped_other_lab_owned')
            return
        digest = canonical_sha256(event)
        if digest in self.kept['alerts'] and digest in self.kept['scoping']:
            self.count('duplicates')
            return
        klass, target = decision.klass, 'alerts.jsonl'
        process = (event.get('output_fields') or {}).get('proc.name')
        if decision.resolver == 'cgroup' and klass == 'sandbox' and (event['rule'], process) in PLATFORM_SIGNATURES:
            klass, target = 'platform', 'platform-alerts.jsonl'
        if digest not in self.kept['alerts']:
            self.sink.write(target, raw)
            self.kept['alerts'].add(digest)
        if digest not in self.kept['scoping']:
            self.sink.write('scoping.jsonl', {
                'raw_event_sha256': digest, 'time': event['time'], 'rule': event['rule'],
                'instance': self.instance, 'container_id': container_id, 'full_container_id': decision.full_id,
                'resolver': decision.resolver, 'run_id': decision.run_id, 'class': klass, 'detail': decision.detail})
            self.kept['scoping'].add(digest)
        self.count('platform_alerts' if klass == 'platform' else 'warden_alerts')

    def snapshot(self):
        with self.lock:
            counts = dict(self.counts)
        counts['pending'] = len(self.pending)
        return counts


ERROR = object()


def _lines(path):
    try:
        with open(path, 'rb') as source:
            return [line for line in source if line.strip()]
    except FileNotFoundError:
        return []


def falco_state(docker, name):
    try:
        inspect = docker.inspect(name)
    except OSError as error:
        return {'error': type(error).__name__}
    if inspect is None:
        return {'running': False, 'exists': False}
    state = inspect.get('State') or {}
    return {'exists': True, 'running': state.get('Running') is True, 'started_at': state.get('StartedAt'),
            'restart_count': inspect.get('RestartCount'), 'oom_killed': state.get('OOMKilled'),
            'exit_code': state.get('ExitCode'), 'image': inspect.get('Image')}


def docker_time(event):
    nano = event.get('timeNano')
    if isinstance(nano, int):
        return now_rfc3339(nano)
    return now_rfc3339(int(event.get('time', 0)) * 1_000_000_000)


def registry_from_docker_event(event):
    actor = event.get('Actor') or {}
    attributes = actor.get('Attributes') or {}
    cid = actor.get('ID') or event.get('id') or ''
    action = event.get('Action') or event.get('status')
    if not FULL_ID.fullmatch(cid) or action not in ('start', 'die'):
        return None
    labels = {k: attributes[k] for k in DOCKER_LABELS if k in attributes}
    return {'source': 'docker', 'event': action, 'container_id': cid, 'time': docker_time(event),
            'name': attributes.get('name'), 'labels': labels,
            'exit_code': attributes.get('exitCode') if action == 'die' else None}


class PodTracker:
    """Turn successive lists of the lab's Warden pods into registry records.
    sandboxes(uid) gives the pod's 64-hex cgroups (detect/falco/collector.py
    sandbox_ids); the one that is not a container of the pod is its sandbox,
    the ID the host Falco instance reports for runsc's sentry."""

    def __init__(self, sandboxes=None):
        self.seen, self.sandbox = {}, {}  # container id -> last state key / sandbox id
        self.sandboxes = sandboxes

    def update(self, items, observed_at):
        records, present = [], set()
        for pod in items:
            meta = pod.get('metadata') or {}
            labels = meta.get('labels') or {}
            if meta.get('namespace') != WARDEN_NAMESPACE or RUN_LABEL not in labels:
                continue
            containers = dict(pod_containers(pod))
            if self.sandboxes is not None and meta.get('uid'):
                others = set(self.sandboxes(meta['uid'])) - set(containers)
                if len(others) == 1:
                    for cid in containers:
                        self.sandbox[cid] = next(iter(others))
            for cid, status in containers.items():
                present.add(cid)
                state = status.get('state') or {}
                running, terminated = state.get('running'), state.get('terminated')
                key = 'terminated' if terminated else 'running' if running else 'waiting'
                if key == 'waiting' or self.seen.get(cid) == key:
                    continue
                self.seen[cid] = key
                records.append({'source': 'k8s', 'event': key, 'container_id': cid, 'run_id': labels[RUN_LABEL],
                                'pod': meta.get('name'), 'pod_uid': meta.get('uid'), 'namespace': meta.get('namespace'),
                                'created_at': meta.get('creationTimestamp'), 'sandbox_id': self.sandbox.get(cid),
                                'started_at': (terminated or running or {}).get('startedAt'),
                                'finished_at': (terminated or {}).get('finishedAt'),
                                'exit_code': (terminated or {}).get('exitCode'), 'observed_at': observed_at})
        for cid in [c for c in self.seen if c not in present]:
            if self.seen[cid] != 'gone':
                records.append({'source': 'k8s', 'event': 'gone', 'container_id': cid, 'sandbox_id': self.sandbox.get(cid),
                                'observed_at': observed_at})
            del self.seen[cid]
        return records


def drop_acl(path):
    """Remove POSIX ACLs (a parent's default ACL is inherited), so the mode
    bits alone say who may open the path."""
    for name in ('system.posix_acl_access', 'system.posix_acl_default'):
        try:
            os.removexattr(path, name, follow_symlinks=False)
        except OSError:
            pass


def open_fifo(path, gid):
    """Create (or reuse) the FIFO Falco writes to and open it read-write, so a
    writer closing it after each alert is not an EOF. Mode 0600, or 0620 with
    group gid for a Falco container that runs without capabilities."""
    try:
        os.mkfifo(path, 0o600)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISFIFO(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError('not our FIFO: ' + path)
    drop_acl(path)
    if gid is not None:
        os.chown(path, -1, gid, follow_symlinks=False)
        os.chmod(path, 0o620)
    else:
        os.chmod(path, 0o600)
    return os.open(path, os.O_RDWR | os.O_CLOEXEC)


def read_lines(fd, out, stop, collector):
    buffer, skipping = b'', False
    while not stop.is_set():
        chunk = os.read(fd, 1 << 16)
        if not chunk:
            continue
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
                collector.count('received')
                collector.count('dropped_malformed')
                continue
            if line.strip():
                try:
                    out.put_nowait(line)
                except queue.Full:
                    collector.count('received')
                    collector.count('dropped_overflow')


def watch_docker(docker, sink, stop, resolver=None):
    filters = {'type': ['container'], 'label': ['project=warden'], 'event': ['start', 'die']}
    while not stop.is_set():
        try:
            for event in docker.events(filters):
                record = registry_from_docker_event(event)
                if record:
                    sink.write('registry.jsonl', record)
                    if resolver is not None:
                        resolver.remember_docker(record)
                if stop.is_set():
                    return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        stop.wait(1)


def watch_k8s(kube, resolver, sink, stop, interval=1.0, docker=None, cgroup_root=None):
    """Every second: the lab's pods (for the pod rule), each pod's sandbox
    cgroup while it exists (so an alert processed after the sandbox went is
    still placed), and registry records of the Warden pods."""
    cgroups = {}
    tracker = PodTracker((lambda uid: cgroups.get(uid, set())) if docker is not None and cgroup_root else None)
    while not stop.is_set():
        try:
            items = kube.pods()
            if items is not None:
                resolver.remember_pods(items)
                cgroups.clear()
                if docker is not None and cgroup_root:
                    for parent in docker.running({'project': 'warden'}):
                        inside = ((docker.inspect(parent) or {}).get('Name') or '').lstrip('/')
                        for pod in items:
                            uid = (pod.get('metadata') or {}).get('uid')
                            if not uid:
                                continue
                            ids = sandbox_ids(cgroup_root, [parent], uid)
                            cgroups.setdefault(uid, set()).update(ids)
                            own = {full for full, _ in pod_containers(pod)}
                            if ids - own:
                                resolver.remember_pod_cgroups(pod, ids - own, inside)
                for record in tracker.update(items, now_rfc3339()):
                    sink.write('registry.jsonl', record)
        except (OSError, ValueError, http.client.HTTPException):
            pass
        stop.wait(interval)


def serve(collector, lines, stop, heartbeat, beat_every, flush, reader=None):
    """The main loop: feed lines, retry pending alerts, beat. An error in a
    step is counted and the loop goes on; a dead reader ends it (systemd
    restarts the collector)."""
    next_beat = time.monotonic()
    while True:
        try:
            try:
                raw = lines.get(timeout=0.2)
                collector.feed(raw)
            except queue.Empty:
                pass
            collector.tick()
        except Exception as error:  # noqa: BLE001 -- counted, never fatal
            collector.count('collector_errors')
            print('collector step failed: %s' % type(error).__name__, file=sys.stderr, flush=True)
        if flush.is_set() or time.monotonic() >= next_beat:
            flush.clear()
            try:
                heartbeat()
            except Exception as error:  # noqa: BLE001
                collector.count('collector_errors')
                print('heartbeat failed: %s' % type(error).__name__, file=sys.stderr, flush=True)
            next_beat = time.monotonic() + beat_every
        if stop.is_set() and lines.empty():
            return 0
        if reader is not None and not reader.is_alive():
            print('collector: the FIFO reader stopped', file=sys.stderr, flush=True)
            return 1


def previous_starts(out):
    """How often this collector ran before in this directory (its heartbeats)."""
    path = os.path.join(out, 'heartbeats.jsonl')
    try:
        with open(path) as source:
            lines = [line for line in source if line.strip()]
    except FileNotFoundError:
        return 0
    if not lines:
        return 0
    try:
        return int(json.loads(lines[-1]).get('counts', {}).get('collector_restarts', 0)) + 1
    except ValueError:
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--instance', required=True, choices=('host', 'gvisor'))
    parser.add_argument('--fifo', required=True)
    parser.add_argument('--fifo-gid', type=int, help='group the Falco container writes the FIFO as')
    parser.add_argument('--out', required=True, help='private directory for the JSONL files')
    parser.add_argument('--falco-container', required=True)
    parser.add_argument('--docker-socket', default='/var/run/docker.sock')
    parser.add_argument('--kubeconfig', help="the k3s lab's kubeconfig (read whenever it exists)")
    parser.add_argument('--cgroup-root', help='also place IDs nested in a Warden container\'s cgroup (host instance)')
    parser.add_argument('--watch-docker', action='store_true')
    parser.add_argument('--watch-k8s', action='store_true')
    parser.add_argument('--resolve-deadline', type=float, default=20.0)
    parser.add_argument('--heartbeat', type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.watch_k8s and not args.kubeconfig:
        parser.error('--watch-k8s needs --kubeconfig')
    stop, flush = threading.Event(), threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGUSR1, lambda *_: flush.set())
    restarts = previous_starts(args.out)
    sink = Sink(args.out)
    docker = DockerAPI(args.docker_socket)
    kube = KubeAPI(args.kubeconfig, os.path.join(args.out, 'kube-client')) if args.kubeconfig else None
    resolver = Resolver(docker, kube, cgroup_root=args.cgroup_root)
    registry = os.path.join(args.out, 'registry.jsonl')
    if os.path.exists(registry):  # after a restart: containers seen before
        with open(registry) as source:
            for line in source:
                try:
                    resolver.remember_docker(json.loads(line))
                except ValueError:
                    pass
    collector = Collector(args.instance, sink, resolver, args.resolve_deadline)
    collector.load_kept(args.out)
    collector.count('collector_restarts', restarts)
    lines = queue.Queue(maxsize=200000)
    fd = open_fifo(args.fifo, args.fifo_gid)
    started = now_rfc3339()
    reader = threading.Thread(target=read_lines, args=(fd, lines, stop, collector), daemon=True)
    threads = [reader]
    if args.watch_docker:
        threads.append(threading.Thread(target=watch_docker, args=(docker, sink, stop, resolver), daemon=True))
    if args.watch_k8s:
        threads.append(threading.Thread(target=watch_k8s, args=(kube, resolver, sink, stop), daemon=True,
                                        kwargs={'docker': docker, 'cgroup_root': args.cgroup_root}))
    for thread in threads:
        thread.start()
    print('collector %s: reading %s, writing %s (start %d)' % (args.instance, args.fifo, args.out, restarts), flush=True)

    def heartbeat():
        sink.write('heartbeats.jsonl', {'time': now_rfc3339(), 'instance': args.instance, 'collector_started_at': started,
                                        'falco': falco_state(docker, args.falco_container), 'counts': collector.snapshot()})
        sink.sync()

    status = serve(collector, lines, stop, heartbeat, args.heartbeat, flush, reader)
    collector.tick(final=True)
    try:
        heartbeat()
    except Exception as error:  # noqa: BLE001
        print('final heartbeat failed: %s' % type(error).__name__, file=sys.stderr, flush=True)
    print('collector %s: stopped, %s' % (args.instance, json.dumps(collector.snapshot(), sort_keys=True)), flush=True)
    sink.close()
    if kube is not None:
        kube.close()
    return status


if __name__ == '__main__':
    sys.exit(main())
