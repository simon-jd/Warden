#!/usr/bin/env python3
"""Trusted bindings {execution_id, run_id, container_id, start, end} from the
collectors' registry.jsonl, for detect/report/alert_import.py.

The container ID is the one Falco reports for the run:
* runc: the Docker container. For a runc lab run that is the lab's outer
  container (the Warden runc driver's sandboxes are cgroups below it, and
  Falco's container matcher takes the docker-<id>.scope component); for a
  container Docker runs with runc it is that container. The run is named by
  the label warden.dev/run, or by the runc lab's session label. start and end
  are Docker's start and die events, to the nanosecond.
* gVisor (host level, the default): the pod sandbox's containerd ID. runsc's
  sentry and gofer run in the sandbox's cgroup, and the host instance reports
  that ID (the collector's registry records it as sandbox_id). The run is the
  pod's warden.dev/run label. The sandbox exists before the container starts
  and after it ends, so start is the pod's creationTimestamp and end the later
  of one second after the container's finishedAt (the API gives whole
  seconds) and when the collector first saw the pod gone. The ID is unique
  to the run's pod, so its whole life cannot take in another run's events.
* gVisor with --gvisor-engine (the opt-in gVisor-engine instance, broken
  upstream: falcosecurity/libs#3074): the pod container's own ID, from its
  startedAt to one second after its finishedAt (or when it was seen gone).

When one container ran several runs (a runc lab container runs all its
tests), give each run its own --start/--end; they must lie inside the
container's lifetime. Nothing is widened beyond that, and a run that has not
ended has no binding.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import re
import sys

FULL_ID = re.compile(r'[0-9a-f]{64}')
RUN_LABEL = 'warden.dev/run'
_TS = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?(Z|z|[+-][0-9]{2}:[0-9]{2})')
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def ns(value):
    match = _TS.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError('timestamp with an explicit offset required: %r' % (value,))
    zone = '+00:00' if match[3] in ('Z', 'z') else match[3]
    seconds = (datetime.fromisoformat(match[1] + zone) - EPOCH) // timedelta(seconds=1)
    return seconds * 1_000_000_000 + int((match[2] or '0')[:9].ljust(9, '0'))


def plus_one_second(value):
    match = _TS.fullmatch(value)
    zone = '+00:00' if match[3] in ('Z', 'z') else match[3]
    later = datetime.fromisoformat(match[1] + zone) + timedelta(seconds=1)
    text = later.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    return text + ('.' + match[2] if match[2] else '') + 'Z'


def runs(registry, run_id):
    """container ID -> its registry records, for every container of run_id."""
    k8s_ids = {r['container_id'] for r in registry if r.get('source') == 'k8s' and r.get('run_id') == run_id}
    found = {}
    for r in registry:
        cid = r.get('container_id', '')
        if not FULL_ID.fullmatch(cid):
            continue
        if r.get('source') == 'docker':
            labels = r.get('labels') or {}
            if run_id in (labels.get(RUN_LABEL), labels.get('session')) and labels.get('project') == 'warden':
                found.setdefault(cid, []).append(r)
        elif r.get('source') == 'k8s' and cid in k8s_ids:
            found.setdefault(cid, []).append(r)
    return found


def lifetime(records, gvisor_engine=False):
    source = records[0]['source']
    if source == 'docker':
        starts = [r['time'] for r in records if r['event'] == 'start']
        dies = [r['time'] for r in records if r['event'] == 'die']
        if len(starts) != 1:
            raise ValueError('container started %d times in the registry' % len(starts))
        later = [d for d in dies if ns(d) > ns(starts[0])]
        if not later:
            raise ValueError('run has not ended (no die event)')
        return starts[0], min(later, key=ns)
    started = {r['started_at'] for r in records if r.get('started_at')}
    if len(started) != 1:
        raise ValueError('pod container has %d start times' % len(started))
    finished = [plus_one_second(r['finished_at']) for r in records if r.get('finished_at')]
    gone = [r['observed_at'] for r in records if r['event'] == 'gone']
    if not finished and not gone:
        raise ValueError('run has not ended (no terminated or gone record)')
    if gvisor_engine:
        return started.pop(), max(finished, key=ns) if finished else min(gone, key=ns)
    created = {r['created_at'] for r in records if r.get('created_at')}
    first = min(created | started, key=ns)
    return first, max(finished + ([min(gone, key=ns)] if gone else []), key=ns)


def sandbox_of(records):
    ids = {r.get('sandbox_id') for r in records} - {None}
    if len(ids) != 1:
        raise ValueError('pod sandbox ID unknown (%d recorded); no host-level binding' % len(ids))
    return ids.pop()


def binding(registry, *, run_id, execution_id, container_id=None, start=None, end=None, gvisor_engine=False):
    if not isinstance(execution_id, str) or not execution_id.strip():
        raise ValueError('execution ID required')
    found = runs(registry, run_id)
    if container_id is not None:
        found = {k: v for k, v in found.items() if k == container_id}
    if len(found) != 1:
        raise ValueError('run %r has %d containers in the registry; name one with --container-id' % (run_id, len(found)))
    cid, records = next(iter(found.items()))
    first, last = lifetime(records, gvisor_engine)
    if records[0]['source'] == 'k8s' and not gvisor_engine:
        cid = sandbox_of(records)
    if (start is None) != (end is None):
        raise ValueError('--start and --end go together')
    if start is not None:
        if not ns(first) <= ns(start) < ns(end) <= ns(last):
            raise ValueError('window must lie inside the container lifetime %s .. %s' % (first, last))
        first, last = start, end
    if not ns(first) < ns(last):
        raise ValueError('binding start must precede end')
    return {'execution_id': execution_id, 'run_id': run_id, 'container_id': cid, 'start': first, 'end': last}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--registry', action='append', required=True, help="a collector's registry.jsonl; repeat")
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--execution-id', required=True)
    parser.add_argument('--container-id')
    parser.add_argument('--start')
    parser.add_argument('--end')
    parser.add_argument('--gvisor-engine', action='store_true', help="gVisor runs: the pod container's ID (opt-in engine)")
    args = parser.parse_args(argv)
    try:
        registry = []
        for path in args.registry:
            with open(path) as source:
                registry += [json.loads(line) for line in source if line.strip()]
        result = binding(registry, run_id=args.run_id, execution_id=args.execution_id,
                         container_id=args.container_id, start=args.start, end=args.end, gvisor_engine=args.gvisor_engine)
    except (OSError, ValueError, KeyError) as error:
        print('error: %s' % error, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
