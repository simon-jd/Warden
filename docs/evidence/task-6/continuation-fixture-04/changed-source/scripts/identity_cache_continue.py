#!/usr/bin/env python3
"""One fixed continuation of the known terminated legacy permission operation.

Capture and continuation require separate controller admissions. No cache data
bodies, subprocesses, retries, services, configurable paths or charge mutations.
The controller must exclude all writers; flock does not exclude hostile same-UID
actors, and metadata equality is not content authentication.
"""
from contextlib import contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import identity_cache as old
from runtime_lab_paths import trusted_directory

ROOT = Path(__file__).absolute().parent.parent
OLD_INTENT_SHA = 'cbc9e3aad72189cf1a048ee1a30270ea43dce2925823563c283fecd3dcf65e5e'
OLD_INTENT_BYTES = 4573737
COUNTS = {'entries': 22682, 'directories': 260, 'files': 22422, 'prefix': 19160}
OLD_SOURCES = {
    'scripts/identity_cache.py': 'f608dc714b79dcc4f3c4c2071ba6dd561c88eec10c45fc905820ec447d8a1ede',
    'scripts/test_identity_cache.py': '807fc390ea6b807f895b39acfd9ffc48d143ccd5a3b3dc4f1f3d05cfdeb93bc2',
    'scripts/runtime_lab_paths.py': '0ce3287feab8197839cf2e7e1cf297fd5cad0e740069023b188e4c366b643f84',
    'scripts/firecracker_recovery.py': 'cccb3378b92816dc5242fd79e72df5fc79fcda338b8f20d34c5a9ca655a8453b',
    'scripts/firecracker_recovery_init.py': '72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2',
    'scripts/azure_guard.py': '303980a3eb5bc2c7a53ae2be985ac29c643b73d4df907e094f8cface2489eb48',
}
HISTORY = {
    'docs/evidence/task-6/controller-cache-execute-result-20261025.json': '8d4be73e27f4bb0fd48a2fd9894e2a68f4e5a0d34c846ae5b0cbd9543a177f86',
    'docs/evidence/task-6/controller-cache-timeout-audit-20261025.json': 'a1c36c66fe505394e3cce7ddd8f32fe6c237b31a576e93a708f13c476f13d6ef',
    'docs/evidence/task-6/controller-cache-preflight-20261025.json': 'ce1bde34cbf69b160541231cb7c4dc766aee632c5e3a32d8c96bcfb98c4d4846',
}
APPROVAL_NAME = 'cache-continuation-checkpoint-approval-20261025.json'
CHECKPOINT = 'identity-cache-continuation-v1-checkpoint.json'
PREPARED = 'identity-cache-continuation-v1-intent.json'
READY = 'identity-cache-continuation-v1-ready.json'
RESULT = 'identity-cache-continuation-v1-result.json'
CHECKPOINT_LIMIT = 16000000
RECEIPT_LIMIT = 65536
OPERATION = 'task6-cache-continuation-v1'


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, 'duplicate metadata member')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('invalid JSON constant')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)


def _schema(value, fields):
    _require(type(value) is dict and set(value) == set(fields), 'unexpected metadata schema')


def _vector(value, length):
    _require(type(value) is list and len(value) == length and
             all(type(n) is int and n >= 0 for n in value), 'invalid metadata vector')


def _meta(info):
    return list(old.fingerprint(info)) + [info.st_blocks]


def _legacy_meta(info):
    # The controller's original public metadata order differs from old fingerprint.
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_blocks, info.st_mtime_ns, info.st_ctime_ns]


def _absent(parent, names):
    for name in names:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise FileExistsError('existing operation state; retain without retry')


class _Record:
    def __init__(self, parent, name, data, info, limit, private):
        self.parent, self.name, self.data, self.info = parent, name, data, info
        self.limit, self.private = limit, private

    def recheck(self):
        other = _read(self.parent, self.name, self.limit, self.private)
        _require(_meta(other.info) == _meta(self.info) and other.data == self.data,
                 'authority metadata changed')


def _read(parent, name, limit, private=False):
    _require('/' not in name and name not in ('', '.', '..'), 'fixed basename required')
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    modes = (0o600,) if private else (0o600, 0o644, 0o700, 0o755)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 1000 and
             info.st_dev == os.fstat(parent).st_dev and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) in modes and 0 < info.st_size <= limit,
             'untrusted fixed metadata file')
    fd = os.open(name, old.FILE_FLAGS, dir_fd=parent)
    try:
        _require(_meta(os.fstat(fd)) == _meta(info), 'metadata changed on open')
        chunks, remaining = [], limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        _require(len(data) == info.st_size and len(data) <= limit, 'metadata read length changed')
        _require(_meta(os.fstat(fd)) == _meta(info), 'metadata changed while read')
        _require(_meta(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _meta(info),
                 'metadata path replaced')
        return _Record(parent, name, data, info, limit, private)
    finally:
        os.close(fd)


def _read_private(parent, name, limit):
    return _read(parent, name, limit, True)


def _durable(parent, name, value):
    _require(name in (CHECKPOINT, PREPARED, READY, RESULT), 'fixed journal required')
    data = _raw(value)
    limit = CHECKPOINT_LIMIT if name == CHECKPOINT else RECEIPT_LIMIT
    _require(len(data) <= limit, 'journal exceeds fixed bound')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        created = os.fstat(fd)
        _require(stat.S_ISREG(created.st_mode) and created.st_uid == created.st_gid == 1000 and
                 created.st_nlink == 1 and stat.S_IMODE(created.st_mode) == 0o600,
                 'new journal identity invalid')
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            _require(count > 0, 'journal write made no progress')
            offset += count
        os.fsync(fd)
        current = os.fstat(fd)
        _require(current.st_ino == created.st_ino and current.st_dev == created.st_dev and
                 current.st_uid == current.st_gid == 1000 and current.st_nlink == 1 and
                 stat.S_IMODE(current.st_mode) == 0o600 and current.st_size == len(data),
                 'new journal changed')
        _require(_meta(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _meta(current),
                 'new journal path replaced')
    finally:
        os.close(fd)
    os.fsync(parent)
    return _read_private(parent, name, limit)


@contextmanager
def _session():
    _require(os.getuid() == os.geteuid() == os.getgid() == 1000, 'ordinary UID/GID1000 required')
    os.umask(0o077)
    fds = {}
    try:
        for key, relative in (('root', ''), ('lab', '.cache/warden-lab'), ('cache', '.cache'),
                              ('public', 'docs/evidence/task-6'), ('scripts', 'scripts')):
            fds[key] = trusted_directory(str(ROOT / relative), 1000)
        with old.project_lock(fds['lab'], 1000):
            yield fds
    finally:
        for fd in reversed(list(fds.values())):
            os.close(fd)


def _anchors(fds):
    result = {key: _meta(os.fstat(fds[key])) for key in ('root', 'cache', 'lab')}
    result['lock'] = _meta(os.stat('docker.lock', dir_fd=fds['lab'], follow_symlinks=False))
    return result


def _check_anchors(fds, expected):
    _schema(expected, ('root', 'cache', 'lab', 'lock'))
    current = _anchors(fds)
    for key in expected:
        _vector(expected[key], 10)
        # Only the cache parent's own size/times/blocks may change as fixed
        # continuation journals are added. Its identity/mode/nlink cannot change.
        count = 6 if key == 'cache' else 10
        _require(current[key][:count] == expected[key][:count], 'trusted anchor changed')
    for key, relative in (('root', ''), ('cache', '.cache'), ('lab', '.cache/warden-lab')):
        # Reopen via unchanged trust helper to bind held ancestors to live paths.
        fd = trusted_directory(str(ROOT / relative), 1000)
        try:
            _require(_meta(os.fstat(fd)) == current[key], 'held anchor detached')
        finally:
            os.close(fd)


def _binding(fds):
    sources = {}
    for name in (*OLD_SOURCES, 'scripts/identity_cache_continue.py', 'scripts/test_identity_cache_continue.py'):
        sources[name] = _sha(_read(fds['scripts'], Path(name).name, 1048576).data)
        if name in OLD_SOURCES:
            _require(sources[name] == OLD_SOURCES[name], 'fixed original source changed')
    history = {}
    for name, digest in HISTORY.items():
        record = _read(fds['public'], Path(name).name, RECEIPT_LIMIT)
        _require(_sha(record.data) == digest, 'fixed public history changed')
        history[Path(name).name] = _json(record.data)
    execution = history['controller-cache-execute-result-20261025.json']
    audit = history['controller-cache-timeout-audit-20261025.json']
    pre = history['controller-cache-preflight-20261025.json']
    _require(type(execution.get('exit_code')) is int and execution['exit_code'] == -15 and
             execution.get('timed_out') is True and execution.get('recorder_error') is None and
             execution.get('command') == ['python3', '-B', 'scripts/identity_cache.py'] and
             execution.get('source_hashes_before') == OLD_SOURCES and
             execution.get('source_hashes_after') == OLD_SOURCES,
             'original terminal outcome not established')
    _require(audit.get('known_original_process_exit') == -15 and audit.get('timeout_seconds') == 180 and
             audit.get('completion_receipt_present') is False and audit.get('maintenance_complete') is False,
             'original timeout audit inconsistent')
    _require(pre.get('source_hashes') == OLD_SOURCES, 'original preflight source mismatch')
    cache_info = _legacy_meta(os.fstat(fds['cache']))
    lab_info = _legacy_meta(os.fstat(fds['lab']))
    lock_info = _legacy_meta(os.stat('docker.lock', dir_fd=fds['lab'], follow_symlinks=False))
    _require(cache_info[:5] == pre['trusted_anchors_metadata']['.cache'][:5] and
             lab_info == pre['trusted_anchors_metadata']['.cache/warden-lab'] and
             lock_info == pre['existing_project_lock_metadata'], 'original parent or lock identity changed')
    return {'operation': OPERATION, 'source_hashes': sources, 'history_hashes': dict(HISTORY),
            'old_intent_sha256': OLD_INTENT_SHA, 'old_intent_bytes': OLD_INTENT_BYTES,
            'original_exit_code': -15, 'original_timeout_seconds': 180, 'counts': dict(COUNTS)}


class _CheckpointPlan(old.CachePlan):
    # This union is only for a read-only scan. Exact per-entry old/prefix and
    # checkpoint comparisons below are mandatory before ANY target mutation.
    def _modes(self, directory, executable):
        if directory:
            return (0o700, 0o755, 0o775)
        return (0o700, 0o755) if executable else (0o600, 0o644, 0o664)


def _rows(plan):
    plan._recheck_all()
    by_fd = {node.fd: node for node in plan.directories}
    result = []
    for node in plan.directories + plan.files + plan.preserved:
        current = os.stat(node.name, dir_fd=node.parent, follow_symlinks=False)
        _require(_meta(current) == _meta(node.info), 'cache blocks or fingerprint changed')
        parts, up = [node.name], node.parent
        while up in by_fd:
            parts.append(by_fd[up].name)
            up = by_fd[up].parent
        result.append({'relative': '/'.join(reversed(parts)), 'metadata': _meta(node.info),
                       'target_mode': 0o700 if node.fd >= 0 or node.executable else 0o600})
    return result


def _validate_original(plan, record):
    _require(len(record.data) == OLD_INTENT_BYTES and _sha(record.data) == OLD_INTENT_SHA,
             'wrong original intent bytes')
    value = _json(record.data)
    _schema(value, ('version', 'state', 'cache_name', 'entries'))
    _require(type(value['version']) is int and value['version'] == 1 and
             value['state'] == 'prepared-not-completed' and value['cache_name'] == 'go-build',
             'wrong original intent state')
    entries = value['entries']
    _require(type(entries) is list and len(entries) == COUNTS['entries'] and
             len(plan.directories) == COUNTS['directories'] and
             len(plan.files) + len(plan.preserved) == COUNTS['files'], 'wrong complete cache counts')
    rows = _rows(plan)
    seen = set()
    for index, (entry, row) in enumerate(zip(entries, rows)):
        _schema(entry, ('relative', 'original', 'target_mode'))
        _vector(entry['original'], 9)
        _require(entry['relative'] == row['relative'] and entry['relative'] not in seen and
                 type(entry['target_mode']) is int and entry['target_mode'] == row['target_mode'],
                 'original intent order/path/target mismatch')
        seen.add(entry['relative'])
        before, current = entry['original'], row['metadata'][:9]
        directory = stat.S_ISDIR(before[4])
        modes = (0o755, 0o775) if directory else ((0o755,) if row['target_mode'] == 0o700 else (0o644, 0o664))
        _require(stat.S_IMODE(before[4]) in modes and stat.S_IFMT(before[4]) == stat.S_IFMT(current[4]),
                 'invalid original type or mode')
        _require(all(before[i] == current[i] for i in (0, 1, 2, 3, 5, 6, 7)),
                 'original stable metadata changed')
        if index < COUNTS['prefix']:
            _require(stat.S_IMODE(current[4]) == row['target_mode'], 'non-contiguous target prefix')
        else:
            _require(before == current, 'original suffix including ctime changed')
    return rows


def _basis(value):
    _require(type(value) is str and 0 < len(value.encode('utf-8')) <= 4096 and value.strip(),
             'explicit controller writer basis required')


def _timestamp(value):
    _require(type(value) is str and len(value) <= 64, 'invalid checkpoint time')
    parsed = datetime.datetime.fromisoformat(value)
    _require(parsed.utcoffset() == datetime.timedelta(0), 'checkpoint time must be UTC')


def _checkpoint_rows(value):
    _require(type(value) is list and len(value) == COUNTS['entries'], 'invalid checkpoint entry count')
    seen = set()
    for row in value:
        _schema(row, ('relative', 'metadata', 'target_mode'))
        _require(type(row['relative']) is str and row['relative'] not in seen and
                 type(row['target_mode']) is int and row['target_mode'] in (0o600, 0o700),
                 'invalid checkpoint row')
        seen.add(row['relative'])
        _vector(row['metadata'], 10)


def capture_checkpoint(writer_basis):
    """Fixed future controller callable; captures metadata once, never approves it.

    No path arguments. Calling this on the real project requires separate
    source-reviewed capture admission; importing this module performs no capture.
    """
    _basis(writer_basis)
    with _session() as fds:
        _absent(fds['public'], (APPROVAL_NAME,))
        _absent(fds['cache'], (CHECKPOINT, PREPARED, READY, RESULT, old.RESULT_NAME))
        binding = _binding(fds)
        original = _read_private(fds['cache'], old.INTENT_NAME, 32000000)
        plan = _CheckpointPlan(fds['cache'], 1000)
        try:
            rows = _validate_original(plan, original)
            anchors = _anchors(fds)
            captured = datetime.datetime.now(datetime.timezone.utc).isoformat()
            checkpoint = {'version': 1, 'state': 'captured', 'binding': binding, 'writer_basis': writer_basis,
                          'captured_at': captured, 'anchors': anchors, 'entries': rows}
            original.recheck()
            _require(_binding(fds) == binding, 'capture authority changed')
            _check_anchors(fds, anchors)
            _require(_rows(plan) == rows, 'capture live metadata changed')
            record = _durable(fds['cache'], CHECKPOINT, checkpoint)
            _require(_rows(plan) == rows, 'cache changed during checkpoint durability')
            original.recheck()
            return {'version': 1, 'state': 'checkpoint-captured-not-approved', 'binding': binding,
                    'writer_basis': writer_basis, 'captured_at': captured,
                    'checkpoint_sha256': _sha(record.data), 'checkpoint_bytes': len(record.data)}
        finally:
            plan.close()


def _approval(record, binding):
    value = _json(record.data)
    _schema(value, ('version', 'state', 'binding', 'writer_basis', 'captured_at', 'checkpoint_sha256', 'checkpoint_bytes'))
    _require(type(value['version']) is int and value['version'] == 1 and value['state'] == 'approved' and
             value['binding'] == binding, 'unapproved checkpoint binding')
    _require(type(value['checkpoint_bytes']) is int and 0 < value['checkpoint_bytes'] <= CHECKPOINT_LIMIT and
             type(value['checkpoint_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['checkpoint_sha256']),
             'invalid approved digest or length')
    _basis(value['writer_basis'])
    _timestamp(value['captured_at'])
    return value


def _verify_authority(fds, binding, anchors, records):
    _require(_binding(fds) == binding, 'frozen source/history changed')
    _check_anchors(fds, anchors)
    _absent(fds['cache'], (old.RESULT_NAME,))
    for record in records:
        record.recheck()


def _tighten_and_sync(plan, progress):
    by_fd = {node.fd: node for node in plan.directories}
    targets = plan.directories + plan.files + plan.preserved
    for count, node in enumerate(targets, 1):
        ancestors, parent = [], node.parent
        while parent in by_fd:
            ancestors.append(by_fd[parent])
            parent = by_fd[parent].parent
        for ancestor in reversed(ancestors):
            plan._recheck_node(ancestor)
        plan._recheck_node(node)
        fd = node.fd if node.fd >= 0 else os.open(node.name, old.FILE_FLAGS, dir_fd=node.parent)
        try:
            before = node.info
            _require(_meta(os.fstat(fd)) == _meta(before), 'target replaced before tightening')
            target = 0o700 if node.fd >= 0 or node.executable else 0o600
            _require(not target & ~stat.S_IMODE(before.st_mode), 'permissions would expand')
            if stat.S_IMODE(before.st_mode) != target:
                os.fchmod(fd, target)
            current = os.fstat(fd)
            old_values, new_values = _meta(before), _meta(current)
            _require(all(old_values[i] == new_values[i] for i in (0, 1, 2, 3, 5, 6, 7, 9)) and
                     stat.S_IFMT(before.st_mode) == stat.S_IFMT(current.st_mode) and
                     stat.S_IMODE(current.st_mode) == target, 'target changed during tightening')
            node.info = current
            plan._recheck_node(node)
            # Also sync every already-target node: the killed operation may have
            # stopped after chmod and before its fsync returned successfully.
            os.fsync(fd)
            _require(_meta(os.fstat(fd)) == _meta(current), 'target changed during fsync')
            plan._recheck_node(node)
        finally:
            if node.fd < 0:
                os.close(fd)
        progress(count)
    plan._recheck_all()


def main(argv=None):
    _require(not (sys.argv[1:] if argv is None else argv), 'fixed continuation takes no arguments')
    with _session() as fds:
        # Missing controller approval fails before any private journal body read.
        approved_record = _read(fds['public'], APPROVAL_NAME, RECEIPT_LIMIT)
        binding = _binding(fds)
        approval = _approval(approved_record, binding)
        _absent(fds['cache'], (PREPARED, READY, RESULT, old.RESULT_NAME))
        checkpoint_record = _read_private(fds['cache'], CHECKPOINT, CHECKPOINT_LIMIT)
        _require(len(checkpoint_record.data) == approval['checkpoint_bytes'] and
                 _sha(checkpoint_record.data) == approval['checkpoint_sha256'], 'checkpoint differs from approval')
        checkpoint = _json(checkpoint_record.data)
        _schema(checkpoint, ('version', 'state', 'binding', 'writer_basis', 'captured_at', 'anchors', 'entries'))
        _require(type(checkpoint['version']) is int and checkpoint['version'] == 1 and checkpoint['state'] == 'captured' and
                 all(checkpoint[k] == approval[k] for k in ('binding', 'writer_basis', 'captured_at')),
                 'checkpoint binding mismatch')
        _checkpoint_rows(checkpoint['entries'])
        original = _read_private(fds['cache'], old.INTENT_NAME, 32000000)
        plan = _CheckpointPlan(fds['cache'], 1000)
        try:
            rows = _validate_original(plan, original)
            _require(rows == checkpoint['entries'], 'live metadata differs from complete checkpoint')
            authorities = [approved_record, checkpoint_record, original]
            anchors = checkpoint['anchors']
            _verify_authority(fds, binding, anchors, authorities)
            state = {'version': 1, 'operation': OPERATION, 'binding': binding,
                     'checkpoint_sha256': approval['checkpoint_sha256'],
                     'approval_sha256': _sha(approved_record.data), 'wall_limit_seconds': 600}
            prepared = _durable(fds['cache'], PREPARED, {**state, 'state': 'prepared-not-completed'})
            authorities.append(prepared)
            _verify_authority(fds, binding, anchors, authorities)
            _require(_rows(plan) == rows, 'cache changed after prepared durability')
            last = time.monotonic()
            print(json.dumps({'phase': 'prepared', 'targets': len(rows)}), flush=True)
            def progress(count):
                nonlocal last
                now = time.monotonic()
                if now - last >= 30:
                    print(json.dumps({'phase': 'syncing', 'targets_done': count}), flush=True)
                    last = now
            _tighten_and_sync(plan, progress)
            tightened = _rows(plan)
            strict = old.CachePlan(fds['cache'], 1000)
            try:
                _require(_rows(strict) == tightened and all(stat.S_IMODE(r['metadata'][4]) == r['target_mode']
                         for r in tightened), 'strict plan differs after all-target fsync')
                os.fsync(fds['cache'])
                _verify_authority(fds, binding, anchors, authorities)
                _absent(fds['cache'], (READY, RESULT))
                ready = _durable(fds['cache'], READY, {**state, 'state': 'ready-not-completed',
                                  'prepared_sha256': _sha(prepared.data),
                                  'synced_entries': len(tightened), 'metadata_sha256': _sha(_raw(tightened))})
                authorities.append(ready)
                _verify_authority(fds, binding, anchors, authorities)
                _absent(fds['cache'], (RESULT,))
                _require(_rows(strict) == tightened, 'strict plan changed before first unlink')
                print(json.dumps({'phase': 'ready', 'targets': len(tightened)}), flush=True)
                removed = strict.remove()
                _verify_authority(fds, binding, anchors, authorities)
                result = {**state, 'state': 'completed', 'prepared_sha256': _sha(prepared.data),
                          'ready_sha256': _sha(ready.data), **removed}
                _durable(fds['cache'], RESULT, result)
                print(json.dumps({'phase': 'completed', **removed}, sort_keys=True), flush=True)
            finally:
                strict.close()
        finally:
            plan.close()


if __name__ == '__main__':
    main()
