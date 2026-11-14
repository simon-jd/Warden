#!/usr/bin/env python3
"""Reviewed one-shot recovery of one stopped bootstrap; no general root runner."""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

from k3s_lab import BASE, ROOT, verify_anchor
from k3s_lab_recovery_init import (CHILD, CHILD_IDENTITY, OUTER_IDENTITY, MARKER,
                                  directory, validate_resource_diagnostic)
from runtime_lab_docker import (docker, owned_inspect, scoped_ids, read_trusted,
                               outstanding_bytes, preflight as ordinary_preflight)
from runtime_lab_paths import NOFOLLOW_DIR, trusted_directory, exclusive_file

ORIGINAL = '9a22e3c1817441fa2c4f50616e68a333d2a06c98641d430a05a810ea3f7cac50'
IMAGE = 'sha256:2504a55c791dba7ca00cadae8b11f937aea70ac9149243eb83e590d343bc44a3'
LABELS = {'owner': 'codex-warden', 'project': 'warden',
          'session': 'b5370b6ce57638aee676a14c3c272592', 'ttl': '2026-10-24T19:09:18Z'}
OUTPUT = BASE / ('docker-' + LABELS['session'])
SCOPE = Path('/sys/fs/cgroup/system.slice/docker-' + ORIGINAL + '.scope')
HELPER_RESERVE = 64000000
TAR_IDENTITY = (66307, 56143030, 1000)
TAR_SIZE = 496619520


def recovery_proof(output):
    # The helper's only public output is one canonical, bounded diagnostic plus
    # the original cleanup marker. No raw helper text is forwarded on failure.
    if not isinstance(output, str) or len(output) > 1024:
        raise ValueError('invalid fixed recovery output')
    lines = output.splitlines()
    if len(lines) != 2 or lines[1] != MARKER:
        raise ValueError('recovery proof absent')
    try:
        value = json.loads(lines[0])
    except ValueError:
        raise ValueError('invalid fixed recovery diagnostic JSON') from None
    if (not isinstance(value, dict) or set(value) != {'resource_diagnostic'}
            or output != json.dumps(value, sort_keys=True) + '\n' + MARKER + '\n'):
        raise ValueError('noncanonical fixed recovery diagnostic')
    return validate_resource_diagnostic(value['resource_diagnostic'])


def verify_archive(parent, archive):
    for info in (os.fstat(archive), os.stat('rootfs.tar', dir_fd=parent, follow_symlinks=False)):
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size != TAR_SIZE
                or (info.st_dev, info.st_ino, info.st_uid) != TAR_IDENTITY):
            raise ValueError('fixed retained archive identity or shape drifted')


def create_args(labels, code):
    args = ['container', 'create', '--pull=never', '--network=none', '--ipc=private',
            '--cgroupns=private', '--read-only', '--cap-drop=ALL',
            '--cap-add=SYS_ADMIN', '--cap-add=DAC_OVERRIDE',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=unconfined',
            '--security-opt=seccomp=unconfined', '--memory=256000000',
            '--memory-swap=256000000', '--pids-limit=32', '--cpus=1',
            '--log-driver=json-file', '--log-opt=max-size=1m', '--log-opt=max-file=2',
            '--entrypoint=/usr/bin/python3', '--mount',
            f'type=bind,src={OUTPUT},dst=/session,readonly,bind-propagation=rprivate',
            '--env', 'WARDEN_LAB_SESSION_IDENTITY=' + ':'.join(map(str, OUTER_IDENTITY)),
            '--env', 'WARDEN_LAB_HOST_MOUNT_NS=' + os.readlink('/proc/self/ns/mnt')]
    for key, value in labels.items():
        args += ['--label', key + '=' + value]
    return args + [IMAGE, '-B', '-c', code]


def scope_absent():
    try:
        os.stat(SCOPE, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError('original runtime scope remains; preserved')


def anchor(fd, *, private):
    verify_anchor(OUTPUT, fd)
    directory(os.fstat(fd), OUTER_IDENTITY)
    if private:
        directory(os.stat(CHILD, dir_fd=fd, follow_symlinks=False), CHILD_IDENTITY)
    else:
        try:
            os.stat(CHILD, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError('private child remains; scene retained')


def original_stopped(cli):
    info = owned_inspect('container', ORIGINAL, LABELS, cli)
    if (info['Image'] != IMAGE or info['State']['Status'] != 'exited'
            or info['State']['Pid'] != 0 or info['State']['Running']
            or info['RestartCount'] != 0 or info['HostConfig']['PidMode'] != ''):
        raise ValueError('original stopped runtime identity mismatch')
    scope_absent()


def allocated_project():
    # Same allocated-file rule as the ordinary guard, with exactly one opaque
    # directory charged in full by the unreleased 6GB reservation. No user path
    # or exclusion argument exists. Directory traversal stays on held FDs.
    skipped = False
    def walk(fd, relative):
        nonlocal skipped
        total = 0
        for name in os.listdir(fd):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            path = relative / name
            if ROOT / path == OUTPUT / CHILD:
                directory(info, CHILD_IDENTITY)
                skipped = True
                continue
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, NOFOLLOW_DIR, dir_fd=fd)
                try:
                    if (os.fstat(child).st_dev, os.fstat(child).st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError('accounting directory drifted')
                    total += walk(child, path)
                    again = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if (again.st_dev, again.st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError('accounting directory drifted')
                finally:
                    os.close(child)
            elif not stat.S_ISLNK(info.st_mode):
                total += info.st_blocks * 512
        return total
    fd = trusted_directory(str(ROOT), os.getuid())
    try:
        result = walk(fd, Path())
    finally:
        os.close(fd)
    if not skipped:
        raise ValueError('fixed reserved private directory absent before recovery')
    return result


def image_charges(cli):
    total = 0
    for image in set(scoped_ids('image', {'project': 'warden'}, cli)):
        info = owned_inspect('image', image, {'project': 'warden'}, cli)
        if type(info['Size']) is not int or info['Size'] < 0:
            raise ValueError('unknown owned image size')
        total += 2 * info['Size'] + 64000000
    return total


def preflight(other_memory, cli):
    used, outstanding, images = allocated_project(), outstanding_bytes(BASE), image_charges(cli)
    if type(other_memory) is not int or other_memory < 0 or outstanding < 6000000000:
        raise ValueError('retained reservation and service maxima required')
    total = used + outstanding + images + HELPER_RESERVE
    memory = other_memory + 256000000 + 64000000
    if total > 12000000000 or memory > 16000000000:
        raise ValueError('fixed recovery exceeds disk/service memory budget')
    return {'project_allocated_bytes': used, 'outstanding_bytes': outstanding,
            'all_owned_image_charges': images, 'helper_reserve_bytes': HELPER_RESERVE,
            'accounted_disk_bytes': total, 'service_memory_bytes': memory}


def removed(kind, identity, labels, cli):
    if identity in scoped_ids(kind, labels, cli):
        raise ValueError('removed owned runtime object remains')
    try:
        cli([kind, 'inspect', identity], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        # A transport/permission failure is never object-absence evidence.
        message = error.stderr.decode() if isinstance(error.stderr, bytes) else error.stderr
        expected = (f'Error response from daemon: No such {kind}: {identity}',
                    f'Error: No such {kind}: {identity}', f'Error: No such object: {identity}')
        if message is not None and message.strip() in expected:
            return
        raise ValueError('object absence not established') from None
    raise ValueError('exact object still inspectable')


def durable(fd, name, data):
    target = exclusive_file(fd, name, json.dumps(data, sort_keys=True).encode() + b'\n')
    try:
        os.fsync(target)
    finally:
        os.close(target)
    os.fsync(fd)


def recover(other_memory, *, reviewed=False, cli=docker):
    if not reviewed:
        raise ValueError('independent fixed recovery review required')
    fd = trusted_directory(str(OUTPUT), os.getuid())
    archive = None
    try:
        anchor(fd, private=True)
        archive = os.open('rootfs.tar', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        verify_archive(fd, archive)
        charge = json.loads(read_trusted(OUTPUT / 'charge.json', os.getuid()))
        if charge != {'version': 1, 'reserved_bytes': 6000000000, 'released': False}:
            raise ValueError('original 6GB reservation must remain held')
        daemon = json.loads(cli(['info', '--format', '{{json .}}']))
        if (daemon['Name'] != os.uname().nodename or daemon['CgroupDriver'] != 'systemd'
                or daemon['CgroupVersion'] != '2' or any('rootless' in x for x in daemon['SecurityOptions'])):
            raise ValueError('fixed local rootful cgroup-v2 Docker required')
        original_stopped(cli)
        owned_inspect('image', IMAGE, LABELS, cli)
        if set(scoped_ids('container', {'project': 'warden'}, cli)) != {ORIGINAL}:
            raise ValueError('unexpected Warden runtime objects; reconcile separately')
        budget = preflight(other_memory, cli)
        code = read_trusted(ROOT / 'scripts/k3s_lab_recovery_init.py', os.getuid()).decode()
        labels = {'owner': 'codex-warden', 'project': 'warden', 'session': secrets.token_hex(16),
                  'ttl': (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  'role': 'fixed-reconciliation'}
        anchor(fd, private=True)
        # Exclusive durable journal fences retries/lost create responses. The
        # original 6GB stays held until every helper/original object is absent.
        durable(fd, 'recovery.json', {'original': ORIGINAL, 'image': IMAGE,
                'helper_labels': labels, 'helper_reserve_bytes': HELPER_RESERVE,
                'code_sha256': hashlib.sha256(code.encode()).hexdigest(), 'budget': budget,
                'archive': {'identity': TAR_IDENTITY, 'size': TAR_SIZE}})
        args = create_args(labels, code)
        cid = cli(args).strip()
        helper = owned_inspect('container', cid, labels, cli)
        if (helper['Image'] != IMAGE or helper['Config']['Entrypoint'] != ['/usr/bin/python3']
                or helper['Config']['Cmd'] != ['-B', '-c', code]):
            raise ValueError('immutable recovery command identity mismatch')
        anchor(fd, private=True)
        original_stopped(cli)
        output = cli(['container', 'start', '--attach', cid], timeout=60)
        if cli(['container', 'wait', cid]).strip() != '0':
            raise ValueError('recovery proof absent; all objects and charges retained')
        diagnostic = recovery_proof(output)
        helper = owned_inspect('container', cid, labels, cli)
        if helper['State']['Pid'] != 0 or helper['State']['Running'] or helper['State']['Status'] != 'exited':
            raise ValueError('recovery helper still active')
        anchor(fd, private=False)
        original_stopped(cli)
        for kind, identity, ownership in [('container', cid, labels), ('container', ORIGINAL, LABELS), ('image', IMAGE, LABELS)]:
            anchor(fd, private=False)
            scope_absent()
            owned_inspect(kind, identity, ownership, cli)
            cli([kind, 'rm', identity])
            removed(kind, identity, ownership, cli)
        anchor(fd, private=False)
        ordinary_preflight(outstanding_bytes(BASE) + image_charges(cli) + HELPER_RESERVE, other_memory + 64000000)
        anchor(fd, private=False)
        verify_archive(fd, archive)
        os.unlink('rootfs.tar', dir_fd=fd)
        os.fsync(fd)
        durable(fd, 'recovery-complete.json', {'original': ORIGINAL, 'helper': cid,
                                             'image': IMAGE, 'objects_absent': True, 'archive_deleted': True,
                                             'helper_resource_diagnostic': diagnostic})
        anchor(fd, private=False)
        durable(fd, 'charge-released.json', {'version': 1, 'reserved_bytes': 6000000000, 'released': True})
        os.replace('charge-released.json', 'charge.json', src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
        print(json.dumps({'recovery': 'complete', 'original': ORIGINAL, 'helper': cid,
                          'image': IMAGE, 'budget': budget,
                          'helper_resource_diagnostic': diagnostic}), flush=True)
    finally:
        if archive is not None:
            os.close(archive)
        os.close(fd)  # Never destructive cleanup on a failed reconciliation.


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reviewed-recovery-profile', action='store_true')
    parser.add_argument('--other-service-memory-bytes', type=int, required=True)
    args = parser.parse_args()
    base = trusted_directory(str(BASE), os.getuid())
    try:
        lock = os.open('docker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=base)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            recover(args.other_service_memory_bytes, reviewed=args.reviewed_recovery_profile)
        finally:
            os.close(lock)
    finally:
        os.close(base)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('{"recovery":"failed-preserved"}', file=sys.stderr, flush=True)
        sys.exit(2)
