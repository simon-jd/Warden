"""One fixed private PostgreSQL sidecar; no ports, downloads or caller commands."""
from contextlib import contextmanager
import json
import re
import subprocess
import time
from runtime_lab_docker import owned_inspect, scoped_ids, defer_signals

PG_IMAGE = 'postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873'
API_RESERVE = 5000000000  # existing 3GB + cached PG image conservative 1GB + tmpfs/logs
PG_MEMORY = 536870912


def cached_postgres(cli):
    data = json.loads(cli(['image', 'inspect', PG_IMAGE]))
    if len(data) != 1 or PG_IMAGE not in data[0].get('RepoDigests', []) or not 0 < data[0]['Size'] <= 450000000:
        raise RuntimeError('required cached immutable PostgreSQL image unavailable or exceeds reserve')
    return data[0]['Id']


def private_target(cid, labels, cli):
    obj = owned_inspect('container', cid, {**labels, 'role': 'postgres'}, cli)
    host, net = obj['HostConfig'], obj['NetworkSettings']
    if (host['NetworkMode'] != 'none' or host['PidMode'] != '' or host['IpcMode'] != 'private'
            or host['CgroupnsMode'] != 'private' or host['Privileged'] or host['PortBindings']
            or not obj['State']['Running'] or not net['SandboxID']
            or any(value for value in net['Ports'].values())):
        raise RuntimeError('PostgreSQL target is not the exact owned private network-none namespace')
    return cid


@contextmanager
def postgres(labels, cli, cleanup_ok=None):
    cached_postgres(cli)
    owned = {**labels, 'role': 'postgres'}
    args = ['container', 'create', '--pull=never', '--network=none', '--ipc=private', '--cgroupns=private',
            '--read-only', '--user=70:70', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory=536870912', '--memory-swap=536870912', '--pids-limit=128', '--cpus=1',
            '--log-driver=json-file', '--log-opt=max-size=10m', '--log-opt=max-file=2',
            '--tmpfs=/var/lib/postgresql:rw,nosuid,nodev,size=512m,uid=70,gid=70,mode=0700',
            '--tmpfs=/var/run/postgresql:rw,nosuid,nodev,size=16m,uid=70,gid=70,mode=0770',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--env', 'POSTGRES_PASSWORD',
            '--env', 'POSTGRES_DB=warden_api_lab']
    for key, value in owned.items(): args += ['--label', f'{key}={value}']
    args += [PG_IMAGE, 'postgres', '-c', 'listen_addresses=127.0.0.1', '-c', 'max_connections=24', '-c', 'shared_buffers=32MB']
    cid = None
    try:
        with defer_signals(): cid = cli(args).strip()
        if not re.fullmatch('[0-9a-f]{64}', cid): raise RuntimeError('exact PostgreSQL container ID required')
        owned_inspect('container', cid, owned, cli)
        cli(['container', 'start', cid])
        private_target(cid, labels, cli)
        for _ in range(100):
            try:
                cli(['container', 'exec', cid, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'warden_api_lab'])
                break
            except subprocess.CalledProcessError:
                time.sleep(.1)
        else: raise RuntimeError('private PostgreSQL readiness failed')
        print('owned private PostgreSQL:', cid, flush=True)
        yield cid
    finally:
        failures = []
        with defer_signals():
            identities = [cid] if cid and re.fullmatch('[0-9a-f]{64}', cid) else scoped_ids('container', owned, cli)
            for identity in identities:
                try:
                    owned_inspect('container', identity, owned, cli)
                    try: cli(['container', 'stop', '--time=20', identity])
                    finally: cli(['container', 'rm', '--force', identity])
                    if identity in cli(['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', 'id=' + identity]).split():
                        raise RuntimeError('owned PostgreSQL still exists')
                    print('owned PostgreSQL removed:', identity, flush=True)
                except BaseException as error: failures.append(type(error).__name__)
        if failures: raise RuntimeError('PostgreSQL cleanup failed; retained charge: ' + ','.join(failures))
        if cleanup_ok is not None and cid and re.fullmatch('[0-9a-f]{64}', cid): cleanup_ok['postgres'] = True
