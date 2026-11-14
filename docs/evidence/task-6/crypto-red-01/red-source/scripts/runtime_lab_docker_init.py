#!/usr/bin/env python3
"""Image-only fixed entrypoint. No host paths, arbitrary commands or daemon reuse."""
import ctypes
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from urllib.parse import quote
from runtime_lab_runner import interrupted, run_lab, system_binary, write_control
from runtime_lab_paths import NOFOLLOW_DIR

CGROUP = Path('/sys/fs/cgroup')


def validate_context(*, pid, uid, host_ns, current_ns, membership, mount_root, memory, pids, cpu):
    if pid != 1 or uid != 0 or not re.fullmatch(r'cgroup:\[\d+\]', host_ns) or host_ns == current_ns or membership.strip() != '0::/' or mount_root != '/':
        raise ValueError('not the private owned Docker cgroup root; no writes allowed')
    quota, period = cpu.split()
    if not (0 < int(memory) <= 4000000000 and 0 < int(pids) <= 512 and 0 < int(quota) <= 2 * int(period)):
        raise ValueError('outer hard limits missing or too large; refusing to change them')


def bootstrap():
    host_ns = os.environ.get('WARDEN_LAB_HOST_CGROUP_NS', '')
    # Check namespace and root membership BEFORE replacing the read-only mount.
    if os.getpid() != 1 or os.getuid() != 0 or not re.fullmatch(r'cgroup:\[\d+\]', host_ns) or os.readlink('/proc/self/ns/cgroup') == host_ns or Path('/proc/self/cgroup').read_text().strip() != '0::/':
        raise ValueError('private namespace/root identity precheck failed')
    libc = ctypes.CDLL(None, use_errno=True)
    # A fresh cgroup2 mount is scoped by our private cgroup namespace. Never
    # remount a host bind tree writable; discard Docker's inherited RO view.
    if libc.umount2(b'/sys/fs/cgroup', 2) != 0:
        raise OSError(ctypes.get_errno(), 'unmount private read-only cgroup view')
    if libc.mount(b'none', b'/sys/fs/cgroup', b'cgroup2', 14, None) != 0:
        raise OSError(ctypes.get_errno(), 'mount private cgroup2')
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if ' - cgroup2 ' in line and line.split()[4] == str(CGROUP)]
    if len(mounts) != 1:
        raise ValueError('unique private cgroup2 mount required')
    limits = dict(memory=(CGROUP / 'memory.max').read_text().strip(), pids=(CGROUP / 'pids.max').read_text().strip(), cpu=(CGROUP / 'cpu.max').read_text().strip())
    validate_context(pid=os.getpid(), uid=os.getuid(), host_ns=host_ns, current_ns=os.readlink('/proc/self/ns/cgroup'), membership=Path('/proc/self/cgroup').read_text(), mount_root=mounts[0][3], **limits)
    if (CGROUP / 'cgroup.procs').read_text().split() != ['1']:
        raise ValueError('unexpected processes at owned root')
    print('verified private outer cgroup limits:', json.dumps(limits), flush=True)
    parent = os.open(CGROUP, NOFOLLOW_DIR)
    try:
        os.mkdir('bootstrap', 0o700, dir_fd=parent)
        leaf = os.open('bootstrap', NOFOLLOW_DIR, dir_fd=parent)
        try:
            write_control(leaf, 'cgroup.procs', '1')
        finally:
            os.close(leaf)
        write_control(parent, 'cgroup.subtree_control', '+cpu +memory +pids')
    finally:
        os.close(parent)


def versions():
    for name in ('containerd', 'ctr', 'containerd-shim-runc-v2', 'runc'):
        output = subprocess.run([system_binary(name), '--version'], check=True, timeout=10, capture_output=True, text=True).stdout
        version = r'1\.5\.2' if name == 'runc' else r'2\.4\.2'
        if not re.search(r'(?<![0-9.])v?' + version + r'(?![0-9.])', output):
            raise ValueError('unexpected runtime version: ' + name)
        if name == 'runc' and 'libseccomp: 2.6.0' not in output:
            raise ValueError('unexpected libseccomp version')
        print(output, end='', flush=True)
    print('Python:', sys.version, flush=True)
    print('libseccomp:', ctypes.CDLL('libseccomp.so.2').seccomp_api_get(), flush=True)
    # Loading all modules used by the runner also checks extension ABI closure.


def smoke():
    versions()
    print('ABI smoke complete; guest conformance NOT EXECUTED', flush=True)


def main():
    if sys.argv[1:] == ['api-code']:
        password = os.environ.get('WARDEN_API_PASSWORD', '')
        if not re.fullmatch('[0-9a-f]{64}', password):
            raise ValueError('own fixture password required')
        environment = {**os.environ, 'WARDEN_TEST_DATABASE_URL': 'postgres://postgres:' + quote(password, safe='') + '@127.0.0.1:5432/warden_api_lab?sslmode=disable'}
        for binary in ('runs.test', 'scheduler.test'):
            subprocess.run(['/opt/warden/input/' + binary, '-test.v', '-test.count=1'], env=environment, check=True, timeout=180)
        print('Capless real PostgreSQL code tests complete; API/runc live NOT EXECUTED', flush=True)
        return 0
    if sys.argv[1:] in (['smoke'], ['api-smoke']):
        smoke()
        if sys.argv[1:] == ['api-smoke']:
            subprocess.run(['/opt/warden/input/api.test', '-test.run', '^TestHTTPPostgresRuntime$', '-test.v'], check=True, timeout=30)
        return 0
    if sys.argv[1:] not in (['run'], ['api']):
        raise ValueError('only fixed smoke/api-smoke/run/api modes supported')
    signal.signal(signal.SIGTERM, interrupted)
    versions()
    bootstrap()
    base = Path('/opt/warden/.cache/warden-lab')
    os.environ['WARDEN_LAB_ACK'] = 'dedicated-warden-lab'
    os.environ['WARDEN_LAB_OWNER_UID'] = str(base.stat().st_uid)
    return run_lab(artifact_base='/opt/warden/input', release_evidence=True, profile=sys.argv[1])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print('Docker bootstrap failed:', error, file=sys.stderr, flush=True)
        sys.exit(2)
