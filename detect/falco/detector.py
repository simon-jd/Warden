#!/usr/bin/env python3
"""Warden's online detector on home-ubuntu: a pinned Falco container and its collector.

    detector.py up [--gvisor-engine] [--k8saudit]
                                 start the host instance and its collector
                                 (--gvisor-engine also the gVisor-engine
                                 instance; opt-in, broken upstream;
                                 --k8saudit also the k8saudit instance for
                                 the kind audit lab)
    detector.py status           what runs, the last heartbeat and the counts
    detector.py down             stop them; compare the host's modules and sysctls
    detector.py purge            down, then remove the images, the socket volume and the FIFOs
    detector.py seven-day-start [--confirm seven-day]
                                 without the confirmation: a dry run. With it:
                                 up, an hourly benign workload, a stop after 7 days
    detector.py seven-day-stop   end the window: timers, down, labs down,
                                 coverage records, review groups, observation

Instances (docs/falco-detector.md):
* host (the default and only source of the seven-day ledger): Falco 0.45.2
  with the modern eBPF probe, in a privileged container (user decision
  2026-11-13). It sees every process on the host, so its collector keeps only
  Warden containers' alerts. On gVisor it sees runsc's sentry and gofer and the
  k3s node, not the sandboxes' own system calls, which are not covered (user
  decision 2026-11-13, as Firecracker's guests). Falco 0.43.1's probe is
  rejected by this kernel's (7.0) verifier.
* gvisor (opt-in, --gvisor-engine): Falco 0.43.1, the last release with the
  gVisor engine, unprivileged with no capabilities, fed by the k3s lab's runsc
  when the lab is up with --falco. It exits at the first event
  (falcosecurity/libs#3074), so it is not part of the default detector.
* k8saudit (opt-in, --k8saudit): Falco 0.45.2 with the k8saudit 0.18.0 and
  json 0.7.4 plugins and the stock k8s_audit_rules.yaml of the plugins' tag
  plugins/k8saudit/v0.18.0, all pinned by SHA-256 (scripts/restore-tools.sh
  falco-k8saudit) and checked before up. It reads the API audit log of the
  kind audit lab (scripts/kind_lab.sh up --audit) through audit_collector.py,
  which also keeps its alerts; no system call source, no capabilities, no
  network.

Both images are pinned by digest (scripts/restore-tools.sh falco), loaded
into Docker from .tools/falco and run by image ID. Each container is pinned
to CPUs 0-7,16-31 (WARDEN_CPUSET overrides that), has memory and pid limits and a rotated log (json-file,
10 MiB x 3) that holds only Falco's own messages: alerts go to the
collector's FIFO. The rules are each image's stock falco_rules.yaml. Every
object carries owner=warden-lab and warden.detect/role=falco; nothing
labelled otherwise is stopped or removed. Collectors run as transient
systemd user units under taskset, restarted if they fail.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recorder  # noqa: E402  (this directory, made explicit: the units run python3 -I)
import review  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
# The CPUs everything here runs on: the make targets' taskset, the Falco
# containers, the collector, benign and stop units, and the labs
# (WARDEN_LAB_CPUSET). WARDEN_CPUSET overrides the default for a host whose
# other CPUs are taken; the seven-day timers pass it on with --setenv, so their
# python sees the same list, and the plan records it.
DEFAULT_CPUSET = '0-7,16-31'
CPUSET = os.environ.get('WARDEN_CPUSET') or DEFAULT_CPUSET
if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*', CPUSET):
    raise SystemExit('WARDEN_CPUSET must be a CPU list such as 0-7,16-31, not %r' % CPUSET)
DETECT = ROOT / '.cache/detect'
STATE = DETECT / 'state'
RUNDIR = DETECT / 'run'
DATA = DETECT / 'data'
TOOLS = ROOT / '.tools/falco'
LAB_KUBECONFIG = ROOT / '.cache/k3s-gvisor/lab/kubeconfig'
# The kind audit lab's API audit log (scripts/kind_lab.sh up --audit).
KIND_AUDIT_LOG = ROOT / '.cache/kind-warden-lab/audit/audit.log'
K8SAUDIT_TOOLS = ROOT / '.tools/falco-k8saudit'
# The kind audit lab's node containers: kind's cluster label, and the names
# attacks/stratus/emulate.py accepts.
KIND_AUDIT_CLUSTER = ('io.x-k8s.kind.cluster', 'warden-lab')
KIND_AUDIT_NODE = re.compile(r'warden-lab-(control-plane[0-9]*|worker[0-9]*)')
# What scripts/restore-tools.sh falco-k8saudit unpacks: the two plugin
# libraries from the official release archives (download.falco.org, the same
# bytes as the ghcr.io/falcosecurity/plugins artifacts' layers) and the
# rules file at the tag plugins/k8saudit/v0.18.0. up refuses any other bytes.
K8SAUDIT_FILES = {
    'libk8saudit.so': '4c28b1bd3b12c5743d70d824055ed147cf3ab355c6d9b4b166959b3b28881acd',
    'libjson.so': '4009cbf7301efa36425ee58e3d281a16b3f13055d78729beec036fd3238b78c5',
    'k8s_audit_rules.yaml': 'fa53280e337db6edaeb44cf49fbd1be4349f3c48e3cd0017c2575097df901a1e',
}
CONFIG = ROOT / 'detect/falco'
RUNSC = ROOT / '.tools/gvisor/runsc'
VOLUME = 'warden-detect-gvisor'
ROLE = 'warden.detect/role'
LABELS = {'owner': 'warden-lab', ROLE: 'falco'}
BENIGN_UNIT, STOP_UNIT = 'warden-detect-benign', 'warden-detect-seven-day-stop'
WINDOW = timedelta(days=7)
INSTANCES = {
    'host': {
        'container': 'warden-detect-falco-host', 'unit': 'warden-detect-collector-host',
        'ref': 'docker.io/falcosecurity/falco:0.45.2@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e',
        'image': 'sha256:27a94a2841d872ec5ff158f2c86a9d87b0b74503d0445d63cbd57d6d1545e102',
        'archive': 'falco-0.45.2.oci.tar', 'memory': 1 << 30, 'pids': 512, 'engine': 'falco-host.yaml',
        'source_id': 'falco-host', 'runtime': 'runc', 'snapshot_gap': 150},
    'gvisor': {
        'container': 'warden-detect-falco-gvisor', 'unit': 'warden-detect-collector-gvisor',
        'ref': 'docker.io/falcosecurity/falco:0.43.1@sha256:b4166a61f41e2fa638c041cac881d8bb32c284e3aaf282fdfed80f15f6eb55e3',
        'image': 'sha256:9f3e058ce652ecf98aa2b4d8a41e80385b08ecb17d3153bb1d1a03a406378a31',
        'archive': 'falco-0.43.1.oci.tar', 'memory': 512 << 20, 'pids': 256, 'engine': 'falco-gvisor.yaml',
        'source_id': 'falco-gvisor', 'runtime': 'gvisor', 'snapshot_gap': None},
    'k8saudit': {
        'container': 'warden-detect-falco-k8saudit', 'unit': 'warden-detect-collector-k8saudit',
        'ref': 'docker.io/falcosecurity/falco:0.45.2@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e',
        'image': 'sha256:27a94a2841d872ec5ff158f2c86a9d87b0b74503d0445d63cbd57d6d1545e102',
        'archive': 'falco-0.45.2.oci.tar', 'memory': 512 << 20, 'pids': 256, 'engine': 'falco-k8saudit.yaml',
        'source_id': 'falco-k8saudit', 'runtime': 'kind', 'snapshot_gap': 150},
}
DEFAULT_ENGINES = ('host',)
# The FIFOs each instance's collector creates in RUNDIR/<instance>/.
FIFOS = {'host': ('alerts.fifo',), 'gvisor': ('alerts.fifo',), 'k8saudit': ('alerts.fifo', 'audit.fifo')}
# The resident memory the benign runc lab run must count besides its own.
FALCO_MEMORY = INSTANCES['host']['memory']
LAB_SCRIPT = ROOT / 'scripts/k3s_gvisor_lab.sh'
# The k3s lab labels its node warden.lab/root=<this> (scripts/k3s_gvisor_lab.sh);
# the runc lab binds <this worktree>/.cache/warden-lab/docker-<session>.
ROOT_ID = hashlib.sha256(str(ROOT.resolve()).encode()).hexdigest()[:16]
RUNC_LAB_DIR = str(ROOT.resolve() / '.cache/warden-lab') + '/'
CONFIRM = 'seven-day'
# Sysctls that are counters or are retuned by the kernel itself; a change in
# them is listed apart, not as a change the detector made.
VOLATILE = re.compile(r'^(fs\.(dentry-state|file-nr|inode-nr|inode-state|aio-nr|quota\..*)|kernel\.(ns_last_pid|pty\.nr|'
                      r'random\.entropy_avail|perf_event_max_sample_rate)|net\.netfilter\.nf_conntrack_count)$')
IFACE = re.compile(r'^net\.(ipv4|ipv6)\.(conf|neigh)\.([^.]+)\.')


class Host:
    """Every command the detector runs on the host. Tests replace it."""

    def run(self, argv, check=True, timeout=120, env=None, cwd=None):
        result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, cwd=cwd,
                                env=env or {'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', ''),
                                            'XDG_RUNTIME_DIR': os.environ.get('XDG_RUNTIME_DIR', ''),
                                            'DBUS_SESSION_BUS_ADDRESS': os.environ.get('DBUS_SESSION_BUS_ADDRESS', '')})
        if check and result.returncode != 0:
            raise RuntimeError('%s failed (%d): %s' % (' '.join(argv[:4]), result.returncode, result.stderr.strip()[-2000:]))
        return result

    def docker(self, args, check=True, timeout=120):
        # The local daemon only; never a remote context from the environment.
        return self.run(['/usr/bin/docker', '--host=unix:///var/run/docker.sock', *args], check=check, timeout=timeout,
                        env={'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', '')})

    def systemd_run(self, args):
        return self.run(['/usr/bin/systemd-run', '--user', *args])

    def systemctl(self, args, check=True):
        return self.run(['/usr/bin/systemctl', '--user', *args], check=check)

    def read(self, path):
        return Path(path).read_text()

    def sleep(self, seconds):
        time.sleep(seconds)

    def now(self):
        return datetime.now(timezone.utc)


def stamp(t):
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


def label_args(instance, session):
    out = []
    for key, value in {**LABELS, 'warden.detect/instance': instance, 'warden.detect/session': session}.items():
        out += ['--label', '%s=%s' % (key, value)]
    return out


def mount(src, dst, readonly=True, kind='bind'):
    return ['--mount', 'type=%s,src=%s,dst=%s%s' % (kind, src, dst, ',readonly' if readonly else '')]


def falco_args(instance, session, gid):
    """docker run arguments for one Falco instance."""
    spec = INSTANCES[instance]
    args = ['run', '-d', '--name', spec['container'], *label_args(instance, session), '--pull', 'never',
            '--restart', 'no', '--network', 'none', '--cpuset-cpus', CPUSET,
            '--memory', str(spec['memory']), '--memory-swap', str(spec['memory']), '--pids-limit', str(spec['pids']),
            '--log-driver', 'json-file', '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3', '--read-only']
    if instance == 'host':
        args += ['--privileged', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
                 *mount('/proc', '/host/proc'),
                 *mount('/var/run/docker.sock', '/host/var/run/docker.sock'),
                 # tracefs, read-only: the probe's TOCTOU programs look up the
                 # syscalls tracepoints there.
                 *mount('/sys/kernel/tracing', '/sys/kernel/tracing')]
    elif instance == 'k8saudit':
        # No capabilities: the FIFOs are opened through the user's group.
        # config.d is an empty tmpfs that holds only Warden's two files, so
        # the image's container plugin is not loaded.
        args += ['--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--group-add', str(gid),
                 '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m', '--tmpfs', '/etc/falco/config.d:rw,nosuid,nodev,noexec,size=64k',
                 *mount(K8SAUDIT_TOOLS, '/warden-plugins')]
    else:
        args += ['--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--group-add', str(gid),
                 '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m', '--tmpfs', '/run/warden-runsc-root:rw,nosuid,nodev,size=1m',
                 *mount(RUNSC, '/usr/local/bin/runsc'),
                 *mount(VOLUME, '/warden-detect', readonly=False, kind='volume'),
                 *mount(CONFIG / 'gvisor-pod-init.json', '/etc/warden-detect/gvisor-pod-init.json')]
    args += [*mount(CONFIG / 'falco-common.yaml', '/etc/falco/config.d/90-warden.yaml'),
             *mount(CONFIG / spec['engine'], '/etc/falco/config.d/91-warden-engine.yaml'),
             *mount(RUNDIR / instance, '/warden-detect-out', readonly=False),
             spec['image'], '/usr/bin/falco']
    if instance == 'k8saudit':
        args += ['--enable-source', 'k8s_audit', '-r', '/warden-plugins/k8s_audit_rules.yaml']
    return args


def collector_args(instance, session, gid):
    """systemd-run arguments for one collector (a transient user service)."""
    spec = INSTANCES[instance]
    if instance == 'k8saudit':
        argv = ['/usr/bin/taskset', '-c', CPUSET, '/usr/bin/python3', '-I', '-B', str(CONFIG / 'audit_collector.py'),
                '--audit-log', str(KIND_AUDIT_LOG), '--audit-fifo', str(RUNDIR / instance / 'audit.fifo'),
                '--fifo', str(RUNDIR / instance / 'alerts.fifo'), '--fifo-gid', str(gid),
                '--out', str(DATA / session / instance), '--falco-container', spec['container']]
        return ['--unit', spec['unit'], '--collect', '--quiet', '--property=TimeoutStopSec=60', '--property=Restart=on-failure',
                '--property=RestartSec=2s', '--', *argv]
    argv = ['/usr/bin/taskset', '-c', CPUSET, '/usr/bin/python3', '-I', '-B', str(CONFIG / 'collector.py'),
            '--instance', instance, '--fifo', str(RUNDIR / instance / 'alerts.fifo'), '--out', str(DATA / session / instance),
            '--falco-container', spec['container'], '--kubeconfig', str(LAB_KUBECONFIG)]
    argv += (['--watch-docker', '--watch-k8s', '--cgroup-root', '/sys/fs/cgroup'] if instance == 'host'
             else ['--watch-k8s', '--fifo-gid', str(gid)])
    return ['--unit', spec['unit'], '--collect', '--quiet', '--property=TimeoutStopSec=60', '--property=Restart=on-failure',
            '--property=RestartSec=2s', '--', *argv]


def load_state():
    path = STATE / 'state.json'
    return json.loads(path.read_text()) if path.exists() else {}


def save_state(state):
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = STATE / 'state.json'
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n')
    os.replace(tmp, path)


def host_snapshot(host):
    """Loaded modules and global sysctls (interfaces other than all, default
    and lo are left out: their names include other projects' network IDs)."""
    modules = sorted(line.split()[0] for line in host.read('/proc/modules').splitlines() if line.strip())
    sysctls = {}
    for line in host.run(['/usr/sbin/sysctl', '-a'], check=False).stdout.splitlines():
        key, sep, value = line.partition(' = ')
        if not sep or key.startswith(('kernel.random.uuid', 'kernel.random.boot_id', 'kernel.hostname', 'kernel.domainname',
                                      'fs.binfmt_misc')):
            continue
        match = IFACE.match(key)
        if match and match.group(3) not in ('all', 'default', 'lo'):
            continue
        sysctls[key] = value
    return {'taken_at': stamp(host.now()), 'modules': modules, 'sysctls': sysctls}


def compare(before, after):
    keys = set(before['sysctls']) | set(after['sysctls'])
    changed = sorted(k for k in keys if before['sysctls'].get(k) != after['sysctls'].get(k))
    return {'before': before['taken_at'], 'after': after['taken_at'],
            'modules_added': sorted(set(after['modules']) - set(before['modules'])),
            'modules_removed': sorted(set(before['modules']) - set(after['modules'])),
            'sysctls_changed': {k: [before['sysctls'].get(k), after['sysctls'].get(k)] for k in changed if not VOLATILE.match(k)},
            'volatile_sysctls_changed': [k for k in changed if VOLATILE.match(k)]}


def owned(host, name):
    """The container's inspect if it is the detector's, None if it does not exist."""
    result = host.docker(['container', 'inspect', name], check=False)
    if result.returncode != 0:
        return None
    data = json.loads(result.stdout)[0]
    labels = (data.get('Config') or {}).get('Labels') or {}
    if any(labels.get(k) != v for k, v in LABELS.items()):
        raise RuntimeError('%s exists and is not the detector\'s (labels %s); left alone' % (name, sorted(labels)))
    return data


def ensure_images(host, engines=DEFAULT_ENGINES):
    for instance in engines:
        spec = INSTANCES[instance]
        result = host.docker(['image', 'inspect', '--format', '{{.Id}}', spec['image']], check=False)
        if result.returncode != 0:
            archive = TOOLS / spec['archive']
            if not archive.exists():
                raise RuntimeError('%s missing: run scripts/restore-tools.sh falco' % archive)
            host.docker(['load', '-i', str(archive)], timeout=600)
            result = host.docker(['image', 'inspect', '--format', '{{.Id}}', spec['image']], check=False)
        if result.returncode != 0 or result.stdout.strip() != spec['image']:
            raise RuntimeError('%s image is not the pinned %s' % (instance, spec['image']))


def private_dir(path, mode):
    path.mkdir(parents=True, exist_ok=True)
    for name in ('system.posix_acl_access', 'system.posix_acl_default'):
        try:
            os.removexattr(path, name)
        except OSError:
            pass
    os.chmod(path, mode)


def ensure_volume(host):
    result = host.docker(['volume', 'inspect', VOLUME], check=False)
    if result.returncode == 0:
        labels = json.loads(result.stdout)[0].get('Labels') or {}
        if any(labels.get(k) != v for k, v in LABELS.items()):
            raise RuntimeError('volume %s exists and is not the detector\'s' % VOLUME)
        return
    host.docker(['volume', 'create', *sum((['--label', '%s=%s' % kv] for kv in LABELS.items()), []), VOLUME])


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def check_k8saudit_inputs():
    """The pinned plugins and rules, and the kind audit lab's audit log."""
    for name, want in K8SAUDIT_FILES.items():
        path = K8SAUDIT_TOOLS / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('%s missing: run scripts/restore-tools.sh falco-k8saudit' % path)
        got = file_sha256(path)
        if got != want:
            raise RuntimeError('%s is not the pinned file (sha256 %s, want %s)' % (path, got, want))
    try:
        info = os.lstat(KIND_AUDIT_LOG)
    except FileNotFoundError:
        info = None
    if info is None or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError('%s is not this user\'s regular file: bring the kind audit lab up first '
                           '(scripts/kind_lab.sh up --audit)' % KIND_AUDIT_LOG)


def unit_active(host, unit):
    return host.systemctl(['is-active', '--quiet', unit], check=False).returncode == 0


def up(host, out=print, engines=DEFAULT_ENGINES):
    engines = [i for i in INSTANCES if i in engines]
    state = load_state()
    if state.get('up'):
        raise RuntimeError('the detector is already up (session %s); run down first' % state.get('session'))
    for spec in INSTANCES.values():
        if owned(host, spec['container']) is not None:
            raise RuntimeError('%s already exists; run down first' % spec['container'])
        if unit_active(host, spec['unit']):
            raise RuntimeError('%s is already running; run down first' % spec['unit'])
    needed = [CONFIG / 'falco-common.yaml'] + ([RUNSC, CONFIG / 'gvisor-pod-init.json'] if 'gvisor' in engines else [])
    for path in needed:
        if not path.is_file():
            raise RuntimeError('%s missing' % path)
    if 'k8saudit' in engines:
        check_k8saudit_inputs()
    ensure_images(host, engines)
    now = host.now()
    session = now.strftime('%Y%m%dT%H%M%SZ')
    gid = os.getgid()
    before = host_snapshot(host)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE / ('host-before-%s.json' % session)).write_text(json.dumps(before, indent=1, sort_keys=True) + '\n')
    private_dir(RUNDIR, 0o711)
    for instance in engines:
        private_dir(RUNDIR / instance, 0o700 if instance == 'host' else 0o710)
        private_dir(DATA / session / instance, 0o700)
    if 'gvisor' in engines:
        ensure_volume(host)
    state = {'up': True, 'session': session, 'started_at': stamp(now), 'gid': gid, 'containers': {}, 'instances': engines}
    save_state(state)
    try:
        for instance in engines:
            host.systemd_run(collector_args(instance, session, gid))
        fifos = [RUNDIR / i / name for i in engines for name in FIFOS[i]]
        for _ in range(100):
            if all(fifo.exists() for fifo in fifos):
                break
            host.sleep(0.1)
        else:
            raise RuntimeError('the collectors did not create their FIFOs; see journalctl --user -u warden-detect-collector-*')
        for instance in engines:
            cid = host.docker(falco_args(instance, session, gid)).stdout.strip()
            state['containers'][instance] = cid
            save_state(state)
        wait_ready(host, session, engines)
    except BaseException:
        # Leave nothing running: what started is stopped, as down would.
        try:
            down(host, out)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            out('rollback after a failed up also failed: %s' % error)
        raise
    out('detector up (%s): session %s, data in %s' % (', '.join(engines), session, DATA / session))
    return state


def wait_ready(host, session, engines=DEFAULT_ENGINES, timeout=150):
    """Up when the host instance's first metrics snapshot arrived (and, with
    the gVisor engine, that engine listens on its socket; with the k8saudit
    instance, that instance opened its source and wrote its first snapshot)."""
    deadline = time.monotonic() + timeout
    health = DATA / session / 'host' / 'health.jsonl'
    while True:
        for instance in engines:
            spec = INSTANCES[instance]
            data = owned(host, spec['container'])
            if data is None or not data['State']['Running']:
                logs = host.docker(['logs', '--tail', '30', spec['container']], check=False)
                raise RuntimeError('%s is not running: %s' % (spec['container'], (logs.stdout + logs.stderr)[-3000:]))
        gvisor = True
        if 'gvisor' in engines:
            logs = host.docker(['logs', INSTANCES['gvisor']['container']], check=False)
            gvisor = "Opening 'syscall' source with gVisor" in logs.stdout + logs.stderr
        snapshot = health.exists() and 'Falco internal: metrics snapshot' in health.read_text()
        audit = True
        if 'k8saudit' in engines:
            logs = host.docker(['logs', INSTANCES['k8saudit']['container']], check=False)
            audit_health = DATA / session / 'k8saudit' / 'health.jsonl'
            audit = ("Opening 'k8s_audit' source with plugin 'k8saudit'" in logs.stdout + logs.stderr and
                     audit_health.exists() and 'Falco internal: metrics snapshot' in audit_health.read_text())
        if gvisor and snapshot and audit:
            return
        if time.monotonic() > deadline:
            raise RuntimeError('detector not ready after %ss (gvisor engine %s, host snapshot %s, k8saudit %s)' % (
                timeout, gvisor, snapshot, audit))
        host.sleep(2)


def flush(host, session, timeout=60, instance='host'):
    """Have an instance's collector write a heartbeat now (SIGUSR1) and wait for it."""
    beats = DATA / session / instance / 'heartbeats.jsonl'
    before = len(beats.read_text().splitlines()) if beats.exists() else 0
    host.systemctl(['kill', '--signal=SIGUSR1', INSTANCES[instance]['unit']])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if beats.exists() and len(beats.read_text().splitlines()) > before:
            return
        host.sleep(0.5)
    raise RuntimeError('the %s collector wrote no heartbeat after SIGUSR1' % instance)


def jsonl_rows(path):
    if not path.exists():
        return []
    return [(line.encode(), json.loads(line)) for line in path.read_text().splitlines() if line.strip()]


def first_healthy_point(host, session, timeout=180):
    """The window starts at the first heartbeat after Falco's first counting
    metrics snapshot: from there the records can cover every nanosecond."""
    d = DATA / session / 'host'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(r.get('rule') == recorder.METRICS_RULE and recorder.counting(r) for _, r in jsonl_rows(d / 'health.jsonl')):
            flush(host, session)
            point = recorder.first_healthy_point(jsonl_rows(d / 'heartbeats.jsonl'), jsonl_rows(d / 'health.jsonl'))
            if point:
                return point
        host.sleep(2)
    raise RuntimeError('no counting metrics snapshot and heartbeat after %ss' % timeout)


def audit_ready_point(host, session, timeout=180):
    """The k8saudit instance's first healthy point: the first heartbeat, after
    its first metrics snapshot, in which Falco runs and the feed is writing
    into the plugin's open FIFO."""
    d = DATA / session / 'k8saudit'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(r.get('rule') == recorder.METRICS_RULE for _, r in jsonl_rows(d / 'health.jsonl')):
            flush(host, session, instance='k8saudit')
            beat = jsonl_rows(d / 'heartbeats.jsonl')[-1][1]
            if (beat.get('falco') or {}).get('running') and (beat.get('feed') or {}).get('alive') and beat['feed'].get('fifo_open'):
                return beat['time']
        host.sleep(2)
    raise RuntimeError('the k8saudit instance had no healthy heartbeat after %ss' % timeout)


def clean_labs(host, runtimes=('runc', 'gvisor'), out=print):
    """Take down what a benign run of this worktree may have left, and
    nothing of another worktree's: the k3s lab only if its node carries this
    worktree's warden.lab/root label (then its own down), runc lab containers
    only if they bind this worktree's .cache/warden-lab."""
    failures = []
    if 'gvisor' in runtimes:
        got = host.docker(['container', 'inspect', 'warden-k3s-gvisor'], check=False)
        if got.returncode == 0:
            labels = (json.loads(got.stdout)[0].get('Config') or {}).get('Labels') or {}
            if labels.get('warden.lab/root') != ROOT_ID:
                out('k3s lab node is not this worktree\'s (warden.lab/root %s); left alone' % labels.get('warden.lab/root'))
            else:
                result = host.run(['/usr/bin/taskset', '-c', CPUSET, str(LAB_SCRIPT), 'down'], check=False, timeout=600,
                                  env={'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', ''), 'WARDEN_LAB_CPUSET': CPUSET})
                if result.returncode != 0:
                    failures.append('k3s lab down failed: %s' % (result.stdout + result.stderr)[-500:])
                else:
                    out('k3s lab taken down')
    if 'runc' in runtimes:
        filters = ['--filter', 'label=project=warden', '--filter', 'label=owner=warden-lab', '--filter', 'label=session']
        for name in host.docker(['ps', '-a', *filters, '--format', '{{.Names}}']).stdout.split():
            got = host.docker(['container', 'inspect', name], check=False)
            if got.returncode != 0:
                continue
            mounts = json.loads(got.stdout)[0].get('Mounts') or []
            if not any(str(m.get('Source', '')).startswith(RUNC_LAB_DIR) for m in mounts):
                out('runc lab container %s is not this worktree\'s; left alone' % name)
                continue
            host.docker(['rm', '-f', name])
            out('runc lab container %s removed' % name)
    if failures:
        raise RuntimeError('; '.join(failures))


def down(host, out=print):
    state = load_state()
    session = state.get('session')
    failures = []
    for instance, spec in INSTANCES.items():
        try:
            data = owned(host, spec['container'])
        except RuntimeError as error:
            failures.append(str(error))
            continue
        if data is None:
            continue
        if data['State']['Running']:
            host.docker(['stop', '--time', '30', spec['container']], timeout=90)
        if session:
            logs = host.docker(['logs', spec['container']], check=False)
            log = DATA / session / instance / 'falco.log'
            log.write_text(logs.stdout + logs.stderr)
            log.chmod(0o600)
        host.docker(['rm', spec['container']])
        out('%s stopped and removed' % spec['container'])
    host.sleep(3)  # the collectors drain what Falco flushed on stop
    for spec in INSTANCES.values():
        if unit_active(host, spec['unit']):
            host.systemctl(['stop', spec['unit']])
            out('%s stopped' % spec['unit'])
    report = None
    if session and (STATE / ('host-before-%s.json' % session)).exists():
        before = json.loads((STATE / ('host-before-%s.json' % session)).read_text())
        after = host_snapshot(host)
        (STATE / ('host-after-%s.json' % session)).write_text(json.dumps(after, indent=1, sort_keys=True) + '\n')
        report = compare(before, after)
        (STATE / ('host-compare-%s.json' % session)).write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')
        out('host modules added %s, removed %s; sysctls changed %s (counters changed: %s)' % (
            report['modules_added'] or 'none', report['modules_removed'] or 'none',
            report['sysctls_changed'] or 'none', ', '.join(report['volatile_sysctls_changed']) or 'none'))
    result = host.docker(['volume', 'inspect', VOLUME], check=False)
    if result.returncode == 0:
        labels = json.loads(result.stdout)[0].get('Labels') or {}
        if all(labels.get(k) == v for k, v in LABELS.items()):
            removed = host.docker(['volume', 'rm', VOLUME], check=False)
            if removed.returncode != 0:
                failures.append('volume %s still in use (is the k3s lab up with --falco?)' % VOLUME)
    if state:
        state['up'] = False
        state['stopped_at'] = stamp(host.now())
        save_state(state)
    if failures:
        raise RuntimeError('; '.join(failures))
    return report


def purge(host, out=print):
    down(host, out)
    for spec in INSTANCES.values():
        if host.docker(['image', 'inspect', spec['image']], check=False).returncode == 0:
            host.docker(['image', 'rm', spec['image']])
            out('image %s removed' % spec['image'])
    if RUNDIR.exists():
        for instance in INSTANCES:
            for name in FIFOS[instance]:
                fifo = RUNDIR / instance / name
                if fifo.exists():
                    fifo.unlink()
            if (RUNDIR / instance).exists():
                (RUNDIR / instance).rmdir()
        RUNDIR.rmdir()
    out('purged; collected data kept in %s' % DATA)


def status(host, out=print):
    state = load_state()
    out('state: %s' % json.dumps({k: state.get(k) for k in ('up', 'session', 'started_at', 'stopped_at')}, sort_keys=True))
    for instance, spec in INSTANCES.items():
        data = owned(host, spec['container'])
        if data is None and instance not in state.get('instances', DEFAULT_ENGINES):
            continue
        running = 'absent' if data is None else ('running since %s' % data['State']['StartedAt'] if data['State']['Running'] else 'stopped')
        out('%s: container %s; collector %s' % (instance, running, 'active' if unit_active(host, spec['unit']) else 'inactive'))
        beats = DATA / str(state.get('session')) / instance / 'heartbeats.jsonl'
        if beats.exists():
            last = beats.read_text().splitlines()[-1:]
            if last:
                beat = json.loads(last[0])
                out('  last heartbeat %s: %s' % (beat['time'], json.dumps(beat['counts'], sort_keys=True)))
    for unit in (BENIGN_UNIT + '.timer', STOP_UNIT + '.timer'):
        out('%s: %s' % (unit, 'active' if unit_active(host, unit) else 'inactive'))
    plan = STATE / 'seven-day.json'
    if plan.exists():
        out('seven-day plan: %s' % plan.read_text().strip())


def seven_day_commands(session):
    """The timers seven-day-start creates (transient systemd user units)."""
    stop_after = int((WINDOW + timedelta(minutes=15)).total_seconds())
    benign = ['--unit', BENIGN_UNIT, '--collect', '--on-active=120', '--on-unit-active=3600',
              '--timer-property=AccuracySec=1s', '--property=RuntimeMaxSec=3000', '--property=KillSignal=SIGTERM',
              '--property=TimeoutStopSec=300', '--setenv=WARDEN_CPUSET=%s' % CPUSET, '--',
              '/usr/bin/taskset', '-c', CPUSET, '/usr/bin/python3', '-I', '-B', str(CONFIG / 'benign.py'),
              '--session', session]
    stop = ['--unit', STOP_UNIT, '--collect', '--on-active=%d' % stop_after, '--timer-property=AccuracySec=1s',
            '--setenv=WARDEN_CPUSET=%s' % CPUSET, '--',
            '/usr/bin/taskset', '-c', CPUSET, '/usr/bin/python3', '-I', '-B', str(CONFIG / 'detector.py'), 'seven-day-stop']
    return benign, stop


def seven_day_start(host, confirm=None, out=print):
    """Without confirm == 'seven-day' this only prints what it would do."""
    dry = confirm != CONFIRM
    if load_state().get('up'):
        raise RuntimeError('the detector is up; the seven-day window starts from a stopped detector (down first)')
    warden = host.docker(['ps', '-a', '--filter', 'label=project=warden', '--format', '{{.Names}}']).stdout.split()
    if warden:
        raise RuntimeError('Warden lab containers exist (%s); bring every lab down first' % ', '.join(warden))
    # The kind audit lab's nodes carry kind's labels, not project=warden.
    kind = set(host.docker(['ps', '-a', '--filter', 'label=%s=%s' % KIND_AUDIT_CLUSTER, '--format', '{{.Names}}']).stdout.split())
    kind |= {name for name in host.docker(['ps', '-a', '--format', '{{.Names}}']).stdout.split() if KIND_AUDIT_NODE.fullmatch(name)}
    if kind:
        raise RuntimeError('kind audit lab nodes exist (%s); make kind-audit-down first' % ', '.join(sorted(kind)))
    for unit in (BENIGN_UNIT + '.timer', STOP_UNIT + '.timer'):
        if unit_active(host, unit):
            raise RuntimeError('%s is already active' % unit)
    build = ['/usr/bin/taskset', '-c', CPUSET, str(ROOT / 'scripts/build-runtime-lab.sh')]
    # The runc lab refuses inputs a group or others can write (docs/runtime-lab.md).
    trust = ['/usr/bin/chmod', 'go-w', str(ROOT), str(ROOT / '.cache'), str(ROOT / '.cache/warden-lab'), str(ROOT / 'scripts'),
             *(str(ROOT / 'scripts' / ('runtime_lab_%s.py' % n)) for n in ('docker', 'docker_init', 'runner', 'paths'))]
    if dry:
        benign, stop = seven_day_commands('<session>')
        out('dry run: nothing started. The real start needs CONFIRM=seven-day (make) or --confirm seven-day, and no DRY_RUN.')
        out('would run: %s' % ' '.join(build))
        out('would run: %s' % ' '.join(trust))
        out('would run: detector.py up (host instance only)')
        out('would wait for the first counting metrics snapshot and flush a heartbeat: the window starts there')
        out('would run: systemd-run --user %s' % ' '.join(benign))
        out('would run: systemd-run --user %s' % ' '.join(stop))
        return None
    host.run(build, timeout=1800, env={'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', '')})
    host.run(trust)
    state = up(host, out)
    try:
        start = first_healthy_point(host, state['session'])
        end = recorder.fmt(recorder.ns(start) + int(WINDOW.total_seconds()) * 1_000_000_000)
        benign, stop = seven_day_commands(state['session'])
        plan = {'session': state['session'], 'window_start': start, 'window_end': end, 'sources': ['falco-host'],
                'runtimes': ['runc', 'gvisor'], 'benign_every_s': 3600, 'benign_first_after_s': 120,
                'stop_after_s': int((WINDOW + timedelta(minutes=15)).total_seconds()), 'cpuset': CPUSET}
        (STATE / 'seven-day.json').write_text(json.dumps(plan, indent=1, sort_keys=True) + '\n')
        host.systemd_run(benign)
        try:
            host.systemd_run(stop)
        except BaseException:
            host.systemctl(['stop', BENIGN_UNIT + '.timer'], check=False)
            raise
    except BaseException:
        try:
            down(host, out)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            out('rollback after a failed start also failed: %s' % error)
        (STATE / 'seven-day.json').unlink(missing_ok=True)
        raise
    out('seven-day window started: %s' % json.dumps(plan, sort_keys=True))
    return plan


def seven_day_stop(host, out=print):
    """End the window. The records are written whatever else fails; the
    failures are raised at the end."""
    plan = json.loads((STATE / 'seven-day.json').read_text())
    session = plan['session']
    failures = []
    host.systemctl(['stop', BENIGN_UNIT + '.timer'], check=False)
    for _ in range(360):  # a benign run in progress finishes first (at most 30 minutes)
        if not unit_active(host, BENIGN_UNIT + '.service'):
            break
        host.sleep(5)
    try:
        flush(host, session)  # the last heartbeat before Falco stops
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        failures.append('flush: %s' % error)
    try:
        down(host, out)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        failures.append('down: %s' % error)
    try:
        clean_labs(host, out=out)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        failures.append('labs: %s' % error)
    result = DATA / session / 'seven-day'
    result.mkdir(mode=0o700, parents=True, exist_ok=True)
    d = DATA / session / 'host'
    explain = []
    rows = recorder.intervals(jsonl_rows(d / 'heartbeats.jsonl'), jsonl_rows(d / 'health.jsonl'),
                              [r for _, r in jsonl_rows(DATA / session / 'workloads.jsonl')], source_id='falco-host',
                              runtimes=tuple(plan['runtimes']), start=plan['window_start'], end=plan['window_end'],
                              period=3600, max_gap=90, snapshot_gap=INSTANCES['host']['snapshot_gap'], explain=explain)
    (result / 'coverage.jsonl').write_text(review.jsonl(rows))
    (result / 'explain.jsonl').write_text(review.jsonl(explain))
    # Every kept alert is reviewed, runsc's start-up signature (platform) too.
    alerts = [r for _, r in jsonl_rows(d / 'alerts.jsonl') + jsonl_rows(d / 'platform-alerts.jsonl')]
    scopings = [r for _, r in jsonl_rows(d / 'scoping.jsonl')]
    found = review.groups(alerts, scopings)
    (result / 'review-groups.jsonl').write_text(review.jsonl(found))
    (result / 'review-map-template.jsonl').write_text(review.jsonl(review.template(found)))
    normal, report = review.apply(alerts, scopings, [], plan['window_start'], plan['window_end'])
    (result / 'normal-alerts-unreviewed.jsonl').write_text(review.jsonl(normal))
    observed = stamp(host.now())
    obs = host.run(['/usr/bin/python3', '-E', '-s', '-B', '-m', 'detect.report.observation', '--coverage', str(result / 'coverage.jsonl'),
                    '--normal-alerts', str(result / 'normal-alerts-unreviewed.jsonl'), '--source', 'falco-host',
                    '--start', plan['window_start'], '--end', plan['window_end'], '--observed-until', observed],
                   check=False, cwd=ROOT)
    (result / 'observation-unreviewed.json').write_text(obs.stdout + obs.stderr)
    out('seven-day window ended; results in %s. %d alerts in %d groups: fill in review-map-template.jsonl (a person '
        'decides each group), then detect/falco/review.py apply and detect/report/observation.py.' % (result, len(normal), len(found)))
    if failures:
        raise RuntimeError('; '.join(failures))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('up', 'down', 'status', 'purge', 'seven-day-start', 'seven-day-stop'))
    parser.add_argument('--dry-run', action='store_true', help='seven-day-start: only print what it would do')
    parser.add_argument('--confirm', help='seven-day-start: must be "seven-day" to really start')
    parser.add_argument('--gvisor-engine', action='store_true', help='up: also the opt-in gVisor-engine instance')
    parser.add_argument('--k8saudit', action='store_true', help='up: also the k8saudit instance (the kind audit lab)')
    args = parser.parse_args(argv)
    host = Host()
    try:
        if args.command == 'up':
            up(host, engines=('host',) + (('gvisor',) if args.gvisor_engine else ()) + (('k8saudit',) if args.k8saudit else ()))
        elif args.command == 'down':
            down(host)
        elif args.command == 'status':
            status(host)
        elif args.command == 'purge':
            purge(host)
        elif args.command == 'seven-day-start':
            seven_day_start(host, None if args.dry_run else args.confirm)
        else:
            seven_day_stop(host)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print('detector %s failed: %s' % (args.command, error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
