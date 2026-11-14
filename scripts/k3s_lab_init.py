#!/usr/bin/env python3
"""Immutable image controller. No tenant Pods/Jobs or forwarded CLI commands."""
import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
import ctypes
import json
import os
from pathlib import Path
import re
import resource
import signal
import ssl
import stat
import subprocess
import sys
import time
import tomllib

from runtime_lab_docker_init import bootstrap
from runtime_lab_paths import NOFOLLOW_DIR, prepare_session
from runtime_lab_runner import cleanup_owned, interrupted, write_control

KERNEL_DEFAULTS = {'vm/overcommit_memory': '1', 'vm/panic_on_oom': '0',
                   'kernel/panic': '10', 'kernel/panic_on_oops': '1',
                   'kernel/keys/root_maxkeys': '1000000', 'kernel/keys/root_maxbytes': '25000000'}
INPUT = Path('/opt/warden/input')
SESSION = Path('/session')
CLIENT_DIRECTORY = Path('/run/k3s-client')
NODE_IP = '198.18.0.1'
RUNSC = '''binary_name = "/usr/bin/runsc"
[runsc_config]
  platform = "systrap"
  network = "none"
  oci-seccomp = "true"
'''
TEMPLATE = '''{{ template "base" . }}
[plugins.'io.containerd.nri.v1.nri']
  disable = true
[plugins.'io.containerd.cri.v1.runtime'.cni]
  bin_dirs = ["/usr/bin"]
  conf_dir = "/opt/warden/input/cni"
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.gvisor]
  runtime_type = "io.containerd.runsc.v1"
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.gvisor.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/opt/warden/input/runsc.toml"
'''


def validate_kernel(values, readonly):
    if values != KERNEL_DEFAULTS or not readonly:
        raise ValueError('protected kernel defaults or read-only /proc/sys mismatch')


def kernel_state():
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    readonly = any(m[4] == '/proc/sys' and 'ro' in m[5].split(',') for m in mounts)
    values = {name: Path('/proc/sys', name).read_text().strip() for name in KERNEL_DEFAULTS}
    validate_kernel(values, readonly)
    return values


def kubelet_config():
    return {'apiVersion': 'kubelet.config.k8s.io/v1beta1', 'kind': 'KubeletConfiguration',
            'protectKernelDefaults': True, 'cgroupDriver': 'cgroupfs',
            'cgroupsPerQOS': True, 'cgroupRoot': '/warden-lab',
            'kubeletCgroups': '/warden-lab/service', 'podPidsLimit': 128,
            'allowedUnsafeSysctls': [], 'maxPods': 8, 'failSwapOn': False,
            'memorySwap': {'swapBehavior': 'NoSwap'},
            'serializeImagePulls': True}


def verify_outer_noswap(parent):
    # /proc/swaps describes host swap even when this private cgroup cannot use
    # any. Verify the actual outer limit; never change host swap or this limit.
    fd = os.open('memory.swap.max', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.read(fd, 16) != b'0\n':
            raise ValueError('private outer cgroup must prohibit swap')
    finally:
        os.close(fd)


def verify_handler(config):
    try:
        handler = config['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['gvisor']
        if (config['plugins'].get('io.containerd.nri.v1.nri') != {'disable': True}
                or config['version'] != 3 or handler != {
                'runtime_type': 'io.containerd.runsc.v1',
                'options': {'TypeUrl': 'io.containerd.runsc.v1.options',
                            'ConfigPath': '/opt/warden/input/runsc.toml'}}):
            raise ValueError('handler drift')
    except (KeyError, TypeError):
        raise ValueError('gvisor v3 handler missing') from None


def public_identity(node, namespaces, ca_sha, input_sha):
    try:
        info = node['status']['nodeInfo']
        if (node['metadata']['name'] != 'warden-node' or not node['metadata']['uid']
                or info['kubeletVersion'] != 'v1.36.5+k3s1'
                or info['containerRuntimeVersion'] != 'containerd://2.3.4-k3s1.36'
                or not any(c['type'] == 'Ready' and c['status'] == 'True' for c in node['status']['conditions'])):
            raise ValueError('node not ready or version/identity mismatch')
        ns = {n['metadata']['name']: n['metadata']['uid'] for n in namespaces}
        if set(ns) != {'kube-system', 'warden-lab'} or not all(ns.values()):
            raise ValueError('namespace identity missing')
        if any(not re.fullmatch('[0-9a-f]{64}', v) for v in (ca_sha, input_sha)):
            raise ValueError('public fingerprints missing')
        return {'node_name': 'warden-node', 'node_uid': node['metadata']['uid'],
                'ready': True, 'kubelet_version': info['kubeletVersion'],
                'containerd_version': info['containerRuntimeVersion'], 'namespaces': ns,
                'endpoint': 'https://' + NODE_IP + ':6443',
                'ca_sha256': ca_sha, 'input_manifest_sha256': input_sha}
    except (KeyError, TypeError):
        raise ValueError('invalid public identity response') from None


EMPTY_APIS = (
    'apiextensions.k8s.io/v1beta1', 'authentication.k8s.io/v1beta1',
    'authentication.k8s.io/v1alpha1', 'authorization.k8s.io/v1beta1', 'batch/v1beta1',
    'certificates.k8s.io/v1beta1', 'certificates.k8s.io/v1alpha1',
    'coordination.k8s.io/v1beta1', 'coordination.k8s.io/v1alpha2', 'discovery.k8s.io/v1beta1',
    'networking.k8s.io/v1beta1', 'node.k8s.io/v1beta1', 'node.k8s.io/v1alpha1',
    'policy/v1beta1', 'rbac.authorization.k8s.io/v1beta1', 'rbac.authorization.k8s.io/v1alpha1',
    'scheduling.k8s.io/v1beta1', 'scheduling.k8s.io/v1alpha2',
    'storage.k8s.io/v1beta1', 'storage.k8s.io/v1alpha1',
    'flowcontrol.apiserver.k8s.io/v1beta3', 'flowcontrol.apiserver.k8s.io/v1beta2',
    'flowcontrol.apiserver.k8s.io/v1beta1', 'apps/v1beta2', 'apps/v1beta1',
    'admissionregistration.k8s.io/v1beta1', 'admissionregistration.k8s.io/v1alpha1',
    'events.k8s.io/v1beta1', 'resource.k8s.io/v1beta2', 'resource.k8s.io/v1beta1',
    'resource.k8s.io/v1alpha3', 'apiregistration.k8s.io/v1beta1',
)


def klog_startup(line, window):
    # These caller locations and enums belong to the pinned Kubernetes fork.
    # The launched process has TZ=UTC; yearless klog timestamps must resolve to
    # exactly one instant in this bounded launch-to-first-Ready interval.
    stamp = r'(?P<stamp>\d{4} \d\d:\d\d:\d\d\.\d{6}) +[1-9][0-9]* '
    patterns = {
        'empty-api': (1, 'W' + stamp + r'genericapiserver\.go:798\] (?P<safe>Skipping API (?P<api>' + '|'.join(map(re.escape, EMPTY_APIS)) + r') because it has no resources\.)'),
        'empty-metrics-manifest': (3, 'E' + stamp + r'options\.go:205\] (?P<safe>The manifest file is empty, ignoring\.)'),
        'missing-machine-id': (1, 'W' + stamp + r'info\.go:54\] (?P<safe>Couldn\'t collect info from any of the files) in "/etc/machine-id,/var/lib/dbus/machine-id"'),
        'reset-endpoints': (1, 'W' + stamp + r'lease\.go:265\] (?P<safe>Resetting endpoints for master service) "kubernetes" to \[198\.18\.0\.1\]'),
        'lease-namespace': (1, 'E' + stamp + r'controller\.go:201\] "(?P<safe>Failed to ensure lease exists, will retry)" err="namespaces \\"kube-system\\" not found" interval="200ms"'),
        'service-namespace': (1, 'E' + stamp + r'controller\.go:95\] (?P<safe>Unable to perform initial Kubernetes service initialization): namespaces "default" not found'),
    }
    for code, (maximum, pattern) in patterns.items():
        match = re.fullmatch(pattern, line)
        if match is None:
            continue
        if (not isinstance(window, tuple) or len(window) != 2
                or any(type(value) is not int for value in window)
                or not 0 < window[1] - window[0] <= 300):
            raise ValueError('bounded verified Ready interval required for klog')
        stamp = match['stamp']
        candidates = []
        for year in {datetime.fromtimestamp(value, timezone.utc).year for value in window}:
            try:
                at = datetime.fromisoformat(f'{year}-{stamp[:2]}-{stamp[2:4]}T{stamp[5:]}+00:00').timestamp()
            except ValueError:
                continue
            if window[0] <= at < window[1]:
                candidates.append(at)
        if len(candidates) != 1:
            raise ValueError('klog observation outside unambiguous verified Ready interval')
        if code == 'empty-api':
            code += ':' + match['api']
        return code, maximum, match['safe']
    return None


def warning_lines(log, *, source=None, root=None, ready_window=None, verified_namespaces=frozenset()):
    observed = []
    counts = {}
    modules = 'overlay|nf_conntrack|br_netfilter|iptable_nat|iptable_filter|nft-expr-counter|nfnetlink-subsys-11|nft-chain-2-nat'
    timestamp = r'time="\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)" '
    duration = r'[0-9]{1,9}(?:\.[0-9]{1,9})?(?:ns|µs|ms|s)'
    templates = {
        'certificate-cache': ('k3s', 1, r'level=warning msg="dynamiclistener 198\.18\.0\.1:6443: (?P<safe>no cached certificate available for preload - deferring certificate load until storage initialization or first client request)"'),
        'core-initializing': ('k3s', 240, r'level=error msg="Sending HTTP/(?:1\.1|2\.0) 503 response to (?:198\.18\.0\.1|127\.0\.0\.1):[0-9]{1,5}: (?P<safe>runtime core not ready)"'),
        'v3-migration': ('containerd', 1, r'level=warning msg="(?P<safe>Configuration migrated from version 3, use `containerd config migrate` to avoid migration)" t=(?:' + duration + '|"' + duration + '")'),
        'legacy-configmap-namespace': ('k3s', 1, r'level=error msg="(?P<safe>Error while syncing ConfigMap)" configmap=kube-system/kube-apiserver-legacy-service-account-token-tracking error="namespaces \\"kube-system\\" not found" logger=k3s/UnhandledError'),
    }
    if isinstance(root, str) and re.fullmatch(r'/proc/1/fd/[0-9]+/root', root):
        templates['fsverity-unsupported'] = ('containerd', 1, r'level=warning msg="(?P<safe>failed check for fsverity support)" error="enable fsverity failed: operation not supported" path=' + re.escape(root + '/agent/containerd/io.containerd.content.v1.content'))
    for line in log.splitlines():
        if not re.search(r'level=(warning|error|fatal)|[WEF]\d{4}\s', line):
            continue
        module = re.fullmatch(timestamp + r'level=warning msg="Failed to load kernel module (' + modules + r') with modprobe"', line)
        sysctl = re.fullmatch(timestamp + r'level=error msg="Failed to set sysctl: open /proc/sys/net/ipv4/conf/(all|default)/forwarding: read-only file system"', line)
        if module or sysctl:
            observed.append(line)  # Existing safe denials keep actual full text.
            continue
        klog = klog_startup(line, ready_window) if source == 'k3s' else None
        if klog is not None:
            code, maximum, safe = klog
            if code.endswith('-namespace') and verified_namespaces != frozenset({'default', 'kube-system'}):
                raise ValueError('final fixed namespace recovery not verified')
            counts[code] = counts.get(code, 0) + 1
            if counts[code] > maximum:
                raise ValueError('startup warning repeated beyond fixed bound')
            observed.append({'template': code, 'safe_fragment': safe,
                             'sha256': hashlib.sha256(line.encode()).hexdigest()})
            continue
        for code, (expected_source, maximum, pattern) in templates.items():
            match = re.fullmatch(timestamp + pattern, line)
            if match and source == expected_source:
                if code.endswith('-namespace') and verified_namespaces != frozenset({'default', 'kube-system'}):
                    raise ValueError('final fixed namespace recovery not verified')
                # Only a caller that has observed initial AND final Ready may
                # supply this startup interval. Seconds precision rounds the
                # upper bound down, refusing messages in/after the Ready second.
                at = datetime.fromisoformat(line.split('"', 2)[1]).timestamp()
                if (not isinstance(ready_window, tuple) or len(ready_window) != 2
                        or any(type(value) is not int for value in ready_window)
                        or not ready_window[0] <= at < ready_window[1]):
                    raise ValueError('startup warning persisted outside verified Ready interval')
                counts[code] = counts.get(code, 0) + 1
                if counts[code] > maximum:
                    raise ValueError('startup warning repeated beyond fixed bound')
                # Preserve the observed safe fragment and per-occurrence hash;
                # never export the internal IP/path/timing fields of these lines.
                observed.append({'template': code, 'safe_fragment': match['safe'],
                                 'sha256': hashlib.sha256(line.encode()).hexdigest()})
                break
        else:
            raise ValueError('unexpected startup warning/error; raw private log not exported')
    return observed


PRIVATE_LOGS = (('k3s', ('private.log',)),
                ('containerd', ('agent', 'containerd', 'containerd.log')))
DIAGNOSTIC_LIMIT = 32000000


def read_private_log(root, parts, limit, *, reject_rotation=False):
    # root may be the controller's own /proc/PID/fd/N/root anchor. Every
    # descendant is opened without following links, including directories.
    fd = os.open(root, NOFOLLOW_DIR)
    try:
        for part in parts[:-1]:
            child = os.open(part, NOFOLLOW_DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        def check_history():
            if reject_rotation and parts[-1] == 'containerd.log' and any(
                    name.startswith('containerd-') and '.log' in name for name in os.listdir(fd)):
                raise ValueError('rotated private diagnostics cannot pass startup gate')
        check_history()
        log = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        with os.fdopen(log, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError('private diagnostics require regular files')
            data = source.read(limit + 1)  # Bound reads even if a file grows.
            check_history()
            return data
    finally:
        os.close(fd)


def startup_denials(root, *, ready_window=None, verified_namespaces=frozenset()):
    remaining = DIAGNOSTIC_LIMIT
    denials = []
    for name, parts in PRIVATE_LOGS:
        data = read_private_log(root, parts, remaining, reject_rotation=True)
        remaining -= len(data)
        if remaining < 0:
            raise ValueError('combined private diagnostics exceeded bound')
        for entry in warning_lines(data.decode('utf-8'), source=name, root=str(root), ready_window=ready_window,
                                   verified_namespaces=verified_namespaces):
            denials.append({'source': name, **({'line': entry} if isinstance(entry, str) else entry)})
    return denials


def preserve_diagnostics(session):
    # Failure-only private snapshot: never returned as public evidence. Headers
    # and truncation/missing markers are included in the same 32MB file limit.
    fd = os.open(session.anchored('startup-private.log'),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as output:
        remaining = DIAGNOSTIC_LIMIT - 256
        for name, parts in PRIVATE_LOGS:
            output.write(('\n--- ' + name + ' ---\n').encode())
            try:
                data = read_private_log(session.anchored('root'), parts, remaining)
            except FileNotFoundError:
                output.write(b'<missing>\n')
                continue
            output.write(data[:remaining])
            if len(data) > remaining:
                output.write(b'\n<truncated>\n')
            remaining -= min(len(data), remaining)


def finish_node(daemon, cg, parent, created, session, *, success):
    try:
        if not success:
            preserve_diagnostics(session)
    finally:
        # Read/growth/missing-file failures cannot skip independent kill/reap.
        cleanup_owned(daemon, cg, parent, created, session, release_evidence=success)


def smoke():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if os.getuid() != 65534 or any(int(status[k].strip(), 16) for k in ('CapEff', 'CapPrm', 'CapBnd')):
        raise ValueError('smoke requires nobody and zero capability sets')
    checks = [(['/usr/bin/k3s', '--version'], 'v1.36.5+k3s1'),
              (['/usr/bin/containerd', '--version'], 'v2.3.4-k3s1.36'),
              (['/usr/bin/runsc', '--network=none', '--oci-seccomp=true', '--platform=systrap', '--version'], '20261019.0'),
              # Shim CLI reports its containerd library version, not the gVisor
              # release tag; the release identity is its verified artifact SHA.
              (['/usr/bin/containerd-shim-runsc-v1', '-v'], 'Version:  2.1.5+unknown')]
    for command, version in checks:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)
        print((result.stdout + result.stderr).strip(), flush=True)
        if version not in result.stdout + result.stderr:
            raise ValueError('fixed binary version mismatch')
    if any(Path('/usr/bin', tool).exists() for tool in ('busybox', 'modprobe', 'insmod', 'rmmod')) or Path('/lib/modules').exists():
        raise ValueError('module-loading material in image')
    # The actual selected binaries were invoked without capabilities. Python
    # imports above cover the controller's stdlib extension/SSL ABI closure.
    print('Capless k3s/runsc ABI smoke complete; node/tenant/conformance NOT EXECUTED', flush=True)


def node_command(root):
    return ['/usr/bin/k3s', 'server', '--data-dir=' + root,
            '--node-name=warden-node', '--node-ip=' + NODE_IP,
            '--advertise-address=' + NODE_IP, '--bind-address=' + NODE_IP,
            '--https-listen-port=6443', '--flannel-backend=none', '--disable-kube-proxy',
            '--disable-network-policy', '--disable-cloud-controller', '--disable-helm-controller',
            '--egress-selector-mode=disabled', '--snapshotter=native', '--protect-kernel-defaults',
            '--disable=coredns,traefik,servicelb,local-storage,metrics-server',
            '--write-kubeconfig=' + root + '/admin.yaml', '--write-kubeconfig-mode=0600',
            '--kubelet-arg=root-dir=' + root + '/kubelet',
            '--kubelet-arg=runtime-cgroups=/warden-lab/service',
            '--kubelet-arg=oom-score-adj=0',
            '--kube-proxy-arg=conntrack-max-per-core=0',
            '--kube-proxy-arg=conntrack-min=0',
            '--kube-proxy-arg=conntrack-tcp-timeout-established=0s',
            '--kube-proxy-arg=conntrack-tcp-timeout-close-wait=0s']


def mountinfo():
    return Path('/proc/self/mountinfo').read_text()


def remount_session(fd, flags):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(None, f'/proc/self/fd/{fd}'.encode(), None, flags, None) != 0:
        raise OSError(ctypes.get_errno(), 'remount verified private session bind')


def session_handshake(*, live):
    expected = os.environ.get('WARDEN_LAB_SESSION_IDENTITY', '')
    host_ns = os.environ.get('WARDEN_LAB_HOST_MOUNT_NS', '')
    if (not re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*:(?:0|[1-9][0-9]*)', expected)
            or not re.fullmatch(r'mnt:\[[1-9][0-9]*\]', host_ns)
            or os.readlink('/proc/self/ns/mnt') == host_ns):
        raise ValueError('owned session identity/private mount namespace required')
    identity = tuple(map(int, expected.split(':')))
    # No listing, file reads, prepare_session, ownership changes or failure
    # snapshot can occur before this mountpoint-only handshake succeeds.
    fd = os.open(SESSION, NOFOLLOW_DIR)
    try:
        def check(readonly):
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o7777 != 0o700
                    or (info.st_dev, info.st_ino, info.st_uid) != identity):
                raise ValueError('mounted session differs from held host FD')
            records = [line.split() for line in mountinfo().splitlines() if len(line.split()) > 6 and line.split()[4] == '/session']
            if len(records) != 1:
                raise ValueError('unique session bind mount required')
            record = records[0]
            options = set(record[5].split(','))
            flags = {'nosuid': 2, 'nodev': 4, 'noexec': 8, 'nosymfollow': 256,
                     'noatime': 1024, 'nodiratime': 2048, 'relatime': 2097152,
                     'strictatime': 16777216, 'lazytime': 33554432}
            if (options - flags.keys() - {'ro', 'rw'} or ('ro' in options) != readonly
                    or ('rw' in options) == readonly or '-' not in record
                    or record[6:record.index('-')]):
                raise ValueError('private readonly session bind flags required')
            return 4096 | 32 | sum(value for key, value in flags.items() if key in options)
        flags = check(True)
        if live:
            remount_session(fd, flags)  # MS_BIND|MS_REMOUNT, preserve other flags.
            if check(False) != flags:
                raise ValueError('session mount flags changed beyond readonly')
        return identity
    finally:
        os.close(fd)


def mount_smoke():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(status[k].strip(), 16) for k in ('CapEff', 'CapPrm', 'CapBnd')):
        raise ValueError('mount smoke requires zero capability sets')
    identity = session_handshake(live=False)
    if os.getuid() != identity[2]:
        raise ValueError('mount smoke requires original session owner UID')
    print('Capless readonly session identity verified; no content read/write/remount or k3s execution', flush=True)


@contextmanager
def diagnostic_stage(name):
    if name not in ('node-startup', 'owned-cleanup', 'adopted-reap', 'kernel-postflight'):
        raise ValueError('fixed diagnostic stage required')
    try:
        yield
    except BaseException as error:
        codes = {ValueError: 'validation', RuntimeError: 'runtime', TimeoutError: 'timeout',
                 OSError: 'os', subprocess.CalledProcessError: 'child-exit'}
        record = {'stage': name, 'code': codes.get(type(error), 'other')}
        if isinstance(error, OSError) and type(error.errno) is int and 0 < error.errno < 4096:
            record['errno'] = error.errno
        print(json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)
        raise


def prepare_client_directory():
    # Immutable /etc/rancher/k3s alias targets only this existing bounded tmpfs.
    os.mkdir(CLIENT_DIRECTORY, 0o700)


def reap_adopted():
    # PID1 adopts k3s grandchildren. cgroup.kill/populated=0 does not imply
    # every just-killed child is immediately waitable by WNOHANG.
    deadline = time.monotonic() + 5
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            if time.monotonic() >= deadline:
                raise TimeoutError('adopted child reap deadline exceeded')
            time.sleep(.01)


def confirm_ready(query):
    time.sleep(1)
    if query(['get', '--raw=/readyz']).strip() != b'ok':
        raise ValueError('API readiness did not persist')
    node = json.loads(query(['get', 'node', 'warden-node', '-o=json']))
    if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in node.get('status', {}).get('conditions', [])):
        raise ValueError('node readiness did not persist')
    return node


def confirm_bootstrap_namespaces(query):
    for name in ('default', 'kube-system'):
        value = json.loads(query(['get', 'namespace', name, '-o=json']))
        try:
            metadata = value['metadata']
            if (metadata['name'] != name or not isinstance(metadata['uid'], str) or not metadata['uid']
                    or 'deletionTimestamp' in metadata or value['status']['phase'] != 'Active'):
                raise ValueError('fixed namespace initialization did not recover')
        except (KeyError, TypeError):
            raise ValueError('invalid fixed namespace response') from None
    return frozenset({'default', 'kube-system'})


def run_node():
    session_handshake(live=True)  # Failure is outside every session cleanup path.
    prepare_client_directory()
    before = kernel_state()  # read-only; no sysctl fixups anywhere in controller
    bootstrap()  # existing private namespace/root-limit check and controller leaf
    parent = os.open('/sys/fs/cgroup', NOFOLLOW_DIR)
    try:
        with diagnostic_stage('node-startup'):
            verify_outer_noswap(parent)
        session = prepare_session('/session', Path('/session').stat().st_uid)
    except BaseException:
        os.close(parent)
        raise
    daemon = cg = None
    created = False
    success = False
    try:
        with diagnostic_stage('node-startup'):
            # K3s explicitly requires cpuset at its private cgroup-v2 root as well.
            write_control(parent, 'cgroup.subtree_control', '+cpuset')
            os.mkdir('warden-lab', 0o700, dir_fd=parent)
            created = True
            cg = os.open('warden-lab', NOFOLLOW_DIR, dir_fd=parent)
            write_control(cg, 'cgroup.subtree_control', '+cpu +cpuset +memory +pids')
            os.mkdir('service', 0o700, dir_fd=cg)
            service = os.open('service', NOFOLLOW_DIR, dir_fd=cg)
            root = session.anchored('root')
            configdir = Path(root) / 'agent/etc'
            for suffix in ('containerd', 'kubelet.conf.d', 'cni/net.d'):
                (configdir / suffix).mkdir(parents=True, mode=0o700)
            (configdir / 'containerd/config-v3.toml.tmpl').write_text(TEMPLATE)
            (configdir / 'kubelet.conf.d/99-warden.conf').write_text(json.dumps(kubelet_config()))
            (configdir / 'cni/net.d/10-loopback.conflist').write_text(json.dumps({
                'cniVersion': '1.0.0', 'name': 'warden-none', 'plugins': [{'type': 'loopback'}]}))
            # A non-loopback IP on lo is entirely inside this container's network
            # namespace. No veth, host networking, kernel module, route or port publish.
            subprocess.run(['/usr/bin/ip', 'address', 'add', NODE_IP + '/32', 'dev', 'lo'], check=True, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            def child_setup():
                write_control(service, 'cgroup.procs', str(os.getpid()))
                resource.setrlimit(resource.RLIMIT_FSIZE, (256000000, 256000000))
            try:
                with open(Path(root) / 'private.log', 'xb') as log:
                    os.chmod(log.name, 0o600)
                    started_at = int(time.time())
                    daemon = subprocess.Popen(node_command(root), stdout=log, stderr=log,
                                              env={'PATH': '/usr/bin', 'HOME': '/run', 'TMPDIR': '/tmp', 'TZ': 'UTC'},
                                              preexec_fn=child_setup, pass_fds=(service,))
            finally:
                os.close(service)
            # Every invocation below is fixed. No caller command/args, existing
            # kubeconfig or credential-bearing environment can reach kubectl.
            kubectl = ['/usr/bin/kubectl', '--kubeconfig=' + root + '/admin.yaml', '--request-timeout=3s']
            def query(args):
                result = subprocess.run(kubectl + args, capture_output=True, timeout=5,
                                        env={'PATH': '/usr/bin', 'HOME': '/run'})
                if result.returncode:
                    raise ValueError('fixed cluster query not ready')
                return result.stdout
            deadline = time.monotonic() + 240
            readiness = {'last_stage': 'not-attempted', 'attempts': 0,
                         'failures': dict.fromkeys(('api-query', 'api-body', 'node-query', 'node-json', 'node-ready'), 0)}
            while True:
                if daemon.poll() is not None:
                    raise RuntimeError('dedicated k3s exited; private diagnostics not emitted')
                if time.monotonic() > deadline:
                    # Fixed enums and saturated counters only. Never publish a
                    # client stderr, HTTP body, Node JSON or exception message.
                    print(json.dumps({'readiness_diagnostic': readiness}, sort_keys=True), file=sys.stderr, flush=True)
                    raise TimeoutError('dedicated k3s readiness timed out')
                allocated = sum(p.stat().st_size for p in Path(root).rglob('*') if p.is_file() and not p.is_symlink())
                if allocated > 1800000000:
                    raise RuntimeError('owned node data budget exceeded')
                try:
                    readiness['attempts'] = min(240, readiness['attempts'] + 1)
                    readiness['last_stage'] = 'api-query'
                    response = query(['get', '--raw=/readyz'])
                    readiness['last_stage'] = 'api-body'
                    if response.strip() != b'ok':
                        raise ValueError('API not ready')
                    readiness['last_stage'] = 'node-query'
                    response = query(['get', 'node', 'warden-node', '-o=json'])
                    readiness['last_stage'] = 'node-json'
                    node = json.loads(response)
                    readiness['last_stage'] = 'node-ready'
                    if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in node.get('status', {}).get('conditions', [])):
                        raise ValueError('node not ready')
                    ready_at = int(time.time())
                    break
                except (ValueError, subprocess.TimeoutExpired):
                    stage = readiness['last_stage']
                    readiness['failures'][stage] = min(240, readiness['failures'][stage] + 1)
                    time.sleep(1)
            verify_handler(tomllib.loads((configdir / 'containerd/config.toml').read_text()))
            # Bootstrap-owned namespace and RuntimeClass only: no Pod/Job probes.
            query(['create', '-f', '/opt/warden/input/bootstrap.json'])
            runtimeclass = json.loads(query(['get', 'runtimeclass', 'gvisor', '-o=json']))
            if runtimeclass.get('handler') != 'gvisor':
                raise ValueError('RuntimeClass handler mismatch')
            namespaces = [json.loads(query(['get', 'namespace', name, '-o=json'])) for name in ('kube-system', 'warden-lab')]
            node = confirm_ready(query)
            verified_namespaces = confirm_bootstrap_namespaces(query)
            ca = ssl.PEM_cert_to_DER_cert((Path(root) / 'server/tls/server-ca.crt').read_text())
            identity = public_identity(node, namespaces, hashlib.sha256(ca).hexdigest(),
                                       hashlib.sha256((INPUT / 'manifest.json').read_bytes()).hexdigest())
            denials = startup_denials(root, ready_window=(started_at, ready_at),
                                     verified_namespaces=verified_namespaces)
            verify_outer_noswap(parent)
            if kernel_state() != before:
                raise ValueError('kernel defaults drifted during bootstrap')
            # Only allowlisted public fields are archived; node annotations/logs
            # can include credentials and never reach Docker stdout or evidence.
            with open(session.anchored('containerd.log'), 'w') as output:
                output.write(json.dumps(identity, sort_keys=True) + '\n')
                output.write(json.dumps({'startup_observations': denials}) + '\n')
            print(json.dumps(identity, sort_keys=True), flush=True)
            success = True
    finally:
        try:
            with diagnostic_stage('owned-cleanup'):
                finish_node(daemon, cg, parent, created, session, success=success)
            with diagnostic_stage('adopted-reap'):
                reap_adopted()
            with diagnostic_stage('kernel-postflight'):
                verify_outer_noswap(parent)
                if kernel_state() != before:
                    raise RuntimeError('kernel postflight mismatch')
            print('{"cleanup":"empty-reaped-deleted"}', flush=True)
        finally:
            if cg is not None:
                os.close(cg)
            os.close(parent)
            session.close()


def main():
    os.umask(0o077)
    if sys.argv[1:] == ['smoke']:
        smoke()
    elif sys.argv[1:] == ['mount-smoke']:
        mount_smoke()
    elif sys.argv[1:] == ['bootstrap']:
        if os.getpid() != 1 or os.getuid() != 0:
            raise ValueError('fixed image PID1 bootstrap required')
        signal.signal(signal.SIGTERM, interrupted)
        run_node()
    else:
        raise ValueError('only fixed smoke/bootstrap entrypoints supported')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        # No exception argv, kubeconfig, diagnostics, annotations or environment.
        print('k3s lab failed: ' + type(error).__name__, file=sys.stderr, flush=True)
        sys.exit(2)
