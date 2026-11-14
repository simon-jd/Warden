"""scripts/k3s_gvisor_lab.sh against a fake docker.

The script runs unchanged from a copy of its directory layout, with fake
tools in .tools/ (go, k3s, runsc, helm, the Cilium chart and images), a fake
/proc (WARDEN_LAB_PROC) and a fake docker first on PATH that keeps its
containers and networks in a JSON file. Nothing touches the real Docker
daemon or reads the host's kernel state.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('k3s_gvisor_lab.sh')
NAME, NET, WORLD = 'warden-k3s-gvisor', 'warden-k3s', 'warden-k3s-world'
STANDINS = ['warden-k3s-origin-allowed', 'warden-k3s-origin-blocked', 'warden-k3s-stream', 'warden-k3s-imds',
            'warden-k3s-dns']
# The sysctls the script snapshots, as files under the fake /proc/sys.
SYSCTLS = ['vm/overcommit_memory', 'vm/panic_on_oom', 'kernel/panic', 'kernel/panic_on_oops',
           'kernel/keys/root_maxkeys', 'kernel/keys/root_maxbytes', 'fs/inotify/max_user_instances',
           'fs/inotify/max_user_watches', 'net/ipv4/ip_forward', 'kernel/timer_migration',
           'kernel/unprivileged_bpf_disabled', 'kernel/perf_event_paranoid', 'net/core/bpf_jit_enable',
           'net/ipv4/conf/all/rp_filter', 'net/ipv4/fib_multipath_use_neigh']
MODULES = ['overlay', 'br_netfilter', 'Zz_upper', 'veth']
WARDEN_NET = {'internal': True, 'labels': {'project': 'warden'}, 'subnet': '172.30.0.0/16'}

# Records every call and keeps containers and networks in FAKE_DOCKER_STATE.
# "fail" in the state lists the steps that fail. When the node starts, the
# fake kernel changes: FAKE_MODULES_ADD lines are appended to the fake
# /proc/modules and FAKE_SYSCTL_SET (path=value) is written, as a node that
# loads modules or writes a global sysctl would. kubectl apply's input goes
# to FAKE_DOCKER_APPLIED.
DOCKER = r'''
import json, os, sys
state_path, log_path = os.environ['FAKE_DOCKER_STATE'], os.environ['FAKE_DOCKER_LOG']
st = json.load(open(state_path)) if os.path.exists(state_path) else {}
st.setdefault('containers', {}); st.setdefault('networks', {}); st.setdefault('fail', []); st.setdefault('volumes', {})
args = sys.argv[1:]
with open(log_path, 'a') as f:
    f.write(json.dumps(args) + '\n')

def save():
    json.dump(st, open(state_path, 'w'))

def die(msg, code=1):
    sys.stderr.write(msg + '\n')
    sys.exit(code)

def label(labels, key):
    return labels.get(key, '<no value>')

def options(rest):
    flags = {'-d', '-i', '-q', '-a', '--privileged', '--internal', '--read-only'}
    opts, labels, pos = {}, {}, []
    while rest:
        a = rest.pop(0)
        if pos or not a.startswith('-'):
            pos.append(a)
        elif a in flags:
            opts[a] = True
        elif '=' in a:
            opts[a.split('=', 1)[0]] = a.split('=', 1)[1]
        else:
            v = rest.pop(0)
            if a == '--label':
                labels[v.split('=', 1)[0]] = v.split('=', 1)[1]
            else:
                opts[a] = v
    return opts, labels, pos

def create(rest, start):
    opts, labels, pos = options(rest)
    name = opts['--name']
    if 'name-taken' in st['fail']:
        st['containers'][name] = {'labels': {'project': 'warden'}, 'network': NET, 'running': True, 'by': 'other'}
        save()
        die('Conflict. The container name "/%s" is already in use' % name, 125)
    if name in st['containers']:
        die('Conflict. The container name "/%s" is already in use' % name, 125)
    if opts.get('--network') not in st['networks']:
        die('network %s not found' % opts.get('--network'), 125)
    st['containers'][name] = {'labels': labels, 'network': opts['--network'], 'networks': [opts['--network']],
                              'ip': opts.get('--ip'), 'running': start, 'by': 'script'}
    st['networks'][opts['--network']]['joined'] = True
    save()
    print('c' * 64)

NAME, NET = 'warden-k3s-gvisor', 'warden-k3s'
cmd = args[0]
if cmd in ('run', 'create'):
    create(args[1:], cmd == 'run')
elif cmd == 'start':
    if args[1] not in st['containers']:
        die('No such container: ' + args[1])
    st['containers'][args[1]]['running'] = True
    save()
    if args[1] == NAME:
        proc = os.environ['WARDEN_LAB_PROC']
        if os.environ.get('FAKE_MODULES_ADD'):
            with open(proc + '/modules', 'a') as f:
                f.write(''.join('%s 16384 0 - Live 0x0\n' % m for m in os.environ['FAKE_MODULES_ADD'].split()))
        if os.environ.get('FAKE_SYSCTL_SET'):
            path, value = os.environ['FAKE_SYSCTL_SET'].split('=')
            open(proc + '/sys/' + path, 'w').write(value + '\n')
elif cmd in ('inspect', 'container'):
    rest = args[2:] if cmd == 'container' else args[1:]
    tmpl = None
    if rest[0] == '-f':
        tmpl, rest = rest[1], rest[2:]
    c = st['containers'].get(rest[0])
    if c is None:
        die('Error: No such object: ' + rest[0])
    if tmpl is None:
        print(json.dumps([{'Name': '/' + rest[0], 'Config': {'Labels': c['labels']}}]))
    elif tmpl == '{{index .Config.Labels "project"}}':
        print(label(c['labels'], 'project'))
    elif tmpl == '{{.State.Running}} {{index .Config.Labels "owner"}} {{index .Config.Labels "warden.detect/role"}}':
        print('%s %s %s' % (str(c['running']).lower(), label(c['labels'], 'owner'), label(c['labels'], 'warden.detect/role')))
    else:
        die('fake docker: unknown template ' + tmpl, 99)
elif cmd == 'rm':
    name = args[-1]
    if name not in st['containers']:
        die('Error: No such container: ' + name)
    del st['containers'][name]
    save()
elif cmd == 'network':
    sub, rest = args[1], args[2:]
    if sub == 'inspect':
        tmpl = None
        if rest[0] == '-f':
            tmpl, rest = rest[1], rest[2:]
        n = st['networks'].get(rest[0])
        if n is None:
            die('Error: No such network: ' + rest[0])
        if tmpl is None:
            print(json.dumps([{'Name': rest[0], 'Internal': n['internal'], 'Labels': n['labels']}]))
        elif tmpl == '{{.Internal}} {{index .Labels "project"}}':
            print('%s %s' % (str(n['internal']).lower(), label(n['labels'], 'project')))
        elif tmpl == '{{index .Labels "project"}}':
            print(label(n['labels'], 'project'))
        elif tmpl == '{{(index .IPAM.Config 0).Subnet}}':
            print(n['subnet'])
        else:
            die('fake docker: unknown template ' + tmpl, 99)
    elif sub == 'create':
        opts, labels, pos = options(rest)
        if pos[0] in st['networks']:
            die('Error response from daemon: network with name %s already exists' % pos[0])
        if '--subnet' in opts and any(n['subnet'] == opts['--subnet'] for n in st['networks'].values()):
            die('Error response from daemon: invalid pool request: Pool overlaps with other one on this address space')
        st['networks'][pos[0]] = {'internal': bool(opts.get('--internal')), 'labels': labels,
                                  'subnet': opts.get('--subnet', '172.30.0.0/16')}
        save()
        print('n' * 64)
    elif sub == 'rm':
        n = rest[0]
        if n not in st['networks']:
            die('Error: No such network: ' + n)
        busy = 'network-busy' in st['fail'] and st['networks'][n].get('joined')
        if busy or any(n in c.get('networks', [c['network']]) for c in st['containers'].values()):
            die('Error response from daemon: error while removing network: network %s has active endpoints' % n)
        del st['networks'][n]
        save()
    elif sub == 'connect':
        opts, labels, pos = options(rest)
        if pos[0] not in st['networks'] or pos[1] not in st['containers']:
            die('Error response from daemon: no such network or container')
        st['containers'][pos[1]]['networks'].append(pos[0])
        save()
    else:
        die('fake docker: network ' + sub, 99)
elif cmd == 'volume' and args[1] == 'inspect':
    tmpl, name = args[3], args[4]
    v = st['volumes'].get(name)
    if v is None:
        die('Error response from daemon: get %s: no such volume' % name)
    if tmpl != '{{index .Labels "owner"}} {{index .Labels "warden.detect/role"}}':
        die('fake docker: unknown template ' + tmpl, 99)
    print('%s %s' % (label(v, 'owner'), label(v, 'warden.detect/role')))
elif cmd == 'build':
    print('sha256:' + 'b' * 64)
elif cmd == 'save':
    open(args[args.index('-o') + 1], 'wb').close()
elif cmd == 'exec':
    rest = args[1:]
    while rest[0].startswith('-'):
        rest.pop(0)
    c = st['containers'].get(rest[0])
    if c is None or not c['running']:
        die('Error response from daemon: container %s is not running' % rest[0])
    inner = rest[1:]
    if inner[0] == 'kubectl':
        if 'apply' in inner:
            with open(os.environ['FAKE_DOCKER_APPLIED'], 'a') as f:
                f.write(sys.stdin.read() + '\n---\n')
        elif 'create' in inner and '--dry-run=client' in inner:
            # YAML in; out, each object as its own JSON document, as kubectl prints them.
            sys.stdin.read()
            for it in json.load(open(os.environ['FAKE_CHART']))['items']:
                print(json.dumps(it, indent=4))
        elif 'exec' in inner and inner[-1] == '/proc/self/mountinfo':
            # The agent's mounts as the applied chart asked for them, unless
            # the runtime ignored that ("agent-kernel-rw").
            ro = False
            for doc in open(os.environ['FAKE_DOCKER_APPLIED']).read().split('\n---\n'):
                try:
                    items = json.loads(doc)['items']
                except ValueError:
                    continue
                for it in items:
                    if it['kind'] == 'DaemonSet' and it['metadata']['name'] == 'cilium':
                        for m in it['spec']['template']['spec']['containers'][0]['volumeMounts']:
                            if m['name'] == 'host-proc-sys-kernel':
                                ro = m.get('readOnly', False)
            if 'agent-kernel-rw' in st['fail']:
                ro = False
            print('1 0 0:1 / / rw,relatime - overlay overlay rw')
            print('2 1 0:2 /sys/kernel /host/proc/sys/kernel %s,nosuid,nodev,noexec,relatime - proc proc rw'
                  % ('ro' if ro else 'rw'))
            print('3 1 0:2 /sys/net /host/proc/sys/net rw,nosuid,nodev,noexec,relatime - proc proc rw')
        elif '-o' in inner:
            print('uid-' + inner[3], end='')
        else:
            print('NAME            STATUS   ROLES           AGE   VERSION')
            print('warden-gvisor   Ready    control-plane   9s    v1.36.5+k3s1')
    elif inner[0] == 'ctr':
        if 'import' in inner:
            sys.stdin.buffer.read()
            if 'ctr-import' in st['fail']:
                die('ctr: failed to import')
    elif inner[0] == 'cat':
        print('clusters:\n- cluster:\n    server: https://127.0.0.1:6443')
    elif inner[0] == 'ip':
        pass
    else:
        die('fake docker: exec ' + inner[0], 99)
elif cmd == 'image' and args[1] == 'inspect':
    if 'no-world-image' in st['fail']:
        die('Error response from daemon: No such image: ' + args[2])
    print('[{}]')
elif cmd in ('ps', 'image'):
    pass
else:
    die('fake docker: ' + cmd, 99)
'''

GO = '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && { : >"$2"; exit 0; }; shift; done\nexit 1\n'
HELM = '#!/bin/sh\necho "$@" >>"$FAKE_HELM_LOG"\necho "kind: List"\n'
# The rendered chart as `kubectl create --dry-run=client -o json` sees it (the
# fake prints the items one after another): Cilium's agent DaemonSet reduced
# to its volumes, as in 1.20.4.
CHART = {'apiVersion': 'v1', 'kind': 'List', 'items': [{
    'apiVersion': 'apps/v1', 'kind': 'DaemonSet', 'metadata': {'name': 'cilium', 'namespace': 'kube-system'},
    'spec': {'template': {'spec': {
        'volumes': [{'name': 'host-proc-sys-net', 'hostPath': {'path': '/proc/sys/net'}},
                    {'name': 'host-proc-sys-kernel', 'hostPath': {'path': '/proc/sys/kernel'}},
                    {'name': 'hostproc', 'hostPath': {'path': '/proc'}},
                    {'name': 'bpf-maps', 'hostPath': {'path': '/sys/fs/bpf'}}],
        'containers': [{'name': 'cilium-agent', 'volumeMounts': [
            {'name': 'host-proc-sys-net', 'mountPath': '/host/proc/sys/net'},
            {'name': 'host-proc-sys-kernel', 'mountPath': '/host/proc/sys/kernel'},
            {'name': 'bpf-maps', 'mountPath': '/sys/fs/bpf'}]}],
        'initContainers': [{'name': 'mount-cgroup', 'volumeMounts': [{'name': 'hostproc', 'mountPath': '/hostproc'}]}],
    }}}}]}
LAB_CILIUM = Path(__file__).resolve().parent.parent / 'runtimes/gvisor/lab/cilium'
RUNSC_TOML = '[runsc_config]\n  platform = "systrap"\n  network = "none"\n'
POD_INIT = '{"trace_session": {"sinks": [{"config": {"endpoint": "/warden-detect/gvisor.sock"}, "name": "remote"}]}}'
DETECTOR = {'labels': {'owner': 'warden-lab', 'warden.detect/role': 'falco'}, 'network': 'none', 'running': True, 'by': 'detector'}
DETECTOR_VOLUME = {'owner': 'warden-lab', 'warden.detect/role': 'falco'}
FALCO_MOUNT = ['--mount', 'type=volume,src=warden-detect-gvisor,dst=/warden-detect,readonly']


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


@unittest.skipUnless(Path('/proc/modules').exists() and shutil.which('bash'), 'the script reads /proc')
class GVisorLabScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = root = self.tmp / 'repo'
        executable(root / 'scripts' / SCRIPT.name, SCRIPT.read_text())
        (root / 'scripts' / 'build-probe-oci.py').write_text('')
        # A stand-in for the corpus build; it also leaves a marker, so a test
        # can tell whether up ran it at all.
        (root / 'scripts' / 'build-corpus-image.py').write_text("from pathlib import Path\nr=Path(__file__).resolve().parent.parent/'.cache/warden-lab'\nr.joinpath('corpus.oci.tar').write_bytes(b'corpus archive')\nr.joinpath('corpus-image-digest').write_text('sha256:'+'c'*64)\nr.joinpath('corpus-image-name').write_text('warden-lab/corpus:matrix')\nr.joinpath('corpus-built').write_text('')\n")
        for tool in ('k3s/k3s', 'gvisor/runsc', 'gvisor/containerd-shim-runsc-v1', 'gvisor/gvisor-bin'):
            executable(root / '.tools' / tool, '#!/bin/sh\n')
        executable(root / '.tools/go/bin/go', GO)
        node = root / 'runtimes/gvisor/lab/node'
        node.mkdir(parents=True)
        (node / 'Dockerfile').write_text('FROM scratch\n')
        (node / '10-warden.conflist').write_text('{}\n')
        (node / 'runsc.toml').write_text(RUNSC_TOML)
        (root / 'detect/falco').mkdir(parents=True)
        (root / 'detect/falco/gvisor-pod-init.json').write_text(POD_INIT)
        if LAB_CILIUM.is_dir():
            shutil.copytree(LAB_CILIUM, root / 'runtimes/gvisor/lab/cilium')
        executable(root / '.tools/helm/helm', HELM)
        cilium = root / '.tools/cilium'
        (cilium / 'images').mkdir(parents=True)
        for f in ('.complete', 'cilium-1.20.4.tgz', 'images/cilium.oci.tar', 'images/coredns.oci.tar'):
            (cilium / f).write_text('')
        self.proc = self.tmp / 'proc'
        for k in SYSCTLS:
            (self.proc / 'sys' / k).parent.mkdir(parents=True, exist_ok=True)
            (self.proc / 'sys' / k).write_text('1\n')
        (self.proc / 'modules').write_text(''.join('%s 16384 0 - Live 0x0\n' % m for m in MODULES))
        cache = root / '.cache/warden-lab'
        cache.mkdir(parents=True)
        (cache / 'image-digest').write_text('sha256:' + 'a' * 64)
        (cache / 'probe.oci.tar').write_bytes(b'')
        executable(self.tmp / 'bin/docker', '#!%s -I\n%s' % (sys.executable, DOCKER))
        self.state, self.log = self.tmp / 'docker.json', self.tmp / 'docker.log'
        self.applied, self.helm_log = self.tmp / 'applied.yaml', self.tmp / 'helm.log'
        self.env = {'PATH': '%s:/usr/bin:/bin' % (self.tmp / 'bin'), 'HOME': str(self.tmp),
                    'FAKE_DOCKER_STATE': str(self.state), 'FAKE_DOCKER_LOG': str(self.log),
                    'FAKE_DOCKER_APPLIED': str(self.applied), 'FAKE_HELM_LOG': str(self.helm_log),
                    'WARDEN_LAB_PROC': str(self.proc), 'FAKE_CHART': str(self.tmp / 'chart.json')}
        (self.tmp / 'chart.json').write_text(json.dumps(CHART))
        self.lab = root / '.cache/k3s-gvisor/lab'

    def docker(self, containers=None, networks=None, fail=(), volumes=None):
        self.state.write_text(json.dumps({'containers': containers or {}, 'networks': networks or {},
                                          'fail': list(fail), 'volumes': volumes or {}}))

    def script(self, *args, **env):
        return subprocess.run(['bash', str(self.root / 'scripts' / SCRIPT.name), *args], cwd=self.root,
                              env=dict(self.env, **env), capture_output=True, text=True, timeout=120)

    def creates(self):
        return [c for c in self.calls() if c[0] == 'create']

    def lines(self, name):
        return (self.lab / name).read_text().splitlines()

    def world(self):
        return json.loads(self.state.read_text())

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def removals(self):
        return [c for c in self.calls() if c[0] == 'rm' or c[:2] == ['network', 'rm']]

    def other_lab(self):
        self.docker({NAME: {'labels': {'project': 'warden'}, 'network': NET, 'running': True, 'by': 'other'}},
                    {NET: dict(WARDEN_NET)})

    # --- run removes what it created, and only that ---

    def test_run_tears_down_the_lab_it_created(self):
        self.docker()
        r = self.script('run', 'true')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.world()['containers'], {})
        self.assertEqual(self.world()['networks'], {})
        self.assertFalse((self.lab / 'kubeconfig').exists())
        self.assertFalse((self.lab / 'lab.env').exists())

    def test_up_imports_corpus_and_exports_matrix_paths(self):
        cache = self.root / '.cache/warden-lab'
        (cache / 'corpus.oci.tar').write_bytes(b'corpus archive')
        (cache / 'corpus-image-digest').write_text('sha256:' + 'c' * 64)
        (cache / 'corpus-image-name').write_text('warden-lab/corpus:matrix')
        self.docker()
        result = self.script('up')
        self.assertEqual(result.returncode, 0, result.stderr)
        env = dict(line.split('=', 1) for line in (self.lab / 'lab.env').read_text().splitlines())
        self.assertEqual(env['WARDEN_MATRIX_IMAGE_DIGEST'], 'sha256:' + 'c' * 64)
        self.assertEqual(env['WARDEN_MATRIX_CORPUS'], str(self.root / 'attacks/corpus'))
        self.assertTrue(Path(env['WARDEN_MATRIX_OUT']).is_dir())
        imports = [c for c in self.calls() if c[:3] == ['exec', '-i', NAME] and 'import' in c]
        self.assertEqual(len(imports), 3)
        self.assertIn(['exec', NAME, 'ctr', '-n', 'k8s.io', 'images', 'tag', 'warden-lab/corpus:matrix', 'docker.io/warden-lab/probe@sha256:' + 'c' * 64], self.calls())
        self.assertIn(['exec', NAME, 'ctr', '-n', 'k8s.io', 'images', 'tag', 'warden-lab/corpus:matrix', 'docker.io/warden-lab/corpus:matrix'], self.calls())

    # --- --without-corpus: no attack helper, corpus image or matrix paths ---

    def corpus_imports(self):
        return [c for c in self.calls() if c[:3] == ['exec', '-i', NAME] and 'import' in c]

    def test_default_up_still_builds_and_imports_the_corpus(self):
        # Without the option, up is f64269a's: it builds the attack helper and
        # the corpus image, imports it and exports the matrix paths.
        self.docker()
        r = self.script('up')
        self.assertEqual(r.returncode, 0, r.stderr)
        cache = self.root / '.cache/warden-lab'
        self.assertTrue((cache / 'warden-attack').exists())
        self.assertTrue((cache / 'corpus-built').exists())
        self.assertEqual(len(self.corpus_imports()), 3)
        env = self.lines('lab.env')
        self.assertTrue(any(line.startswith('WARDEN_MATRIX_CORPUS=') for line in env), env)
        self.assertFalse(any(line.startswith('WARDEN_K3S_CORPUS=') for line in env), env)

    def test_up_without_corpus_builds_and_imports_no_corpus(self):
        # A corpus image left in the cache by an earlier build is not imported either.
        cache = self.root / '.cache/warden-lab'
        (cache / 'corpus.oci.tar').write_bytes(b'corpus archive')
        (cache / 'corpus-image-digest').write_text('sha256:' + 'c' * 64)
        (cache / 'corpus-image-name').write_text('warden-lab/corpus:matrix')
        for mode in ([], ['--cilium']):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                self.docker()
                r = self.script('up', *mode, '--without-corpus')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertFalse((cache / 'warden-attack').exists())
                self.assertFalse((cache / 'corpus-built').exists())
                # pause and probe only (plus the Cilium images in that mode)
                self.assertEqual(len(self.corpus_imports()), 2 + (2 if mode else 0))
                self.assertFalse(any('corpus' in ' '.join(c) for c in self.calls()), self.calls())
                env = self.lines('lab.env')
                self.assertIn('WARDEN_K3S_CORPUS=without', env)
                self.assertFalse(any(line.startswith('WARDEN_MATRIX_') for line in env), env)
                self.assertFalse((self.lab / 'matrix').exists())
                r = self.script('down')
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_up_without_corpus_needs_no_corpus_image(self):
        self.docker()
        r = self.script('up', '--without-corpus')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('corpus image missing', r.stderr)

    def test_run_takes_the_lab_options_in_either_order(self):
        for flags in (['--without-corpus'], ['--cilium', '--without-corpus'], ['--without-corpus', '--cilium']):
            with self.subTest(flags=flags):
                self.log.unlink(missing_ok=True)
                self.docker()
                r = self.script('run', *flags, 'touch', str(self.tmp / 'ran'))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue((self.tmp / 'ran').exists())
                self.assertEqual(self.world()['containers'], {})
                self.assertEqual(self.world()['networks'], {})
                self.assertFalse((self.root / '.cache/warden-lab/corpus-built').exists())
                node = [c for c in self.creates() if c[c.index('--name') + 1] == NAME][0]
                self.assertEqual('--entrypoint' in node, '--cilium' in flags, node)

    # --- --falco: runsc sends trace events to the detector's gVisor instance ---

    def detector_up(self, container=None, volume=None):
        self.docker({'warden-detect-falco-gvisor': container or dict(DETECTOR)},
                    volumes={'warden-detect-gvisor': volume or dict(DETECTOR_VOLUME)})

    def node_create(self):
        return [c for c in self.creates() if c[c.index('--name') + 1] == NAME][0]

    def has(self, args, flag):
        return any(args[i:i + len(flag)] == flag for i in range(len(args)))

    def test_up_falco_mounts_the_detector_socket_and_points_runsc_at_it(self):
        self.detector_up()
        r = self.script('up', '--without-corpus', '--falco')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.has(self.node_create(), FALCO_MOUNT), self.node_create())
        ctx = self.lab / 'node-ctx'
        self.assertIn('  pod-init-config = "/etc/containerd/warden-falco-pod-init.json"\n', (ctx / 'runsc.toml').read_text())
        self.assertEqual((ctx / 'extra/etc/containerd/warden-falco-pod-init.json').read_text(), POD_INIT)
        self.assertIn('./extra/etc/containerd/warden-falco-pod-init.json', (self.lab / 'node-manifest.txt').read_text())
        self.assertIn('WARDEN_K3S_FALCO=1', self.lines('lab.env'))
        r = self.script('down')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('warden-detect-falco-gvisor', self.world()['containers'], 'the lab never removes the detector')
        self.assertIn('warden-detect-gvisor', self.world()['volumes'])

    def test_the_node_says_which_worktree_made_it(self):
        # The detector's cleanup takes down only a node its own worktree made.
        import hashlib
        want = 'warden.lab/root=' + hashlib.sha256(str(self.root.resolve()).encode()).hexdigest()[:16]
        for mode in ([], ['--cilium']):
            with self.subTest(mode=mode):
                self.log.unlink(missing_ok=True)
                self.docker()
                r = self.script('run', *mode, '--without-corpus', 'true')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue(self.has(self.node_create(), ['--label', want]), self.node_create())

    def test_default_up_has_no_detector_mount_or_trace_config(self):
        self.detector_up()
        r = self.script('up')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any('warden-detect' in a for a in self.node_create()), self.node_create())
        self.assertEqual((self.lab / 'node-ctx/runsc.toml').read_text(), RUNSC_TOML)
        self.assertFalse((self.lab / 'node-ctx/extra/etc/containerd/warden-falco-pod-init.json').exists())
        self.assertFalse(any(line.startswith('WARDEN_K3S_FALCO') for line in self.lines('lab.env')))

    def test_up_falco_needs_the_detectors_gvisor_instance(self):
        stopped = dict(DETECTOR, running=False)
        theirs = dict(DETECTOR, labels={'owner': 'someone'})
        for label, setup in (('absent', lambda: self.docker()),
                             ('stopped', lambda: self.detector_up(container=stopped)),
                             ('not the detector', lambda: self.detector_up(container=theirs)),
                             ('foreign volume', lambda: self.detector_up(volume={'owner': 'someone'}))):
            with self.subTest(case=label):
                self.log.unlink(missing_ok=True)
                setup()
                r = self.script('up', '--without-corpus', '--falco')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('detector', r.stderr)
                self.assertEqual(self.creates(), [])

    def test_falco_in_cilium_mode_configures_both_handlers(self):
        self.detector_up()
        r = self.script('up', '--cilium', '--without-corpus', '--falco')
        self.assertEqual(r.returncode, 0, r.stderr)
        line = '  pod-init-config = "/etc/containerd/warden-falco-pod-init.json"\n'
        self.assertIn(line, (self.lab / 'node-ctx/runsc.toml').read_text())
        self.assertIn(line, (self.lab / 'node-ctx/extra/etc/containerd/runsc-netstack.toml').read_text())
        self.assertTrue(self.has(self.node_create(), FALCO_MOUNT))

    def test_run_falco_tears_down_only_the_lab(self):
        self.detector_up()
        r = self.script('run', '--falco', '--without-corpus', 'true')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(list(self.world()['containers']), ['warden-detect-falco-gvisor'])
        self.assertEqual(list(self.world()['volumes']), ['warden-detect-gvisor'])

    def test_run_keeps_the_commands_exit_status(self):
        self.docker()
        r = self.script('run', 'sh', '-c', 'exit 3')
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertEqual(self.world()['containers'], {})
        self.assertEqual(self.world()['networks'], {})

    def test_run_tears_down_what_it_created_when_up_fails(self):
        self.docker(fail=['ctr-import'])
        r = self.script('run', 'true')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.world()['containers'], {})
        self.assertEqual(self.world()['networks'], {})

    def test_run_leaves_a_lab_that_was_already_up(self):
        self.other_lab()
        r = self.script('run', 'true')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('already exists', r.stderr)
        self.assertIn(NAME, self.world()['containers'])
        self.assertIn(NET, self.world()['networks'])
        self.assertEqual(self.removals(), [])

    def test_run_leaves_a_node_someone_else_created_first(self):
        # The name is free when up checks it and taken when the node is
        # created: the container is not this run's.
        self.docker(fail=['name-taken'])
        r = self.script('run', 'true')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.world()['containers'].get(NAME, {}).get('by'), 'other')
        self.assertNotIn(['rm', '-f', NAME], self.calls())

    def test_run_leaves_a_warden_network_it_did_not_create(self):
        self.docker(networks={NET: dict(WARDEN_NET)})
        r = self.script('run', 'true')
        self.assertIn(['network', 'inspect', NET], self.calls())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.world()['containers'], {})
        self.assertIn(NET, self.world()['networks'])

    def test_run_fails_when_its_teardown_fails(self):
        # The network cannot be removed once the node has joined it.
        self.docker(fail=['network-busy'])
        r = self.script('run', 'touch', str(self.tmp / 'ran'))
        self.assertTrue((self.tmp / 'ran').exists(), r.stderr)
        self.assertIn('still in use', r.stderr)
        self.assertNotEqual(r.returncode, 0, 'the command passed, the teardown failed, and run passed')

    # --- --cilium: the world network, its stand-ins and the Cilium node ---

    def test_up_cilium_builds_the_world_and_the_node(self):
        self.docker()
        r = self.script('up', '--cilium')
        self.assertEqual(r.returncode, 0, r.stderr)
        w = self.world()
        self.assertEqual({k: w['networks'][WORLD][k] for k in ('internal', 'labels', 'subnet')},
                         {'internal': True, 'labels': {'project': 'warden'}, 'subnet': '198.18.18.0/24'})
        self.assertEqual({c: w['containers'][c]['ip'] for c in STANDINS},
                         {'warden-k3s-origin-allowed': '198.18.18.20', 'warden-k3s-origin-blocked': '198.18.18.21',
                          'warden-k3s-stream': '198.18.18.22', 'warden-k3s-imds': '198.18.18.30',
                          'warden-k3s-dns': '198.18.18.40'})
        for c in self.creates():
            if c[c.index('--name') + 1] in STANDINS:
                for flag in (['--pull', 'never'], ['--read-only'], ['--cap-drop', 'ALL'], ['--network', WORLD]):
                    self.assertTrue(any(c[i:i + len(flag)] == flag for i in range(len(c))), (flag, c))
                imds = c[c.index('--name') + 1] == 'warden-k3s-imds'
                self.assertEqual('NET_ADMIN' in c, imds, c)
                self.assertEqual('65534:65534' in c, not imds, c)
        node = [c for c in self.creates() if c[c.index('--name') + 1] == NAME][0]
        self.assertEqual(node[node.index('--entrypoint') + 1:node.index('--entrypoint') + 3],
                         ['/warden-node-init', 'warden-k3s-gvisor:cilium'])
        self.assertEqual(w['containers'][NAME]['networks'], [NET, WORLD])
        self.assertIn(['network', 'connect', '--ip', '198.18.18.10', WORLD, NAME], self.calls())
        self.assertIn(['exec', NAME, 'ip', 'route', 'replace', '169.254.169.254/32', 'via', '198.18.18.30'],
                      self.calls())
        self.assertIn('--set k8sServiceHost=172.30.0.10', self.helm_log.read_text())
        applied = self.applied.read_text()
        self.assertIn('handler: runsc-netstack', applied)
        self.assertIn('198.18.18.20 allowed.warden.test', applied)
        self.assertNotIn('@WORLD@', applied)
        env = self.lines('lab.env')
        for line in ('WARDEN_K3S_CNI=cilium', 'WARDEN_CILIUM_WORLD_NETWORK=' + WORLD,
                     'WARDEN_CILIUM_WORLD_PREFIX=198.18.18'):
            self.assertIn(line, env)
        for stage in ('before', 'at-node-registered', 'at-cilium-ready', 'at-up'):
            self.assertEqual(self.lines('modules-%s.txt' % stage), sorted(MODULES), stage)
        r = self.script('down')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.world()['containers'], {})
        self.assertEqual(self.world()['networks'], {})

    def test_run_cilium_tears_down_everything_it_created(self):
        for fail in ([], ['ctr-import']):
            with self.subTest(fail=fail):
                self.log.unlink(missing_ok=True)
                self.docker(fail=fail)
                r = self.script('run', '--cilium', 'true')
                self.assertEqual(r.returncode != 0, bool(fail), r.stderr)
                self.assertEqual(self.world()['containers'], {})
                self.assertEqual(self.world()['networks'], {})
                self.assertFalse((self.lab / 'lab.env').exists())

    def test_cpuset_pins_every_container_the_lab_creates(self):
        self.docker()
        r = self.script('run', '--cilium', 'true', WARDEN_LAB_CPUSET='0-7,16-31')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.creates()), 1 + len(STANDINS))
        for c in self.creates():
            self.assertEqual(c[c.index('--cpuset-cpus') + 1], '0-7,16-31', c)

    def test_cilium_node_turns_src_valid_mark_off_in_its_own_netns(self):
        # A new netns copies net.ipv4.conf.all.* from the host's; with the
        # host's src_valid_mark=1, the node's reverse-path check routes a
        # pod's proxied packets by Cilium's proxy mark to a local route and
        # drops them, so the DNS proxy never sees a query.
        for cni, want in ((['--cilium'], True), ([], False)):
            with self.subTest(cni=cni):
                self.log.unlink(missing_ok=True)
                self.docker()
                r = self.script('run', *cni, 'true')
                self.assertEqual(r.returncode, 0, r.stderr)
                node = [c for c in self.creates() if c[c.index('--name') + 1] == NAME][0]
                flag = ['--sysctl', 'net.ipv4.conf.all.src_valid_mark=0']
                self.assertEqual(any(node[i:i + 2] == flag for i in range(len(node))), want, node)

    def test_world_network_skips_a_subnet_another_network_uses(self):
        other = {'internal': False, 'labels': {}, 'subnet': '198.18.18.0/24'}
        self.docker(networks={'someone-else': other})
        r = self.script('up', '--cilium')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.world()['networks'][WORLD]['subnet'], '198.18.19.0/24')
        self.assertIn('WARDEN_CILIUM_WORLD_PREFIX=198.18.19', self.lines('lab.env'))
        self.assertEqual(self.world()['containers']['warden-k3s-imds']['ip'], '198.18.19.30')
        self.script('down')
        self.assertEqual(self.world()['networks'], {'someone-else': other})

    def test_up_cilium_leaves_a_standin_name_that_exists(self):
        theirs = {'labels': {}, 'network': 'bridge', 'running': True, 'by': 'other'}
        self.docker({'warden-k3s-dns': theirs}, {'bridge': {'internal': False, 'labels': {}, 'subnet': '172.17.0.0/16'}})
        r = self.script('run', '--cilium', 'true')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('already exists', r.stderr)
        self.assertEqual(self.world()['containers'], {'warden-k3s-dns': theirs})
        self.assertEqual(self.creates(), [])
        self.assertEqual(self.removals(), [])

    def test_up_cilium_does_not_pull_the_world_image(self):
        self.docker(fail=['no-world-image'])
        r = self.script('run', '--cilium', 'true')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('does not pull', r.stderr)
        self.assertEqual(self.creates(), [])
        self.assertFalse(any('pull' in c[:2] for c in self.calls()))

    def test_up_rejects_an_unknown_option(self):
        self.docker()
        r = self.script('up', '--calico')
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(self.creates(), [])

    # --- the host's kernel state, before and after ---

    def test_cilium_run_reports_the_modules_it_added_and_passes(self):
        self.docker()
        r = self.script('run', '--cilium', 'true', FAKE_MODULES_ADD='xt_TPROXY cls_bpf')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('added: cls_bpf xt_TPROXY', r.stderr)
        self.assertEqual(self.lines('modules-added.txt'), ['cls_bpf', 'xt_TPROXY'])
        self.assertEqual(self.lines('modules-removed.txt'), [])
        self.assertEqual(self.lines('modules-before.txt'), sorted(MODULES))
        self.assertEqual(self.lines('modules-after.txt'), sorted(MODULES + ['xt_TPROXY', 'cls_bpf']))

    def test_bridge_run_fails_when_the_modules_change(self):
        self.docker()
        r = self.script('run', 'true', FAKE_MODULES_ADD='xt_TPROXY')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('modules changed', r.stderr)
        self.assertEqual(self.lines('modules-added.txt'), ['xt_TPROXY'])
        self.assertEqual(self.world()['containers'], {})

    def test_a_sysctl_change_fails_in_both_modes(self):
        for mode in ([], ['--cilium']):
            with self.subTest(mode=mode):
                (self.proc / 'sys/kernel/timer_migration').write_text('1\n')
                self.docker()
                r = self.script('run', *mode, 'true', FAKE_SYSCTL_SET='kernel/timer_migration=0')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('sysctls changed', r.stderr)
                self.assertIn('kernel.timer_migration=0', r.stderr)

    def test_module_lists_sort_bytewise_whatever_the_locale(self):
        # comm needs both lists in one order; a list written under another
        # locale would make it fail or misreport.
        self.docker()
        r = self.script('run', '--cilium', 'true', LC_ALL='en_US.UTF-8', LANG='en_US.UTF-8',
                        FAKE_MODULES_ADD='a_new')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lines('modules-before.txt'), sorted(MODULES))
        self.assertEqual(self.lines('modules-added.txt'), ['a_new'])

    def applied_agent(self):
        for doc in self.applied.read_text().split('\n---\n'):
            try:
                items = json.loads(doc)['items']
            except ValueError:
                continue
            for it in items:
                if it['kind'] == 'DaemonSet' and it['metadata']['name'] == 'cilium':
                    spec = it['spec']['template']['spec']
                    return {(c['name'], m['name']): m.get('readOnly', False)
                            for c in spec['initContainers'] + spec['containers'] for m in c['volumeMounts']}
        self.fail('no cilium DaemonSet was applied')

    def test_cilium_agent_gets_the_nodes_proc_read_only(self):
        # The node's /proc/sys/kernel is the host's: on 2026-11-12 the agent
        # wrote two host sysctls through its hostPath mount of it.
        self.docker()
        r = self.script('up', '--cilium')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.applied_agent(), {
            ('cilium-agent', 'host-proc-sys-net'): False, ('cilium-agent', 'host-proc-sys-kernel'): True,
            ('cilium-agent', 'bpf-maps'): False, ('mount-cgroup', 'hostproc'): True})
        self.assertIn('/host/proc/sys/kernel ro,', (self.lab / 'agent-mountinfo.txt').read_text())

    def test_up_cilium_fails_when_the_agent_can_write_kernel_sysctls(self):
        self.docker(fail=['agent-kernel-rw'])
        r = self.script('run', '--cilium', 'true')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("agent can write the host's kernel sysctls", r.stderr)
        self.assertEqual(self.world()['containers'], {})
        self.assertEqual(self.world()['networks'], {})

    def test_up_cilium_fails_as_soon_as_a_sysctl_changed(self):
        # Not only at down: a lab that changed the host stops before any test runs on it.
        (self.proc / 'sys/kernel/timer_migration').write_text('1\n')
        self.docker()
        r = self.script('up', '--cilium', FAKE_SYSCTL_SET='kernel/timer_migration=0')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('host sysctls changed while Cilium started', r.stderr)
        self.assertIn('kernel.timer_migration=0', r.stderr)
        self.assertFalse((self.lab / 'lab.env').exists())
        self.script('down')

    # --- the network named warden-k3s has to be Warden's ---

    def test_up_refuses_a_network_that_is_not_wardens(self):
        for labels, internal in (({}, True), ({'project': 'other'}, True), ({'project': 'warden'}, False)):
            with self.subTest(labels=labels, internal=internal):
                self.log.unlink(missing_ok=True)
                foreign = {'internal': internal, 'labels': labels, 'subnet': '10.9.0.0/24'}
                self.docker(networks={NET: foreign})
                r = self.script('up')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('not Warden', r.stderr)
                self.assertEqual(self.world()['networks'], {NET: foreign})
                self.assertEqual(self.world()['containers'], {})
                self.assertEqual(self.removals(), [])

    def test_down_leaves_a_network_that_is_not_wardens(self):
        foreign = {'internal': True, 'labels': {}, 'subnet': '10.9.0.0/24'}
        self.docker(networks={NET: foreign})
        r = self.script('down')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not a Warden network', r.stderr)
        self.assertEqual(self.world()['networks'], {NET: foreign})
        self.assertEqual(self.removals(), [])

    def test_down_removes_the_warden_lab(self):
        self.other_lab()
        r = self.script('down')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.world()['containers'], {})
        self.assertEqual(self.world()['networks'], {})

    def test_down_leaves_a_container_that_is_not_wardens(self):
        self.docker({NAME: {'labels': {}, 'network': NET, 'running': True, 'by': 'other'}}, {NET: dict(WARDEN_NET)})
        r = self.script('down')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(NAME, self.world()['containers'])
        self.assertEqual(self.removals(), [])


if __name__ == '__main__':
    unittest.main()
