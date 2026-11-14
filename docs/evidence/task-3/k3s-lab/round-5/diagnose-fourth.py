"""Fixed fourth-scene RO diagnosis. Raw archive/log bytes never leave memory."""
import base64
import collections
from datetime import datetime, timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tarfile
import urllib.parse
sys.path.insert(0, str(Path(__file__).resolve().parents[5] / 'scripts'))
import k3s_lab_init as init
import k3s_lab_recover as recovery
from runtime_lab_paths import trusted_directory

CID = '9a22e3c1817441fa2c4f50616e68a333d2a06c98641d430a05a810ea3f7cac50'
IMAGE = 'sha256:2504a55c791dba7ca00cadae8b11f937aea70ac9149243eb83e590d343bc44a3'
LABELS = {'owner':'codex-warden','project':'warden','session':'b5370b6ce57638aee676a14c3c272592','ttl':'2026-10-24T19:09:18Z'}
OUTER = '/home/postedism/Desktop/Warden/.cache/warden-lab/docker-' + LABELS['session']
CHILD = 'session-7ca9caee772671b1'
PREFIX = '/session/' + CHILD
OUTER_ID = (66307, 56143028, 1000)
CHILD_ID = (66307, 56143043, 0)
TAR_ID = (66307, 56143030, 1000)
TAR_SIZE = 496619520
CONTENT_LIMIT = 32000000

class Local(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect('/var/run/docker.sock')

def request(method, path, limit):
    connection = Local('localhost')
    try:
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError('response-bound')
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()

def archivepath(path):
    return '/containers/' + CID + '/archive?path=' + urllib.parse.quote(path, safe='')

def verify(outer, archive):
    status, _, body = request('GET', '/containers/' + CID + '/json', 262144)
    if status != 200:
        raise ValueError('inspect-status')
    data = json.loads(body); state = data['State']
    if not (data['Id'] == CID and data['Image'] == IMAGE and data['Config']['Labels'] == LABELS
            and state['Status'] == 'exited' and state['Pid'] == 0 and state['ExitCode'] == 2
            and not any(state[key] for key in ('Running','Paused','Restarting','OOMKilled','Dead'))
            and data['RestartCount'] == 0):
        raise ValueError('scene-drift')
    for info in (os.fstat(outer), os.stat(OUTER, follow_symlinks=False)):
        if not (stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_dev, info.st_ino, info.st_uid) == OUTER_ID):
            raise ValueError('outer-drift')
    info = os.stat(CHILD, dir_fd=outer, follow_symlinks=False)
    if not (stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_dev, info.st_ino, info.st_uid) == CHILD_ID):
        raise ValueError('child-drift')
    for info in (os.fstat(archive), os.stat('rootfs.tar', dir_fd=outer, follow_symlinks=False)):
        if not (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_size == TAR_SIZE
                and (info.st_dev, info.st_ino, info.st_uid) == TAR_ID):
            raise ValueError('tar-drift')
    if os.path.lexists('/sys/fs/cgroup/system.slice/docker-' + CID + '.scope'):
        raise ValueError('original-scope-remains')
    return dict(exact_stopped_identity=True, held_outer_identity=True, private_child_identity=True,
                held_tar_identity=True, scope_absent=True)

def head(path, name):
    status, headers, _ = request('HEAD', archivepath(path), 0)
    if status == 404:
        return {'status': 404}
    if status != 200:
        raise ValueError('head-status')
    value = json.loads(base64.b64decode(headers['X-Docker-Container-Path-Stat'], validate=True))
    if value['name'] != name or value.get('linkTarget'):
        raise ValueError('head-alias')
    if type(value['size']) is not int or not 0 <= value['size'] <= CONTENT_LIMIT:
        raise ValueError('head-size')
    if value['mode'] != 0o600:
        raise ValueError('unexpected-fixed-head-shape')
    return {'status': 200, 'bytes': value['size'], 'mode': value['mode']}

def read(path, name, remaining, expected):
    status, _, body = request('GET', archivepath(path), remaining + 65536)
    if status != 200 or expected['status'] != 200:
        raise ValueError('archive-status')
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:') as packed:
        members = packed.getmembers()
        if (len(members) != 1 or not members[0].isreg() or members[0].name != name
                or members[0].linkname or members[0].pax_headers or members[0].uid != 0
                or members[0].mode != 0o600 or members[0].size != expected['bytes']
                or not 0 <= members[0].size <= remaining):
            raise ValueError('archive-member')
        data = packed.extractfile(members[0]).read(remaining + 1)
        if len(data) != members[0].size:
            raise ValueError('archive-size')
    return data

STAMP=r'(?:time="\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)" )'
KSTAMP=r'\d{4} \d\d:\d\d:\d\d\.\d{6} +[1-9][0-9]* '
EXACT_ISSUES={
 'ca-watcher-emfile':('k3s', 'E'+KSTAMP+r'dynamic_cafile_content\.go:170\] "Failed to watch CA file, will retry later" err="error creating fsnotify watcher: too many open files"'),
 'cert-watcher-emfile':('k3s','E'+KSTAMP+r'dynamic_serving_content\.go:144\] "Failed to watch cert and key file, will retry later" err="error creating fsnotify watcher: too many open files"'),
 'cri-cni-watcher-emfile':('containerd',STAMP+r'level=warning msg="failed to load plugin" error="failed to create CRI service: failed to create cni conf monitor for default: failed to create fsnotify watcher: too many open files" id=io\.containerd\.grpc\.v1\.cri type=io\.containerd\.grpc\.v1'),
 'cri-service-unimplemented':('k3s',STAMP+r'level=info msg="Waiting for containerd startup: rpc error: code = Unimplemented desc = unknown service runtime\.v1\.RuntimeService"'),
 'flexvolume-missing-default':('k3s','W'+KSTAMP+r'probe\.go:275\] Flexvolume plugin directory at /usr/libexec/kubernetes/kubelet-plugins/volume/exec/ does not exist\. Recreating\.'),
 'flexvolume-ro-default':('k3s','E'+KSTAMP+r'plugins\.go:577\] "Error initializing dynamic plugin prober" err="error \(re-\)creating driver directory: mkdir /usr/libexec: read-only file system"'),
}

def classify(data, source=None):
    lines = data.decode('utf-8').splitlines()
    records = []; issues = collections.Counter()
    start = int(datetime(2026,10,24,18,9,45,tzinfo=timezone.utc).timestamp())
    for line in lines:
        if line == '--- k3s ---': source = 'k3s'; continue
        if line == '--- containerd ---': source = 'containerd'; continue
        matched = next((code for code, (expected, pattern) in EXACT_ISSUES.items()
                        if source == expected and re.fullmatch(pattern, line)), None)
        if matched:
            issues[matched] += 1
            records.append({'template_enum': matched, 'source': source, 'sha256': hashlib.sha256(line.encode()).hexdigest()})
            continue
        if not re.search(r'level=(warning|error|fatal)|[WEF]\d{4}\s', line):
            continue
        enum = 'rejected-unknown'
        # Matching old templates is classification only. The failed snapshot
        # has no actual Ready or namespace proof; these inputs are synthetic.
        for fd in range(3, 30):
            try:
                value = init.warning_lines(line, source=source, root=f'/proc/1/fd/{fd}/root',
                                           ready_window=(start, start + 240),
                                           verified_namespaces=frozenset({'default','kube-system'}))
                if value:
                    enum = value[0]['template'] if isinstance(value[0], dict) else 'safe-kernel-denial'
                break
            except ValueError:
                pass
        records.append({'template_enum': enum, 'source': source, 'sha256': hashlib.sha256(line.encode()).hexdigest()})
    return {'bytes': len(data), 'lines': len(lines), 'sha256': hashlib.sha256(data).hexdigest(),
            'exact_issue_counts': dict(issues),
            'template_counts': dict(collections.Counter(row['template_enum'] for row in records)),
            'records': records, 'context': 'synthetic-classification-only', 'ready_proven': False}

def main():
    if os.getuid() != 1000 or sys.argv[1:]:
        raise ValueError('fixed-operator-entrypoint')
    outer = trusted_directory(OUTER, 1000)
    archive = None
    try:
        archive = os.open('rootfs.tar', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=outer)
        result = {'before': verify(outer, archive)}
        heads = {name: head(PREFIX + '/' + name, name) for name in
                 ('root','state','io','containerd.toml','containerd.log','startup-private.log')}
        result['head'] = heads
        remaining = CONTENT_LIMIT; logs = {}
        for enum, path, name in (
            ('snapshot', PREFIX + '/startup-private.log', 'startup-private.log'),
            ('k3s', PREFIX + '/root/private.log', 'private.log'),
            ('containerd', PREFIX + '/root/agent/containerd/containerd.log', 'containerd.log')):
            observed = heads['startup-private.log'] if enum == 'snapshot' else head(path, name)
            if observed['status'] == 404:
                logs[enum] = {'status': 404}
                continue  # No alternative path or broader archive request.
            data = read(path, name, remaining, observed)
            remaining -= len(data)
            logs[enum] = classify(data, None if enum == 'snapshot' else enum)
        result['logs'] = logs
        result['remaining_content_budget'] = remaining
        if (str(recovery.OUTPUT) != OUTER or recovery.ORIGINAL != CID or recovery.IMAGE != IMAGE
                or recovery.CHILD != CHILD or recovery.CHILD_IDENTITY != CHILD_ID):
            raise ValueError('fixed-accounting-source-mismatch')
        result['budget'] = recovery.preflight(0, recovery.docker)  # Read-only; full 6GB held.
        result['after'] = verify(outer, archive)
        print(json.dumps(result, indent=2, sort_keys=True))
    finally:
        if archive is not None: os.close(archive)
        os.close(outer)

if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print(json.dumps({'diagnostic_error': type(error).__name__}))
        raise SystemExit(2)
