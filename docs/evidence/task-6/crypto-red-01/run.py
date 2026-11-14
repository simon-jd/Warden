#!/usr/bin/env python3
"""Prospective evidence for the single fixed identity-unit RED command."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).absolute().parents[4]
OUT = Path(__file__).absolute().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from runtime_lab_docker import docker, scoped_ids, outstanding_bytes, owned_inspect
from runtime_lab_paths import trusted_directory

os.umask(0o077)
if sys.argv[1:] or os.getuid() != 1000 or os.geteuid() != 1000:
    raise RuntimeError('fixed ordinary-UID evidence entrypoint only')
expected = {'vm/overcommit_memory':'1', 'vm/panic_on_oom':'0', 'kernel/panic':'10',
            'kernel/panic_on_oops':'1', 'kernel/keys/root_maxkeys':'1000000',
            'kernel/keys/root_maxbytes':'25000000'}
def sysctls():
    return {name:(Path('/proc/sys') / name).read_text().strip() for name in expected}
names = set(subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0'))
names.update(str(p.relative_to(ROOT)) for p in (ROOT / 'controlplane/internal/authn').glob('*.go'))
names = sorted(n for n in names if n and not n.startswith(('.superpowers/','docs/evidence/'))
               and (n.endswith(('.go','.py','.sh','.sql','.tf','.toml','.yaml','.yml'))
                    or Path(n).name in ('go.mod','go.sum','Dockerfile','Makefile')))
def source():
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}
def save(name, value):
    with (OUT/name).open('x') as output:
        output.write(json.dumps(value,sort_keys=True,indent=2)+'\n')
pre = source()
save('pre-source.json',pre)
for name in names:
    target = OUT/'red-source'/name
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with target.open('xb') as output:
        output.write((ROOT/name).read_bytes())
before = sysctls()
save('pre-sysctls.json',before)
if before != expected:
    raise RuntimeError('protected sysctl baseline changed')
command = ['python3','-B',str(ROOT/'scripts/firecracker_code.py'),'identity-unit']
start = time.monotonic()
receipt = {'command':command,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
           'layer':'local cryptographic/JWKS unit only; no Entra/SQL/SCIM'}
save('intent.json',receipt)
try:
    with (OUT/'output.txt').open('x') as output:
        result = subprocess.run(command,cwd=ROOT,stdout=output,stderr=subprocess.STDOUT)
    receipt['exit_code'] = result.returncode
finally:
    receipt['duration_seconds'] = time.monotonic()-start
    post = source(); save('post-source.json',post)
    after = sysctls(); save('post-sysctls.json',after)
    receipt['source_unchanged'] = pre == post
    receipt['protected_sysctls_unchanged'] = before == after == expected
    receipt['source_files'] = len(pre)
    save('receipt.json',receipt)

# The unchanged runner has released its project lock after owned-ID cleanup.
# Acquire that same lock for the ordinary final account/guard observation.
lab = trusted_directory(str(ROOT/'.cache/warden-lab'),1000)
lock = os.open('docker.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=lab)
os.close(lab)
try:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    containers = scoped_ids('container',{'project':'warden'},docker)
    if containers:
        raise RuntimeError('owned container remains; postguard blocked')
    images = scoped_ids('image',{'project':'warden'},docker)
    charge = 0
    for identity in set(images):
        info = owned_inspect('image',identity,{'project':'warden'},docker)
        charge += 2*info['Size']+64000000
    outstanding = outstanding_bytes(ROOT/'.cache/warden-lab')
    if outstanding < 5000000000:
        raise RuntimeError('retained Q charge unexpectedly missing')
    guard = ['python3','-B',str(ROOT/'scripts/azure_guard.py'),'preflight',
             '--additional-bytes',str(512000000+charge+outstanding),
             '--service-memory-bytes','3000000000','--download-bytes','0']
    checked = subprocess.run(guard,cwd=ROOT,capture_output=True,text=True)
    save('postguard.json',{'command':guard,'exit_code':checked.returncode,'stdout':checked.stdout,
                           'stderr':checked.stderr,'owned_containers':containers,'owned_images':images,
                           'owned_image_charge':charge,'outstanding_bytes':outstanding})
    if checked.returncode or not receipt['source_unchanged'] or not receipt['protected_sysctls_unchanged']:
        raise RuntimeError('postflight checks failed')
finally:
    os.close(lock)
print(json.dumps(receipt,sort_keys=True),flush=True)
