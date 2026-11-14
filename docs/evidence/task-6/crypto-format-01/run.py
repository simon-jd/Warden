#!/usr/bin/env python3
"""One controller-authorized fixed gofmt edit, not a Go build or test."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).absolute().parents[4]
OUT = Path(__file__).absolute().parent
sys.path.insert(0,str(ROOT/'scripts'))
from runtime_lab_paths import trusted_directory
os.umask(0o077)
if sys.argv[1:] or os.getuid()!=1000 or os.geteuid()!=1000:
    raise RuntimeError('fixed ordinary-UID format operation only')
binary = ROOT/'.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin/gofmt'
files = [ROOT/'controlplane/internal/authn'/name for name in ('verifier.go','jwks.go','verifier_test.go')]
def checked(path, executable=False):
    parent=trusted_directory(str(path.parent),1000)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=1000 or info.st_nlink!=1
                or info.st_mode & 0o6022 or (executable and not info.st_mode & stat.S_IXUSR)):
            raise RuntimeError('unsafe fixed formatter source/material')
        digest=hashlib.file_digest(os.fdopen(os.dup(fd),'rb'),'sha256').hexdigest()
        return {'sha256':digest,'uid':info.st_uid,'mode':oct(stat.S_IMODE(info.st_mode)),
                'dev':info.st_dev,'ino':info.st_ino,'nlink':info.st_nlink}
    finally:
        os.close(fd)
material=checked(binary,True)
pre={str(path.relative_to(ROOT)):checked(path) for path in files}
command=[str(binary),'-w',*[str(path) for path in files]]
with (OUT/'intent.json').open('x') as stream:
    json.dump({'command':command,'binary':material,'source_before':pre,
               'env':{'GOMAXPROCS':'2','GOMEMLIMIT':'256MiB'},'timeout_seconds':10},stream,indent=2)
start=time.monotonic()
result=subprocess.run(command,cwd=ROOT,env={'PATH':'/usr/bin:/bin','GOMAXPROCS':'2','GOMEMLIMIT':'256MiB'},
                      timeout=10,capture_output=True,text=True)
post={str(path.relative_to(ROOT)):checked(path) for path in files}
receipt={'exit_code':result.returncode,'duration_seconds':time.monotonic()-start,'stdout':result.stdout,
         'stderr':result.stderr,'source_after':post,'source_changed_as_expected':pre!=post,
         'classification':'authorized reversible gofmt source edit; not test evidence'}
with (OUT/'receipt.json').open('x') as stream:json.dump(receipt,stream,indent=2)
print(json.dumps(receipt),flush=True)
