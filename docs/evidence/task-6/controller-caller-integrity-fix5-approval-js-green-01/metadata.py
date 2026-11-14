#!/usr/bin/env python3
# BEGIN DEADLINE PREFIX
import time
wall_start = time.monotonic()
wall_end = wall_start + 45
import os
import signal
def expired(signum=None, frame=None):
    os._exit(124)
def remaining():
    value = wall_end - time.monotonic()
    if value <= 0:
        expired()
    return value
def finish_timer():
    remaining()
    signal.setitimer(signal.ITIMER_REAL, 0)
signal.signal(signal.SIGALRM, expired)
signal.setitimer(signal.ITIMER_REAL, remaining())
# END DEADLINE PREFIX
import hashlib, json, resource, sys
from pathlib import Path
ROOT=Path(__file__).absolute().parents[4]
OUT=Path(__file__).absolute().parent
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CPU,(30,30))
resource.setrlimit(resource.RLIMIT_AS,(536870912,536870912))
resource.setrlimit(resource.RLIMIT_FSIZE,(33554432,33554432))
phase=sys.argv[1]
if phase not in ('pre','post') or len(sys.argv)!=3: raise ValueError('fixed metadata phase')
baseline=json.loads((ROOT/'docs/evidence/task-6/controller-caller-integrity-fix5-baseline.json').read_text())
kind='material' if '-material-' in OUT.name else 'approval'
mode='red' if '-red-' in OUT.name else 'green'
def save(name,value):
 with (OUT/name).open('x') as f: f.write(json.dumps(value,sort_keys=True,indent=2)+'\n')
names=sorted([*baseline['sources'],*baseline['controller_sources']])
current={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names}
save(phase+'-source.json',{n:current[n] for n in baseline['sources']})
save(phase+'-controller.json',{n:current[n] for n in baseline['controller_sources']})
files={'candidate':('controller-four-get-material-source-caller-candidate.js' if kind=='material' else 'controller-approval-writer-caller-candidate.js') if mode=='red' else 'controller-caller-integrity-fix5-'+kind+'-candidate.js','fixture':'controller-caller-integrity-fix5-'+kind+'-fixture.js'}
payload={k:(ROOT/'docs/evidence/task-6'/v).read_text() for k,v in files.items()}
code={k:{'path':'docs/evidence/task-6/'+files[k],'bytes':len(v.encode()),'sha256':hashlib.sha256(v.encode()).hexdigest()} for k,v in payload.items()}
save(phase+'-code.json',code)
if phase=='pre':
 save('baseline.json',{**baseline,'source_commit_at_launch':sys.argv[2]})
 for n,h in current.items():
  if {**baseline['sources'],**baseline['controller_sources']}[n]!=h:
   target=OUT/'changed-source'/n; target.parent.mkdir(parents=True,exist_ok=True)
   with target.open('xb') as f: f.write((ROOT/n).read_bytes())
 for k,v in payload.items():
  with (OUT/(k+'.js')).open('x') as f: f.write(v)
else:
 assert json.loads((OUT/'pre-source.json').read_text())==json.loads((OUT/'post-source.json').read_text())
 assert json.loads((OUT/'pre-controller.json').read_text())==json.loads((OUT/'post-controller.json').read_text())
 assert json.loads((OUT/'pre-code.json').read_text())==code
receipt={'phase':phase,'source_files':150,'controller_files':2,'code':code,'elapsed_seconds':time.monotonic()-wall_start,'limits':{'wall_seconds':45,'cpu_seconds':30,'address_bytes':536870912,'file_bytes':33554432},'timing_scope':'metadata recorder only; JS isolate and interpreter startup not measured','equal':True if phase=='post' else None}
save(phase+'-receipt.json',receipt)
print(json.dumps({'receipt':receipt,**({**payload,'mode':mode} if phase=='pre' else {})},sort_keys=True),flush=True)
finish_timer()
