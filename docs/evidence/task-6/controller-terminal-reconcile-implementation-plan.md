# Terminal reconciliation implementation / exact-root-call PLAN

2026-10-25 R1–R4 PLAN ONLY; b2b3482/ce10703 frozen/root Git. No execution; Task6/fix3of5/Q5 unchanged.

## Five existing files

control.py: after import time sample U=monotonic_ns(),B=clock_gettime_ns(CLOCK_BOOTTIME),A=monotonic_ns(); ENTRY_NS=U. reconcile MODE/six modes, remaining alarm30/CPU5/AS128MiB/FSIZE1MiB. Same loader→Controller→invoker.reconcile(control,mode,(U,B,A)); no adopt/claim/load_modules/hard raises.

observe.py: validators/terminal_gate; OwnClock/birth shortens ENTRY+30, both-clock final checks, separate PID/birth. Passive invoker adds writer/historical validate_target parameter, no adoption. Existing testcontrol/docs fixture only. Names150/other147/product8/capture/maintenance/None pins/shared unchanged.

preparation gates preprobe success/age<=60s before private. launch adds/rechecks preprobe_terminal:Proof; launch_binding no new age. outer_gate gates before imports/private/guard; pure validator avoids recursion; run_probe preserves order. validate_target/history_deadline enforce stamps<=U. Probe incomplete-or-unknown-retain refuses; complete postflight incomplete/1=failure.

## Strict bindings

Raw keys exactly JS object below. Six MODE-root-tool.json<=65536B incl LF, UID/GID1000 regular/nlink1/0600or0644. Proof={sha256:hex64,bytes:positive int,metadata:10 ints},bool!=int. Commit hex40; machine_id/boot_id match admission. Events1..32 exact seq/tool/request/response, consecutive seq,last terminal.

Exec exact below; sandbox_permissions/justification/prefix_rule absent, adding requires review. Poll session_id positive int,chars empty,yield45000,max2000. Response requires output:str,wall_time_seconds:finite nonnegative number; optional chunk_id:str,original_token_count:nonnegative int,exit_code:int,session_id:positive int. Extra/null/bool numeric refuses. Running=session/no exit; final=int exit/no session; echo needs provider review. No omitted polls/relaunch/input/truncation; exit0/1 matches supervisor/target.

Marker exact keys: version,mode,stage,state,source_commit,source_manifest_sha256,admission,invoker,envelope,claim,root_tool,supervisor,result,clock_identity,timing,tool_exit_code,child_exit_code,Q_released. timing exactly start_lower_ns,terminal_upper_ns,entry_boot_ns,entry_after_ns,verified_sample,metadata_end_ns. State known-success/known-failure; Q=false; child null capture/probes, exact int continue. Six MODE-terminal.json<=16384B; raw+markers<=480KiB. result=outer full Proof(operation)/probe full Proof. Existing strict outer unchanged, start=M0 lower bound/end=U upper bound.

Require0<=U-M0<=T*NS,0<=B-B0<=T*NS,T90/600/180;0<=A-U<=100ms. Common [B-A,B-U]/envelope/supervisor/new brackets, same host/boot/namespace/order; historic stamps<=U. Metadata30 never extends operation. Early namespace=fixed-entry/no-setns assumption; no synthetic clock/physical-stop claim.

Validate full supervisor/outcome/target_proof/log<=1MiB(including empty)/source/known nested terminal. Forced/unknown/overflow/late EOF refuses. Recheck inputs around outer then LAST marker; orphan/partial/final failure unusable, no retry. Consumers reconstruct chain; root awaits reconcile terminal.

## Concrete root workflow, NOT executed

First cell once, poll only pending<=31 times/45s; every return stored. Uncertainty retains transcript/stops. MODE is frozen literal.

```js
const mode='capture-preprobe';
const req={cmd:'exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py supervise '+mode,workdir:'/home/postedism/Desktop/Warden',shell:'/bin/bash',login:false,tty:false,yield_time_ms:1000,max_output_tokens:2000};
store('terminal-mode',mode);store('terminal-events',[]);
const r=await tools.exec_command(req);
store('terminal-events',[{seq:0,tool:'exec_command',request:req,response:r}]);
// Separate poll cell:
const es=load('terminal-events'),first=es[0].response,last=es[es.length-1].response;
if(es.length>=32||!Number.isInteger(first.session_id)||last.session_id!==first.session_id||'exit_code' in last)throw Error('stop');
const poll={session_id:first.session_id,chars:'',yield_time_ms:45000,max_output_tokens:2000};
const next=await tools.write_stdin(poll);
es.push({seq:es.length,tool:'write_stdin',request:poll,response:next});
store('terminal-events',es);
```

After terminal, proof-reader request same shell/cwd/login/tty,yield1000,max4000; cmd=`exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'`+LF+below+LF+`PY`. M frozen; separate transcript/poll session, exit0/full JSON required. Delay counts until U; no product entry/loader.

```python
import os,stat,json,hashlib,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):resource.setrlimit(k,(n,n))
M='capture-preprobe';S=M.split('-')[0]
W='/home/postedism/Desktop/Warden';D='docs/evidence/task-6/'
P='controller-cache-continuation-v1-20261025-'
I='controller-cache-continuation-outer-invoker-20261025.py'
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
held=[]
def read(name):
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for part in (W+'/'+D+name).split('/')[1:-1]:
  g=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=g
  s=os.fstat(f);assert s.st_uid in (0,1000) and not s.st_mode&0o022
 h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=f);s=os.fstat(h)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and 0<s.st_size<=65536
 b=b''
 while len(b)<=65536:
  c=os.read(h,65537-len(b))
  if not c:break
  b+=c
 assert len(b)==s.st_size
 held.append((f,h,name,meta(s)))
 return b,{'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':meta(s)}
out={}
for key,name in [('admission',P+S+'-admission.json'),('invoker',I),('envelope',P+M+'-deadline.json'),('claim',P+M+'-deadline-accepted.json'),('supervisor',P+M+'-supervisor.json')]:
 b,out[key]=read(name)
 if key=='envelope':
  v=json.loads(b)
  for k in ('source_commit','source_manifest_sha256','clock_identity'):out[k]=v[k]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
try:os.stat(P+M+'-root-tool.json',dir_fd=held[0][0],follow_symlinks=False)
except FileNotFoundError:pass
else:raise ValueError('raw exists')
print(json.dumps(out,separators=(',',':')),flush=True)
```

Root stores JSON.parse(readerEvents.map(e=>e.response.output).join('')) as terminal-proofs only after reader exit0/no truncation. Reconciler independently validates; events must pass above:

```js
const mode=load('terminal-mode'),events=load('terminal-events'),p=load('terminal-proofs');
const raw={version:1,origin:'root-controller-actual-tool',mode,stage:mode.split('-')[0],...p,events,terminal_event_index:events.length-1,root_assertion:'awaited-terminal-before-record-before-reconcile'};
const body=JSON.stringify(raw)+'\n';let size=0;
for(const c of body){const n=c.codePointAt(0);size+=n<128?1:n<2048?2:n<65536?3:4;}
if(size>65536)throw Error('stop');
const path='/home/postedism/Desktop/Warden/docs/evidence/task-6/controller-cache-continuation-v1-20261025-'+mode+'-root-tool.json';
text(await tools.apply_patch('*** Begin Patch\n*** Add File: '+path+'\n'+body.split('\n').slice(0,-1).map(x=>'+'+x).join('\n')+'\n*** End Patch'));
```

Absence+AddFile under quiescence!=O_EXCL; uncertain write stops/no retry. Next exec changes supervise→reconcile; separate chain/exit0 required before separately authorized next action. Exit1/124/unknown stops despite marker. No autoauthority; wall_time!=lifetime,U includes reader/write delay; no recursive sampler.

## Later tests / gates

RED/GREEN/one frozen cover: actual validators/writers/gates, chains/optional/polls/types/size/replay;90/600/180 edges/suspend/namespace/stamps>U; child/failure/unknown/EOF; replacements/orphan/stale/forbidden-private. Generated fixtures only;150+2 maps/changed bodies,whole45s,preserved failures,separate commits/report/index/plan append.

NEEDS_CONTEXT source handoff. Caller/binary/provider review before actual. Capture→continue history/material30 OUTSIDE. Mocks prove no root causality/quiescence/physical stop/headroom.
