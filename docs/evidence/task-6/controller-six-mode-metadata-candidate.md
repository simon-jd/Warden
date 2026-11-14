# Six-mode fixed raw metadata caller - separately authorized scope completion

Complete superseding cell protocol below. Freeze MODE in the common prelude and M in the unchanged collector to the SAME one reviewed literal before use. The six closed modes have exactly one fresh raw mutation target each: capture-preprobe(180s), capture(90s), capture-postflight(180s), continue-preprobe(180s), continue(600s), continue-postflight(180s), under the existing fixed prefix. Each root-tool path is separately proved absent/owned before its original AddFile. No old/unknown file, material attempt or supplemental transcript is finalized.

The new helper binds the original envelope Proof from original collector text, exact intended raw bytes, original dual-clock deadline and held FDs. Local5/CPU2/AS128MiB/FSIZE1MiB does not extend the operation; native yield10000 is only scheduling. No observer/reader/authority/umask change. Unsupported original metadata values remain outer-only; no lossy failure record or new authority is invented. Root must retain outer state including pending/throw/session evidence. Actual gates and unknown prior Task16 descendants/quiescence remain unresolved. No automatic successor or actual admission follows this source artifact. Original5/5 and material1/1 remain consumed. This scope has only one affected cover and one independent review; any failure/unknown stops without repair.

## Exact common prelude and separately admitted cells

The following is proposed caller text, **not executed**. Actual bootstrap/binary/parent/UID1000 trust, root quiescence, source/admission identity, fixed clocks, resources, writer/scene/Q and eligibility remain separate gates. `yield_time_ms` and `wall_time_seconds` are not deadlines/lifetime. No provider FD or signature is invented. Root is the external authority for complete awaited tool history; same-UID hostile writers are excluded by continuous quiescence, not proven by metadata.

Use functions.exec with the common prelude below pasted into each relevant cell. MODE is frozen to one reviewed literal per operation; its five siblings are capture, capture-postflight, continue-preprobe, continue, continue-postflight. No arbitrary command/argument/environment. Store keys retain each phase across cells; no automatic relaunch/cancellation. Each poll is an individual empty45s wait, at most31 polls/32 events per chain. Preserve every request/return immediately, including unsuccessful validation. Transport uncertainty retains available memory/transcript and stops without valid raw authority. No truncation/overflow may be trimmed into success.

```javascript
const MODE='capture-preprobe';
const W='/home/postedism/Desktop/Warden';
const P='controller-cache-continuation-v1-20261025-';
const PUB=W+'/docs/evidence/task-6/';
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
const key=phase=>P+MODE+'-'+phase;
function bytes(s){let n=0;for(const c of s){const v=c.codePointAt(0);n+=v<128?1:v<2048?2:v<65536?3:4;}return n;}
function request(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,tty:false,
 yield_time_ms:1000,max_output_tokens:max,sandbox_permissions:'require_escalated',justification:WHY};}
function operation(action){if(action==='reconcile')metadataTerminal();return request('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py '+action+' '+MODE);}
function response(r,max){
 const allowed=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
 if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!allowed.includes(k))||
 typeof r.output!=='string'||bytes(r.output)>65536||typeof r.wall_time_seconds!=='number'||
 !Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('unknown response');
 if('chunk_id'in r&&(typeof r.chunk_id!=='string'||r.chunk_id.length<1||r.chunk_id.length>128))throw Error('chunk');
 if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||r.original_token_count<0||r.original_token_count>max))throw Error('truncation');
 if('exit_code'in r){if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('unknown terminal');return 'terminal';}
 if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('unknown session');return 'running';
}
async function first(phase,req){
 if(load(key(phase))!==undefined)throw Error('existing no retry');
 const s={request:req,events:[],state:'awaiting'};store(key(phase),s);
 try{const r=await tools.exec_command(req);s.events.push({seq:0,tool:'exec_command',request:req,response:r});
 store(key(phase),s);s.state=response(r,req.max_output_tokens);store(key(phase),s);}
 catch(e){s.state='unknown';store(key(phase),s);throw e;}
}
async function poll(phase){
 const s=load(key(phase));if(!s||s.state!=='running'||s.events.length>=32)throw Error('stop');
 const id=s.events[0].response.session_id,last=s.events[s.events.length-1].response;
 if(last.session_id!==id||'exit_code'in last)throw Error('changed session');
 const req={session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000};
 try{const r=await tools.write_stdin(req);s.events.push({seq:s.events.length,tool:'write_stdin',request:req,response:r});
 store(key(phase),s);s.state=response(r,2000);if(s.state==='running'&&r.session_id!==id)throw Error('changed session');store(key(phase),s);}
 catch(e){s.state='unknown';store(key(phase),s);throw e;}
}
function terminal(phase,zero=false){const s=load(key(phase));if(!s||s.state!=='terminal'||
 (zero&&s.events[s.events.length-1].response.exit_code!==0))throw Error('terminal required');return s;}
async function add(suffix,body){
 if(!body.endsWith('\n')||bytes(body)>65536)throw Error('record overflow');
 const result=await tools.apply_patch('*** Begin Patch\n*** Add File: '+PUB+P+MODE+suffix+'\n'+
 body.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch');
 store(key('patch'+suffix),result);text(result);
}
// Fixed metadata step only; original supervise/reader/raw/reconcile schemas stay unchanged.
const METADATA_SECONDS=Object.freeze({"capture-preprobe":180,"capture":90,"capture-postflight":180,"continue-preprobe":180,"continue":600,"continue-postflight":180});
if(!Object.hasOwn(METADATA_SECONDS,MODE))throw Error('fixed metadata mode');
const metadataBody=String.raw`import time
M0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()
import os,sys,signal,resource
def need(ok):
 if not ok:raise ValueError('six-mode metadata refusal')
need(0<=A0-M0<=100000000)
me=M0+5000000000;be=B0+5000000000;lo=B0-A0;hi=B0-M0;fm=A0;fb=B0
def check():
 global lo,hi,fm,fb
 u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
 need(0<=a-u<=100000000 and fm<=u<=a<me and fb<=b<be)
 lo=max(lo,b-a);hi=min(hi,b-u);need(lo<=hi);fm=a;fb=b
 return a,b
def arm():
 a,b=check();signal.setitimer(signal.ITIMER_REAL,min(me-a,be-b)/1000000000)
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));arm()
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):
 soft,hard=resource.getrlimit(k);need(hard==resource.RLIM_INFINITY or hard>=n);resource.setrlimit(k,(n,n))
import json,hashlib,stat
def pairs(items):
 value={}
 for k,v in items:need(k not in value);value[k]=v
 return value
def bad(_):raise ValueError('noninteger JSON')
def parse(s):return json.loads(s,object_pairs_hook=pairs,parse_float=bad,parse_constant=bad)
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
fds=[];dirs=[];records=[]
def keep(fd):fds.append(fd);return fd
def parents():
 check()
 for parent,name,fd,before in dirs:
  now=meta(os.fstat(fd));need(now==before)
  if parent is not None:need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==now)
 check()
def same(record):
 check();parents();fd,name,data,m=record
 need(meta(os.fstat(fd))==m==meta(os.stat(name,dir_fd=public,follow_symlinks=False)))
 need(os.pread(fd,65537,0)==data)
 need(meta(os.fstat(fd))==m==meta(os.stat(name,dir_fd=public,follow_symlinks=False)));check()
def all_same():
 for record in records:same(record)
def read(name,cap,modes,want=None):
 check();parents()
 fd=keep(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=public));s=os.fstat(fd)
 need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_dev==os.fstat(public).st_dev and stat.S_IMODE(s.st_mode) in modes and 0<s.st_size<=cap)
 data=os.pread(fd,cap+1,0);need(len(data)==s.st_size and (want is None or data==want))
 record=[fd,name,data,meta(s)];same(record);records.append(record);return record
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and len(sys.argv)==2)
 value=parse(sys.argv[1]);need(type(value) is dict and set(value)=={'collector','raw'} and all(type(v) is str for v in value.values()))
 intended=value['raw'].encode();need(0<len(intended)<=65536 and intended.endswith(b'\n'))
 collected=parse(value['collector']);expected=collected['envelope']
 need(type(expected) is dict and set(expected)=={'bytes','metadata','sha256'} and type(expected['bytes']) is int and type(expected['metadata']) is list and len(expected['metadata'])==10 and all(type(x) is int for x in expected['metadata']))
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 public=keep(os.open('/',flags));s=os.fstat(public);need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((None,None,public,meta(s)))
 for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)
  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))
 P='controller-cache-continuation-v1-20261025-';M='${MODE}'
 SECONDS={"capture-preprobe":180,"capture":90,"capture-postflight":180,"continue-preprobe":180,"continue":600,"continue-postflight":180}
 need(M in SECONDS);T=SECONDS[M]
 envelope=read(P+M+'-deadline.json',4096,(0o600,0o644))
 need(expected=={'bytes':len(envelope[2]),'metadata':envelope[3],'sha256':hashlib.sha256(envelope[2]).hexdigest()})
 received=parse(envelope[2]);need(received['mode']==M and received['stage']==M.split('-')[0] and type(received['wall_seconds']) is int and received['wall_seconds']==T)
 need(all(received[k]==collected[k] for k in ('source_commit','source_manifest_sha256','clock_identity')))
 timing=received['timing'];need(type(timing) is dict and set(timing)=={'sample','budget_start_monotonic_lower_ns','outer_entry_monotonic_ns'})
 first=timing['sample'];names=('pid','hz','birth_ticks','birth_boot_lower_ns','monotonic_before_ns','boottime_ns','monotonic_after_ns')
 need(type(first) is dict and set(first)==set(names)|{'namespace'})
 values=[timing['budget_start_monotonic_lower_ns'],timing['outer_entry_monotonic_ns']]+[first[k] for k in names]
 need(all(type(x) is int and 0<=x<10**18 for x in values))
 need(first['pid']>0 and first['hz']==100 and first['birth_ticks']>0 and first['birth_boot_lower_ns']==first['birth_ticks']*1000000000//100-1000000000//100)
 need(type(first['namespace']) is list and len(first['namespace'])==2 and all(type(x) is int and x>=0 for x in first['namespace']))
 start=first['birth_boot_lower_ns']-(first['boottime_ns']-first['monotonic_before_ns'])
 need(start==timing['budget_start_monotonic_lower_ns'] and 0<=start<=timing['outer_entry_monotonic_ns']<=first['monotonic_after_ns'])
 need(0<=first['monotonic_before_ns']<=first['monotonic_after_ns']<=M0 and first['monotonic_after_ns']-first['monotonic_before_ns']<=100000000)
 need(first['monotonic_before_ns']<=first['boottime_ns']<=B0 and first['birth_boot_lower_ns']<=first['boottime_ns'])
 lo=max(lo,first['boottime_ns']-first['monotonic_after_ns']);hi=min(hi,first['boottime_ns']-first['monotonic_before_ns']);need(lo<=hi)
 next_me=min(me,start+T*1000000000);next_be=min(be,first['birth_boot_lower_ns']+T*1000000000)
 a,b=check();need(a<next_me and b<next_be)
 me=next_me;be=next_be;arm()
 target=read(P+M+'-root-tool.json',65536,(0o600,0o644,0o664),intended);all_same()
 for record in (target,):
  all_same();check();before=record[3];os.fchmod(record[0],0o600);check();after=meta(os.fstat(record[0]))
  need(after[4]==stat.S_IFREG|0o600 and all(after[i]==before[i] for i in (0,1,2,3,5,6,7,9)))
  record[3]=after;os.fsync(record[0]);check();all_same()
 all_same();sys.stdout.write('{"state":"six-mode-metadata-finalized","authority":false}\n');sys.stdout.flush();all_same()
finally:
 for fd in reversed(fds):check();os.close(fd);check()
check()
`;
function exactJSON(value){
 const seen=new Set();
 function check(v){
  if(v===null||typeof v==='string'||typeof v==='boolean')return;
  if(typeof v==='number'){
   if(!Number.isFinite(v)||Object.is(v,-0))throw Error('unrepresentable number');return;
  }
  if(typeof v!=='object'||seen.has(v))throw Error('unserializable');
  const array=Array.isArray(v),proto=Object.getPrototypeOf(v);
  if(proto!==(array?Array.prototype:Object.prototype))throw Error('nonplain');
  for(let p=v;p!==null;p=Object.getPrototypeOf(p))
   if(Object.getOwnPropertyDescriptor(p,'toJSON'))throw Error('serialization hook');
  seen.add(v);
  const keys=Reflect.ownKeys(v);
  if(array){
   const n=Object.getOwnPropertyDescriptor(v,'length').value;
   if(keys.length!==n+1)throw Error('array fields');
   for(let i=0;i<n;i++){
    const d=Object.getOwnPropertyDescriptor(v,String(i));
    if(!d||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('array data');
    check(d.value);
   }
  }else{
   for(const k of keys){
    const d=Object.getOwnPropertyDescriptor(v,k);
    if(typeof k!=='string'||!Object.hasOwn(d,'value')||!d.enumerable)throw Error('object data');
    check(d.value);
   }
  }
  seen.delete(v);
 }
 check(value);return JSON.stringify(value);
}

function shellQuote(s){return "'"+s.replaceAll("'","'\\''")+"'";}
function metadataTerminal(){
 const s=load(key('metadata'));exactJSON(s);
 if(s.state!=='terminal'||s.events.length!==1||s.events[0].response.exit_code!==0||
    s.events[0].response.output!=='{"state":"six-mode-metadata-finalized","authority":false}\n')throw Error('metadata terminal required');
}
async function finalizeMetadata(){
 if(load(key('metadata'))!==undefined)throw Error('metadata consumed');
 const s={state:'preparing',events:[]};store(key('metadata'),s);
 try{
  const patch=load(key('patch-root-tool.json'));exactJSON(patch);
  if(patch===null||typeof patch!=='object'||Array.isArray(patch)||Object.getPrototypeOf(patch)!==Object.prototype||Reflect.ownKeys(patch).length!==0)throw Error('known raw patch required');
  const reader=terminal('reader',true),collector=reader.events.map(e=>e.response.output).join(''),raw=load(key('raw-body'));
  if(typeof raw!=='string'||!raw.endsWith('\n')||bytes(raw)>65536||bytes(collector)>16384)throw Error('metadata inputs');
  const data=exactJSON({collector,raw});
  const cmd="exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B - "+shellQuote(data)+" <<'PY'\n"+metadataBody+"PY";
  if(bytes(cmd)>65536)throw Error('metadata command bound');
  const req={...request(cmd),yield_time_ms:10000},e={seq:0,tool:'exec_command',request:req};
  s.request=req;s.events.push(e);s.state='awaiting';store(key('metadata'),s);
  let r;
  try{r=await tools.exec_command(req);}
  catch(error){e.thrown=error;store(key('metadata'),s);throw error;}
  e.response=r;store(key('metadata'),s);exactJSON(r);
  if(response(r,req.max_output_tokens)!=='terminal'||r.exit_code!==0||r.output!=='{"state":"six-mode-metadata-finalized","authority":false}\n')throw Error('metadata unknown');
  s.state='terminal';store(key('metadata'),s);
  text({state:'metadata-finalized',authority:false,Q_released:false});
 }catch(error){s.state='unknown';store(key('metadata'),s);throw error;}
}

```

Cell1: `await first('supervise',operation('supervise'));`. Later cells only if its stored state is running: `await poll('supervise');`. Immediate terminal has one event; running chain must end in integer0/1 with no session echo. Unknown/124/forced/ambiguous exits stop. The exact request has require_escalated/WHY and no prefix_rule; ordinaryUID1000 must still be verified independently. Approval rejection, if any, must be preserved explicitly rather than replaced by another profile.

After known supervise terminal, use the fixed five-public-record collector below. Its body is assigned to `readerBody` as an exact literal in a separate root cell (including the frozen MODE literal). Then `await first('reader',request("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000));`. Reader polls use the common exact45s/2000 shape and their own session/transcript. Reader's alarm5 after minimal imports/CPU2/AS128MiB/FSIZE1MiB is metadata containment, not a whole-startup/physical5s guarantee; every delay still counts before U.

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
for k,n in [('admission',P+S+'-admission.json'),('invoker',I),('envelope',P+M+'-deadline.json'),('claim',P+M+'-deadline-accepted.json'),('supervisor',P+M+'-supervisor.json')]:
 b,out[k]=read(n)
 if k=='envelope':
  v=json.loads(b)
  for field in ('source_commit','source_manifest_sha256','clock_identity'):out[field]=v[field]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
for suffix in ('-root-tool.json','-root-proof-reader-tool.json','-root-reconcile-tool.json'):
 try:os.stat(P+M+suffix,dir_fd=held[0][0],follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('existing root transcript')
print(json.dumps(out,separators=(',',':')),flush=True)
```

This collector reads exactly five public bodies, holds their FDs and rechecks metadata; the added absence checks read no sixth body. It is caller text, not an unchecked project import, product action or second loader. The reconciler independently re-reads/validates all proofs/source bindings. Root maintains fresh absence/quiescence through each structured AddFile. AddFile is workflow exclusivity, not O_EXCL. Any unexpected existing/partial file, uncertain patch result, overflow or provider error stops without overwrite/delete/retry. Root inspects the actual apply_patch result before issuing the next cell; no invented success field or automatic action follows.

**Lossless proof handling:** metadata contains nanosecond integers above JS safe precision. Do not JSON.parse→JSON.stringify proof numbers or reconstruct clocks from a JS preview. Retain collector output text verbatim; parse only to reject malformed structure, and splice its exact object members into the raw record. Tool events' output strings remain exact strings. API session/exit/token fields require Number.isSafeInteger; generated seq/index are bounded0..31 and therefore safe. Python reconciliation performs the strict integer/proof comparison. No extra cover was run for this caller-text correction.

```javascript
const reader=terminal('reader',true), sup=terminal('supervise');
const proofText=reader.events.map(e=>e.response.output).join('');
if(bytes(proofText)>16384||!proofText.startsWith('{')||!proofText.endsWith('}\n'))throw Error('collector output');
const preview=JSON.parse(proofText); // structural view only; never serialize its numeric proofs
const fields=['admission','invoker','envelope','claim','supervisor','source_commit','source_manifest_sha256','clock_identity'];
if(Object.keys(preview).length!==8||fields.some(k=>!(k in preview)))throw Error('collector keys');
const head=JSON.stringify({version:1,origin:'root-controller-actual-tool',mode:MODE,stage:MODE.split('-')[0]});
const tail=JSON.stringify({events:sup.events,terminal_event_index:sup.events.length-1,
 root_assertion:'awaited-terminal-before-record-before-reconcile'});
const body=head.slice(0,-1)+','+proofText.slice(1,-2)+','+tail.slice(1)+'\n';
store(key('raw-body'),body);
const supplemental={version:1,producer:'root-controller-actual-tool',mode:MODE,phase:'proof-reader',
 budget:{alarm_after_import_seconds:5,cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,
 whole_startup_bound_proven:false,max_events:32,record_bytes:65536},
 events:reader.events,terminal_event_index:reader.events.length-1};
await add('-root-proof-reader-tool.json',JSON.stringify(supplemental)+'\n');
// In the NEXT cell after known successful patch, common prelude then:
// await add('-root-tool.json',load(key('raw-body')));
```

The raw keys/types exactly match the source R1 validator. Its size includes newline and every event. Root's assertion is external causal trust, not source authentication. A malformed record is retained and refused, never repaired into a new attempt. After both known patch completions, a separate cell with the same common prelude executes ONLY `await finalizeMetadata();`. This consumes key('metadata') once. Its original request, actual return or original thrown value are retained before validation. Require known normal0 and exact sole nonauthority output. Session/nonzero/throw/unsupported/uncertain stops, with no metadata poll/retry/reconcile. Only after that terminal, a separately issued cell may execute `await first('reconcile',operation('reconcile'));`, then its own empty45s polls. operation('reconcile') now rejects unless metadata is terminal. No operation target runs again. A reader/patch/scheduling delay can make U too late and cause refusal; do not subtract it or extend90/600/180.

Under the controller's A resolution, matching marker proof means the reviewed writer's sole normal terminal output associated with the exact reconcile MODE request; it is **not** an independent post-exit disk reread. Require actual reconcile exit0, strict sole canonical stdout and retain its full raw chain. Inspect proof decimals losslessly; there is no sixth public read/helper. The next separately authorized consumer re-reads and validates the on-disk marker and entire chain under continuous quiescence. Any mismatch/extra stdout/late/unknown exit stops.

```javascript
const r=terminal('reconcile',true), output=r.events.map(e=>e.response.output).join('');
const match=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[([0-9]+(?:,[0-9]+){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(output);
if(!match)throw Error('sole fixed marker output required');
const n=BigInt(match[2]),m=match[3].split(',').map(v=>BigInt(v));
if(n>16384n||m[0]<=0n||m[1]<=0n||m[2]!==1000n||m[3]!==1000n||m[4]!==33152n||m[5]!==1n||m[6]!==n)throw Error('marker proof shape');
store(key('normal-marker-proof-json'),match[1]); // exact decimal bytes, no numeric conversion
const transcript={version:1,producer:'root-controller-actual-tool',mode:MODE,phase:'reconcile',
 budget:{wall_seconds:30,cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,
 whole_physical_stop_proven:false,max_events:32,record_bytes:65536},
 events:r.events,terminal_event_index:r.events.length-1,marker_proof_json:match[1]};
await add('-root-reconcile-tool.json',JSON.stringify(transcript)+'\n');
```

After known transcript write, root may separately consider the next action; this script grants none. Supplemental reader/reconcile records are external evidence, not marker authority or a recursive sampler: six each<=64KiB add786432B logical within existing96MB reserve/ordinaryR. Original six raw+six marker bound480KiB remains separate. Their own writing/scheduling delays after U do not retroactively change the accepted old terminal upper bound, and can stale a preprobe before launch. Source rechecks original<=60s freshness. Current quiescence, complete actual resource/disk/resident guards and all operational eligibility remain unmeasured/unadmitted here.

The source-only tests include one preserved failed GREEN that accidentally reached bounded own-clock `/proc`/namespace reads due to a fixture mock ending early; it is not described as entirely fake. Persistent fail-closed sentinels and fresh fake-deadline consumers fixed that fixture, subsequent generated tests and unique frozen177-case cover passed. See the full substage report for exact history; source PASS is not actual terminal/material/cache/PG eligibility or Task6 completion.
