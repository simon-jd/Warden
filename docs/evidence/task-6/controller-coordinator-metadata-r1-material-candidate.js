// @exec: {"yield_time_ms": 30000, "max_output_tokens": 2000}
const W='/home/postedism/Desktop/Warden';
const D=W+'/docs/evidence/task-6/';
const P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-';
const K=s=>P+s;
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
if(load(K('one-shot-admitted'))!==true||load(K('one-shot'))!==undefined)
  throw Error('not admitted or already attempted');
// Root's prior absence checks cover these outputs, receipt and terminal;
// admission/invoker are existing verified inputs. No absence is inferred here.
const free=new Set(['root-tool.json','root-proof-reader-tool.json',
  'root-reconcile-tool.json','diagnostic-tool.json']);
const S={state:'active',chains:{get:null,reader:null,metadata:null,reconcile:null},patch_events:[]};
function persist(){store(K('one-shot'),S);}
persist();
function bytes(s){let n=0;for(const c of s){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function req(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,
  tty:false,yield_time_ms:1000,max_output_tokens:max,
  sandbox_permissions:'require_escalated',justification:WHY};}
const getRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-four-get');
const reconcileRequest=req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py material-reconcile');
const readerBody=String.raw`import os,stat,json,hashlib,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
for k,n in ((resource.RLIMIT_CPU,2),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):resource.setrlimit(k,(n,n))
D='/home/postedism/Desktop/Warden/docs/evidence/task-6/';P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-'
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
held=[];out={}
for key,name in [('admission',P+'admission.json'),('invoker','controller-cache-continuation-outer-invoker-20261025.py'),('receipt',P+'receipt.json')]:
 f=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 for part in D.strip('/').split('/'):
  g=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=f);os.close(f);f=g
  s=os.fstat(f);assert s.st_uid in (0,1000) and not s.st_mode&0o022
 h=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=f);s=os.fstat(h);cap=16384 if key=='receipt' else 65536
 assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o644) and 0<s.st_size<=cap
 b=b''
 while len(b)<=cap:
  c=os.read(h,cap+1-len(b))
  if not c:break
  b+=c
 assert len(b)==s.st_size
 held.append((f,h,name,meta(s)));out[key]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'metadata':meta(s)}
 if key=='receipt':
  v=json.loads(b)
  for k in ('source_commit','source_manifest_sha256','clock_identity'):out[k]=v[k]
for f,h,n,s in held:assert meta(os.fstat(h))==s==meta(os.stat(n,dir_fd=f,follow_symlinks=False))
for n in ('root-tool.json','root-proof-reader-tool.json','root-reconcile-tool.json'):
 try:os.stat(P+n,dir_fd=f,follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('existing')
print(json.dumps(out,separators=(',',':')),flush=True)`;
const readerRequest=req("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000);
const metadataBody=String.raw`import time
M0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()
import os,sys,signal,resource
def need(ok):
 if not ok:raise ValueError('material metadata refusal')
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
 value=parse(sys.argv[1]);need(type(value) is dict and set(value)=={'collector','raw','reader'} and all(type(v) is str for v in value.values()))
 intended=[value['raw'].encode(),value['reader'].encode()];need(all(0<len(v)<=65536 and v.endswith(b'\n') for v in intended))
 collected=parse(value['collector']);expected=collected['receipt']
 need(type(expected) is dict and set(expected)=={'bytes','metadata','sha256'} and type(expected['bytes']) is int and type(expected['metadata']) is list and len(expected['metadata'])==10 and all(type(x) is int for x in expected['metadata']))
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 public=keep(os.open('/',flags));s=os.fstat(public);need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((None,None,public,meta(s)))
 for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)
  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))
 P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-'
 receipt=read(P+'receipt.json',16384,(0o600,0o644))
 need(expected=={'bytes':len(receipt[2]),'metadata':receipt[3],'sha256':hashlib.sha256(receipt[2]).hexdigest()})
 received=parse(receipt[2]);need(received['clock_identity']==collected['clock_identity'])
 timing=received['timing'];origin=timing['origin'];first=origin['sample'];last=timing['final_sample']
 names=('monotonic_before_ns','boottime_ns','monotonic_after_ns')
 values=[origin['budget_start_monotonic_lower_ns'],first['birth_boot_lower_ns'],timing['ended_monotonic_ns']]+[s[n] for s in (first,last) for n in names]
 need(all(type(x) is int and x>=0 for x in values))
 need(origin['budget_start_monotonic_lower_ns']<=first['monotonic_before_ns']<=first['monotonic_after_ns']<=last['monotonic_before_ns']<=last['monotonic_after_ns']<=timing['ended_monotonic_ns'])
 need(first['birth_boot_lower_ns']<=first['boottime_ns']<=last['boottime_ns']<=B0 and last['monotonic_after_ns']<=M0)
 for sample in (first,last):
  need(sample['monotonic_after_ns']-sample['monotonic_before_ns']<=100000000)
  lo=max(lo,sample['boottime_ns']-sample['monotonic_after_ns']);hi=min(hi,sample['boottime_ns']-sample['monotonic_before_ns'])
 need(lo<=hi)
 me=min(me,origin['budget_start_monotonic_lower_ns']+30000000000);be=min(be,first['birth_boot_lower_ns']+30000000000);arm()
 targets=[read(P+name,65536,(0o600,0o644,0o664),want) for name,want in zip(('root-tool.json','root-proof-reader-tool.json'),intended)]
 need(targets[0][3][:2]!=targets[1][3][:2]);all_same()
 for record in targets:
  all_same();check();before=record[3];os.fchmod(record[0],0o600);check();after=meta(os.fstat(record[0]))
  need(after[4]==stat.S_IFREG|0o600 and all(after[i]==before[i] for i in (0,1,2,3,5,6,7,9)))
  record[3]=after;os.fsync(record[0]);check();all_same()
 all_same();sys.stdout.write('{"state":"material-metadata-finalized","authority":false}\n');sys.stdout.flush();all_same()
finally:
 for fd in reversed(fds):check();os.close(fd);check()
check()
`;
function shellQuote(s){return "'"+s.replaceAll("'","'\\''")+"'";}
async function finalizeMetadata(collector,raw,reader){
 reason='metadata-unknown';
 if(S.chains.metadata!==null)throw Error('metadata consumed');
 const data=exactJSON({collector,raw,reader});
 const cmd="exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B - "+shellQuote(data)+" <<'PY'\n"+metadataBody+"PY";
 if(bytes(cmd)>65536)throw Error('metadata command bound');
 S.chains.metadata=[];persist();
 const state=await nativeCall('metadata','exec_command',{...req(cmd),yield_time_ms:10000});
 const r=S.chains.metadata.at(-1).response;
 if(state!=='terminal')throw Error('metadata session unknown');
 if(r.exit_code!==0){reason='metadata-nonzero';throw Error('metadata nonzero');}
 if(r.output!=='{"state":"material-metadata-finalized","authority":false}\n')throw Error('metadata output');
}
function response(r,max){
  exactJSON(r); // Retain first; refuse unsupported values before reading fields.
  const keys=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
  if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!keys.includes(k))||
     typeof r.output!=='string'||bytes(r.output)>65536||
     !Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');
  if('chunk_id'in r&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');
  if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||
     r.original_token_count<0||r.original_token_count>max))throw Error('truncated');
  if('exit_code'in r){
    if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('exit');
    return 'terminal';
  }
  if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');
  return 'running';
}
let reason='get-unknown';
async function nativeCall(p,tool,q){
  const events=S.chains[p];
  if(events.length>=32)throw Error('event bound');
  const e={seq:events.length,tool,request:q};
  events.push(e);persist(); // outbound request survives a rejected Promise
  let r;
  if(p==='metadata'){
    try{r=await tools.exec_command(q);}
    catch(error){e.thrown=error;persist();throw error;} // original rejection; no response invented
  }else r=await(tool==='exec_command'?tools.exec_command(q):tools.write_stdin(q));
  e.response=r;persist(); // actual returned value, even if subsequently refused
  return response(r,q.max_output_tokens);
}
async function run(p,q){
  if(S.chains[p]!==null)throw Error('no retry');
  S.chains[p]=[];reason=p+'-unknown';persist();
  let state=await nativeCall(p,'exec_command',q);
  const events=S.chains[p];
  const id=state==='running'?events[0].response.session_id:undefined;
  while(state==='running'){
    if(events.length>=32||events.at(-1).response.session_id!==id)throw Error('poll bound/session');
    state=await nativeCall(p,'write_stdin',{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000});
    if(state==='running'&&events.at(-1).response.session_id!==id)throw Error('session changed');
  }
  if(events.some(e=>!Object.hasOwn(e,'response')))throw Error('incomplete normal chain');
  if(events.at(-1).response.exit_code!==0){reason=p+'-nonzero';throw Error('nonzero');}
  return events;
}
async function checkedPatch(suffix,body,cap){
  if(!free.has(suffix)||!body.endsWith('\n')||bytes(body)>cap)throw Error('patch gate');
  const request='*** Begin Patch\n*** Add File: '+D+P+suffix+'\n'+
    body.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch';
  free.delete(suffix); // consume even if the following call throws
  const e={seq:S.patch_events.length,tool:'apply_patch',request};
  S.patch_events.push(e);persist();
  const r=await tools.apply_patch(request);
  e.response=r;persist();
  // M8 ordinary-object/empty-key normal return profile was calibrated by root; no disk readback.
  notify({patch_seq:e.seq,actual_return:r});
  if(r===null||typeof r!=='object'||Array.isArray(r)||
     Object.getPrototypeOf(r)!==Object.prototype||Reflect.ownKeys(r).length!==0)
    throw Error('unexpected patch return');
}
// Refuse lossy JSON serialization of available tool data. Never strip fields.
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
function readerTranscript(events){return {version:1,mode:'material-four-get',phase:'reader',
  events,terminal_event_index:events.length-1,budget:{alarm_after_import_seconds:5,
  cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
function reconcileTranscript(events,proof){return {version:1,mode:'material-four-get',phase:'reconcile',
  events,terminal_event_index:events.length-1,marker_proof_json:proof,budget:{wall_seconds:30,
  cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}};}
async function failureSave(){
  const reasons=['get-nonzero','get-unknown','receipt-unavailable-or-invalid',
    'reader-nonzero','reader-unknown','metadata-nonzero','metadata-unknown',
    'reconcile-nonzero','reconcile-unknown',
    'invalid-marker','recording-failure'];
  if(!reasons.includes(reason))throw Error('failure reason');
  const body=exactJSON({version:1,mode:'material-four-get',authority:false,
    state:'unknown-no-authority',reason,chains:S.chains,
    patch_events:S.patch_events,Q_released:false})+'\n';
  const small=free.has('root-proof-reader-tool.json')&&bytes(body)<=65536;
  const suffix=small?'root-proof-reader-tool.json':'diagnostic-tool.json';
  const cap=small?65536:4194304;
  if(!free.has(suffix)||bytes(body)>cap)throw Error('retain outer record only');
  await checkedPatch(suffix,body,cap); // exactly one failure-save attempt
}
try{
  const es=await run('get',getRequest);
  const rs=await run('reader',readerRequest);
  reason='receipt-unavailable-or-invalid';
  const t=rs.map(e=>e.response.output).join('');
  if(bytes(t)>16384||!t.startsWith('{')||!t.endsWith('}\n'))throw Error('collector output');
  const p=JSON.parse(t); // structural preview only; never serialize p
  const keys=['admission','invoker','receipt','source_commit','source_manifest_sha256','clock_identity'];
  if(p===null||typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==6||
     keys.some(k=>!Object.hasOwn(p,k)))throw Error('collector keys');
  const h=exactJSON({version:1,mode:'material-four-get',origin:'root-controller-actual-tool'});
  const z=exactJSON({events:es,terminal_event_index:es.length-1,
    root_assertion:'awaited-terminal-before-record-before-reconcile'});
  const raw=h.slice(0,-1)+','+t.slice(1,-2)+','+z.slice(1)+'\n';
  // Proof/clock JSON member text is spliced unchanged; final Python validates it.
  reason='recording-failure';
  const readerText=exactJSON(readerTranscript(rs))+'\n';
  await checkedPatch('root-proof-reader-tool.json',readerText,65536);
  await checkedPatch('root-tool.json',raw,65536);
  await finalizeMetadata(t,raw,readerText);
  const re=await run('reconcile',reconcileRequest);
  reason='invalid-marker';
  const out=re.map(e=>e.response.output).join('');
  const m=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(out);
  if(!m)throw Error('sole canonical marker');
  const n=BigInt(m[2]),v=m[3].split(',').map(BigInt);
  if(n>16384n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||
     v[4]!==33152n||v[5]!==1n||v[6]!==n)throw Error('marker proof');
  reason='recording-failure';
  await checkedPatch('root-reconcile-tool.json',exactJSON(reconcileTranscript(re,m[1]))+'\n',65536);
  S.state='normal-chain-recorded';persist();
  text({state:S.state,authority:false,Q_released:false});
}catch(error){
  S.state='stopped-unknown';persist();
  try{await failureSave();}
  catch(retentionError){S.state='stopped-unknown-outer-retention-only';persist();}
  text({state:S.state,reason,authority:false,Q_released:false});
}
