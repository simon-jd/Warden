// @exec: {"yield_time_ms": 30000, "max_output_tokens": 2000}
const W='/home/postedism/Desktop/Warden';
const D=W+'/docs/evidence/task-6/';
const P='controller-cache-continuation-v1-20261025-material-';
const K=s=>P+s;
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
if(load(K('one-shot-admitted'))!==true||load(K('one-shot'))!==undefined)
  throw Error('not admitted or already attempted');
// Root's prior absence checks cover these outputs, receipt and terminal;
// admission/invoker are existing verified inputs. No absence is inferred here.
const free=new Set(['root-tool.json','root-proof-reader-tool.json',
  'root-reconcile-tool.json','diagnostic-tool.json']);
const S={state:'active',chains:{get:null,reader:null,reconcile:null},patch_events:[]};
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
D='/home/postedism/Desktop/Warden/docs/evidence/task-6/';P='controller-cache-continuation-v1-20261025-material-'
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
  const r=await(tool==='exec_command'?tools.exec_command(q):tools.write_stdin(q));
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
    'reader-nonzero','reader-unknown','reconcile-nonzero','reconcile-unknown',
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
  await checkedPatch('root-proof-reader-tool.json',exactJSON(readerTranscript(rs))+'\n',65536);
  await checkedPatch('root-tool.json',raw,65536);
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
