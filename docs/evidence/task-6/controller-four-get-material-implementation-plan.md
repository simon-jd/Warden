# Future four-GET material implementation and exact-caller plan — full preserved proposal

Origin: /root/identity, gpt-6-astra/high, subagent architecture/call-plan proposal, not human or actual evidence. Root read all13499 bytes; SHA256 704026f167569f5df759c77fa451164aed777980bbf1541291bb1b8729cd9f60. Body follows verbatim. This is future architecture only: terminal originalround4 Important fixes and independent re-review have priority; no source/index/admission/actual authority is granted here. Current source basis a05 remains unchanged by this proposal.

# Material implementation/caller PLAN — 2026-10-25

Only this ignored plan; a05/e9 frozen/root owns Git. M1–M5 and terminal A/lossless govern. No snippet executed. Root permits this approximately12KiB complete caller. Terminal review has two Important findings: round4 takes priority; Task6/Q5 unchanged. This is not source authority.

Five existing files: observer extracts verify_sources150(admission)→held source/invoker Records, recheck_bound(deadline,records,sources), compile_fixed_invoker(context). Controller delegates old loops only; six admissions/policies unchanged. Separate MaterialContext shares these helpers/public Record/clock, no operation/private/recovery/guard/claim/envelope/Popen/cleanup rights. Bootstrap adds four-argv literals material-four-get/material-reconcile, same loader/early U/B/A. Passive invoker adds material_run/material_reconcile; testcontrol/docsfixture only. No new module/cap.

ReadOnlyDocker(deadline,recovery,*,project_only=False): true requires recovery=None/project=warden only; default unchanged. Publish summary only after exchange/finally close, validation/serialization/final deadline; peer candidate reset each call/sticky failure. Two lists then first sorted currently-listed image/container inspect; empty inspect NOT EXERCISED. No raw body/Env/oldlabels/fallback. First producer success-only; exceptions fixed exit1/no traceback/no usable receipt/marker; partial retained. Birth30 shared IO10/close15/return20/receipt25/independent terminal30; metadata reconcile30 never extends it.

## Exact contracts

P=controller-cache-continuation-v1-20261025-material-. Six suffixes admission/root-tool/root-proof-reader-tool/root-reconcile-tool .json<=65536 each; receipt/terminal .json<=16384:294912B/existing reserve/ordinaryR, allocation separate. Root regular UID/GID1000/nlink1/0600or0644; output exclusive0600/fsync/heldFD readback; no retry.

Admission exact M1 keys version,mode,authority,source_commit,source_hashes,review_sha256,ruling_sha256,writer_basis,clock_identity,outer_invoker_sha256,policy. Fixed1/material-four-get/readonly-four-get-only; hex40 commit/hex64 hashes/150 exact/writer1..4096UTF8. Policy wall30/CPU5/AS134217728/FSIZE1048576/output65536/phases[10,15,20,25,30].

C=version,mode,source_commit,source_manifest_sha256,admission,invoker,clock_identity. Proof={sha256,bytes,metadata[10]} strict integers/full Record. Receipt=C+state,timing,slots,reason,Q_released; observed-success/null/false. timing={origin:timing_from_birth,final_sample:OwnClockSample,ended_monotonic_ns},both-clock<=25. Ordered four routes image-list/container-list/image-inspect/container-inspect; each slot exact route,state,count,selected_id_sha256,output_bytes,output_sha256,http_status,peer. ok:listcount0..1000/inspect1,bytes0..1048576,hex64,status200,peer[positivepid,0,nonnegativegid]; empty LF list0 valid. Corresponding inspect not-exercised/all data null. Failure shapes reserved/refused initially.

D1 ruled: nonempty list selected_id_sha256 carries first sorted validated ID hash; empty null; inspect hash equals list. Cross-slot consistency only: reviewed writer/adapter attests lexical-first selection; opaque list output hash cannot establish membership or ordering.

Raw=C+origin,receipt,events,terminal_event_index,root_assertion. Marker=C+state,receipt,root_tool,timing,tool_exit_code,Q_released; known-success/0/false. timing exact start_lower_ns,terminal_upper_ns,entry_boot_ns,entry_after_ns,verified_sample,metadata_end_ns. Reuse proof_matches; extract pure exact-request event/clock(original,last,stamps,T) validators, retain six wrappers. Same host/boot/ns/brackets,U-M0/B-B0<=30,A-U<=100ms,history<=U; new ownPID/birth separate. Recheck inputs around marker. No fabricated capture envelope.

## Future exact cells, not executed

Prelude per cell. Start `await first('get',action('material-four-get'))`; pending cells `await poll('get')`. Normal0 then reader below. Inspect each patch result before next cell. Fresh absence/quiescence AddFile!=O_EXCL.

```js
const W='/home/postedism/Desktop/Warden',D=W+'/docs/evidence/task-6/',P='controller-cache-continuation-v1-20261025-material-',K=s=>P+s;
const WHY='以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。';
function bytes(s){let n=0;for(const c of s){let x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function req(cmd,max=2000){return {cmd,workdir:W,shell:'/bin/bash',login:false,tty:false,yield_time_ms:1000,max_output_tokens:max,sandbox_permissions:'require_escalated',justification:WHY};}
function action(a){if(!['material-four-get','material-reconcile'].includes(a))throw Error('action');return req('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py '+a);}
function response(r,max){const keys=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!keys.includes(k))||typeof r.output!=='string'||bytes(r.output)>65536||!Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');if('chunk_id'in r&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||r.original_token_count<0||r.original_token_count>max))throw Error('truncated');if('exit_code'in r){if('session_id'in r||!Number.isSafeInteger(r.exit_code)||![0,1].includes(r.exit_code))throw Error('exit');return 'terminal';}if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');return 'running';}
async function call(p,q,first){let s=load(K(p));if(first){if(s!==undefined)throw Error('retry');s={events:[],state:'awaiting'};}store(K(p),s);try{let r=await(first?tools.exec_command(q):tools.write_stdin(q));s.events.push({seq:s.events.length,tool:first?'exec_command':'write_stdin',request:q,response:r});store(K(p),s);s.state=response(r,q.max_output_tokens);if(!first&&s.state==='running'&&r.session_id!==q.session_id)throw Error('session');store(K(p),s);}catch(e){s.state='unknown';store(K(p),s);throw e;}}
const first=(p,q)=>call(p,q,true);
async function poll(p){let s=load(K(p));if(!s||s.state!=='running'||s.events.length>=32)throw Error('stop');let id=s.events[0].response.session_id;if(s.events.at(-1).response.session_id!==id)throw Error('session');await call(p,{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000},false);}
function done(p){let s=load(K(p));if(!s||s.state!=='terminal'||s.events.at(-1).response.exit_code!==0)throw Error('normal0');return s.events;}
async function save(s,b){if(!b.endsWith('\n')||bytes(b)>65536)throw Error('size');text(await tools.apply_patch('*** Begin Patch\n*** Add File: '+D+P+s+'\n'+b.slice(0,-1).split('\n').map(x=>'+'+x).join('\n')+'\n*** End Patch'));}
```

Reader cell: `done('get'); await first('reader',req("exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - <<'PY'\n"+readerBody+"\nPY",4000))`; pending `await poll('reader')`. Literal readerBody:

```python
import os,stat,json,hashlib,signal,resource
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
print(json.dumps(out,separators=(',',':')),flush=True)
```

After-import alarm is not startup5s physical proof. Next cells (common prelude):

```js
const es=done('get'),rs=done('reader'),t=rs.map(e=>e.response.output).join('');
if(bytes(t)>16384||!t.startsWith('{')||!t.endsWith('}\n'))throw Error('reader');
const p=JSON.parse(t);if(Object.keys(p).length!==6||['admission','invoker','receipt','source_commit','source_manifest_sha256','clock_identity'].some(k=>!(k in p)))throw Error('keys'); // preview only; never stringify p
const h=JSON.stringify({version:1,mode:'material-four-get',origin:'root-controller-actual-tool'}),z=JSON.stringify({events:es,terminal_event_index:es.length-1,root_assertion:'awaited-terminal-before-record-before-reconcile'});
store(K('raw'),h.slice(0,-1)+','+t.slice(1,-2)+','+z.slice(1)+'\n');
await save('root-proof-reader-tool.json',JSON.stringify({version:1,mode:'material-four-get',phase:'reader',events:rs,terminal_event_index:rs.length-1,budget:{alarm_after_import_seconds:5,cpu_seconds:2,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}})+'\n');
// Separate checked-patch cells:
// await save('root-tool.json',load(K('raw')));
// await first('reconcile',action('material-reconcile')); pending: poll('reconcile')
const re=done('reconcile'),o=re.map(e=>e.response.output).join('');
const m=/^\{"marker":(\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}),"state":"reconcile-terminal-pending"\}\n$/.exec(o);
if(!m)throw Error('marker');const n=BigInt(m[2]),v=m[3].split(',').map(BigInt);
if(n>16384n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||v[4]!==33152n||v[5]!==1n||v[6]!==n)throw Error('proof');
await save('root-reconcile-tool.json',JSON.stringify({version:1,mode:'material-four-get',phase:'reconcile',events:re,terminal_event_index:re.length-1,marker_proof_json:m[1],budget:{wall_seconds:30,cpu_seconds:5,address_bytes:134217728,file_bytes:1048576,max_events:32,record_bytes:65536}})+'\n');
```

D2 ruled: success receipt/marker ONLY. Any error/nonzero/unknown has no usable receipt/marker, even if partial output exists; no reconciliation/retry. Preserve complete available actual chains, including invalid responses. Strict failure-envelope exact keys version,mode,authority,state,reason,chains,Q_released; fixed1/material-four-get/false/unknown-no-authority/false. reason is one of get-nonzero,get-unknown,receipt-unavailable-or-invalid,reader-nonzero,reader-unknown,reconcile-nonzero,reconcile-unknown,invalid-marker,recording-failure. chains exact get,reader,reconcile, each null(not invoked) or full recorded event array<=32. Requests/responses remain actual bytes/values, not repaired into a valid chain; no C/Proof/clock fields. Existing normal record never overwritten. Before actual, root proves both failure destinations absent and maintains exclusive quiescence; successful own writes update that knowledge. AddFile does not supply this guarantee.

Fallback procedure: construct that envelope from stored get/reader/reconcile events without repair. If complete UTF8 JSON<=65536 and reader transcript remains proven absent, use save('root-proof-reader-tool.json',body). Otherwise, only with proven diagnostic absence and complete JSON<=4194304, use the same AddFile expression with literal diagnostic-tool.json and that cap. Root clears absence after any attempt; existing/partial/unknown stops, no retry. Diagnostic sole seventh path has same nonauthority schema; maximum4489216B within96MB/ordinaryR, no charge. Beyond bound/non-JSON failure retains original tool/memory evidence, no trimming/fabrication/restart. Unknown/extra stdout/exit124/session mismatch stops. Normal0+sole marker stdout matches exact request under continuous root quiescence(A), not postexit disk reread; later consumer rechecks bindings. wall_time not lifetime; delays before U consume30. UID/binary/ancestors/clock/headroom/API viability remain future gates; no auto-successor.

Persistent failclosed OwnClock.sample/own_proc_text/clock_identity/socket/Popen/native guards before fixtures; local generated overrides restore sentinel/no escaped live ClockBudget(G1). Genuine old-entry RED; source/admission isolation/routes/hash/privacy/close/phase/proof/size/schema/chain/ns/partial/exclusive/replay/no-action. Full150+2 maps/changed-only futureBASE,finiteGREEN/one frozen cover/report/index/append. No tests now. D1/D2 resolved; NEEDS_CONTEXT terminal fixes/PASS and explicit source handoff. No business/PG/capture/maintenance or actual authority.

## Append 2026-10-25: ONE frozen functions.exec caller proposal (M8 pending)

The preceding13499B is preserved. This appendix replaces the future multi-cell sequencing, not its protocol, native steps, timing, permissions or records. Terminal fix4 source2c911c8/worker46adcd2 and74PASS are parent-reported; scoped review remains prior to material authorization. Nothing below has run. Freeze this entire literal script before actual; root first supplies separately reviewed actual admission, original six-file inputs/absence, diagnostic absence, native/clock/headroom/source gates and continuous quiescence. Only then root may set the exact functions store key `controller-cache-continuation-v1-20261025-material-one-shot-admitted` to true. That orchestration interlock grants no authority to the program and substitutes for none of those external facts. This plan neither sets it nor prepares admission.

One functions.exec awaits get→its original-session polls→three-proof reader→reader transcript patch→lossless raw patch→reconcile→its polls→sole marker validation→reconcile transcript patch. There is no intervening LLM generation, file-reading step or extra native command. The same1000 initial/45000 poll limits remain. Awaiting functions.exec itself may yield; the existing isolate continues its awaited sequence. Root only collects that same outstanding execution's completion, never relaunches the script or changes arguments. Tool scheduling, imports and actual tool-terminal sampling still consume the original30s. This removes avoidable model gaps; it does not guarantee30s, physical stop, API compatibility or successful reconciliation. At most32 actual events per native chain; no JS clock manufactures elapsed proof. wall_time_seconds remains metadata only.

Minimal event amendment: normal events retain exactly `{seq,tool,request,response}`. Before invoking the tool, persist `{seq,tool,request}`; only a real resolved return adds `response`, even when invalid. A throw leaves the pending form, never `response:null`. Normal validators reject a missing response. Failure-envelope chains permit at most one pending last event per chain; null chain means never invoked. Non-authority failure-envelope additionally has required `patch_events`, an array of at most4 `{seq,tool:'apply_patch',request}` plus optional actual `response`. Request is the literal patch string; no invented exception return. Arrays preserve full available requests/returns, including invalid shapes. Failure reason enum and other fields remain as above. The diagnostic is the same schema/cap, never an alternative authority format.

checkedPatch accepts only a normal Promise return whose exact shape is an empty ordinary object. Parent observed the JSON shape `{}` twice, but did not record prototype: the Object.prototype equality below is an unverified conservative runtime check, not an observed fact. It rejects null/array/string/nonempty/foreign prototype or a thrown/rejected call. Preserve the actual object in functions store and tool transcript. This is sufficient to continue the proposed workflow under that explicitly selected profile, not proof of exclusive creation, disk durability or independently read-back bytes. The reconciler still validates raw/input files. Any profile mismatch stops normal progress and enters evidence-only handling. Changing the accepted shape needs another ruling, not runtime adaptation.

Each patch destination is consumed BEFORE awaiting apply_patch, so unknown/partial writes cannot be reused. Failure save chooses an untouched reader-transcript path if<=64KiB, otherwise the sole untouched diagnostic path if<=4MiB. If the first failure-save attempt itself fails, stop: do not try a second destination. The last diagnostic/normal patch cannot contain its own future return; that request and real result/pending state remain in functions store plus the actual outer tool transcript. No recursive rewrite claims to close this causal boundary. This applies also to successful final transcript creation. Root must retain the complete functions/tool record; a thrown tool may have no returned result to retain. Non-JSON/unrepresentable results or oversized full evidence remain unknown in that outer record, without truncation or a fabricated disk record.

The script below is complete and fixed. The heredoc is the same three-record collector, not a fourth reader; its after-import5s alarm is not a startup bound. No automatic successor, cleanup, retry, authority marker or admission is produced by JS. The final printed state reports orchestration completion only, and never releases Q.

```js
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
  // Preserve actual return separately; this does not assert disk readback.
  notify({patch_seq:e.seq,actual_return:r});
  if(r===null||typeof r!=='object'||Array.isArray(r)||
     Object.getPrototypeOf(r)!==Object.prototype||Reflect.ownKeys(r).length!==0)
    throw Error('unexpected patch return');
}
// Refuse lossy JSON serialization of available tool data. Never strip fields.
function exactJSON(v){
  function check(x){
    if(x===null||typeof x==='string'||typeof x==='boolean')return;
    if(typeof x==='number'){if(!Number.isFinite(x))throw Error('nonfinite');return;}
    if(Array.isArray(x)){for(let i=0;i<x.length;i++){if(!Object.hasOwn(x,i))throw Error('hole');check(x[i]);}return;}
    if(typeof x!=='object'||Object.getPrototypeOf(x)!==Object.prototype||
       Reflect.ownKeys(x).length!==Object.keys(x).length)throw Error('not plain JSON');
    for(const k of Object.keys(x))check(x[k]);
  }
  check(v);return JSON.stringify(v);
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
```

Full normal authority still requires the strict producer/reconciler files and normal exits, round4 post-output Record rechecks, continuous root quiescence and later conditional consumer proof revalidation; `normal-chain-recorded` is not an independent disk read or success authorization. No native clock/record/guard step was inserted. Generated future mocks must cover rejected Promise at initial/poll/patch, last pending event preservation, invalid actual return, exact `{}` vs other patch shapes, caps, consumed destinations and no fallback retry; none run now. NEEDS_CONTEXT: root M8 acceptance of this one-shot caller and the two explicit schema/profile clarifications, then existing source/actual gates. No source/index authority transferred.
