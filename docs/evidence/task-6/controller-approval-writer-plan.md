# Fixed approval-writer plan — preserved subagent text

Origin: /root/identity, gpt-6-astra/high, subagent plan, not human or actual approval. Root read the full12206-byte original (SHA256 b9b4e42cc73020383af2307b4ac2e089ca53103b759b7f3337fa887f0a6edb0d). Rulings are separate; this original prefix is retained verbatim. No execution/pins/approval/admission.

# Fixed approval-writer / audit PLAN — 2026-10-25

Subagent /root/identity, not human/actual approval. Basis b578 + handoff D1/D2; only this plan written, no mutable source/test/snippet/index/actual action. Task6 round4/5/four Minors/Q5/scene22/budgets unchanged.

Review BEFORE capture; insert only accepted summary Proof AFTER successful capture/postflight/full normal reconcile under S_c. Code/paths fixed; root approval external. No private read/project import/loader/new authority format.

Actual gates: trusted native/stdlib/ancestors/UID1000/clock/resources, unchanged S_c/150/private8/HISTORY, accepted capture histories/Proof, fresh output absence/quiescence, separate root admission. Output changes only the canonical state token. No capture90/original180 renewal/pins/continue; constant review remains.

## Fixed program and caller

Future ONE functions.exec: root supplies K+'-summary-proof-json' and K+'-admitted'=true after gates; absent now. Freeze code/template SHA; audit data-only insertion. Canonical decimal Proof text remains lossless; regexp excludes shell injection. No extra reader.

```js
// @exec: {"yield_time_ms":30000,"max_output_tokens":2000}
const K='controller-cache-continuation-v1-20261025-approval-writer';
if(load(K+'-admitted')!==true||load(K+'-attempt')!==undefined)throw Error('closed/no retry');
const input=load(K+'-summary-proof-json');
const proofRE=/^\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}$/;
function proof(s){if(typeof s!=='string')throw Error('proof');const m=proofRE.exec(s);if(!m)throw Error('canonical proof');const n=BigInt(m[1]),v=m[2].split(',').map(BigInt);if(n>65536n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||v[5]!==1n||v[6]!==n||![33152n,33188n].includes(v[4]))throw Error('proof metadata');return m;}
proof(input);
const body=String.raw`import time
M0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()
import os,sys,signal,resource
def need(ok):
 if not ok:raise ValueError('approval refusal')
def check():
 u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
 need(0<=a-u<=100000000 and 0<=a-M0<=30000000000 and 0<=b-B0<=30000000000)
 need(max(B0-A0,b-a)<=min(B0-M0,b-u))
 return a
signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
need(0<=A0-M0<=100000000)
check();signal.setitimer(signal.ITIMER_REAL,(30000000000-(time.monotonic_ns()-M0))/1000000000)
for k,n in ((resource.RLIMIT_CPU,5),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):
 soft,hard=resource.getrlimit(k);need(hard==resource.RLIM_INFINITY or hard>=n);resource.setrlimit(k,(n,n))
import json,hashlib,stat,re
os.umask(0o077)
def pairs(items):
 d={}
 for k,v in items:need(k not in d);d[k]=v
 return d
def invalid(_):raise ValueError('noninteger/nonfinite JSON')
def parse(b):return json.loads(b,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
def raw(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
def sha(b):return hashlib.sha256(b).hexdigest()
fds=[];dirs=[]
def keep(fd):fds.append(fd);return fd
def parents():
 for parent,name,fd,before in dirs:
  now=os.fstat(fd);need(meta(now)[:6]==before[:6])
  if parent is not None:need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==meta(now))
 check()
def path_read(name,mode):
 check();parents()
 fd=keep(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=public))
 s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_dev==os.fstat(public).st_dev and stat.S_IMODE(s.st_mode) in mode and 0<s.st_size<=65536)
 data=os.pread(fd,65537,0);need(len(data)==s.st_size and meta(os.fstat(fd))==meta(s) and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==meta(s))
 check();return fd,data,meta(s)
def same(fd,name,data,m):
 check();parents()
 need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m and os.pread(fd,65537,0)==data)
 need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m)
 check()
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and len(sys.argv)==2)
 expected=parse(sys.argv[1]);need(type(expected) is dict and set(expected)=={'sha256','bytes','metadata'})
 need(type(expected['sha256']) is str and re.fullmatch('[0-9a-f]{64}',expected['sha256']) is not None and type(expected['bytes']) is int and 0<expected['bytes']<=65536)
 need(type(expected['metadata']) is list and len(expected['metadata'])==10 and all(type(x) is int and x>=0 for x in expected['metadata']))
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 public=keep(os.open('/',flags));dirs.append((None,None,public,meta(os.fstat(public))))
 for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)
  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))
 summary='controller-cache-continuation-v1-20261025-capture-summary.json'
 approval='cache-continuation-checkpoint-approval-20261025.json'
 sf,data,sm=path_read(summary,(0o600,0o644))
 need(expected=={'sha256':sha(data),'bytes':len(data),'metadata':sm})
 value=parse(data)
 need(type(value) is dict and set(value)=={'version','state','binding','writer_basis','captured_at','checkpoint_sha256','checkpoint_bytes'})
 need(type(value['version']) is int and value['version']==1 and value['state']=='checkpoint-captured-not-approved')
 need(type(value['binding']) is dict and type(value['writer_basis']) is str and 0<len(value['writer_basis'].encode())<=4096 and type(value['captured_at']) is str)
 need(type(value['checkpoint_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['checkpoint_sha256']) is not None and type(value['checkpoint_bytes']) is int and 0<value['checkpoint_bytes']<=16000000)
 need(data==raw(value)) # accepted source's canonical serializer
 old=b'"state":"checkpoint-captured-not-approved"';need(data.count(old)==1)
 approved=data.replace(old,b'"state":"approved"',1)
 want=dict(value);want['state']='approved';need(parse(approved)==want and len(approved)<=65536)
 same(sf,summary,data,sm)
 af=keep(os.open(approval,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=public))
 created=meta(os.fstat(af));need(created[2]==created[3]==1000 and created[4]==stat.S_IFREG|0o600 and created[5]==1)
 same(sf,summary,data,sm);offset=0
 while offset<len(approved):
  check();n=os.write(af,approved[offset:]);need(n>0);offset+=n
 check();os.fsync(af);check();final=meta(os.fstat(af))
 need(final[:6]==created[:6] and final[6]==len(approved))
 same(af,approval,approved,final);same(sf,summary,data,sm)
 os.fsync(public);check()
 same(af,approval,approved,final);same(sf,summary,data,sm)
 rf,readback,rm=path_read(approval,(0o600,));need(rm==final and readback==approved)
 same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)
 output={'approval':{'bytes':len(approved),'metadata':final,'sha256':sha(approved)}}
 sys.stdout.write(raw(output).decode());sys.stdout.flush()
 same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)
 check()
except BaseException:
 raise SystemExit(1)
finally:
 for fd in reversed(fds):os.close(fd)
check()
`;
const W='/home/postedism/Desktop/Warden';
const q={cmd:"exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - '"+input+"' <<'PY'\n"+body+"PY",
 workdir:W,shell:'/bin/bash',login:false,tty:false,yield_time_ms:1000,max_output_tokens:2000,
 sandbox_permissions:'require_escalated',justification:'以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。'};
const s={state:'pending',events:[]};store(K+'-attempt',s);
function bytes(t){let n=0;for(const c of t){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function valid(r){const ks=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(k=>!ks.includes(k))||typeof r.output!=='string'||bytes(r.output)>65536||!Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');if('chunk_id'in r&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');if('original_token_count'in r&&(!Number.isSafeInteger(r.original_token_count)||r.original_token_count<0||r.original_token_count>2000))throw Error('truncated');if('exit_code'in r){if('session_id'in r||!Number.isSafeInteger(r.exit_code)||r.exit_code!==0)throw Error('not normal0');return false;}if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');return true;}
async function call(tool,request){const e={seq:s.events.length,tool,request};s.events.push(e);store(K+'-attempt',s);const r=await(tool==='exec_command'?tools.exec_command(request):tools.write_stdin(request));e.response=r;store(K+'-attempt',s);return valid(r);}
try{
 let running=await call('exec_command',q);const id=running?s.events[0].response.session_id:undefined;
 while(running){if(s.events.length>=32||s.events.at(-1).response.session_id!==id)throw Error('stop');running=await call('write_stdin',{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000});if(running&&s.events.at(-1).response.session_id!==id)throw Error('session changed');}
 const out=s.events.map(e=>e.response.output).join('');
 if(!out.startsWith('{"approval":')||!out.endsWith('}\n'))throw Error('output');
 const result=out.slice(12,-2);proof(result);
 if(!result.includes('"metadata":[')||BigInt(proofRE.exec(result)[2].split(',')[4])!==33152n)throw Error('approval mode');
 s.approval_proof_json=result;s.state='normal0-proof-returned';store(K+'-attempt',s);
 text({state:s.state,authority:false,Q_released:false});
}catch(e){s.state='unknown-retain-no-pins';store(K+'-attempt',s);text({state:s.state,authority:false,Q_released:false});}
```

## Timing, audit and remaining decisions

Profile CPU5/AS128MiB/FSIZE1MiB,30s from earliest MONOTONIC/BOOTTIME/nonrenewed alarm, including flush/checks/close. Startup precedes sampling; last check precedes exit; physical stop unproved. Actual normal0/API wall_time do NOT prove birth-to-terminal<=30s. Accept this limit or separately review another bound before actual; no sampler/borrowed time/reset/retry here. Clock ABI/namespace continuity remain external.

Root's S_c Proof pins validated binding/time. Summary and created approval FD/bytes/metadata are rechecked around fsync/readback/stdout; partial files remain. No copied product parser or hostile-same-UID atomicity claim.

Proposed audit `docs/evidence/task-6/controller-approval-writer-audit-20261025.json`<=65536 within96MB/ordinaryR. Keys version(1),kind(approval-writer-audit),authority(false),source_commit,program_sha256,summary_proof_json,approval_proof_json(null on failure),state,events,Q_released(false). Full requests/returns; pending last event lacks response. Proof strings stay lossless. Root handoff also binds code/template/data-insertion/authorization/quiescence. Existing checked AddFile needs fresh absence/quiescence, not O_EXCL. Unknown/overflow/non-JSON stays in original tool evidence, no trimming/retry/pins. Last write result stays outside its own file; no record created now.

Require normal writer0/sole Proof/faithful derivation/preserved history and known approval commit before two-pin150 freeze/review. Unknown writer/commit/audit, partial/existing approval or changed source/summary/anchors/quiescence stops; presence never permits pins. Approval<=65536 plus audit<=65536 fit existing reserve, no charge/Q release/automatic continue.

NEEDS_CONTEXT A: accept measured30s+actual normal0 with whole-startup/terminal limit unproved, or require another bound? B: approve this audit path/schema/checked AddFile plan? Independent code/caller/data-insertion review and actual gates remain; no execution authority here.

## Final ONE caller candidate — 2026-10-25, replaces preceding candidate

Original12206B retained. Root A/B now adopt measured30s+known normal0 with physical startup-to-terminal30 unproved, and the sole64KiB nonauthority audit. This complete candidate supersedes the earlier callable text; no runtime adaptation or execution occurred. Python body is unchanged. JS now joins typed future source/program data, writes the actual audit once, and checks the calibrated exact empty ordinary-object patch return. A fully returned native event must contain its actual response; a thrown call leaves only its already-stored pending request. Audit patch request/result are kept outside the audit file in store/actual tool history. No recursive write, fallback, retry or pins follows uncertainty.

Before actual, root freezes/reviews this entire script and the exact UTF8 LF Python body between String.raw delimiters. `program_sha256` means SHA256 of that body, including its final LF, not the argv/data or full JS. Root independently records that digest and the full script/template digest in its existing handoff audit; this JS does not invent a crypto API or claim to recompute the digest. Under unchanged S_c/current150/private8/HISTORY, successful capture/postflight/normal reconcile, expected summary Proof, actual native/clock/resource checks, output absence and continuous quiescence, root supplies exactly one store object at K+'-data': {source_commit: actual S_c hex40, program_sha256: actual reviewed Python-body hex64, summary_proof_json: exact canonical accepted Proof string}. Root checks these values against its independently retained source/review/capture records, then separately sets K+'-admitted'=true. These are data-only insertion points, never paths/commands or substitutes for external authorization. Neither actual values nor admission are provided here.

Audit keys remain exactly rulingB. `state` is normal0-proof-returned or unknown-retain-no-pins; approval_proof_json is null for the latter. A normal audit state describes the writer's observed terminal, not the outcome of the audit's own later patch. The final caller store/state separately records that patch. Only a known normal writer0/sole Proof AND known accepted audit return can yield normal0-audit-recorded; even that does not authorize pins without root's faithful-derivation/approval-commit and constant-only review. Same-UID causality/quiescence are external facts, not authenticated by source_commit or SHA fields.

If code/data/admission gates fail before any tool call, throw without an audit. Once invoked, preserve all native requests/returns; unknown/nonzero/invalid/truncated/32-event overflow stops native calls and attempts only this bounded audit. Serialization/size refusal makes no patch call. A patch attempt consumes the destination before await; a throw/unexpected return is final. Store keeps the complete available original evidence; no truncation into a misleading smaller file. A failed audit's own actual result cannot be included in its preceding file and is never retrospectively written. AddFile exclusion remains fresh-absence/quiescence workflow, not O_EXCL/readback/durability/authorship. No extra native reader or sampler.

```js
// @exec: {"yield_time_ms":30000,"max_output_tokens":2000}
const K='controller-cache-continuation-v1-20261025-approval-writer';
const W='/home/postedism/Desktop/Warden';
const AUDIT=W+'/docs/evidence/task-6/controller-approval-writer-audit-20261025.json';
function own(o,k){return Object.hasOwn(o,k);}
function plain(o){return o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.getPrototypeOf(o)===Object.prototype;}
function hex(s,n){return typeof s==='string'&&s.length===n&&/^[0-9a-f]+$/.test(s);}
const data=load(K+'-data');
if(load(K+'-admitted')!==true||load(K+'-attempt')!==undefined)throw Error('closed/no retry');
if(!plain(data)||Reflect.ownKeys(data).length!==3||
   !['source_commit','program_sha256','summary_proof_json'].every(k=>own(data,k))||
   !hex(data.source_commit,40)||!hex(data.program_sha256,64))throw Error('typed data');
const proofRE=/^\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}$/;
function proof(s,approval=false){
 if(typeof s!=='string')throw Error('proof type');
 const m=proofRE.exec(s);if(!m||m[0]!==s)throw Error('canonical proof');
 const n=BigInt(m[1]),v=m[2].split(',').map(BigInt);
 if(n>65536n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||
    v[5]!==1n||v[6]!==n||!(approval?[33152n]:[33152n,33188n]).includes(v[4]))throw Error('proof metadata');
 return s;
}
const input=proof(data.summary_proof_json);
const body=String.raw`import time
M0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()
import os,sys,signal,resource
def need(ok):
 if not ok:raise ValueError('approval refusal')
def check():
 u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
 need(0<=a-u<=100000000 and 0<=a-M0<=30000000000 and 0<=b-B0<=30000000000)
 need(max(B0-A0,b-a)<=min(B0-M0,b-u))
 return a
signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
need(0<=A0-M0<=100000000)
check();signal.setitimer(signal.ITIMER_REAL,(30000000000-(time.monotonic_ns()-M0))/1000000000)
for k,n in ((resource.RLIMIT_CPU,5),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):
 soft,hard=resource.getrlimit(k);need(hard==resource.RLIM_INFINITY or hard>=n);resource.setrlimit(k,(n,n))
import json,hashlib,stat,re
os.umask(0o077)
def pairs(items):
 d={}
 for k,v in items:need(k not in d);d[k]=v
 return d
def invalid(_):raise ValueError('noninteger/nonfinite JSON')
def parse(b):return json.loads(b,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
def raw(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
def sha(b):return hashlib.sha256(b).hexdigest()
fds=[];dirs=[]
def keep(fd):fds.append(fd);return fd
def parents():
 for parent,name,fd,before in dirs:
  now=os.fstat(fd);need(meta(now)[:6]==before[:6])
  if parent is not None:need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==meta(now))
 check()
def path_read(name,mode):
 check();parents()
 fd=keep(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=public))
 s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_dev==os.fstat(public).st_dev and stat.S_IMODE(s.st_mode) in mode and 0<s.st_size<=65536)
 data=os.pread(fd,65537,0);need(len(data)==s.st_size and meta(os.fstat(fd))==meta(s) and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==meta(s))
 check();return fd,data,meta(s)
def same(fd,name,data,m):
 check();parents()
 need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m and os.pread(fd,65537,0)==data)
 need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m)
 check()
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and len(sys.argv)==2)
 expected=parse(sys.argv[1]);need(type(expected) is dict and set(expected)=={'sha256','bytes','metadata'})
 need(type(expected['sha256']) is str and re.fullmatch('[0-9a-f]{64}',expected['sha256']) is not None and type(expected['bytes']) is int and 0<expected['bytes']<=65536)
 need(type(expected['metadata']) is list and len(expected['metadata'])==10 and all(type(x) is int and x>=0 for x in expected['metadata']))
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 public=keep(os.open('/',flags));dirs.append((None,None,public,meta(os.fstat(public))))
 for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)
  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))
 summary='controller-cache-continuation-v1-20261025-capture-summary.json'
 approval='cache-continuation-checkpoint-approval-20261025.json'
 sf,data,sm=path_read(summary,(0o600,0o644))
 need(expected=={'sha256':sha(data),'bytes':len(data),'metadata':sm})
 value=parse(data)
 need(type(value) is dict and set(value)=={'version','state','binding','writer_basis','captured_at','checkpoint_sha256','checkpoint_bytes'})
 need(type(value['version']) is int and value['version']==1 and value['state']=='checkpoint-captured-not-approved')
 need(type(value['binding']) is dict and type(value['writer_basis']) is str and 0<len(value['writer_basis'].encode())<=4096 and type(value['captured_at']) is str)
 need(type(value['checkpoint_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['checkpoint_sha256']) is not None and type(value['checkpoint_bytes']) is int and 0<value['checkpoint_bytes']<=16000000)
 need(data==raw(value)) # accepted source's canonical serializer
 old=b'"state":"checkpoint-captured-not-approved"';need(data.count(old)==1)
 approved=data.replace(old,b'"state":"approved"',1)
 want=dict(value);want['state']='approved';need(parse(approved)==want and len(approved)<=65536)
 same(sf,summary,data,sm)
 af=keep(os.open(approval,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=public))
 created=meta(os.fstat(af));need(created[2]==created[3]==1000 and created[4]==stat.S_IFREG|0o600 and created[5]==1)
 same(sf,summary,data,sm);offset=0
 while offset<len(approved):
  check();n=os.write(af,approved[offset:]);need(n>0);offset+=n
 check();os.fsync(af);check();final=meta(os.fstat(af))
 need(final[:6]==created[:6] and final[6]==len(approved))
 same(af,approval,approved,final);same(sf,summary,data,sm)
 os.fsync(public);check()
 same(af,approval,approved,final);same(sf,summary,data,sm)
 rf,readback,rm=path_read(approval,(0o600,));need(rm==final and readback==approved)
 same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)
 output={'approval':{'bytes':len(approved),'metadata':final,'sha256':sha(approved)}}
 sys.stdout.write(raw(output).decode());sys.stdout.flush()
 same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)
 check()
except BaseException:
 raise SystemExit(1)
finally:
 for fd in reversed(fds):os.close(fd)
check()
`;
const request={cmd:"exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B - '"+input+"' <<'PY'\n"+body+"PY",
 workdir:W,shell:'/bin/bash',login:false,tty:false,yield_time_ms:1000,max_output_tokens:2000,
 sandbox_permissions:'require_escalated',justification:'以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。'};
const S={state:'pending',data,events:[],audit_event:null};
function persist(){store(K+'-attempt',S);}
persist(); // permanent one-attempt interlock, before any native invocation
function bytes(s){let n=0;for(const c of s){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function valid(r){
 const keys=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
 if(!plain(r)||Reflect.ownKeys(r).length!==Object.keys(r).length||Object.keys(r).some(k=>!keys.includes(k))||
    typeof r.output!=='string'||bytes(r.output)>65536||!Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');
 if(own(r,'chunk_id')&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');
 if(own(r,'original_token_count')&&(!Number.isSafeInteger(r.original_token_count)||r.original_token_count<0||r.original_token_count>2000))throw Error('truncation');
 if(own(r,'exit_code')){
  if(own(r,'session_id')||!Number.isSafeInteger(r.exit_code)||r.exit_code!==0)throw Error('not normal0');
  return false;
 }
 if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');
 return true;
}
async function call(tool,q){
 if(S.events.length>=32)throw Error('event limit');
 const e={seq:S.events.length,tool,request:q};S.events.push(e);persist();
 const r=await(tool==='exec_command'?tools.exec_command(q):tools.write_stdin(q));
 e.response=r;persist();return valid(r);
}
let approval=null;
try{
 let running=await call('exec_command',request);
 const id=running?S.events[0].response.session_id:undefined;
 while(running){
  if(S.events.length>=32||S.events.at(-1).response.session_id!==id)throw Error('stop');
  running=await call('write_stdin',{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000});
  if(running&&S.events.at(-1).response.session_id!==id)throw Error('session changed');
 }
 if(S.events.some(e=>!own(e,'response')))throw Error('missing response');
 const out=S.events.map(e=>e.response.output).join('');
 if(!out.startsWith('{"approval":')||!out.endsWith('}\n'))throw Error('sole output');
 approval=proof(out.slice(12,-2),true);
 S.state='normal0-proof-returned';
}catch(error){approval=null;S.state='unknown-retain-no-pins';}
S.approval_proof_json=approval;persist();
// Non-authority audit only. Reject non-JSON data instead of silently dropping it.
function exactJSON(value){
 const seen=new Set();
 function check(v){
  if(v===null||typeof v==='string'||typeof v==='boolean')return;
  if(typeof v==='number'){if(!Number.isFinite(v))throw Error('nonfinite');return;}
  if(typeof v!=='object'||seen.has(v))throw Error('unserializable');
  seen.add(v);
  if(Array.isArray(v)){
   if(Reflect.ownKeys(v).length!==v.length+1)throw Error('array fields');
   for(let i=0;i<v.length;i++){if(!own(v,i))throw Error('array hole');check(v[i]);}
  }else{
   if(!plain(v)||Reflect.ownKeys(v).length!==Object.keys(v).length)throw Error('nonplain');
   for(const k of Object.keys(v)){
    const d=Object.getOwnPropertyDescriptor(v,k);
    if(!own(d,'value'))throw Error('accessor');check(d.value);
   }
  }
  seen.delete(v);
 }
 check(value);return JSON.stringify(value);
}
try{
 const audit={version:1,kind:'approval-writer-audit',authority:false,
  source_commit:data.source_commit,program_sha256:data.program_sha256,
  summary_proof_json:input,approval_proof_json:approval,state:S.state,
  events:S.events,Q_released:false};
 const textBody=exactJSON(audit)+'\n';
 if(bytes(textBody)>65536)throw Error('audit overflow');
 const patch='*** Begin Patch\n*** Add File: '+AUDIT+'\n'+
  textBody.slice(0,-1).split('\n').map(line=>'+'+line).join('\n')+'\n*** End Patch';
 if(S.audit_event!==null)throw Error('audit already attempted');
 S.audit_event={seq:0,tool:'apply_patch',request:patch};persist();
 // Prior root gate established absence/quiescence. Consumed before await.
 const r=await tools.apply_patch(patch);
 S.audit_event.response=r;persist();
 if(!plain(r)||Reflect.ownKeys(r).length!==0)throw Error('unknown patch result');
 S.state=approval===null?'unknown-audit-recorded-no-pins':'normal0-audit-recorded';persist();
 text({state:S.state,audit_actual_return:r,authority:false,Q_released:false});
}catch(error){
 S.state='unknown-outer-retention-only-no-pins';persist();
 text({state:S.state,authority:false,Q_released:false});
}
```

No remaining policy choice is invented: A/B govern; final candidate needs independent code/exact-call review. Real source/program/summary values remain absent until the ruled successful capture handoff. Review should check fixed Python-body equality, proof-only quoting/canonical full match, both pending/returned request paths,64KiB audit bound, exact empty-object profile, one consumed audit attempt and no implicit pin permission. This proposal runs none of those cases. Native prototype checking is a conservative runtime condition; only the patch's exact ordinary-object return profile was calibrated by root. All startup/physical-stop/clock/causality/quiescence limitations and independent approval-commit/constant-only source review remain. No source/index/actual authority is granted.


## Original Task6 fix5/5: sole replacement approval caller

This complete caller explicitly supersedes every earlier approval caller in this plan. Earlier text remains historical. Actual admission/interlocks/data remain absent and root-owned; generated fixture PASS is not actual authority. F1–F6 and the unchanged original limits apply. Unsupported native values are stored first and refused before property reads or disk serialization; no getter/hook/negative-zero normalization. Approval uses isolated/no-site -I -S -B; its unchanged Python body remains5657B. The exact replacement candidate below is byte-identical to controller-caller-integrity-fix5-approval-candidate.js.

```javascript
// @exec: {"yield_time_ms":30000,"max_output_tokens":2000}
const K='controller-cache-continuation-v1-20261025-approval-writer';
const W='/home/postedism/Desktop/Warden';
const AUDIT=W+'/docs/evidence/task-6/controller-approval-writer-audit-20261025.json';
function own(o,k){return Object.hasOwn(o,k);}
function plain(o){return o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.getPrototypeOf(o)===Object.prototype;}
function hex(s,n){return typeof s==='string'&&s.length===n&&/^[0-9a-f]+$/.test(s);}
const data=load(K+'-data');
if(load(K+'-admitted')!==true||load(K+'-attempt')!==undefined)throw Error('closed/no retry');
if(!plain(data)||Reflect.ownKeys(data).length!==3||
   !['source_commit','program_sha256','summary_proof_json'].every(k=>own(data,k))||
   !hex(data.source_commit,40)||!hex(data.program_sha256,64))throw Error('typed data');
const proofRE=/^\{"bytes":([1-9][0-9]*),"metadata":\[((?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)){9})\],"sha256":"([0-9a-f]{64})"\}$/;
function proof(s,approval=false){
 if(typeof s!=='string')throw Error('proof type');
 const m=proofRE.exec(s);if(!m||m[0]!==s)throw Error('canonical proof');
 const n=BigInt(m[1]),v=m[2].split(',').map(BigInt);
 if(n>65536n||v[0]<=0n||v[1]<=0n||v[2]!==1000n||v[3]!==1000n||
    v[5]!==1n||v[6]!==n||!(approval?[33152n]:[33152n,33188n]).includes(v[4]))throw Error('proof metadata');
 return s;
}
const input=proof(data.summary_proof_json);
const body=String.raw`import time
M0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()
import os,sys,signal,resource
def need(ok):
 if not ok:raise ValueError('approval refusal')
def check():
 u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
 need(0<=a-u<=100000000 and 0<=a-M0<=30000000000 and 0<=b-B0<=30000000000)
 need(max(B0-A0,b-a)<=min(B0-M0,b-u))
 return a
signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
need(0<=A0-M0<=100000000)
check();signal.setitimer(signal.ITIMER_REAL,(30000000000-(time.monotonic_ns()-M0))/1000000000)
for k,n in ((resource.RLIMIT_CPU,5),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):
 soft,hard=resource.getrlimit(k);need(hard==resource.RLIM_INFINITY or hard>=n);resource.setrlimit(k,(n,n))
import json,hashlib,stat,re
os.umask(0o077)
def pairs(items):
 d={}
 for k,v in items:need(k not in d);d[k]=v
 return d
def invalid(_):raise ValueError('noninteger/nonfinite JSON')
def parse(b):return json.loads(b,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
def raw(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
def sha(b):return hashlib.sha256(b).hexdigest()
fds=[];dirs=[]
def keep(fd):fds.append(fd);return fd
def parents():
 for parent,name,fd,before in dirs:
  now=os.fstat(fd);need(meta(now)[:6]==before[:6])
  if parent is not None:need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==meta(now))
 check()
def path_read(name,mode):
 check();parents()
 fd=keep(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=public))
 s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_dev==os.fstat(public).st_dev and stat.S_IMODE(s.st_mode) in mode and 0<s.st_size<=65536)
 data=os.pread(fd,65537,0);need(len(data)==s.st_size and meta(os.fstat(fd))==meta(s) and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==meta(s))
 check();return fd,data,meta(s)
def same(fd,name,data,m):
 check();parents()
 need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m and os.pread(fd,65537,0)==data)
 need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m)
 check()
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and len(sys.argv)==2)
 expected=parse(sys.argv[1]);need(type(expected) is dict and set(expected)=={'sha256','bytes','metadata'})
 need(type(expected['sha256']) is str and re.fullmatch('[0-9a-f]{64}',expected['sha256']) is not None and type(expected['bytes']) is int and 0<expected['bytes']<=65536)
 need(type(expected['metadata']) is list and len(expected['metadata'])==10 and all(type(x) is int and x>=0 for x in expected['metadata']))
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 public=keep(os.open('/',flags));dirs.append((None,None,public,meta(os.fstat(public))))
 for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)
  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))
 summary='controller-cache-continuation-v1-20261025-capture-summary.json'
 approval='cache-continuation-checkpoint-approval-20261025.json'
 sf,data,sm=path_read(summary,(0o600,0o644))
 need(expected=={'sha256':sha(data),'bytes':len(data),'metadata':sm})
 value=parse(data)
 need(type(value) is dict and set(value)=={'version','state','binding','writer_basis','captured_at','checkpoint_sha256','checkpoint_bytes'})
 need(type(value['version']) is int and value['version']==1 and value['state']=='checkpoint-captured-not-approved')
 need(type(value['binding']) is dict and type(value['writer_basis']) is str and 0<len(value['writer_basis'].encode())<=4096 and type(value['captured_at']) is str)
 need(type(value['checkpoint_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['checkpoint_sha256']) is not None and type(value['checkpoint_bytes']) is int and 0<value['checkpoint_bytes']<=16000000)
 need(data==raw(value)) # accepted source's canonical serializer
 old=b'"state":"checkpoint-captured-not-approved"';need(data.count(old)==1)
 approved=data.replace(old,b'"state":"approved"',1)
 want=dict(value);want['state']='approved';need(parse(approved)==want and len(approved)<=65536)
 same(sf,summary,data,sm)
 af=keep(os.open(approval,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=public))
 created=meta(os.fstat(af));need(created[2]==created[3]==1000 and created[4]==stat.S_IFREG|0o600 and created[5]==1)
 same(sf,summary,data,sm);offset=0
 while offset<len(approved):
  check();n=os.write(af,approved[offset:]);need(n>0);offset+=n
 check();os.fsync(af);check();final=meta(os.fstat(af))
 need(final[:6]==created[:6] and final[6]==len(approved))
 same(af,approval,approved,final);same(sf,summary,data,sm)
 os.fsync(public);check()
 same(af,approval,approved,final);same(sf,summary,data,sm)
 rf,readback,rm=path_read(approval,(0o600,));need(rm==final and readback==approved)
 same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)
 output={'approval':{'bytes':len(approved),'metadata':final,'sha256':sha(approved)}}
 sys.stdout.write(raw(output).decode());sys.stdout.flush()
 same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)
 check()
except BaseException:
 raise SystemExit(1)
finally:
 for fd in reversed(fds):os.close(fd)
check()
`;
const request={cmd:"exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B - '"+input+"' <<'PY'\n"+body+"PY",
 workdir:W,shell:'/bin/bash',login:false,tty:false,yield_time_ms:1000,max_output_tokens:2000,
 sandbox_permissions:'require_escalated',justification:'以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。'};
const S={state:'pending',data,events:[],audit_event:null};
function persist(){store(K+'-attempt',S);}
persist(); // permanent one-attempt interlock, before any native invocation
function bytes(s){let n=0;for(const c of s){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function valid(r){
  exactJSON(r); // Retain first; refuse unsupported values before reading fields.
 const keys=['output','wall_time_seconds','chunk_id','original_token_count','exit_code','session_id'];
 if(!plain(r)||Reflect.ownKeys(r).length!==Object.keys(r).length||Object.keys(r).some(k=>!keys.includes(k))||
    typeof r.output!=='string'||bytes(r.output)>65536||!Number.isFinite(r.wall_time_seconds)||r.wall_time_seconds<0)throw Error('response');
 if(own(r,'chunk_id')&&(typeof r.chunk_id!=='string'||!r.chunk_id.length||r.chunk_id.length>128))throw Error('chunk');
 if(own(r,'original_token_count')&&(!Number.isSafeInteger(r.original_token_count)||r.original_token_count<0||r.original_token_count>2000))throw Error('truncation');
 if(own(r,'exit_code')){
  if(own(r,'session_id')||!Number.isSafeInteger(r.exit_code)||r.exit_code!==0)throw Error('not normal0');
  return false;
 }
 if(!Number.isSafeInteger(r.session_id)||r.session_id<=0)throw Error('session');
 return true;
}
async function call(tool,q){
 if(S.events.length>=32)throw Error('event limit');
 const e={seq:S.events.length,tool,request:q};S.events.push(e);persist();
 const r=await(tool==='exec_command'?tools.exec_command(q):tools.write_stdin(q));
 e.response=r;persist();return valid(r);
}
let approval=null;
try{
 let running=await call('exec_command',request);
 const id=running?S.events[0].response.session_id:undefined;
 while(running){
  if(S.events.length>=32||S.events.at(-1).response.session_id!==id)throw Error('stop');
  running=await call('write_stdin',{session_id:id,chars:'',yield_time_ms:45000,max_output_tokens:2000});
  if(running&&S.events.at(-1).response.session_id!==id)throw Error('session changed');
 }
 if(S.events.some(e=>!own(e,'response')))throw Error('missing response');
 const out=S.events.map(e=>e.response.output).join('');
 if(!out.startsWith('{"approval":')||!out.endsWith('}\n'))throw Error('sole output');
 approval=proof(out.slice(12,-2),true);
 S.state='normal0-proof-returned';
}catch(error){approval=null;S.state='unknown-retain-no-pins';}
S.approval_proof_json=approval;persist();
// Non-authority audit only. Reject non-JSON data instead of silently dropping it.
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
try{
 const audit={version:1,kind:'approval-writer-audit',authority:false,
  source_commit:data.source_commit,program_sha256:data.program_sha256,
  summary_proof_json:input,approval_proof_json:approval,state:S.state,
  events:S.events,Q_released:false};
 const textBody=exactJSON(audit)+'\n';
 if(bytes(textBody)>65536)throw Error('audit overflow');
 const patch='*** Begin Patch\n*** Add File: '+AUDIT+'\n'+
  textBody.slice(0,-1).split('\n').map(line=>'+'+line).join('\n')+'\n*** End Patch';
 if(S.audit_event!==null)throw Error('audit already attempted');
 S.audit_event={seq:0,tool:'apply_patch',request:patch};persist();
 // Prior root gate established absence/quiescence. Consumed before await.
 const r=await tools.apply_patch(patch);
 S.audit_event.response=r;persist();
 if(!plain(r)||Reflect.ownKeys(r).length!==0)throw Error('unknown patch result');
 S.state=approval===null?'unknown-audit-recorded-no-pins':'normal0-audit-recorded';persist();
 text({state:S.state,audit_actual_return:r,authority:false,Q_released:false});
}catch(error){
 S.state='unknown-outer-retention-only-no-pins';persist();
 text({state:S.state,authority:false,Q_released:false});
}
```
