"""ONE affected native batch: four owned FD cases and six static mappings."""
import time
START=time.monotonic_ns();END=START+45000000000
import os,sys,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
remaining=(END-time.monotonic_ns())/1000000000
if remaining<=0:os._exit(124)
signal.setitimer(signal.ITIMER_REAL,remaining)
for key,cap in ((resource.RLIMIT_CPU,20),(resource.RLIMIT_AS,268435456),(resource.RLIMIT_FSIZE,2097152)):
 soft,hard=resource.getrlimit(key)
 if hard!=resource.RLIM_INFINITY and hard<cap:raise ValueError('inherited fixture ceiling')
 resource.setrlimit(key,(cap,cap))
import json,hashlib,stat,tempfile,subprocess,traceback,shutil
from pathlib import Path
W=Path('/home/postedism/Desktop/Warden');D=W/'docs/evidence/task-6'
N='controller-six-mode-metadata';P='controller-cache-continuation-v1-20261025-';M='capture-preprobe'
OUT=D/(N+'-verification');OUT.mkdir(mode=0o700)
def need(value,message):
 if not value:raise AssertionError(message)
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
def snap(path):return {'metadata':meta(path.lstat()),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
def footprint(path):
 seen=set();total=0
 for base,dirs,files in os.walk(path,followlinks=False):
  for p in [Path(base)]+[Path(base)/n for n in dirs+files]:
   s=p.lstat();key=(s.st_dev,s.st_ino)
   if key not in seen:total+=s.st_blocks*512;seen.add(key)
 need(total<=5242880,'owned temporary allocation exceeds 5MiB');return total

# No actual project FD can be reached: first root is routed; every later helper
# filesystem call is fenced by exact literal path, flags and tracked owned FDs.
PREFIX=r'''import os,sys,time,signal,resource,json,hashlib,stat
_root=ROOT_LITERAL
_P='controller-cache-continuation-v1-20261025-capture-preprobe'
_parts=('home','postedism','Desktop','Warden','docs','evidence','task-6')
_names=(_P+'-deadline.json',_P+'-root-tool.json')
_df=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
_ff=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
_open,_stat,_fstat,_pread,_close,_chmod,_sync=os.open,os.stat,os.fstat,os.pread,os.close,os.fchmod,os.fsync
_held={};_root_used=False;_chmods=[];_syncs=[];_opens=[]
def _need(v):
 if not v:raise RuntimeError('fixture path/FD firewall')
def _o(path,flags,mode=0o777,*,dir_fd=None):
 global _root_used
 if dir_fd is None:
  _need(not _root_used and path=='/' and flags==_df);_root_used=True
  fd=_open(_root,flags);_held[fd]=('dir',0);_opens.append('ROUTED_ROOT');return fd
 _need(dir_fd in _held and _held[dir_fd][0]=='dir');depth=_held[dir_fd][1]
 if depth<len(_parts):
  _need(path==_parts[depth] and flags==_df);fd=_open(path,flags,dir_fd=dir_fd);_held[fd]=('dir',depth+1)
 else:
  _need(path in _names and flags==_ff);fd=_open(path,flags,dir_fd=dir_fd);_held[fd]=('file',path)
 _opens.append(path);return fd
def _s(path,*,dir_fd=None,follow_symlinks=True):
 _need(dir_fd in _held and _held[dir_fd][0]=='dir' and follow_symlinks is False)
 depth=_held[dir_fd][1];_need(path==_parts[depth] if depth<len(_parts) else path in _names)
 return _stat(path,dir_fd=dir_fd,follow_symlinks=False)
def _f(fd):_need(fd in _held);return _fstat(fd)
def _p(fd,n,offset):
 _need(fd in _held and _held[fd][0]=='file' and 0<n<=65537 and offset==0);return _pread(fd,n,offset)
def _c(fd):_need(fd in _held);_close(fd);del _held[fd]
def _m(fd,mode):
 _need(fd in _held and _held[fd]==('file',_names[1]) and mode==0o600);_chmods.append(_names[1]);return _chmod(fd,mode)
def _y(fd):
 _need(fd in _held and _held[fd]==('file',_names[1]));_syncs.append(_names[1]);return _sync(fd)
os.open,os.stat,os.fstat,os.pread,os.close,os.fchmod,os.fsync=_o,_s,_f,_p,_c,_m,_y
try:
 exec(compile(BODY_LITERAL,'<unchanged-six-metadata-body>','exec'),{})
finally:
 sys.stderr.write('WARDEN_SIX_METADATA_FD_TELEMETRY '+json.dumps({'root_routed':_root_used,'opens':_opens,'fchmod':_chmods,'fsync':_syncs,'held_count':len(_held)},separators=(',',':'))+'\n');sys.stderr.flush()
'''
result={'scope':'four FD cases plus static six path/time mappings only','cases':[],'failures':0,'errors':0,'missing':['happy','wrong-intended','envelope-proof-mismatch','spent-deadline'],'limits':{'wall_seconds':45,'cpu_seconds':20,'address_bytes':268435456,'file_bytes':2097152,'temporary_bytes':5242880},'real_runtime_paths_accessed':False}
temp=None;active=None;common=None;events=None
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000,'ordinary identity')
 frozen=json.loads((D/(N+'-source-manifest.json')).read_text())
 for name,entry in frozen['files'].items():
  source=(W/name).read_bytes();need(len(source)==entry['bytes'] and hashlib.sha256(source).hexdigest()==entry['sha256'],'changed source freeze: '+name)
 result['frozen_changed_sources_verified']=len(frozen['files'])
 candidate=(D/(N+'-candidate.md')).read_text();events=(D/(N+'-events-fixture.js')).read_text()
 common=candidate.split('```javascript\n',1)[1].split('\n```',1)[0]
 body=common.split('const metadataBody=String.raw`',1)[1].split('`;\nfunction exactJSON',1)[0]
 need(body.count('${MODE}')==1,'one literal mode interpolation');body=body.replace('${MODE}',M)
 need(body.endswith('\n') and len(body.encode())<8192,'bounded unchanged instantiated body')
 mapping=json.loads(common.split('const METADATA_SECONDS=Object.freeze(',1)[1].split(');',1)[0])
 expected={'capture-preprobe':180,'capture':90,'capture-postflight':180,'continue-preprobe':180,'continue':600,'continue-postflight':180}
 need(mapping==expected and json.loads(body.split(' SECONDS=',1)[1].split('\n',1)[0])==expected,'six fixed T values')
 need("const W='/home/postedism/Desktop/Warden';" in common and "const P='controller-cache-continuation-v1-20261025-';" in common and "target=read(P+M+'-root-tool.json'" in body and "envelope=read(P+M+'-deadline.json'" in body,'fixed path expressions')
 result['static_mapping']=[{'mode':mode,'seconds':seconds,'target':'/home/postedism/Desktop/Warden/docs/evidence/task-6/'+P+mode+'-root-tool.json'} for mode,seconds in expected.items()]
 result['helper_sha256']=hashlib.sha256(body.encode()).hexdigest()
 temp=Path(tempfile.mkdtemp(prefix='warden-six-metadata-'));temp.chmod(0o700);result['owned_temp']=str(temp)
 for mode in ('happy','wrong-intended','envelope-proof-mismatch','spent-deadline'):
  need(time.monotonic_ns()<END,'wrapper remaining deadline');root=temp/mode;root.mkdir(mode=0o700);public=root
  for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
   public/=part;public.mkdir(mode=0o700)
  raw=public/(P+M+'-root-tool.json');envelope=public/(P+M+'-deadline.json')
  rawbytes=b'{"fixture":"raw apostrophe \' retained"}\n';raw.write_bytes(rawbytes);raw.chmod(0o664)
  u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
  if mode=='spent-deadline':u-=181000000000;b-=181000000000;a-=181000000000
  ticks=b//10000000;birth=(ticks-1)*10000000
  first={'pid':1,'hz':100,'birth_ticks':ticks,'birth_boot_lower_ns':birth,'namespace':[1,1],'monotonic_before_ns':u,'boottime_ns':b,'monotonic_after_ns':a}
  identity={'machine_id':'fixture-only','boot_id':'fixture-only'};commit='b'*40;manifest='c'*64
  envelopebytes=(json.dumps({'mode':M,'stage':'capture','source_commit':commit,'source_manifest_sha256':manifest,'clock_identity':identity,'wall_seconds':180,'timing':{'budget_start_monotonic_lower_ns':birth-(b-u),'outer_entry_monotonic_ns':u,'sample':first}},separators=(',',':'))+'\n').encode()
  envelope.write_bytes(envelopebytes);envelope.chmod(0o600)
  proof={'bytes':len(envelopebytes),'metadata':meta(envelope.stat()),'sha256':hashlib.sha256(envelopebytes).hexdigest()}
  need(proof['metadata'][7]>9007199254740991,'real nanosecond fidelity');supplied=dict(proof)
  if mode=='envelope-proof-mismatch':supplied['sha256']='0'*64
  before={p.name:snap(p) for p in public.iterdir()}
  data={'collector':json.dumps({'envelope':supplied,'source_commit':commit,'source_manifest_sha256':manifest,'clock_identity':identity},separators=(',',':')),'raw':(rawbytes if mode!='wrong-intended' else b'{"fixture":"wrong intended"}\n').decode()}
  stdin=PREFIX.replace('ROOT_LITERAL',repr(str(root))).replace('BODY_LITERAL',repr(body));argv=[sys.executable,'-I','-S','-B','-',json.dumps(data,separators=(',',':'))]
  row={'case':mode,'request':{'argv':argv,'stdin':stdin,'cwd':str(root),'env':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}},'actual_envelope_proof':proof,'before':before,'temporary_allocated_before':footprint(temp)};result['cases'].append(row)
  child_end=min(END,time.monotonic_ns()+5000000000)
  active=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=root,env=row['request']['env']);row['owned_pid']=active.pid
  try:stdout,stderr=active.communicate(stdin.encode(),timeout=max(0,(child_end-time.monotonic_ns())/1e9))
  except subprocess.TimeoutExpired:
   active.kill();stdout,stderr=active.communicate();row.update({'stdout':stdout.decode(),'stderr':stderr.decode(),'exit_code':active.returncode,'timed_out':True});active=None;raise
  row.update({'stdout':stdout.decode(),'stderr':stderr.decode(),'exit_code':active.returncode,'timed_out':False});active=None
  row['after']={p.name:snap(p) for p in public.iterdir()};row['temporary_allocated_after']=footprint(temp)
  tag='WARDEN_SIX_METADATA_FD_TELEMETRY ';lines=stderr.decode().splitlines();telemetry=[line[len(tag):] for line in lines if line.startswith(tag)]
  need(len(telemetry)==1,'unique telemetry line');trace=json.loads(telemetry[0]);row['telemetry']=trace
  need(set(trace)=={'root_routed','opens','fchmod','fsync','held_count'} and trace['root_routed'] is True and type(trace['held_count']) is int and trace['held_count']==0,'strict telemetry/checked closes')
  need(trace['opens']==['ROUTED_ROOT','home','postedism','Desktop','Warden','docs','evidence','task-6',envelope.name]+([raw.name] if mode in ('happy','wrong-intended') else []),'only routed envelope/raw reads')
  if mode=='happy':
   need(row['exit_code']==0 and stdout==b'{"state":"six-mode-metadata-finalized","authority":false}\n' and len(lines)==1,'happy known terminal')
   need(trace['fchmod']==trace['fsync']==[raw.name],'only one fixed target mutated')
   old=before[raw.name];now=row['after'][raw.name];need(now['metadata'][4]==stat.S_IFREG|0o600 and now['sha256']==old['sha256'] and all(now['metadata'][i]==old['metadata'][i] for i in (0,1,2,3,5,6,7,9)),'bytes/inode/stable metadata preserved')
  else:
   need(row['exit_code']==1 and stdout==b'' and 'Traceback (most recent call last):' in stderr.decode() and stderr.decode().endswith('ValueError: six-mode metadata refusal\n'),'intended known refusal')
   need(trace['fchmod']==trace['fsync']==[] and row['after']==before,'refusal before mutation')
   row['stderr_classification']='expected intended refusal traceback retained in full; exact telemetry separately parsed'
  need(row['after'][envelope.name]==before[envelope.name],'envelope unchanged')
  row['passed']=True;result['missing'].remove(mode)
 result['cases_passed']=4;result['static_mappings_passed']=6
except BaseException:
 result['errors']=1;result['failure_traceback']=traceback.format_exc()
finally:
 result['elapsed_monotonic_ns']=time.monotonic_ns()-START
 if temp is not None and active is None:
  result['temporary_peak_final']=footprint(temp);shutil.rmtree(temp);result['owned_temp_removed_after_known_terminal']=True
 else:result['owned_temp_removed_after_known_terminal']=False
 with (OUT/'native.json').open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
summary={k:result[k] for k in ('errors','failures','missing','elapsed_monotonic_ns')}
for key in ('cases_passed','static_mappings_passed','helper_sha256','frozen_changed_sources_verified','failure_traceback'):
 if key in result:summary[key]=result[key]
print(json.dumps({'native':summary,'common':common,'events_fixture':events},separators=(',',':')),flush=True)
sys.exit(1 if result['errors'] or result['failures'] else 0)
