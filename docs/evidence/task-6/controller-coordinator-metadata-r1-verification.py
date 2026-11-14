"""ONE finite affected native check. Never import or launch project code."""
import time
START=time.monotonic_ns();END=START+45000000000
import os,sys,signal,resource
signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
remaining=(END-time.monotonic_ns())/1000000000
if remaining<=0:os._exit(124)
signal.setitimer(signal.ITIMER_REAL,remaining)
for key,cap in ((resource.RLIMIT_CPU,20),(resource.RLIMIT_AS,268435456),(resource.RLIMIT_FSIZE,2097152)):
 resource.setrlimit(key,(cap,cap))
import json,hashlib,stat,tempfile,subprocess,traceback,shutil
from pathlib import Path
W=Path('/home/postedism/Desktop/Warden');D=W/'docs/evidence/task-6'
N='controller-coordinator-metadata-r1';P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-'
OUT=D/(N+'-verification');OUT.mkdir(mode=0o700)
def need(value,message):
 if not value:raise AssertionError(message)
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
def sample():
 u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()
 return {'monotonic_before_ns':u,'boottime_ns':b,'monotonic_after_ns':a,'birth_boot_lower_ns':b}
def snap(path):
 s=path.lstat();row={'metadata':meta(s)}
 if stat.S_ISREG(s.st_mode):row['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
 elif stat.S_ISLNK(s.st_mode):row['link']=os.readlink(path)
 return row
def footprint(path):
 seen=set();total=0
 for base,dirs,files in os.walk(path,followlinks=False):
  for p in [Path(base)]+[Path(base)/n for n in dirs+files]:
   s=p.lstat();key=(s.st_dev,s.st_ino)
   if key not in seen:total+=s.st_blocks*512;seen.add(key)
 need(total<=5242880,'owned temporary allocation exceeds 5MiB');return total

# Only the first literal root open is routed. Every subsequent path/FD operation
# is fenced; replacement injection uses saved functions on known owned files.
PREFIX=r'''import os,sys,time,signal,resource,json,hashlib,stat
_root=ROOT_LITERAL
_mode=MODE_LITERAL
_P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-'
_parts=('home','postedism','Desktop','Warden','docs','evidence','task-6')
_names=(_P+'receipt.json',_P+'root-tool.json',_P+'root-proof-reader-tool.json')
_df=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
_ff=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
_open,_stat,_fstat,_pread,_close,_chmod,_sync=os.open,os.stat,os.fstat,os.pread,os.close,os.fchmod,os.fsync
_rename=os.rename
_held={};_root_used=False;_chmods=[];_syncs=[];_opens=[];_replaced=False
def _need(v):
 if not v:raise RuntimeError('fixture path/FD firewall')
def _o(path,flags,mode=0o777,*,dir_fd=None):
 global _root_used,_replaced
 if dir_fd is None:
  _need(not _root_used and path=='/' and flags==_df);_root_used=True
  fd=_open(_root,flags);_held[fd]=('dir',0);_opens.append('ROUTED_ROOT');return fd
 _need(dir_fd in _held and _held[dir_fd][0]=='dir')
 depth=_held[dir_fd][1]
 if depth<len(_parts):
  _need(path==_parts[depth] and flags==_df);fd=_open(path,flags,dir_fd=dir_fd);_held[fd]=('dir',depth+1)
 else:
  _need(path in _names and flags==_ff)
  if _mode=='replacement' and path==_names[2]:
   _need(not _replaced);_replaced=True
   _rename(_names[1],'displaced.raw',src_dir_fd=dir_fd,dst_dir_fd=dir_fd)
   _rename('prepared.raw',_names[1],src_dir_fd=dir_fd,dst_dir_fd=dir_fd)
  fd=_open(path,flags,dir_fd=dir_fd);_held[fd]=('file',path)
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
 _need(fd in _held and _held[fd][0]=='file' and _held[fd][1] in _names[1:] and mode==0o600)
 _chmods.append(_held[fd][1]);return _chmod(fd,mode)
def _y(fd):
 _need(fd in _held and _held[fd][0]=='file' and _held[fd][1] in _names[1:]);_syncs.append(_held[fd][1]);return _sync(fd)
os.open,os.stat,os.fstat,os.pread,os.close,os.fchmod,os.fsync=_o,_s,_f,_p,_c,_m,_y
try:
 exec(compile(BODY_LITERAL,'<unchanged-metadata-body>','exec'),{})
finally:
 sys.stderr.write('WARDEN_COORD_R1_FD_TELEMETRY '+json.dumps({'root_routed':_root_used,'opens':_opens,'fchmod':_chmods,'fsync':_syncs,'held_count':len(_held),'replacement_injected':_replaced},separators=(',',':'))+'\n');sys.stderr.flush()
'''
result={'scope':'four FD groups / five finite children only','cases':[],'failures':0,'errors':0,'missing':['happy','wrong-intended','replacement','symlink','hardlink'],'limits':{'wall_seconds':45,'cpu_seconds':20,'address_bytes':268435456,'file_bytes':2097152,'temporary_bytes':5242880},'real_runtime_paths_accessed':False}
temp=None;active=None;candidate=None;events=None
try:
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000,'ordinary identity')
 frozen=json.loads((D/(N+'-source-manifest.json')).read_text())
 for name,entry in frozen['files'].items():
  source=(W/name).read_bytes();need(len(source)==entry['bytes'] and hashlib.sha256(source).hexdigest()==entry['sha256'],'changed source freeze binding: '+name)
 result['frozen_changed_sources_verified']=len(frozen['files'])
 candidate=(D/(N+'-material-candidate.js')).read_text();events=(D/(N+'-events-fixture.js')).read_text()
 begin='const metadataBody=String.raw`';need(candidate.count(begin)==1,'one metadata body')
 body=candidate.split(begin,1)[1].split('`;\nfunction shellQuote',1)[0]
 need(body.endswith('\n') and len(body.encode())<8192,'bounded unchanged helper body')
 result['helper_sha256']=hashlib.sha256(body.encode()).hexdigest()
 temp=Path(tempfile.mkdtemp(prefix='warden-coord-r1-'));temp.chmod(0o700);result['owned_temp']=str(temp)
 for mode in ('happy','wrong-intended','replacement','symlink','hardlink'):
  need(time.monotonic_ns()<END,'wrapper remaining deadline')
  root=temp/mode;root.mkdir(mode=0o700);public=root
  for part in ('home','postedism','Desktop','Warden','docs','evidence','task-6'):
   public/=part;public.mkdir(mode=0o700)
  raw=public/(P+'root-tool.json');reader=public/(P+'root-proof-reader-tool.json');receipt=public/(P+'receipt.json')
  rawbytes=b'{"fixture":"raw apostrophe \' retained"}\n';readerbytes=b'{"fixture":"reader exact bytes"}\n'
  raw.write_bytes(rawbytes);reader.write_bytes(readerbytes);raw.chmod(0o664);reader.chmod(0o664)
  first=sample();last=sample();identity={'machine_id':'fixture-only','boot_id':'fixture-only'}
  receiptbytes=(json.dumps({'clock_identity':identity,'timing':{'origin':{'budget_start_monotonic_lower_ns':first['monotonic_before_ns'],'sample':first},'final_sample':last,'ended_monotonic_ns':time.monotonic_ns()}},separators=(',',':'))+'\n').encode()
  receipt.write_bytes(receiptbytes);receipt.chmod(0o600)
  proof={'bytes':len(receiptbytes),'metadata':meta(receipt.stat()),'sha256':hashlib.sha256(receiptbytes).hexdigest()}
  need(proof['metadata'][7]>9007199254740991,'real nanosecond integer fidelity')
  if mode=='replacement':
   prepared=public/'prepared.raw';prepared.write_bytes(rawbytes);prepared.chmod(0o664)
  elif mode=='symlink':raw.unlink();raw.symlink_to(reader.name)
  elif mode=='hardlink':reader.unlink();os.link(raw,reader)
  before={p.name:snap(p) for p in public.iterdir()}
  data={'collector':json.dumps({'receipt':proof,'clock_identity':identity},separators=(',',':')),'raw':(rawbytes if mode!='wrong-intended' else b'{"fixture":"different intended bytes"}\n').decode(),'reader':readerbytes.decode()}
  stdin=PREFIX.replace('ROOT_LITERAL',repr(str(root))).replace('MODE_LITERAL',repr(mode)).replace('BODY_LITERAL',repr(body))
  argv=[sys.executable,'-I','-S','-B','-',json.dumps(data,separators=(',',':'))]
  row={'case':mode,'request':{'argv':argv,'stdin':stdin,'cwd':str(root),'env':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}},'receipt_proof':proof,'before':before,'temporary_allocated_before':footprint(temp)}
  result['cases'].append(row)
  child_end=min(END,time.monotonic_ns()+5000000000)
  active=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=root,env=row['request']['env'])
  row['owned_pid']=active.pid
  try:stdout,stderr=active.communicate(stdin.encode(),timeout=max(0,(child_end-time.monotonic_ns())/1e9))
  except subprocess.TimeoutExpired:
   active.kill();stdout,stderr=active.communicate();row.update({'stdout':stdout.decode(),'stderr':stderr.decode(),'exit_code':active.returncode,'timed_out':True});active=None;raise
  row.update({'stdout':stdout.decode(),'stderr':stderr.decode(),'exit_code':active.returncode,'timed_out':False});active=None
  row['after']={p.name:snap(p) for p in public.iterdir()};row['temporary_allocated_after']=footprint(temp)
  tag='WARDEN_COORD_R1_FD_TELEMETRY ';lines=stderr.decode().splitlines();telemetry=[line[len(tag):] for line in lines if line.startswith(tag)]
  need(len(telemetry)==1,'unique exact telemetry line');trace=json.loads(telemetry[0]);row['telemetry']=trace
  need(set(trace)=={'root_routed','opens','fchmod','fsync','held_count','replacement_injected'} and trace['root_routed'] is True and type(trace['held_count']) is int and trace['held_count']==0,'strict telemetry schema')
  need(type(trace['opens']) is list and trace['opens']==['ROUTED_ROOT','home','postedism','Desktop','Warden','docs','evidence','task-6',P+'receipt.json']+([P+'root-tool.json',P+'root-proof-reader-tool.json'] if mode in ('happy','replacement') else [P+'root-tool.json'] if mode in ('wrong-intended','hardlink') else []),'bounded routed opens')
  need(trace['replacement_injected'] is (mode=='replacement'),'replacement seam')
  if mode=='happy':
   need(row['exit_code']==0 and stdout==b'{"state":"material-metadata-finalized","authority":false}\n' and len(lines)==1,'happy known terminal')
   need(trace['fchmod']==trace['fsync']==[raw.name,reader.name],'only two fixed fds mutated')
   for p in (raw,reader):
    old=before[p.name];now=row['after'][p.name];need(now['metadata'][4]==stat.S_IFREG|0o600 and now['sha256']==old['sha256'] and all(now['metadata'][i]==old['metadata'][i] for i in (0,1,2,3,5,6,7,9)),'happy bytes/inode preserved')
  else:
   need(row['exit_code']==1 and stdout==b'' and 'Traceback (most recent call last):' in stderr.decode(),'expected bounded refusal')
   need(trace['fchmod']==trace['fsync']==[],'refusal before mutation')
   row['stderr_classification']='expected refusal traceback retained in full; only exact telemetry separately parsed'
   if mode=='replacement':
    need(row['after']['displaced.raw']['metadata'][:2]==before[raw.name]['metadata'][:2] and row['after'][raw.name]['metadata'][:2]==before['prepared.raw']['metadata'][:2],'replacement identities')
    for name in ('displaced.raw',raw.name):need(row['after'][name]['sha256']==before[raw.name]['sha256'] and row['after'][name]['metadata'][4]==stat.S_IFREG|0o664,'replacement retained bytes/mode')
    need(row['after'][reader.name]==before[reader.name],'reader unchanged on replacement')
   else:need(row['after']==before,'refused inputs fully unchanged')
  need(row['after'][receipt.name]==before[receipt.name],'read-only receipt')
  row['passed']=True;result['missing'].remove(mode)
 result['groups_passed']=4;result['children_passed']=5
except BaseException:
 result['errors']=1;result['failure_traceback']=traceback.format_exc()
finally:
 result['elapsed_monotonic_ns']=time.monotonic_ns()-START
 if temp is not None and active is None:
  result['temporary_peak_final']=footprint(temp);shutil.rmtree(temp);result['owned_temp_removed_after_known_terminal']=True
 else:result['owned_temp_removed_after_known_terminal']=False
 with (OUT/'native.json').open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
summary={k:result[k] for k in ('errors','failures','missing','elapsed_monotonic_ns')}
for key in ('groups_passed','children_passed','helper_sha256','frozen_changed_sources_verified','failure_traceback'):
 if key in result:summary[key]=result[key]
print(json.dumps({'native':summary,'candidate':candidate,'events_fixture':events},separators=(',',':')),flush=True)
sys.exit(1 if result['errors'] or result['failures'] else 0)
