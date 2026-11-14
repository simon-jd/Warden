#!/usr/bin/env python3
# Earliest measured deadline covers setup, maps, children, observations and output.
import time
START=time.monotonic();END=START+45
import os,signal
CHILD=None
def expired(*_):
 if CHILD is not None and CHILD.poll() is None: CHILD.kill()
 os._exit(124)
def remaining():
 n=END-time.monotonic()
 if n<=0:expired()
 return n
signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,remaining())
import resource
for k,n in ((resource.RLIMIT_CPU,30),(resource.RLIMIT_AS,536870912),(resource.RLIMIT_FSIZE,33554432)):
 soft,hard=resource.getrlimit(k)
 if hard!=resource.RLIM_INFINITY and hard<n:raise RuntimeError('parent inherited ceiling')
 resource.setrlimit(k,(n,n))
import hashlib,json,sys,tempfile,subprocess,stat,traceback
from pathlib import Path
os.umask(0o077)
ROOT=Path(__file__).absolute().parents[3];D=ROOT/'docs/evidence/task-6'
assert len(sys.argv)==3 and sys.argv[1] in ('red-01','green-01','green-02','cover-01')
LABEL=sys.argv[1];OUT=D/('controller-caller-integrity-fix5-native-'+LABEL);OUT.mkdir(mode=0o700)
BASE=json.loads((D/'controller-caller-integrity-fix5-baseline.json').read_text())
def save(n,v):
 with (OUT/n).open('x') as f:f.write(json.dumps(v,sort_keys=True,indent=2)+'\n')
def digest(b):return hashlib.sha256(b).hexdigest()
def maps(phase):
 for group in ('sources','controller_sources'):
  m={n:digest((ROOT/n).read_bytes()) for n in BASE[group]};save(phase+'-'+group+'.json',m);assert m==BASE[group]
 code={}
 for n in ('controller-caller-integrity-fix5-material-candidate.js','controller-caller-integrity-fix5-approval-candidate.js','controller-caller-integrity-fix5-material-fixture.js','controller-caller-integrity-fix5-approval-fixture.js',Path(__file__).name):
  b=(D/n).read_bytes();code[n]={'bytes':len(b),'sha256':digest(b)}
  if phase=='pre':(OUT/n).write_bytes(b)
 save(phase+'-code.json',code)
 if phase=='post':assert code==json.loads((OUT/'pre-code.json').read_text())
 remaining()
assert os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000,'fixture requires real UID/GID1000'
source=(D/'controller-caller-integrity-fix5-approval-candidate.js').read_text()
BODY=source.split('const body=String.raw`',1)[1].split('`;\nconst request=',1)[0]
assert len(BODY.encode())==5657 and digest(BODY.encode())=='cfe6d2a9db0b2a7d00526a174bcc530fb611e84ecde7bc62a8f1f6ab125530f2'
SUMMARY='controller-cache-continuation-v1-20261025-capture-summary.json';APPROVAL='cache-continuation-checkpoint-approval-20261025.json'
CHAIN=('home','postedism','Desktop','Warden','docs','evidence','task-6')
# This prefix imports no signal; the selected cwd sentinel is still reachable in RED.
PREFIX=r'''import os,sys,resource
fixture_root=ROOT_LITERAL
fault=FAULT_LITERAL
summary=SUMMARY_LITERAL
approval=APPROVAL_LITERAL
chain=('home','postedism','Desktop','Warden','docs','evidence','task-6')
real_open,real_stat,real_fstat=os.open,os.stat,os.fstat
real_pread,real_write,real_fsync,real_close=os.pread,os.write,os.fsync,os.close
held={};counts={'root_routes':0,'opens':0,'writes':0,'fsyncs':0,'preads':0,'blocked':0};injected=False
flags_dir=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
flags_read=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
flags_create=os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC
def reject():
 counts['blocked']+=1;raise RuntimeError('fixture path/FD firewall')
def checked(fd):
 if fd not in held:reject()
 return held[fd]
def opened(path,flags,mode=0o777,*,dir_fd=None):
 if dir_fd is None:
  if path!='/' or flags!=flags_dir or counts['root_routes']!=0:reject()
  counts['root_routes']+=1;fd=real_open(fixture_root,flags);held[fd]=('dir',-1)
 else:
  kind,stage=checked(dir_fd)
  if kind!='dir' or type(path) is not str or '/' in path or path in ('.','..'):reject()
  if stage<len(chain)-1:
   if path!=chain[stage+1] or flags!=flags_dir:reject()
   fd=real_open(path,flags,dir_fd=dir_fd);held[fd]=('dir',stage+1)
  else:
   if path not in (summary,approval):reject()
   if not (flags==flags_read or path==approval and flags==flags_create and mode==0o600):reject()
   fd=real_open(path,flags,mode,dir_fd=dir_fd);held[fd]=(path,stage)
 counts['opens']+=1;return fd
def stated(path,*,dir_fd=None,follow_symlinks=True):
 kind,stage=checked(dir_fd)
 if kind!='dir' or follow_symlinks is not False:reject()
 allowed=(chain[stage+1],) if stage<len(chain)-1 else (summary,approval)
 if path not in allowed:reject()
 return real_stat(path,dir_fd=dir_fd,follow_symlinks=False)
def fstated(fd):checked(fd);return real_fstat(fd)
def pread(fd,n,offset):
 checked(fd);counts['preads']+=1;return real_pread(fd,n,offset)
def write(fd,b):
 if checked(fd)[0]!=approval:reject()
 counts['writes']+=1
 return real_write(fd,b[:7] if fault=='short-write' and counts['writes']==1 else b)
def fsync(fd):
 kind,stage=checked(fd);counts['fsyncs']+=1
 if fault=='dir-fsync' and kind=='dir':raise OSError('fixture dir fsync failure')
 return real_fsync(fd)
def close(fd):checked(fd);real_close(fd);del held[fd]
os.open,os.stat,os.fstat=opened,stated,fstated
os.pread,os.write,os.fsync,os.close=pread,write,fsync,close
# Self-check firewall before body: no real open/stat is reached by these denials.
for forbidden in ('/home/postedism/Desktop/Warden/docs/evidence/task-6/'+summary,'../'+summary):
 try:opened(forbidden,flags_read)
 except RuntimeError:pass
 else:raise AssertionError('firewall missing')
original_stdout=sys.stdout
class Output:
 def __init__(self):self.printed=False
 def write(self,s):self.printed|='"approval":' in s;return original_stdout.write(s)
 def flush(self):
  global injected
  original_stdout.flush()
  if fault=='post-output' and self.printed and not injected:
   injected=True
   public=next(fd for fd,value in held.items() if value==('dir',6))
   fd=real_open(summary,os.O_WRONLY|os.O_NOFOLLOW,dir_fd=public)
   try:real_write(fd,b'!')
   finally:real_close(fd)
 def __getattr__(self,k):return getattr(original_stdout,k)
sys.stdout=Output()
if fault.startswith('cap-'):
 key={'cap-cpu':resource.RLIMIT_CPU,'cap-as':resource.RLIMIT_AS,'cap-fsize':resource.RLIMIT_FSIZE}[fault]
 limit={'cap-cpu':4,'cap-as':67108864,'cap-fsize':524288}[fault];resource.setrlimit(key,(limit,limit))
try:
 exec(compile(BODY_LITERAL,'<unchanged-approval-body>','exec'),{'__name__':'__main__'})
finally:
 sys.stdout=original_stdout
 import json
 telemetry={'counts':counts,'held_remaining':len(held),'injected':injected,'flags':{'isolated':sys.flags.isolated,'no_site':sys.flags.no_site,'dont_write_bytecode':sys.flags.dont_write_bytecode},'site_loaded':'site' in sys.modules,'origins':{n:getattr(sys.modules.get(n),'__file__',None) for n in ('signal','json','resource')},'limits':{n:list(resource.getrlimit(k)) for n,k in [('cpu',resource.RLIMIT_CPU),('as',resource.RLIMIT_AS),('fsize',resource.RLIMIT_FSIZE)]}}
 sys.stderr.write('FIXTURE_TELEMETRY '+json.dumps(telemetry,sort_keys=True)+'\n');sys.stderr.flush()
'''
results=[];save('baseline.json',BASE);maps('pre')
save('intent.json',{'dispatch_base':BASE['dispatch_base'],'source_commit_at_launch':sys.argv[2],'label':LABEL,'parent_limits':{n:list(resource.getrlimit(k)) for n,k in [('cpu',resource.RLIMIT_CPU),('as',resource.RLIMIT_AS),('fsize',resource.RLIMIT_FSIZE)]},'wall_seconds':45,'production_paths_accessible':False,'old_launch_seam':'-S -B disables unrelated real site while preserving cwd import exposure; old full -B startup is not executed','optional_site_view':'not used; sys.flags/no site/stdlb origins observed','body_sha256':digest(BODY.encode())})
cases=['old-cwd-sentinel'] if LABEL.startswith('red') else ['happy','existing','symlink','wrong-proof','short-write','dir-fsync','post-output','cap-cpu','cap-as','cap-fsize']
def meta(s):return [getattr(s,'st_'+k) for k in ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns','blocks')]
for name in cases:
 remaining();result={'name':name}
 with tempfile.TemporaryDirectory(prefix='warden-fix5-') as temporary:
  temp=Path(temporary);root=temp/'root';root.mkdir(mode=0o700);public=root
  for part in CHAIN:public=public/part;public.mkdir(mode=0o700)
  cwd=temp/'cwd';cwd.mkdir(mode=0o700);sentinel=cwd/'signal.py';hit=cwd/'sentinel-hit'
  sentinel.write_text('with open('+repr(str(hit))+",'x') as f:f.write('cwd sentinel')\nraise SystemExit(73)\n")
  value={'version':1,'state':'checkpoint-captured-not-approved','binding':{'fixture':True},'writer_basis':'generated fixture','captured_at':'generated','checkpoint_sha256':'a'*64,'checkpoint_bytes':123}
  raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();summary=public/SUMMARY;summary.write_bytes(raw);summary.chmod(0o600)
  before=meta(summary.stat());assert before[7]>2**53
  expected={'bytes':len(raw),'metadata':before,'sha256':digest(raw)}
  if name=='wrong-proof':expected['sha256']='b'*64
  existing=b'preexisting approval\n';approval=public/APPROVAL
  if name=='existing':approval.write_bytes(existing);approval.chmod(0o600)
  if name=='symlink':approval.symlink_to(SUMMARY)
  script=PREFIX
  for token,value_ in [('ROOT_LITERAL',repr(str(root))),('FAULT_LITERAL',repr(name)),('SUMMARY_LITERAL',repr(SUMMARY)),('APPROVAL_LITERAL',repr(APPROVAL)),('BODY_LITERAL',repr(BODY))]:script=script.replace(token,value_)
  flags=['-S','-B'] if name=='old-cwd-sentinel' else ['-I','-S','-B']
  args=['/usr/bin/python3',*flags,'-',json.dumps(expected,sort_keys=True,separators=(',',':'))]
  request={'argv':args,'env':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},'cwd':str(cwd),'stdin_sha256':digest(script.encode()),'stdin_bytes':len(script.encode()),'timeout_seconds':min(30,remaining()-1)}
  assert request['timeout_seconds']>0
  (OUT/(name+'-stdin.py')).write_text(script);save(name+'-request.json',request)
  CHILD=subprocess.Popen(args,cwd=cwd,env=request['env'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  timedout=False
  try:stdout,stderr=CHILD.communicate(script.encode(),timeout=request['timeout_seconds'])
  except subprocess.TimeoutExpired:
   timedout=True;CHILD.terminate()
   try:stdout,stderr=CHILD.communicate(timeout=min(0.2,remaining()))
   except subprocess.TimeoutExpired:CHILD.kill();stdout,stderr=CHILD.communicate(timeout=remaining())
  result.update(exit_code=CHILD.returncode,stdout=stdout.decode(),stderr=stderr.decode(),timed_out=timedout);CHILD=None
  save(name+'-terminal.json',result)
  telemetry_lines=[line for line in stderr.decode().splitlines() if line.startswith('FIXTURE_TELEMETRY ')]
  assert len(telemetry_lines)==1
  telemetry=json.loads(telemetry_lines[0][len('FIXTURE_TELEMETRY '):]);result['telemetry']=telemetry
  result['sentinel_observed']=hit.exists();result['summary_unchanged']=summary.read_bytes()==raw
  result['approval_exists']=approval.exists();result['approval_symlink']=approval.is_symlink()
  if approval.exists() and not approval.is_symlink():result['approval_bytes_hex']=approval.read_bytes().hex();result['approval_metadata']=meta(approval.stat())
  (OUT/(name+'-summary-observed.bin')).write_bytes(summary.read_bytes())
  if approval.exists() and not approval.is_symlink():(OUT/(name+'-approval-observed.bin')).write_bytes(approval.read_bytes())
  try:
   assert not timedout
   if name=='old-cwd-sentinel':
    assert result['exit_code']==73 and hit.exists() and not approval.exists() and telemetry['counts']['root_routes']==0
    result.update(passed=False,expected_regression_observed=True)
   else:
    assert not hit.exists() and telemetry['flags']=={'isolated':1,'no_site':1,'dont_write_bytecode':1} and not telemetry['site_loaded']
    for n,path in telemetry['origins'].items():
     if path is not None:assert path.startswith('/usr/lib/python3.') or path.startswith('/usr/lib/python3/'),(n,path)
    if name in ('happy','short-write'):
     want=raw.replace(b'"state":"checkpoint-captured-not-approved"',b'"state":"approved"',1)
     assert result['exit_code']==0 and approval.read_bytes()==want and stat.S_IMODE(approval.stat().st_mode)==0o600 and result['summary_unchanged']
     observed=json.loads(stdout);assert set(observed)=={'approval'} and observed['approval']=={'bytes':len(want),'metadata':meta(approval.stat()),'sha256':digest(want)}
     assert stdout==(json.dumps(observed,sort_keys=True,separators=(',',':'))+'\n').encode()
     assert telemetry['counts']['fsyncs']==2 and telemetry['counts']['preads']>=3 and telemetry['held_remaining']==0
     assert telemetry['limits']=={'cpu':[5,5],'as':[134217728,134217728],'fsize':[1048576,1048576]}
     if name=='short-write':assert telemetry['counts']['writes']==2
    else:
     assert result['exit_code']!=0
     if name=='existing':assert approval.read_bytes()==existing
     if name=='symlink':assert approval.is_symlink() and os.readlink(approval)==SUMMARY
     if name in ('wrong-proof','cap-cpu','cap-as','cap-fsize'):assert not approval.exists()
     if name=='dir-fsync':assert approval.exists() and stdout==b''
     if name=='post-output':assert stdout.startswith(b'{"approval":') and telemetry['injected'] and not result['summary_unchanged']
     if name!='post-output':assert result['summary_unchanged']
     if name.startswith('cap-'):assert telemetry['counts']['root_routes']==0
    result['passed']=True
   assert telemetry['counts']['blocked']==2
  except BaseException:result.update(passed=False,assertion_error=traceback.format_exc())
  save(name+'-observation.json',result);results.append(result)
 remaining()
maps('post')
failed=sum(not r['passed'] for r in results)
receipt={'tests_run':len(results),'failures':failed,'errors':0,'skipped':0,'expected_regression_observed':LABEL.startswith('red') and all(r.get('expected_regression_observed') for r in results),'cases':[{k:r.get(k) for k in ('name','passed','exit_code','expected_regression_observed','assertion_error')} for r in results],'elapsed_seconds':time.monotonic()-START,'source_unchanged':True,'body_unchanged':True,'physical_production_integration':False,'timing_scope':'earliest measured parent entry through maps/output; startup and physical termination unproved'}
save('receipt.json',receipt);print(json.dumps(receipt,sort_keys=True),flush=True);remaining();signal.setitimer(signal.ITIMER_REAL,0)
raise SystemExit(1 if failed else 0)
