import os,sys,resource
fixture_root='/tmp/warden-fix5-k5zmhgjd/root'
fault='cap-fsize'
summary='controller-cache-continuation-v1-20261025-capture-summary.json'
approval='cache-continuation-checkpoint-approval-20261025.json'
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
 exec(compile('import time\nM0=time.monotonic_ns();B0=time.clock_gettime_ns(time.CLOCK_BOOTTIME);A0=time.monotonic_ns()\nimport os,sys,signal,resource\ndef need(ok):\n if not ok:raise ValueError(\'approval refusal\')\ndef check():\n u=time.monotonic_ns();b=time.clock_gettime_ns(time.CLOCK_BOOTTIME);a=time.monotonic_ns()\n need(0<=a-u<=100000000 and 0<=a-M0<=30000000000 and 0<=b-B0<=30000000000)\n need(max(B0-A0,b-a)<=min(B0-M0,b-u))\n return a\nsignal.signal(signal.SIGALRM,lambda *_:os._exit(124))\nneed(0<=A0-M0<=100000000)\ncheck();signal.setitimer(signal.ITIMER_REAL,(30000000000-(time.monotonic_ns()-M0))/1000000000)\nfor k,n in ((resource.RLIMIT_CPU,5),(resource.RLIMIT_AS,134217728),(resource.RLIMIT_FSIZE,1048576)):\n soft,hard=resource.getrlimit(k);need(hard==resource.RLIM_INFINITY or hard>=n);resource.setrlimit(k,(n,n))\nimport json,hashlib,stat,re\nos.umask(0o077)\ndef pairs(items):\n d={}\n for k,v in items:need(k not in d);d[k]=v\n return d\ndef invalid(_):raise ValueError(\'noninteger/nonfinite JSON\')\ndef parse(b):return json.loads(b,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)\ndef raw(v):return (json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False)+\'\\n\').encode()\ndef meta(s):return [getattr(s,\'st_\'+k) for k in (\'dev\',\'ino\',\'uid\',\'gid\',\'mode\',\'nlink\',\'size\',\'mtime_ns\',\'ctime_ns\',\'blocks\')]\ndef sha(b):return hashlib.sha256(b).hexdigest()\nfds=[];dirs=[]\ndef keep(fd):fds.append(fd);return fd\ndef parents():\n for parent,name,fd,before in dirs:\n  now=os.fstat(fd);need(meta(now)[:6]==before[:6])\n  if parent is not None:need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))==meta(now))\n check()\ndef path_read(name,mode):\n check();parents()\n fd=keep(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=public))\n s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==1000 and s.st_nlink==1 and s.st_dev==os.fstat(public).st_dev and stat.S_IMODE(s.st_mode) in mode and 0<s.st_size<=65536)\n data=os.pread(fd,65537,0);need(len(data)==s.st_size and meta(os.fstat(fd))==meta(s) and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==meta(s))\n check();return fd,data,meta(s)\ndef same(fd,name,data,m):\n check();parents()\n need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m and os.pread(fd,65537,0)==data)\n need(meta(os.fstat(fd))==m and meta(os.stat(name,dir_fd=public,follow_symlinks=False))==m)\n check()\ntry:\n need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1000 and len(sys.argv)==2)\n expected=parse(sys.argv[1]);need(type(expected) is dict and set(expected)=={\'sha256\',\'bytes\',\'metadata\'})\n need(type(expected[\'sha256\']) is str and re.fullmatch(\'[0-9a-f]{64}\',expected[\'sha256\']) is not None and type(expected[\'bytes\']) is int and 0<expected[\'bytes\']<=65536)\n need(type(expected[\'metadata\']) is list and len(expected[\'metadata\'])==10 and all(type(x) is int and x>=0 for x in expected[\'metadata\']))\n flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC\n public=keep(os.open(\'/\',flags));dirs.append((None,None,public,meta(os.fstat(public))))\n for part in (\'home\',\'postedism\',\'Desktop\',\'Warden\',\'docs\',\'evidence\',\'task-6\'):\n  parent=public;public=keep(os.open(part,flags,dir_fd=parent));s=os.fstat(public)\n  need(s.st_uid in (0,1000) and not s.st_mode&0o022);dirs.append((parent,part,public,meta(s)))\n summary=\'controller-cache-continuation-v1-20261025-capture-summary.json\'\n approval=\'cache-continuation-checkpoint-approval-20261025.json\'\n sf,data,sm=path_read(summary,(0o600,0o644))\n need(expected=={\'sha256\':sha(data),\'bytes\':len(data),\'metadata\':sm})\n value=parse(data)\n need(type(value) is dict and set(value)=={\'version\',\'state\',\'binding\',\'writer_basis\',\'captured_at\',\'checkpoint_sha256\',\'checkpoint_bytes\'})\n need(type(value[\'version\']) is int and value[\'version\']==1 and value[\'state\']==\'checkpoint-captured-not-approved\')\n need(type(value[\'binding\']) is dict and type(value[\'writer_basis\']) is str and 0<len(value[\'writer_basis\'].encode())<=4096 and type(value[\'captured_at\']) is str)\n need(type(value[\'checkpoint_sha256\']) is str and re.fullmatch(\'[0-9a-f]{64}\',value[\'checkpoint_sha256\']) is not None and type(value[\'checkpoint_bytes\']) is int and 0<value[\'checkpoint_bytes\']<=16000000)\n need(data==raw(value)) # accepted source\'s canonical serializer\n old=b\'"state":"checkpoint-captured-not-approved"\';need(data.count(old)==1)\n approved=data.replace(old,b\'"state":"approved"\',1)\n want=dict(value);want[\'state\']=\'approved\';need(parse(approved)==want and len(approved)<=65536)\n same(sf,summary,data,sm)\n af=keep(os.open(approval,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=public))\n created=meta(os.fstat(af));need(created[2]==created[3]==1000 and created[4]==stat.S_IFREG|0o600 and created[5]==1)\n same(sf,summary,data,sm);offset=0\n while offset<len(approved):\n  check();n=os.write(af,approved[offset:]);need(n>0);offset+=n\n check();os.fsync(af);check();final=meta(os.fstat(af))\n need(final[:6]==created[:6] and final[6]==len(approved))\n same(af,approval,approved,final);same(sf,summary,data,sm)\n os.fsync(public);check()\n same(af,approval,approved,final);same(sf,summary,data,sm)\n rf,readback,rm=path_read(approval,(0o600,));need(rm==final and readback==approved)\n same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)\n output={\'approval\':{\'bytes\':len(approved),\'metadata\':final,\'sha256\':sha(approved)}}\n sys.stdout.write(raw(output).decode());sys.stdout.flush()\n same(af,approval,approved,final);same(rf,approval,approved,final);same(sf,summary,data,sm)\n check()\nexcept BaseException:\n raise SystemExit(1)\nfinally:\n for fd in reversed(fds):os.close(fd)\ncheck()\n','<unchanged-approval-body>','exec'),{'__name__':'__main__'})
finally:
 sys.stdout=original_stdout
 import json
 telemetry={'counts':counts,'held_remaining':len(held),'injected':injected,'flags':{'isolated':sys.flags.isolated,'no_site':sys.flags.no_site,'dont_write_bytecode':sys.flags.dont_write_bytecode},'site_loaded':'site' in sys.modules,'origins':{n:getattr(sys.modules.get(n),'__file__',None) for n in ('signal','json','resource')},'limits':{n:list(resource.getrlimit(k)) for n,k in [('cpu',resource.RLIMIT_CPU),('as',resource.RLIMIT_AS),('fsize',resource.RLIMIT_FSIZE)]}}
 sys.stderr.write('FIXTURE_TELEMETRY '+json.dumps(telemetry,sort_keys=True)+'\n');sys.stderr.flush()
