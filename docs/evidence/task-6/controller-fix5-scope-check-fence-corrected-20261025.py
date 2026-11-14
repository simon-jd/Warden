"""One-off public fix5 artifact check; no project imports/tests/operational calls."""
import time
S=time.monotonic()
import os,signal
signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
signal.setitimer(signal.ITIMER_REAL,max(.001,45-(time.monotonic()-S)))
import hashlib,json,re,resource,stat,subprocess
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(20,20));resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456));resource.setrlimit(resource.RLIMIT_FSIZE,(33554432,33554432))
R=Path(__file__).absolute().parents[3];D='docs/evidence/task-6/';P=D+'controller-caller-integrity-fix5-'
B='50a8f7ca76b65348210752d7a7a93108d4237f8a';C='8bf623b6b5fc04a1d2c0a979a274cfeb3f643f51';E='2c2b869cce28bdfe602e80c5f0415e41492e073c';H='aaad04b685a9b4e8fbece34a416e468f3d8a4728'
OUT=R/(D+'controller-fix5-scope-check-20261025.json')
assert os.getuid()==1000 and not OUT.exists()
def sha(b):return hashlib.sha256(b).hexdigest()
def read(n):return (R/n).read_bytes()
def load(n):return json.loads(read(n))
def git(*a):return subprocess.check_output(['git',*a],cwd=R,timeout=10)
cache={}
def blob(c,n):
 if (c,n) not in cache:cache[c,n]=git('show',c+':'+n)
 return cache[c,n]
def names(a,b):return set(git('diff','--name-only',a,b).decode().splitlines())
ib=read(P+'artifact-sizes.json');v=json.loads(ib);rows=v['artifacts'];i=load(P+'integrity.json');t=load(P+'text-map.json');m=load(P+'missing-and-cleanup.json')
assert len(ib)==96742 and sha(ib)=='7c802eb45741936728fcf73713ddcecaac83578037efd1ad3d794d3bacd26532'
assert len(rows)==v['artifact_count']==310 and v['dispatch_base']==i['dispatch_base']==B and v['source_commit']==i['source_commit']==C
for n,r in rows.items():
 assert n.startswith(P) or n in (D+'continuation-controller-operations-execution-plan.md',D+'controller-approval-writer-plan.md')
 b=read(n);s=(R/n).lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and len(b)==r['bytes'] and sha(b)==r['sha256'] and s.st_blocks*512==r['allocated_bytes']
 assert b==blob(E,n)==blob(H,n)
assert ib==blob(E,P+'artifact-sizes.json')==blob(H,P+'artifact-sizes.json')
assert set(rows)|{P+'artifact-sizes.json'}==names(B,E)
assert sum(r['bytes'] for r in rows.values())==v['logical_bytes_excluding_index']==1988043
assert sum(r['allocated_bytes'] for r in rows.values())==v['allocated_bytes_excluding_index']==2867200
assert sum(r.get('baseline_bytes',0) for r in rows.values())==v['baseline_logical_bytes']==106346
assert sum(r.get('baseline_allocated_bytes',0) for r in rows.values())==v['baseline_allocated_bytes']==110592
assert 1988043-106346==v['net_logical_bytes_excluding_index']==1881697 and 2867200-110592==v['net_allocated_bytes_excluding_index']==2756608
report=read(P+'substage-report.md');assert len(report)==15885 and sha(report)=='3d567146defcc7f58a1a457484987344badd98f195ef1e6903e18561c5b19087'
assert report==(R/'.superpowers/sdd/2-warden-security-plan/task-6-caller-integrity-fix5-report.md').read_bytes()
canon=i['canonical'];assert len(canon['sources'])==150 and len(canon['controller_sources'])==2
frozen={**canon['sources'],**canon['controller_sources']}
for n,h in frozen.items():assert sha(read(n))==h==sha(blob(B,n))==sha(blob(C,n))==sha(blob(H,n))
assert len(i['source_files'])==21 and set(i['source_files'])==names(B,C)
for n,h in i['source_files'].items():assert sha(read(n))==(h['sha256'] if isinstance(h,dict) else h)==sha(blob(C,n))
for kind in ('material','approval'):
 z=t[kind];b=read(D+z['plan']);base=blob(B,D+z['plan']);candidate=read(D+z['candidate'])
 assert len(base)==z['preserved_prefix_bytes'] and sha(base)==z['preserved_prefix_sha256'] and b.startswith(base)
 assert len(b)==z['plan_bytes'] and sha(b)==z['plan_sha256'] and len(candidate)==z['candidate_bytes'] and sha(candidate)==z['candidate_sha256']
 assert b'```javascript\n'+candidate+b'```' in b
body=re.search(rb'const body=String.raw`(.*?)`;',read(P+'approval-candidate.js'),re.S).group(1)
assert len(body)==5657 and sha(body)=='cfe6d2a9db0b2a7d00526a174bcc530fb611e84ecde7bc62a8f1f6ab125530f2'
old=load(D+'controller-four-get-material-artifact-sizes.json')['artifacts'];assert len(old)==139
for n,r in old.items():
 if n==D+'continuation-controller-operations-execution-plan.md':assert read(n)[:r['bytes']]==blob(B,n) and sha(read(n)[:r['bytes']])==r['sha256']
 else:assert len(read(n))==r['bytes'] and sha(read(n))==r['sha256']
assert len(m['native_green1_missing_outputs'])==16
for n in m['native_green1_missing_outputs']:assert not (R/(P+'native-green-01')/n).exists()
for n in m['owned_temporary_roots_confirmed_absent']:assert n.startswith('/tmp/warden-fix5-') and not Path(n).exists()
def chain(x,code):
 assert set(x)=={'request','initial','polls','final'} and x['initial']==x['final'] and x['polls']==[]
 q=x['request'];r=x['final'];assert set(q)=={'cmd','workdir','shell','login','tty','yield_time_ms','max_output_tokens'}
 assert q['cmd'].startswith('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B ')
 assert q['workdir']==str(R) and q['shell']=='/bin/bash' and q['login'] is q['tty'] is False and q['yield_time_ms']==1000
 assert r['exit_code']==code and 'session_id' not in r
 return q,r
js=[];native=[]
for a in i['js_runs']:
 kind=a['kind'];stage=a['stage'];d=P+kind+'-js-'+stage+'-01';baseline=load(d+'/baseline.json');tool=load(d+'/outer-tool-result.json')
 assert baseline['sources']==canon['sources'] and baseline['controller_sources']==canon['controller_sources'] and baseline['dispatch_base']==B
 assert load(d+'/pre-source.json')==load(d+'/post-source.json')==canon['sources'] and load(d+'/pre-controller.json')==load(d+'/post-controller.json')==canon['controller_sources']
 code=load(d+'/pre-code.json');assert code==load(d+'/post-code.json')
 for name,z in code.items():assert len(read(d+'/'+name+'.js'))==z['bytes'] and sha(read(d+'/'+name+'.js'))==z['sha256']
 for phase,tokens in (('pre',18000),('post',3000)):
  q,r=chain(tool[phase],0);assert q['max_output_tokens']==tokens and q['cmd'].endswith('/metadata.py '+phase+' '+a['source_commit_at_launch'])
  assert r['chunk_id']==a['metadata_'+phase+'_chunk'];p=json.loads(r['output']);receipt=load(d+'/'+phase+'-receipt.json')
  assert p['receipt']==receipt and receipt['code']==code and receipt['source_files']==150 and receipt['controller_files']==2
  if phase=='pre':assert p['candidate'].encode()==read(d+'/candidate.js') and p['fixture'].encode()==read(d+'/fixture.js')
  else:assert receipt['equal'] is True
 o=tool['isolate_result'];assert o==a['result'] and o['errors']==o['skipped']==0 and o['actual_nested_tools']==0
 assert o.get('actual_store_interlock_set',False) is False and o.get('actual_interlocks',False) is False
 expected=(1 if kind=='material' else 3) if stage=='red' else (22 if kind=='material' else 35)
 assert o['tests_run']==len(o['cases'])==expected and o['failures']==(expected if stage=='red' else 0)
 if stage=='cover':
  assert a['source_commit_at_launch']==C
  for name in ('candidate','fixture'):assert read(d+'/'+name+'.js')==read(P+kind+'-'+name+'.js')==blob(C,P+kind+'-'+name+'.js')
 js.append({'kind':kind,'stage':stage,'cases':expected,'failures':o['failures'],'metadata_pre':a['metadata_pre_chunk'],'metadata_post':a['metadata_post_chunk']})
for a in i['native_runs']:
 label=a['label'];d=P+'native-'+label;tool=load(d+'/outer-tool-result.json');q,r=chain(tool,a['exit_code']);baseline=load(d+'/baseline.json');intent=load(d+'/intent.json')
 assert baseline['sources']==canon['sources'] and baseline['controller_sources']==canon['controller_sources'] and r['chunk_id']==a['initial_chunk'] and q['max_output_tokens']==3000
 assert q['cmd'].endswith(' '+label+' '+intent['source_commit_at_launch']) and intent['body_sha256']==sha(body) and intent['wall_seconds']==45
 assert intent['parent_limits']=={'as':[536870912,536870912],'cpu':[30,30],'fsize':[33554432,33554432]} and intent['production_paths_accessible'] is False
 assert load(d+'/pre-sources.json')==canon['sources'] and load(d+'/pre-controller_sources.json')==canon['controller_sources']
 code=load(d+'/pre-code.json')
 for name,z in code.items():assert len(read(d+'/'+name))==z['bytes'] and sha(read(d+'/'+name))==z['sha256']
 if label=='green-01':assert a['receipt'] is None and 'JSONDecodeError: Extra data' in r['output']
 else:
  receipt=load(d+'/receipt.json');assert json.loads(r['output'])==receipt==a['receipt'] and receipt['errors']==receipt['skipped']==0
  assert load(d+'/post-sources.json')==canon['sources'] and load(d+'/post-controller_sources.json')==canon['controller_sources'] and load(d+'/post-code.json')==code
  assert receipt['tests_run']==(1 if label=='red-01' else 10) and receipt['failures']==(1 if label=='red-01' else 0)
  for c in receipt['cases']:
   name=c['name'];request=load(d+'/'+name+'-request.json');terminal=load(d+'/'+name+'-terminal.json');stdin=read(d+'/'+name+'-stdin.py')
   assert request['stdin_bytes']==len(stdin) and request['stdin_sha256']==sha(stdin) and stdin.endswith(body) and 0<request['timeout_seconds']<=30
   assert request['env']=={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'} and request['cwd'].startswith('/tmp/warden-fix5-')
   assert terminal['exit_code']==c['exit_code'] and terminal['timed_out'] is False
   assert request['argv'][1:-2]==(['-S','-B'] if label=='red-01' else ['-I','-S','-B'])
  if label=='cover-01':
   assert intent['source_commit_at_launch']==C
   for name in code:assert read(d+'/'+name)==read(D+name)==blob(C,D+name)
 native.append({'label':label,'terminal_chunk':r['chunk_id'],'exit_code':a['exit_code'],'complete':label!='green-01','cases':None if label=='green-01' else a['receipt']['tests_run']})
assert git('diff','--cached','--name-only')==b''
packages=[]
for label,base in (('material','20fdff98c16d51d02cc2d9021bb373b6fb4a2dcf'),('approval','6bbf995e4a069b596660e00d99d81fd9e93a1815')):
 path=R/('.superpowers/sdd/2-warden-security-plan/review-fix5-'+label+'-'+base[:7]+'..'+H[:7]+'.diff');raw=git('diff','--binary',base,H,'--')
 with path.open('xb') as f:f.write(raw)
 packages.append({'scope':label,'base':base,'head':H,'path':str(path.relative_to(R)),'bytes':len(raw),'sha256':sha(raw),'filtering_or_dedup':False})
result={'status':'PASS','scope':'new fix5 artifacts/runs/freeze only; no old proof expansion, project imports, tests or actual operation','dispatch_base':B,'source':C,'evidence':E,'review_head':H,'artifacts':310,'index_bytes':len(ib),'index_sha256':sha(ib),'logical_excluding_index':1988043,'allocated_excluding_index':2867200,'net_logical_excluding_index':1881697,'net_allocated_excluding_index':2756608,'all150plus2_unchanged':True,'approval_python_body_unchanged':True,'old138_bodies_and_plan_prefix_preserved':True,'missing_outputs_preserved':16,'js':js,'native':native,'packages':packages,'elapsed_before_write_seconds':time.monotonic()-S,'physical_startup_termination_bound_proved':False,'actual_admission':False}
assert time.monotonic()-S<45
with OUT.open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps(result,sort_keys=True),flush=True)
assert time.monotonic()-S<45
