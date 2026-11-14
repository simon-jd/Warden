#!/usr/bin/env python3
"""Root public/Git metadata corroboration only; no project imports or test reruns."""
import time
START = time.monotonic()
import os
import signal
signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
signal.setitimer(signal.ITIMER_REAL, max(.001, 45-(time.monotonic()-START)))
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import resource
import stat
import subprocess
resource.setrlimit(resource.RLIMIT_CPU, (20,20))
resource.setrlimit(resource.RLIMIT_AS, (268435456,268435456))
resource.setrlimit(resource.RLIMIT_FSIZE, (33554432,33554432))
ROOT=Path(__file__).absolute().parents[3]
BASE='c2436684c511bf2ae92982fb8141b1b7d0c41ee9'
FIX_BASE='bb7224cdc9ce4106b39c3a7ddad514d9e5ac6175'
SOURCE='2c911c8ca2b8148f47380bab53c732ed0bc17f62'
WORKER='46adcd26574437d83e8fc0a109ff85db5c780794'
HEAD='c836a235b0c1760fa1ffebbcac0ae4ab2546bbb8'
D='docs/evidence/task-6/'
INDEX=D+'controller-terminal-reconcile-fix4-artifact-sizes.json'
OUT=ROOT/(D+'controller-terminal-fix4-verification-20261025.json')
PACKAGE=ROOT/'.superpowers/sdd/2-warden-security-plan/review-bb7224c..c836a23.diff'
VIEW=PACKAGE.with_name('review-bb7224c..c836a23-deduplicated-view.diff')
SOURCE_PATHS={D+'controller-cache-continuation-outer-invoker-20261025.py', D+'test_controller_cache_continuation_invoker_20261025.py'}
assert os.getuid()==os.getgid()==1000 and not OUT.exists() and not VIEW.exists()
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,timeout=10)
cache={}
def body(c,n):
    if (c,n) not in cache:cache[c,n]=git('show',c+':'+n)
    return cache[c,n]
def load(n):return json.loads((ROOT/n).read_bytes())
def changed(a,b):return set(git('diff','--name-only',a,b).decode().splitlines())
ib=(ROOT/INDEX).read_bytes();v=json.loads(ib);rows=v['artifacts']
assert len(ib)==19413 and sha(ib)=='1a52be45121aecc695f81838053b8585866ae83200774f028832bb584da51edd'
assert v['dispatch_base']==BASE and v['review_fix_base']==FIX_BASE and v['source_commit']==SOURCE
assert len(rows)==v['artifact_count']==42 and v['index_self_excluded']
plan=D+'continuation-controller-operations-execution-plan.md'
report=D+'controller-terminal-reconcile-substage-report.md'
for n,r in rows.items():
    assert not Path(n).is_absolute() and '..' not in Path(n).parts
    assert n in SOURCE_PATHS|{plan,report} or n.startswith(D+'controller-terminal-reconcile-fix4-')
    b=(ROOT/n).read_bytes();s=(ROOT/n).lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and len(b)==r['bytes'] and sha(b)==r['sha256'] and s.st_blocks*512==r['allocated_bytes']
    assert b==body(WORKER,n)==body(HEAD,n)
assert ib==body(WORKER,INDEX)==body(HEAD,INDEX)
assert changed(BASE,SOURCE)==SOURCE_PATHS
assert changed(BASE,WORKER)==set(rows)|{INDEX}
assert sum(r['bytes'] for r in rows.values())==v['package_logical_bytes']==676517
assert sum(r['allocated_bytes'] for r in rows.values())==v['package_allocated_bytes']==782336
old=v['old_sizes_and_allocations_for_net']
assert set(old)==SOURCE_PATHS|{plan,report}
for n,r in old.items():assert len(body(BASE,n))==r['bytes'] and sha(body(BASE,n))==r['sha256']
assert 676517-sum(r['bytes'] for r in old.values())==v['incremental_logical_bytes_vs_dispatch_excluding_index']==526619
assert 782336-sum(r['allocated_bytes'] for r in old.values())==v['incremental_allocated_bytes_vs_prior_indexed_baseline_excluding_index']==622592
for n,r in v['preserved_prefixes'].items():
    b=(ROOT/n).read_bytes();old_b=body(BASE,n)
    assert len(old_b)==r['bytes'] and sha(old_b)==r['sha256'] and b.startswith(old_b)
assert len(body(BASE,plan))==58113 and len((ROOT/plan).read_bytes())==60832
assert len(body(BASE,report))==14048 and len((ROOT/report).read_bytes())==27169
assert (ROOT/report).read_bytes()==(ROOT/'.superpowers/sdd/2-warden-security-plan/task-6-terminal-reconcile-source-report.md').read_bytes()
old_name=D+'controller-terminal-reconcile-artifact-sizes.json';ob=(ROOT/old_name).read_bytes();ov=json.loads(ob)
assert ob==body(BASE,old_name)==body(WORKER,old_name) and sha(ob)=='d22cd13338670bea2323ccbbd5873a47a8bafbd827e2a6b334f5920f34ba65bc'
prior={n:r for n,r in ov['artifacts'].items() if n not in SOURCE_PATHS|{plan,report}}
assert len(prior)==75
for n,r in prior.items():assert len((ROOT/n).read_bytes())==r['bytes'] and sha((ROOT/n).read_bytes())==r['sha256']
for key,size in (('preserved_api_sha256',60),('preserved_prior_seven_run_sha256',101)):
    assert len(ov[key])==size and not set(ov[key])&changed(BASE,HEAD)
    for n,h in ov[key].items():assert sha((ROOT/n).read_bytes())==h
for n in v['partial_old_api_missing_unchanged']:assert not (ROOT/n).exists()
history=[];frozen=None;canonical_base=None;controller_base=None
for stage,tests,failures,code in [('red-01',7,11,1),('green-01',12,0,0),('cover-01',74,0,0)]:
    d=D+'controller-terminal-reconcile-fix4-'+stage
    baseline=load(d+'/baseline.json');pre=load(d+'/pre-source.json');post=load(d+'/post-source.json')
    pc=load(d+'/pre-controller.json');qc=load(d+'/post-controller.json');receipt=load(d+'/receipt.json');tool=load(d+'/outer-tool-result.json')
    if canonical_base is None:
        canonical_base=baseline['sources'];controller_base=baseline['controller_sources']
        assert len(canonical_base)==150 and len(controller_base)==2
        assert all(sha(body(BASE,n))==h for n,h in {**canonical_base,**controller_base}.items())
    assert baseline['dispatch_base']==BASE and baseline['sources']==canonical_base and baseline['controller_sources']==controller_base
    assert pre==post==canonical_base and pc==qc and len(pc)==2
    delta={n:h for n,h in pc.items() if h!=controller_base[n]}
    snap=ROOT/d/'changed-source';actual={str(p.relative_to(snap)):sha(p.read_bytes()) for p in snap.rglob('*') if p.is_file()}
    assert delta==actual and sorted(delta)==receipt['changed_source_snapshots']==v['runs'][stage]['changed_only_snapshots']
    assert (receipt['tests_run'],receipt['failures'],receipt['errors'],receipt['skipped'],receipt['exit_code'])==(tests,failures,0,0,code)
    assert receipt['source_files']==150 and receipt['controller_files']==2 and receipt['source_unchanged'] and receipt['live_cache_access'] is False
    assert receipt['limits']=={'wall_seconds':45,'cpu_seconds':30,'address_bytes':536870912,'file_bytes':33554432}
    assert set(tool)=={'request','initial','polls','final'} and len(tool['polls'])==1
    q=tool['request'];initial=tool['initial'];poll=tool['polls'][0];end=tool['final']
    assert q['cmd']=='python3 -B '+d+'/run.py' and q['workdir']==str(ROOT) and q['sandbox_permissions']=='require_escalated'
    assert q['yield_time_ms']==1000 and q['max_output_tokens']==3000 and type(q['justification']) is str
    assert type(initial['session_id']) is int and initial['session_id']>0 and 'exit_code' not in initial and initial['output']==''
    assert poll['request']=={'session_id':initial['session_id'],'chars':'','yield_time_ms':1000,'max_output_tokens':3000}
    assert poll['response']==end and type(end['exit_code']) is int and end['exit_code']==code and 'session_id' not in end
    assert json.loads(end['output'])==receipt and v['runs'][stage]['receipt']==receipt
    out=(ROOT/d/'output.txt').read_text();assert re.search(r'Ran '+str(tests)+r' tests? in ',out)
    if code==0:assert out.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$',out,re.M))==tests
    else:assert out.count('\nFAIL: ')==11 and out.count('AssertionError: ValueError not raised')==11 and '\nERROR: ' not in out
    prefix=(ROOT/d/'run.py').read_bytes().split(b'# END DEADLINE PREFIX\n',1)[0]+b'# END DEADLINE PREFIX\n'
    assert sha(prefix)==receipt['tested_prefix_sha256']=='7b46ff9acbebfc9d3cae6e9d5b80c0d2c7cdc0a082cbdb3a486021ff250a51aa'
    assert 'interpreter startup and essential timer bootstrap externally unbounded' in receipt['timing_scope']
    if stage=='cover-01':
        assert receipt['source_commit_at_launch']==SOURCE
        frozen={**pre,**pc};assert all(sha(body(SOURCE,n))==h==sha((ROOT/n).read_bytes()) for n,h in frozen.items())
        assert sha((ROOT/d/'pre-source.json').read_bytes())=='9c778497e4a79b088af25f776a519fc9ee58b4779613e4d3960436e3ec8fe24b'
        assert sha((ROOT/d/'pre-controller.json').read_bytes())=='32fcb9888136a176a9a8d10f21d962202537e47aa77fd3ba8b54ea8293141a7a'
    history.append({'run':stage,'methods':tests,'failures':failures,'errors':0,'skips':0,'exit_code':code,'terminal_chunk':end['chunk_id'],'pre_post_150_plus_2_equal':True,'changed_only':sorted(delta),'entry_to_receipt_seconds':receipt['whole_wall_until_receipt_seconds']})
assert len(frozen)==152 and all(frozen[n]==h for n,h in canonical_base.items())
assert sha(('\n'.join(sorted(canonical_base))+'\n').encode())=='f61b1c1e7613ee67e38bd9f31a6b023f34df39e4d805ef7f6f5bb9907aa7f079'
tree=ast.parse((ROOT/(D+'test_controller_cache_continuation_invoker_20261025.py')).read_bytes())
counts={n.name:sum(isinstance(x,ast.FunctionDef) and x.name.startswith('test_') for x in n.body) for n in tree.body if isinstance(n,ast.ClassDef)}
assert {n:counts[n] for n in ('InvokerTests','ClockTests','GeneratedInvokerTests','ReconcileTests')}=={'InvokerTests':5,'ClockTests':10,'GeneratedInvokerTests':25,'ReconcileTests':34}
assert sum(counts.values())==74
root_changes=changed(WORKER,HEAD)
assert root_changes=={'docs/STATUS.md','docs/evidence/plan-review.md',D+'controller-four-get-material-rulings.md',D+'controller-four-get-material-implementation-plan.md'}
raw=PACKAGE.read_bytes();parts=re.split(rb'(?=^diff --git )',raw,flags=re.M);blocks=[]
for block in parts[1:]:
    n=block.splitlines()[0].split(b' b/',1)[1].decode();data=None
    if b'\nnew file mode ' in block:
        lines=block.splitlines(keepends=True);i=next(i for i,x in enumerate(lines) if x.startswith(b'@@ '));chunks=[]
        for line in lines[i+1:]:
            if line.startswith(b'+'):chunks.append(line[1:])
            else:
                assert line==b'\\ No newline at end of file\n' and chunks and chunks[-1].endswith(b'\n')
                chunks[-1]=chunks[-1][:-1]
        data=b''.join(chunks);assert data==body(HEAD,n)==(ROOT/n).read_bytes()
    blocks.append((n,block,data))
assert {n for n,_,_ in blocks}==changed(FIX_BASE,HEAD)
keepers={}
for n,block,data in sorted(blocks,key=lambda x:(0 if '/controller-terminal-reconcile-fix4-cover-01/changed-source/' in x[0] else 1,x[0])):
    if data is not None:keepers.setdefault(sha(data),(n,data))
kept=[];duplicates=[];render=[parts[0]]
for n,block,data in blocks:
    keeper,kdata=keepers[sha(data)] if data is not None else (n,None)
    if n==keeper:render.append(block);kept.append({'path':n,'block_sha256':sha(block)})
    else:
        assert data==kdata
        duplicates.append({'path':n,'block_sha256':sha(block),'body_sha256':sha(data),'body_bytes':len(data),'identical_body_kept_at':keeper})
        render.append(('# Exact duplicate body: '+n+'\n# Kept verbatim at: '+keeper+'\n# SHA256: '+sha(data)+'\n# Raw and every artifact stay intact.\n\n').encode())
assert all(any(r['path']==n for r in kept) for n in SOURCE_PATHS)
view=b''.join(render)
result={'status':'PASS','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'dispatch_base':BASE,'review_fix_base':FIX_BASE,'source':SOURCE,'worker':WORKER,'review_head':HEAD,'index_bytes':len(ib),'index_sha256':sha(ib),'artifacts_verified':42,'package_logical_bytes':676517,'package_allocated_bytes':782336,'net_logical_excluding_index':526619,'net_allocated_vs_prior_index_excluding_index':622592,'canonical_150_names_and_bodies_unchanged':True,'all152_frozen_git_worktree_equal':True,'old_immutable_rows':75,'prior_api_rows':60,'prior_run_rows':101,'old_report_and_plan_prefixes_preserved':True,'runs':history,'method_counts':counts,'raw_package':{'path':str(PACKAGE.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw)},'view':{'path':str(VIEW.relative_to(ROOT)),'bytes':len(view),'sha256':sha(view),'all_blocks':len(blocks),'verbatim_blocks':kept,'exact_whole_new_body_duplicates':duplicates},'tests_rerun':False,'actual_operation':False,'timing_scope':'earliest measured metadata entry; interpreter/essential bootstrap externally unbounded','elapsed_before_writes_seconds':time.monotonic()-START}
assert time.monotonic()-START<45
with VIEW.open('xb') as f:f.write(view)
with OUT.open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
assert time.monotonic()-START<45
print(json.dumps({k:v for k,v in result.items() if k not in ('view','runs','method_counts')},sort_keys=True),flush=True)
print(json.dumps({'view_bytes':len(view),'view_sha256':sha(view),'blocks':len(blocks),'verbatim':len(kept),'whole_exact_duplicates':len(duplicates)}),flush=True)
assert time.monotonic()-START<45
