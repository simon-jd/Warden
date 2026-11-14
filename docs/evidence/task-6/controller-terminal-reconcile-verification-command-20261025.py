#!/usr/bin/env python3
"""Public/Git metadata only. Never import project modules or rerun fixtures."""
import time
START = time.monotonic()
import os
import signal
signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
signal.setitimer(signal.ITIMER_REAL, max(0.001,45-(time.monotonic()-START)))
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import resource
import stat
import subprocess
resource.setrlimit(resource.RLIMIT_CPU,(20,20))
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
resource.setrlimit(resource.RLIMIT_FSIZE,(33554432,33554432))
ROOT=Path(__file__).absolute().parents[3]
BASE='0766662fd4dd88b9e77812554909898a71b96e13'
SOURCE='a05d077cd4885b5ddc662e0a8854ba0a8208b7da'
WORKER='e9d44ea1d82948960295ba3d46351acb3f4bf86b'
HEAD='bb7224cdc9ce4106b39c3a7ddad514d9e5ac6175'
OUT=ROOT/'docs/evidence/task-6/controller-terminal-reconcile-verification-20261025.json'
PACKAGE=ROOT/'.superpowers/sdd/2-warden-security-plan/review-0766662..bb7224c.diff'
VIEW=PACKAGE.with_name('review-0766662..bb7224c-deduplicated-view.diff')
assert os.getuid()==os.getgid()==1000 and not OUT.exists() and not VIEW.exists()
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*a):return subprocess.check_output(['git',*a],cwd=ROOT,timeout=10)
cache={}
def body(c,n):
    if (c,n) not in cache:cache[c,n]=git('show',c+':'+n)
    return cache[c,n]
def load(n):return json.loads((ROOT/n).read_bytes())
def changed(a,b):return set(git('diff','--name-only',a,b).decode().splitlines())
I='docs/evidence/task-6/controller-terminal-reconcile-artifact-sizes.json'
ib=(ROOT/I).read_bytes();v=json.loads(ib);rows=v['artifacts'];sources=v['source_files']
assert len(ib)==53984 and sha(ib)=='d22cd13338670bea2323ccbbd5873a47a8bafbd827e2a6b334f5920f34ba65bc'
assert v['dispatch_base']==BASE and v['source_commit']==SOURCE and v['index_self_excluded']
assert len(rows)==v['artifact_count']==79 and len(sources)==5 and set(sources)<=set(rows)
plan=v['plan_prefix']['path'];report='docs/evidence/task-6/controller-terminal-reconcile-substage-report.md'
for n,r in rows.items():
    assert not Path(n).is_absolute() and '..' not in Path(n).parts
    assert n in sources or n in (plan,report) or n.startswith('docs/evidence/task-6/controller-terminal-reconcile-source-')
    b=(ROOT/n).read_bytes();s=(ROOT/n).lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and len(b)==r['bytes'] and sha(b)==r['sha256'] and s.st_blocks*512==r['allocated_bytes']
    assert b==body(WORKER,n)==body(HEAD,n)
assert sum(r['bytes'] for r in rows.values())==v['package_logical_bytes']==1706172
assert sum(r['allocated_bytes'] for r in rows.values())==v['package_allocated_bytes']==1900544
assert sum(r['bytes'] for r in sources.values())==244256
assert changed(BASE,SOURCE)==set(sources) and changed(BASE,WORKER)==set(rows)|{I}
assert ib==body(WORKER,I)==body(HEAD,I)
old_sizes=v['old_sizes_from_prior_frozen_index'];assert sum(old_sizes.values())==239220
assert all(len(body(BASE,n))==z for n,z in old_sizes.items())
assert 1706172-239220==v['incremental_logical_bytes_vs_dispatch_excluding_index']==1466952
old_plan=body(BASE,plan);new_plan=(ROOT/plan).read_bytes()
assert len(old_plan)==v['plan_prefix']['preserved_prefix_bytes']==40886
assert sha(old_plan)==v['plan_prefix']['preserved_prefix_sha256']=='9fc37f2f9803ed5b5492356f527b9abf6ae2e21b52267981c52a799c7fee405c'
assert new_plan.startswith(old_plan) and len(new_plan)==58113 and len(new_plan)-len(old_plan)==17227
rb=(ROOT/report).read_bytes();assert len(rb)==14048 and sha(rb)=='2b2d7e6aeda351169888e6ac07cee1f2bcfbe3372d476cbce87fcbec5cdbaf9e'
assert rb==(ROOT/'.superpowers/sdd/2-warden-security-plan/task-6-terminal-reconcile-source-report.md').read_bytes()
root_changes=changed(WORKER,HEAD)
assert root_changes=={'docs/STATUS.md','docs/evidence/plan-review.md','docs/evidence/task-6/controller-terminal-reconcile-rulings.md',
    'docs/evidence/task-6/controller-four-get-material-proposal.md','docs/evidence/task-6/controller-four-get-material-rulings.md'}
old_index_name='docs/evidence/task-6/controller-readonly-api-artifact-sizes.json'
old_ib=body(BASE,old_index_name);old_index=json.loads(old_ib)
assert sha(old_ib)==v['prior_api_index_sha256']=='ccb5cd375f796d60477584709291065baa7643daeb7f372183b0695861504939'
assert old_ib==body(WORKER,old_index_name)==(ROOT/old_index_name).read_bytes()
prior={n:r['sha256'] for n,r in old_index['artifacts'].items() if n not in set(sources)|{plan}}
assert len(prior)==v['preserved_api_artifact_rows']==60 and prior==v['preserved_api_sha256']
assert v['preserved_prior_seven_run_sha256']==old_index['preserved_prior_seven_run_sha256'] and v['preserved_prior_seven_run_file_count']==101
assert not (set(prior)|set(v['preserved_prior_seven_run_sha256'])) & changed(BASE,HEAD)
for n in v['prior_api_partial_red_missing_unchanged']:
    assert not (ROOT/'docs/evidence/task-6/controller-readonly-api-source-red-01'/n).exists()

expected=[('red-01',2,2,0,1),('green-01',165,2,4,1),('green-02',174,0,1,1),('green-03',26,0,0,0),('cover-01',177,0,0,0)]
history=[];baseline_sources=None;baseline_controllers=None
for stage,tests,failures,errors,code in expected:
    d='docs/evidence/task-6/controller-terminal-reconcile-source-'+stage
    base=load(d+'/baseline.json');pre=load(d+'/pre-source.json');post=load(d+'/post-source.json')
    pc=load(d+'/pre-controller.json');qc=load(d+'/post-controller.json');receipt=load(d+'/receipt.json');tool=load(d+'/outer-tool-result.json')
    if baseline_sources is None:
        baseline_sources=base['sources'];baseline_controllers=base['controller_sources']
        assert len(baseline_sources)==150 and len(baseline_controllers)==2
        assert all(sha(body(BASE,n))==h for n,h in {**baseline_sources,**baseline_controllers}.items())
    assert base['dispatch_base']==BASE and base['sources']==baseline_sources and base['controller_sources']==baseline_controllers
    assert len(pre)==150 and len(pc)==2 and pre==post and pc==qc
    assert all(pre[n]==h for n,h in baseline_sources.items() if n not in sources)
    all_pre={**pre,**pc};all_base={**baseline_sources,**baseline_controllers}
    delta={n:h for n,h in all_pre.items() if all_base.get(n)!=h}
    snap=ROOT/d/'changed-source';actual={str(p.relative_to(snap)):sha(p.read_bytes()) for p in snap.rglob('*') if p.is_file()}
    assert actual==delta==v['runs'][stage]['changed_only_sha256']
    assert sorted(delta)==sorted(receipt['changed_source_snapshots'])
    assert (receipt['tests_run'],receipt['failures'],receipt['errors'],receipt['exit_code'])==(tests,failures,errors,code)
    assert receipt['skipped']==0 and receipt['source_files']==150 and receipt['controller_files']==2 and receipt['source_unchanged'] and receipt['live_cache_access'] is False
    assert receipt['limits']=={'address_bytes':536870912,'cpu_seconds':30,'file_bytes':33554432,'wall_seconds':45}
    assert v['runs'][stage]['recording_complete'] and v['runs'][stage]['host_own_clock_read_incident']==(stage=='green-01')
    assert set(tool) in ({'request','initial'},{'request','initial','final'})
    assert tool['request']['workdir']==str(ROOT) and tool['request']['sandbox_permissions']=='require_escalated'
    assert tool['request']['cmd']=='python3 -B '+d+'/run.py'
    end=tool.get('final',tool['initial']);assert type(end['exit_code']) is int and end['exit_code']==code and 'session_id' not in end
    if 'final' in tool:assert type(tool['initial']['session_id']) is int and 'exit_code' not in tool['initial'] and tool['initial']['output']==''
    assert json.loads(end['output'])==receipt
    out=(ROOT/d/'output.txt').read_text();assert re.search(r'Ran '+str(tests)+r' tests? in ',out)
    if code==0:assert out.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$',out,re.M))==tests
    else:assert out.count('\nFAIL: ')==failures and out.count('\nERROR: ')==errors
    if stage=='green-01':assert 'namespace_changed' in out and 'launch_target_entry' in out
    wrapper=(ROOT/d/'run.py').read_bytes();marker=b'# END DEADLINE PREFIX\n';prefix=wrapper.split(marker,1)[0]+marker
    assert sha(prefix)==receipt['tested_prefix_sha256']=='7b46ff9acbebfc9d3cae6e9d5b80c0d2c7cdc0a082cbdb3a486021ff250a51aa'
    assert 'interpreter startup and essential timer bootstrap externally unbounded' in receipt['timing_scope']
    if stage=='cover-01':
        assert receipt['source_commit_at_launch']==SOURCE
        assert all(sha(body(SOURCE,n))==h==sha((ROOT/n).read_bytes()) for n,h in all_pre.items())
        assert sha((ROOT/d/'pre-source.json').read_bytes())=='9c778497e4a79b088af25f776a519fc9ee58b4779613e4d3960436e3ec8fe24b'
        assert sha((ROOT/d/'pre-controller.json').read_bytes())=='10be732897dbc69611acb203df6127b04a313b515a98f49b11df91e78739cd23'
        frozen=all_pre
    history.append({'run':stage,'tests':tests,'failures':failures,'errors':errors,'exit_code':code,'canonical':150,'controller':2,
        'pre_post_equal':True,'changed_sources':sorted(delta),'tool_format':'actual request plus initial/final' if 'final'in tool else 'actual request plus initial terminal',
        'terminal_chunk':end['chunk_id'],'entry_to_receipt_seconds':receipt['whole_wall_until_receipt_seconds'],
        'host_read_incident':stage=='green-01'})
assert sum(baseline_sources[n]==frozen[n] for n in baseline_sources)==147
assert sha(('\n'.join(sorted(baseline_sources))+'\n').encode())=='f61b1c1e7613ee67e38bd9f31a6b023f34df39e4d805ef7f6f5bb9907aa7f079'
for n in sources:
    s=(ROOT/n).lstat();assert s.st_uid==s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644
def nodes(c):
    t=body(c,'scripts/identity_cache_observe.py').decode()
    return {n.name:ast.get_source_segment(t,n).encode() for n in ast.parse(t).body if isinstance(n,(ast.ClassDef,ast.FunctionDef))}
a,b=nodes(BASE),nodes(SOURCE);names=['read','_docker_anchor','_docker_headers','ReadOnlyDocker','docker_adapter','Deadline','OwnClock','ClockBudget','OwnedProcess']
components={n:sha(b[n]) for n in names};assert all(a[n]==b[n] for n in names)

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
assert {n for n,_,_ in blocks}==changed(BASE,HEAD)
keepers={}
for n,block,data in sorted(blocks,key=lambda x:(0 if x[0] in sources else 1 if '/controller-terminal-reconcile-source-cover-01/changed-source/' in x[0] else 2,x[0])):
    if data is not None:keepers.setdefault(sha(data),(n,data))
kept=[];duplicates=[];render=[parts[0]]
for n,block,data in blocks:
    keeper,kdata=keepers[sha(data)] if data is not None else (n,None)
    if n==keeper:render.append(block);kept.append({'path':n,'block_sha256':sha(block)})
    else:
        assert data==kdata
        duplicates.append({'path':n,'block_sha256':sha(block),'body_sha256':sha(data),'body_bytes':len(data),'identical_body_kept_at':keeper})
        render.append(('# Exact duplicate body: '+n+'\n# Kept verbatim at: '+keeper+'\n# SHA256: '+sha(data)+'\n# Raw package and all files remain intact.\n\n').encode())
assert all(any(r['path']==n for r in kept) for n in sources)
view=b''.join(render);assert time.monotonic()-START<45
with VIEW.open('xb') as f:f.write(view)
result={'status':'PASS','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'dispatch_base':BASE,'source':SOURCE,'worker_evidence':WORKER,'review_head':HEAD,
 'artifact_rows':79,'artifact_bytes_excluding_index':1706172,'index_bytes':53984,'package_bytes_including_index':1760156,
 'net_growth_including_index':1520936,'ignored_report_mirror_bytes':14048,'source_bytes':244256,'canonical':150,'controller':2,'unchanged_canonical':147,
 'plan_prefix':{'bytes':40886,'sha256':sha(old_plan),'append_bytes':17227},'runs':history,'unchanged_observer_components':components,
 'prior_history':'60 API hashes match old index;101 prior run hashes match declared prior index; exact Git changes exclude those paths, old API partial post/receipt remain absent. No old semantic crawl.',
 'root_coordinator_paths':sorted(root_changes),'review_view':{'raw_path':str(PACKAGE.relative_to(ROOT)),'raw_bytes':len(raw),'raw_sha256':sha(raw),
 'view_path':str(VIEW.relative_to(ROOT)),'view_bytes':len(view),'view_sha256':sha(view),'raw_blocks':len(blocks),'retained_blocks':kept,'omitted_exact_duplicate_bodies':duplicates},
 'scope':'Verifier only public/Git reads and AST byte-segment comparisons, no project imports/tests/host/private/runtime/cloud operations. The separate GREEN1 fixture own-host read incident is disclosed, not reclassified as fake.',
 'diagnostic_note':'First metadata verifier omitted the newly retained request key from expected tool-record shape, exit1 before any proof/view write. Corrected verifier validates request too; worker evidence/tests unchanged. Actual failure preserved separately.',
 'raw_whitespace_note':'Historical GREEN1/output.txt:161 interrupted unittest trailing whitespace retained verbatim; not a current source cleanup/bypass.'}
with OUT.open('x') as f:f.write(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':'PASS','artifacts':79,'complete_runs':5,'frozen_tests':177,'raw_bytes':len(raw),'view_bytes':len(view),'blocks':len(blocks),'duplicates':len(duplicates),'result':str(OUT.relative_to(ROOT))}),flush=True)
assert time.monotonic()-START<45
signal.setitimer(signal.ITIMER_REAL,0)
