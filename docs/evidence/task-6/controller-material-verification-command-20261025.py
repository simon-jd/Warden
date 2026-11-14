#!/usr/bin/env python3
"""Root public/Git corroboration only. No project imports, tests or actual operation."""
import time
START=time.monotonic()
import os, signal
signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
signal.setitimer(signal.ITIMER_REAL,max(.001,45-(time.monotonic()-START)))
import ast, datetime, hashlib, json, re, resource, stat, subprocess
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(20,20))
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
resource.setrlimit(resource.RLIMIT_FSIZE,(33554432,33554432))
ROOT=Path(__file__).absolute().parents[3]
D='docs/evidence/task-6/'
BASE='b5780a09cb3c0a81b37207dca31ad5c2103c4395'
SOURCE='2f0bb21f7cad5eaf0d5f1a7d05cc058138eb8460'
WORKER='e25f400a20fe04b6476e8ef4b79c61a759bcf402'
HEAD='20fdff98c16d51d02cc2d9021bb373b6fb4a2dcf'
INDEX=D+'controller-four-get-material-artifact-sizes.json'
PACKAGE=ROOT/'.superpowers/sdd/2-warden-security-plan/review-b5780a0..20fdff9.diff'
VIEW=PACKAGE.with_name('review-b5780a0..20fdff9-deduplicated-view.diff')
OUT=ROOT/(D+'controller-material-verification-20261025.json')
SOURCES={'scripts/identity_cache_control.py','scripts/identity_cache_observe.py','scripts/test_identity_cache_control.py',D+'controller-cache-continuation-outer-invoker-20261025.py',D+'test_controller_cache_continuation_invoker_20261025.py'}
PLAN=D+'continuation-controller-operations-execution-plan.md'
REPORT=D+'controller-four-get-material-substage-report.md'
OLD_REPORT=D+'controller-terminal-reconcile-substage-report.md'
LIMITS={'wall_seconds':45,'cpu_seconds':30,'address_bytes':536870912,'file_bytes':33554432}
PREFIX_SHA='7b46ff9acbebfc9d3cae6e9d5b80c0d2c7cdc0a082cbdb3a486021ff250a51aa'
assert os.getuid()==os.getgid()==1000 and not OUT.exists() and not VIEW.exists()
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,timeout=10)
cache={}
def body(c,n):
    if (c,n) not in cache:cache[c,n]=git('show',c+':'+n)
    return cache[c,n]
def load(n):return json.loads((ROOT/n).read_bytes())
def changed(a,b):return set(git('diff','--name-only',a,b).decode().splitlines())
def row_ok(n,r):
    p=ROOT/n;s=p.lstat();b=p.read_bytes()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    assert len(b)==r['bytes'] and sha(b)==r['sha256'] and s.st_blocks*512==r['allocated_bytes']
    return b
ib=(ROOT/INDEX).read_bytes();v=json.loads(ib);rows=v['artifacts']
assert len(ib)==62385 and sha(ib)=='d061fa481af490b84fe74fb8938ff134e1c65b3028e322d16ab14c6fb85fd0ca'
assert v['dispatch_base']==BASE and v['source_commit']==SOURCE and len(rows)==v['artifact_count']==139 and v['index_self_excluded']
for n,r in rows.items():
    assert not Path(n).is_absolute() and '..' not in Path(n).parts
    assert n in SOURCES|{PLAN,REPORT} or n.startswith(D+'controller-four-get-material-source-')
    b=row_ok(n,r);assert b==body(WORKER,n)==body(HEAD,n)
assert ib==body(WORKER,INDEX)==body(HEAD,INDEX)
assert changed(BASE,SOURCE)==SOURCES and changed(BASE,WORKER)==set(rows)|{INDEX}
assert sum(r['bytes'] for r in rows.values())==v['package_logical_bytes']==3354634
assert sum(r['allocated_bytes'] for r in rows.values())==v['package_allocated_bytes']==3727360
old=v['old_sizes_and_allocations_for_net'];assert set(old)==SOURCES|{PLAN}
for n,r in old.items():assert len(body(BASE,n))==r['bytes'] and sha(body(BASE,n))==r['sha256']
assert 3354634-sum(r['bytes'] for r in old.values())==v['incremental_logical_bytes_vs_dispatch_excluding_index']==3043599
assert 3727360-sum(r['allocated_bytes'] for r in old.values())==v['incremental_allocated_bytes_vs_prior_indexed_baseline_excluding_index']==3403776
assert sum(rows[n]['bytes']-old[n]['bytes'] for n in SOURCES)==v['source_net_logical_bytes']==37380
assert sum(rows[n]['allocated_bytes']-old[n]['allocated_bytes'] for n in SOURCES)==v['source_net_allocated_bytes_vs_prior_index']==40960
assert 3043599-37380==v['evidence_net_logical_bytes_excluding_index']==3006219
assert 3403776-40960==v['evidence_net_allocated_bytes_vs_prior_index_excluding_index']==3362816
for n,r in v['preserved_prefixes'].items():
    b=(ROOT/n).read_bytes();ob=body(BASE,n)
    assert len(ob)==r['bytes'] and sha(ob)==r['sha256'] and b.startswith(ob)
assert len(body(BASE,PLAN))==60832 and len((ROOT/PLAN).read_bytes())==77887
assert len((ROOT/REPORT).read_bytes())==58445 and sha((ROOT/REPORT).read_bytes())=='7779d78398eee96d980805597ae641a95259665c22310109dc72e7a644527ac1'
assert (ROOT/REPORT).read_bytes()==(ROOT/'.superpowers/sdd/2-warden-security-plan/task-6-four-get-material-source-report.md').read_bytes()
assert (ROOT/OLD_REPORT).read_bytes()==body(BASE,OLD_REPORT)
preserved={}
for short,description in v['preserved_indexes'].items():
    n=D+short;ob=row_ok(n,description['index']);ov=json.loads(ob)
    assert ob==body(BASE,n)==body(WORKER,n)==body(HEAD,n)
    assert len(ov['artifacts'])==description['row_count']
    ignored=SOURCES|{PLAN}
    if description['row_count']==79:ignored|={OLD_REPORT}
    prior={n:r for n,r in ov['artifacts'].items() if n not in ignored}
    assert len(prior)==description['preserved_row_count']
    for n,r in prior.items():row_ok(n,r)
    preserved[short]=len(prior)
    if description['row_count']==79:
        for key,size in (('preserved_api_sha256',60),('preserved_prior_seven_run_sha256',101)):
            assert len(ov[key])==size and not set(ov[key])&changed(BASE,HEAD)
            for n,h in ov[key].items():assert sha((ROOT/n).read_bytes())==h
for n in v['old_partial_missing_still_absent']:assert not (ROOT/n).exists()
canonical_base=None;controller_base=None;frozen=None;history=[];js_history=[]
def prospective(d,index_row):
    global canonical_base,controller_base
    baseline=load(d+'/baseline.json');pre=load(d+'/pre-source.json');post=load(d+'/post-source.json')
    pc=load(d+'/pre-controller.json');qc=load(d+'/post-controller.json')
    if canonical_base is None:
        canonical_base=baseline['sources'];controller_base=baseline['controller_sources']
        assert len(canonical_base)==150 and len(controller_base)==2
        assert all(sha(body(BASE,n))==h for n,h in {**canonical_base,**controller_base}.items())
    assert baseline['dispatch_base']==BASE and baseline['sources']==canonical_base and baseline['controller_sources']==controller_base
    assert pre==post and pc==qc and len(pre)==150 and len(pc)==2 and set(pre)==set(canonical_base) and set(pc)==set(controller_base)
    combined={**pre,**pc};base={**canonical_base,**controller_base}
    delta={n:h for n,h in combined.items() if h!=base[n]}
    snap=ROOT/d/'changed-source';actual={str(p.relative_to(snap)):sha(p.read_bytes()) for p in snap.rglob('*') if p.is_file()}
    assert delta==actual and sorted(delta)==sorted(index_row['changed_only_snapshots']) and index_row['pre_post_equal'] is True
    return baseline,combined,delta
def native(q,d,suffix,max_tokens):
    assert set(q)=={'cmd','workdir','sandbox_permissions','justification','yield_time_ms','max_output_tokens'}
    assert q['cmd']=='python3 -B '+d+'/'+suffix and q['workdir']==str(ROOT) and q['sandbox_permissions']=='require_escalated'
    assert q['yield_time_ms']==1000 and q['max_output_tokens']==max_tokens and type(q['justification']) is str and q['justification']
def chain(t,code):
    initial=t['initial'];end=t['final']
    if 'session_id' in initial:
        assert set(t)=={'request','initial','polls','final'} and initial['output']=='' and 'exit_code' not in initial
        assert type(initial['session_id']) is int and initial['session_id']>0 and t['polls']
        for i,p in enumerate(t['polls']):
            assert p['request']=={'session_id':initial['session_id'],'chars':'','yield_time_ms':1000,'max_output_tokens':3000}
            if i<len(t['polls'])-1:assert p['response']['session_id']==initial['session_id'] and p['response']['output']=='' and 'exit_code' not in p['response']
        assert t['polls'][-1]['response']==end
    else:assert set(t)=={'request','initial','final'} and initial==end
    assert type(end['exit_code']) is int and end['exit_code']==code and 'session_id' not in end
    return initial,end
for stage,tests,failures,errors,code in [('red-01',1,2,0,1),('green-01',18,13,0,1),('green-02',18,0,10,1),('green-03',18,0,0,0),('cover-01',203,0,0,0)]:
    d=D+'controller-four-get-material-source-'+stage;ir=v['runs'][stage]
    baseline,combined,delta=prospective(d,ir);receipt=load(d+'/receipt.json');tool=load(d+'/outer-tool-result.json')
    assert set(delta)==({D+'test_controller_cache_continuation_invoker_20261025.py'} if stage=='red-01' else SOURCES)
    assert (receipt['tests_run'],receipt['failures'],receipt['errors'],receipt['skipped'],receipt['exit_code'])==(tests,failures,errors,0,code)
    assert receipt['dispatch_base']==BASE and receipt['source_files']==150 and receipt['controller_files']==2 and receipt['source_unchanged'] and receipt['live_cache_access'] is False
    assert receipt['limits']==LIMITS and set(receipt['changed_source_snapshots'])==set(delta) and receipt['completion_requires_process_exit_zero'] is True
    native(tool['request'],d,'run.py',3000);initial,end=chain(tool,code)
    assert json.loads(end['output'])==receipt==ir['receipt']
    assert (ir['actual_exit_code'],ir['actual_initial'],ir['actual_terminal'],ir['actual_session'])==(code,initial['chunk_id'],end['chunk_id'],initial.get('session_id'))
    out=(ROOT/d/'output.txt').read_text();assert re.search(r'Ran '+str(tests)+r' tests? in ',out)
    if code==0:assert out.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$',out,re.M))==tests
    else:assert out.count('\nFAIL: ')==failures and out.count('\nERROR: ')==errors and not out.rstrip().endswith('OK')
    if stage=='red-01':assert out.count('one_fixed_controller_mode')>=2
    if stage=='green-01':assert 'AssertionError' in out
    if stage=='green-02':assert out.count('TypeError:')==10
    prefix=(ROOT/d/'run.py').read_bytes().split(b'# END DEADLINE PREFIX\n',1)[0]+b'# END DEADLINE PREFIX\n'
    assert sha(prefix)==receipt['tested_prefix_sha256']==PREFIX_SHA
    assert 'interpreter startup and essential timer bootstrap externally unbounded' in receipt['timing_scope']
    assert 0<=receipt['whole_wall_until_receipt_seconds']<45
    if stage=='cover-01':
        assert receipt['source_commit_at_launch']==baseline['source_commit_at_launch']==SOURCE
        frozen=combined;assert all(sha(body(SOURCE,n))==h==sha((ROOT/n).read_bytes()) for n,h in frozen.items())
    history.append({'run':stage,'methods':tests,'failures':failures,'errors':errors,'skips':0,'exit_code':code,'terminal_chunk':end['chunk_id'],'complete_150_plus_2_equal':True,'changed_only':sorted(delta),'entry_to_receipt_seconds':receipt['whole_wall_until_receipt_seconds']})
assert len(frozen)==152 and all(frozen[n]==h for n,h in canonical_base.items() if n not in SOURCES)
assert len(set(canonical_base)-SOURCES)==147
assert sha(('\n'.join(sorted(canonical_base))+'\n').encode())=='f61b1c1e7613ee67e38bd9f31a6b023f34df39e4d805ef7f6f5bb9907aa7f079'
candidate=(ROOT/(D+'controller-four-get-material-source-caller-candidate.js')).read_bytes()
fixture=(ROOT/(D+'controller-four-get-material-source-caller-fixture.js')).read_bytes()
assert len(candidate)==10842 and sha(candidate)=='58095573ef0f31c78429d9dd5169ced6ea58c5c23f04526b651f73b1eb8b73b1'
assert len(fixture)==10578 and sha(fixture)=='41d7755dbef715914e54d3732c326d2db1a0c42fd0c9360c2971f3164fc973a9'
assert b'```js\n'+candidate+b'```' in (ROOT/PLAN).read_bytes()
execute=b"const input=JSON.parse(load('material-source-js-input').initial.output);\nconst Fixture=Object.getPrototypeOf(async function(){}).constructor;\nconst result=await new Fixture('candidate',input.fixture)(input.candidate);\nstore('material-source-js-result',result);\ntext(result);\n"
for stage in ('js-green-01','js-green-02','js-cover-01'):
    d=D+'controller-four-get-material-source-'+stage;ir=v['js_runs'][stage]
    baseline,combined,delta=prospective(d,ir);assert set(delta)==SOURCES and combined==frozen
    tool=load(d+'/outer-tool-result.json');assert set(tool)=={'metadata_pre','simulation','metadata_post'}
    precode=load(d+'/pre-code.json');assert precode==load(d+'/post-code.json')==ir['code']
    for name,r in precode.items():
        b=(ROOT/d/(name+'.js')).read_bytes();assert r['bytes']==len(b) and r['sha256']==sha(b)
        assert r['path']==D+'controller-four-get-material-source-caller-'+name+'.js'
        if name=='candidate':assert b==candidate
        elif stage!='js-green-01':assert b==fixture
        else:assert sha(b)=='1ab75f32849d81f6bc545a4b9f562ff432b6f975605ad9093e398317b08342fb'
    assert (ROOT/d/'execute.js').read_bytes()==execute
    for phase,max_tokens in (('pre',16000),('post',3000)):
        t=tool['metadata_'+phase];native(t['request'],d,'metadata.py '+phase,max_tokens)
        initial,end=chain(t,0);assert initial['chunk_id']==ir['actual_metadata_'+phase]
        payload=json.loads(end['output']);r=load(d+'/'+phase+'-receipt.json')
        assert payload['receipt']==r and set(payload)==({'candidate','fixture','receipt'} if phase=='pre' else {'receipt'})
        assert r['phase']==phase and r['equal']==(True if phase=='post' else None) and r['source_files']==150 and r['controller_files']==2 and r['code']==precode and r['limits']==LIMITS
        assert r['timing_scope']=='metadata recorder only; JS isolate and interpreter startup not measured' and 0<=r['elapsed_seconds']<45
        if phase=='pre':assert payload['candidate'].encode()==candidate and payload['fixture'].encode()==(ROOT/d/'fixture.js').read_bytes()
    prefix=(ROOT/d/'metadata.py').read_bytes().split(b'# END DEADLINE PREFIX\n',1)[0]+b'# END DEADLINE PREFIX\n';assert sha(prefix)==PREFIX_SHA
    sim=tool['simulation'];assert sim['code_artifact']=='execute.js' and sim['actual_tool_result']==ir['simulation']
    actual=sim['actual_tool_result']
    if stage=='js-green-01':assert actual['status']=='Script failed' and type(actual['output']) is str and 'lossless large metadata' in actual['output']
    else:
        assert actual['status']=='Script completed';o=actual['output']
        assert (o['tests_run'],o['failures'],o['errors'],o['skipped'])==(18,0,0,0) and len(o['cases'])==18 and len({c['name'] for c in o['cases']})==18 and all(c['passed'] is True for c in o['cases'])
        assert o['total_fake_native_calls']==sum(c['native_calls'] for c in o['cases'])==35
        assert o['total_fake_patch_calls']==sum(c['patch_calls'] for c in o['cases'])==30
        assert all(c['native_calls']<=4 and c['patch_calls']<=4 for c in o['cases'])
        assert o['actual_nested_tools']==0 and o['actual_store_interlock_set'] is False and o['generated_payload_max_output_bytes']==65537
    js_history.append({'run':stage,'status':actual['status'],'pre':ir['actual_metadata_pre'],'post':ir['actual_metadata_post'],'complete_150_plus_2_equal':True,'candidate_sha256':sha(candidate),'fixture_sha256':precode['fixture']['sha256'],'native_limits_prove_js_containment':False})
counts={}
for n in ('scripts/test_identity_cache_control.py',D+'test_controller_cache_continuation_invoker_20261025.py'):
    tree=ast.parse((ROOT/n).read_bytes())
    counts.update({x.name:sum(isinstance(y,ast.FunctionDef) and y.name.startswith('test_') for y in x.body) for x in tree.body if isinstance(x,ast.ClassDef)})
expected={'ControllerTests':84,'APITests':27,'InvokerTests':5,'ClockTests':10,'GeneratedInvokerTests':25,'ReconcileTests':34,'MaterialEntryTests':1,'MaterialTests':17}
assert all(counts[n]==k for n,k in expected.items()) and sum(expected.values())==203
assert changed(WORKER,HEAD)=={'docs/STATUS.md','docs/evidence/plan-review.md',D+'controller-four-get-material-one-shot-ruling.md',D+'controller-capture-continue-handoff-proposal.md',D+'controller-capture-continue-handoff-rulings.md'}
assert git('diff','--cached','--name-only')==b''
raw=PACKAGE.read_bytes();assert raw==git('diff','--binary',BASE,HEAD,'--')
parts=re.split(rb'(?=^diff --git )',raw,flags=re.M);blocks=[]
for block in parts[1:]:
    n=block.splitlines()[0].split(b' b/',1)[1].decode();data=None
    if b'\nnew file mode ' in block:
        lines=block.splitlines(keepends=True);i=next(i for i,x in enumerate(lines) if x.startswith(b'@@ '));chunks=[]
        for line in lines[i+1:]:
            if line.startswith(b'+'):chunks.append(line[1:])
            else:
                assert line==b'\\ No newline at end of file\n' and chunks and chunks[-1].endswith(b'\n');chunks[-1]=chunks[-1][:-1]
        data=b''.join(chunks);assert data==body(HEAD,n)==(ROOT/n).read_bytes()
    else:assert body(HEAD,n)==(ROOT/n).read_bytes()
    blocks.append((n,block,data))
assert {n for n,_,_ in blocks}==changed(BASE,HEAD)
keepers={}
for n,block,data in sorted(blocks,key=lambda x:(0 if '/controller-four-get-material-source-cover-01/changed-source/' in x[0] else 1,x[0])):
    if data is not None:keepers.setdefault(sha(data),(n,data))
kept=[];duplicates=[];render=[parts[0]]
for n,block,data in blocks:
    keeper,kdata=keepers[sha(data)] if data is not None else (n,None)
    if n==keeper:render.append(block);kept.append({'path':n,'block_sha256':sha(block)})
    else:
        assert data==kdata
        duplicates.append({'path':n,'block_sha256':sha(block),'body_sha256':sha(data),'body_bytes':len(data),'identical_body_kept_at':keeper})
        render.append(('# Exact duplicate body: '+n+'\n# Kept verbatim at: '+keeper+'\n# SHA256: '+sha(data)+'\n# Raw and every artifact stay intact.\n\n').encode())
assert all(any(r['path']==n for r in kept) for n in SOURCES)
view=b''.join(render)
result={'status':'PASS','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'dispatch_base':BASE,'source':SOURCE,'worker':WORKER,'review_head':HEAD,'index_bytes':len(ib),'index_sha256':sha(ib),'artifacts_verified':139,'package_logical_bytes':3354634,'package_allocated_bytes':3727360,'net_logical_excluding_index':3043599,'net_allocated_vs_prior_index_excluding_index':3403776,'net_logical_including_index':3105984,'net_allocated_vs_prior_index_including_index':3469312,'canonical_150_names_unchanged':True,'other147_equal_dispatch':True,'all152_frozen_git_worktree_equal':True,'preserved_old_rows':preserved,'prior_api_rows':60,'prior_run_rows':101,'old_report_and_plan_prefixes_preserved':True,'runs':history,'js_runs':js_history,'method_counts':expected,'raw_package':{'path':str(PACKAGE.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw)},'view':{'path':str(VIEW.relative_to(ROOT)),'bytes':len(view),'sha256':sha(view),'all_blocks':len(blocks),'verbatim_blocks':kept,'exact_whole_new_body_duplicates':duplicates},'tests_rerun':False,'project_imports':False,'actual_operation':False,'timing_scope':'earliest measured metadata entry; interpreter/essential bootstrap externally unbounded; no JS physical containment claim','elapsed_before_writes_seconds':time.monotonic()-START}
assert time.monotonic()-START<45
with VIEW.open('xb') as f:f.write(view)
with OUT.open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
assert time.monotonic()-START<45
print(json.dumps({k:v for k,v in result.items() if k not in ('view','runs','js_runs','method_counts')},sort_keys=True),flush=True)
print(json.dumps({'view_bytes':len(view),'view_sha256':sha(view),'blocks':len(blocks),'verbatim':len(kept),'whole_exact_duplicates':len(duplicates)}),flush=True)
assert time.monotonic()-START<45
