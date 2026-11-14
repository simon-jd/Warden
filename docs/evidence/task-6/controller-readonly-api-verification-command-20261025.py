#!/usr/bin/env python3
"""Public/Git provenance only; no project imports, tests or host probes."""
import time
START = time.monotonic()
import os
import signal
signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
signal.setitimer(signal.ITIMER_REAL, max(0.001, 45 - (time.monotonic() - START)))
import datetime
import hashlib
import json
from pathlib import Path
import re
import resource
import stat
import subprocess

resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
resource.setrlimit(resource.RLIMIT_FSIZE, (33554432, 33554432))
ROOT = Path(__file__).absolute().parents[3]
BASE = '4e197bd899a768449bb5b19dace8b5e88b9b713d'
SOURCE = 'b2b348205bdb3fbd4573ab04237c1a9e166371e2'
WORKER = 'ce107038c36933a295fe043b451fb7be77f136f7'
HEAD = '43aee0ea921d0f55d48010e3490e5dc999933b3b'
OUT = ROOT/'docs/evidence/task-6/controller-readonly-api-verification-20261025.json'
PACKAGE = ROOT/'.superpowers/sdd/2-warden-security-plan/review-4e197bd..43aee0e.diff'
VIEW = PACKAGE.with_name('review-4e197bd..43aee0e-deduplicated-view.diff')
assert not OUT.exists() and not VIEW.exists()
assert os.getuid() == os.getgid() == 1000

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, timeout=10)

cache = {}
def body(commit, name):
    key = (commit, name)
    if key not in cache:
        cache[key] = git('show', commit+':'+name)
    return cache[key]

def load(name):
    return json.loads((ROOT/name).read_bytes())

index_name = 'docs/evidence/task-6/controller-readonly-api-artifact-sizes.json'
index_bytes = (ROOT/index_name).read_bytes()
index = json.loads(index_bytes)
artifacts, sources, controllers = index['artifacts'], index['source_files'], index['controller_files']
assert index['dispatch_base'] == BASE and index['source_commit'] == SOURCE
assert len(artifacts) == index['artifact_count'] == 66
assert len(sources) == 3 and len(controllers) == 2 and set(sources) | set(controllers) <= set(artifacts)
assert len(index_bytes) == 36307 and index['index_self_excluded']
assert sha(index_bytes) == 'ccb5cd375f796d60477584709291065baa7643daeb7f372183b0695861504939'
plan = index['plan_prefix']['path']
report = 'docs/evidence/task-6/controller-readonly-api-substage-report.md'
for name, row in artifacts.items():
    assert not Path(name).is_absolute() and '..' not in Path(name).parts
    assert name in sources or name in controllers or name in (plan, report) or name.startswith('docs/evidence/task-6/controller-readonly-api-source-')
    data = (ROOT/name).read_bytes()
    info = (ROOT/name).lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    assert len(data) == row['bytes'] and sha(data) == row['sha256'] and info.st_blocks*512 == row['allocated_bytes']
    assert data == body(WORKER, name) == body(HEAD, name)
assert sum(r['bytes'] for r in artifacts.values()) == index['package_logical_bytes'] == 1208572
assert sum(r['allocated_bytes'] for r in artifacts.values()) == index['package_allocated_bytes'] == 1388544
assert sum(r['bytes'] for r in sources.values()) == 164158
assert sum(r['bytes'] for r in controllers.values()) == 34176
assert set(git('diff', '--name-only', BASE, SOURCE).decode().splitlines()) == set(sources)
assert set(git('diff', '--name-only', BASE, WORKER).decode().splitlines()) == (set(artifacts) | {index_name}) - set(controllers)
assert index_bytes == body(WORKER, index_name) == body(HEAD, index_name)
old_sizes = index['old_sizes_from_dispatch_git_blobs']
assert sum(old_sizes.values()) == 198478
assert all(len(body(BASE,n)) == size for n,size in old_sizes.items())
assert 1208572-198478 == index['incremental_logical_bytes_vs_dispatch_excluding_index'] == 1010094
old_plan, new_plan = body(BASE, plan), (ROOT/plan).read_bytes()
assert len(old_plan) == index['plan_prefix']['prefix_bytes'] == 33536
assert sha(old_plan) == index['plan_prefix']['prefix_sha256'] == 'd68ca5aa148be8727915598b4559cad4a3a55b7274018cbf1a8321a920e0d2f9'
assert new_plan.startswith(old_plan) and len(new_plan)-len(old_plan) == 7350
assert (ROOT/report).read_bytes() == (ROOT/'.superpowers/sdd/2-warden-security-plan/task-6-readonly-api-source-report.md').read_bytes()
assert sha((ROOT/report).read_bytes()) == '1271c7df465f1ddadc90a6defb3de12dcd7b08fef767c00026b1ce118ba5a6c8'
root_changes = set(git('diff', '--name-only', WORKER, HEAD).decode().splitlines())
assert root_changes == {'docs/STATUS.md','docs/evidence/plan-review.md',
    'docs/evidence/task-6/controller-terminal-reconcile-proposal.md','docs/evidence/task-6/controller-terminal-reconcile-rulings.md'}
prior_index = json.loads(body(BASE, 'docs/evidence/task-6/controller-invoker-artifact-sizes.json'))
prior_rows = {n:r['sha256'] for n,r in prior_index['artifacts'].items()
              if re.fullmatch(r'docs/evidence/task-6/controller-invoker-source-(?:red|green|cover)-[0-9]+/.+', n)}
assert len(prior_rows) == index['preserved_prior_seven_run_file_count'] == 101
assert prior_rows == index['preserved_prior_seven_run_sha256']
# Exact Git change sets and clean tracked history establish no previous run was
# changed; compare declared old hashes to the prior index, not an old semantic crawl.

expected = [('red-01',None,None,None,1),('red-02',3,0,2,1),('green-01',109,0,0,0),
            ('green-02',2,0,0,0),('cover-01',149,0,0,0)]
runs, baseline_sources, baseline_controllers = [], None, None
for stage, tests, failures, errors, exit_code in expected:
    directory = 'docs/evidence/task-6/controller-readonly-api-source-'+stage
    baseline = load(directory+'/baseline.json')
    pre, pre_c = load(directory+'/pre-source.json'), load(directory+'/pre-controller.json')
    outer = load(directory+'/outer-tool-result.json')
    if baseline_sources is None:
        baseline_sources, baseline_controllers = baseline['sources'], baseline['controller_sources']
        assert len(baseline_sources) == 150 and len(baseline_controllers) == 2
        assert all(sha(body(BASE,n)) == h for n,h in {**baseline_sources,**baseline_controllers}.items())
    assert baseline['dispatch_base'] == BASE and baseline['sources'] == baseline_sources and baseline['controller_sources'] == baseline_controllers
    assert len(pre) == 150 and len(pre_c) == 2 and pre_c == baseline_controllers
    assert all(pre[n] == h for n,h in baseline_sources.items() if n not in sources)
    combined = {**pre, **pre_c}
    baseline_combined = {**baseline_sources, **baseline_controllers}
    changed = sorted(n for n,h in combined.items() if baseline_combined.get(n) != h)
    snapshot_root = ROOT/directory/'changed-source'
    snapshots = {str(p.relative_to(snapshot_root)):sha(p.read_bytes()) for p in snapshot_root.rglob('*') if p.is_file()}
    assert sorted(snapshots) == changed and all(snapshots[n] == combined[n] for n in changed)
    assert set(outer) in ({'initial'}, {'initial','final'})
    terminal = outer.get('final',outer['initial'])
    assert type(terminal['exit_code']) is int and terminal['exit_code'] == exit_code and 'session_id' not in terminal
    if 'final' in outer:
        assert type(outer['initial']['session_id']) is int and 'exit_code' not in outer['initial'] and outer['initial']['output'] == ''
    row = {'stage':stage,'canonical_files':150,'controller_files':2,'changed_snapshots':changed,
           'outer_format':'actual structured initial/final' if 'final' in outer else 'actual structured initial terminal',
           'terminal_chunk':terminal['chunk_id'],'exit_code':exit_code}
    if stage == 'red-01':
        missing = ['post-source.json','post-controller.json','receipt.json']
        assert all(not (ROOT/directory/n).exists() for n in missing)
        assert index['runs'][stage]['missing_artifacts'] == missing and index['runs'][stage]['recording_complete'] is False
        assert 'CLI forbidden' in terminal['output'] and 'Traceback' in terminal['output']
        row.update({'recording_complete':False,'classification':'recording/fixture failure','missing_artifacts':missing})
    else:
        post, post_c = load(directory+'/post-source.json'), load(directory+'/post-controller.json')
        receipt = load(directory+'/receipt.json')
        assert pre == post and pre_c == post_c and json.loads(terminal['output']) == receipt
        assert (receipt['tests_run'],receipt['failures'],receipt['errors'],receipt['exit_code']) == (tests,failures,errors,exit_code)
        assert receipt['skipped'] == 0 and receipt['source_files'] == 150 and receipt['controller_files'] == 2
        assert receipt['source_unchanged'] and receipt['live_cache_access'] is False
        assert receipt['limits'] == {'address_bytes':536870912,'cpu_seconds':30,'file_bytes':33554432,'wall_seconds':45}
        assert sorted(receipt['changed_source_snapshots']) == changed
        assert 'interpreter startup and essential timer bootstrap externally unbounded' in receipt['timing_scope']
        output = (ROOT/directory/'output.txt').read_text()
        assert re.search(r'Ran '+str(tests)+r' tests? in ',output)
        if exit_code == 0:
            assert output.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$',output,re.M)) == tests
        else:
            assert output.count('\nFAIL: ') == failures and output.count('\nERROR: ') == errors
        assert index['runs'][stage]['tests'] == tests and index['runs'][stage]['recording_complete'] is True
        row.update({'recording_complete':True,'tests':tests,'failures':failures,'errors':errors,'pre_post_equal':True,
                    'entry_to_receipt_seconds':receipt['whole_wall_until_receipt_seconds']})
        if stage == 'cover-01':
            assert receipt['source_commit_at_launch'] == SOURCE
            assert all(sha(body(SOURCE,n)) == h == sha((ROOT/n).read_bytes()) for n,h in combined.items())
            assert sha((ROOT/directory/'pre-source.json').read_bytes()) == '36a6e24e177180be1f9ff339d88c3cf59e8abdeaebbb172e3c165577ebbbe265'
            assert sha((ROOT/directory/'pre-controller.json').read_bytes()) == 'a389ed447c1b100ea933e3de35510e7528b1ed2786c10b48dd335cf435c66b53'
            frozen = combined
    wrapper = (ROOT/directory/'run.py').read_bytes()
    marker = b'# END DEADLINE PREFIX\n'
    prefix = wrapper.split(marker,1)[0]+marker
    assert sha(prefix) == '7b46ff9acbebfc9d3cae6e9d5b80c0d2c7cdc0a082cbdb3a486021ff250a51aa'
    runs.append(row)
assert sum(baseline_sources[n] == frozen[n] for n in baseline_sources) == 147
assert sha(('\n'.join(sorted(baseline_sources))+'\n').encode()) == 'f61b1c1e7613ee67e38bd9f31a6b023f34df39e4d805ef7f6f5bb9907aa7f079'
for name in (*sources,*controllers):
    info = (ROOT/name).lstat()
    assert info.st_uid == info.st_gid == 1000 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o644

raw = PACKAGE.read_bytes()
parts = re.split(rb'(?=^diff --git )',raw,flags=re.M)
blocks = []
for block in parts[1:]:
    name = block.splitlines()[0].split(b' b/',1)[1].decode()
    data = None
    if b'\nnew file mode ' in block:
        lines = block.splitlines(keepends=True)
        hunk = next(i for i,line in enumerate(lines) if line.startswith(b'@@ '))
        chunks = []
        for line in lines[hunk+1:]:
            if line.startswith(b'+'):
                chunks.append(line[1:])
            else:
                assert line == b'\\ No newline at end of file\n' and chunks and chunks[-1].endswith(b'\n')
                chunks[-1] = chunks[-1][:-1]
        data = b''.join(chunks)
        assert data == body(HEAD,name) == (ROOT/name).read_bytes()
    blocks.append((name,block,data))
assert {n for n,_,_ in blocks} == set(git('diff','--name-only',BASE,HEAD).decode().splitlines())
keepers = {}
for name,block,data in sorted(blocks,key=lambda row:(0 if row[0] in sources else 1 if '/controller-readonly-api-source-cover-01/changed-source/' in row[0] else 2,row[0])):
    if data is not None:
        keepers.setdefault(sha(data),(name,data))
retained,omitted,rendered = [],[],[parts[0]]
for name,block,data in blocks:
    keeper,keeper_data = keepers[sha(data)] if data is not None else (name,None)
    if name == keeper:
        rendered.append(block); retained.append({'path':name,'block_sha256':sha(block)})
    else:
        assert data == keeper_data
        omitted.append({'path':name,'block_sha256':sha(block),'body_sha256':sha(data),'body_bytes':len(data),'identical_body_kept_at':keeper})
        rendered.append(('# Exact duplicate body: '+name+'\n# Kept verbatim at: '+keeper+'\n# SHA256: '+sha(data)+'\n# Raw package and all files remain intact.\n\n').encode())
assert all(any(row['path']==name for row in retained) for name in sources)
view = b''.join(rendered)
assert time.monotonic()-START < 45
with VIEW.open('xb') as f: f.write(view)
result = {'status':'PASS','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'dispatch_base':BASE,'source':SOURCE,'worker_evidence':WORKER,'review_head':HEAD,
          'artifact_rows':66,'artifact_bytes_excluding_index':1208572,'index_bytes':36307,
          'package_bytes_including_index':1244879,'net_growth_including_index':1046401,
          'source_bytes':164158,'canonical_sources':150,'separate_controller_sources':2,'unchanged_canonical':147,
          'preserved_plan_prefix':{'bytes':33536,'sha256':sha(old_plan),'append_bytes':7350},
          'preserved_prior_run_provenance':'Exact Git change sets exclude all previous runs;101 declared old hashes match prior index. No old semantic/test crawl.',
          'root_coordinator_paths':sorted(root_changes),'runs':runs,
          'review_view':{'raw_path':str(PACKAGE.relative_to(ROOT)),'raw_bytes':len(raw),'raw_sha256':sha(raw),
                         'view_path':str(VIEW.relative_to(ROOT)),'view_bytes':len(view),'view_sha256':sha(view),
                         'raw_blocks':len(blocks),'retained_blocks':retained,'omitted_exact_duplicate_bodies':omitted},
          'scope':'Public/Git provenance only. No project code imported, test rerun, host/runtime/private-body/CLI/cloud operation. Receipt timing not whole invocation.',
          'diagnostic_note':'First verifier attempt included the separate old plan-prefix file in the seven-run prefix count (102 vs101), exited1 before writing view/proof. Corrected path selection only; actual failure retained separately, no tests/evidence regenerated.',
          'raw_whitespace_note':'Interrupted red01/output.txt:1 historical trailing whitespace/no-newline preserved; new-file Git no-newline markers reconstructed exactly for comparison, never changed.'}
with OUT.open('x') as f: f.write(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':'PASS','artifacts':66,'complete_runs':4,'partial_runs':1,'frozen_tests':149,
                  'raw_bytes':len(raw),'view_bytes':len(view),'raw_blocks':len(blocks),
                  'duplicate_blocks':len(omitted),'result':str(OUT.relative_to(ROOT))}),flush=True)
assert time.monotonic()-START < 45
signal.setitimer(signal.ITIMER_REAL,0)
