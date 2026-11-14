#!/usr/bin/env python3
"""Public/Git provenance only; never import project code or rerun a test."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).absolute().parents[3]
BASE = '8184e9659a0d28a392dea64859f04f92005f2ed6'
SOURCE = 'a87b85072e0fb279d5337c077a30bfcbb8efcd62'
WORKER = 'fbac7dc13c9001b38c81cf4273d966c63f06eb0b'
HEAD = 'cd5768fa57f91e98e0f6b66856637e95727a60e1'
OUT = ROOT/'docs/evidence/task-6/controller-invoker-verification-20261025.json'
PACKAGE = ROOT/'.superpowers/sdd/2-warden-security-plan/review-8184e96..cd5768f.diff'
VIEW = PACKAGE.with_name('review-8184e96..cd5768f-deduplicated-view.diff')
assert not OUT.exists() and not VIEW.exists()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

cache = {}
def body(commit, name):
    key = (commit, name)
    if key not in cache:
        cache[key] = git('show', commit+':'+name)
    return cache[key]

def load(name):
    return json.loads((ROOT/name).read_bytes())

index_name = 'docs/evidence/task-6/controller-invoker-artifact-sizes.json'
index_bytes = (ROOT/index_name).read_bytes()
index = json.loads(index_bytes)
artifacts, sources = index['artifacts'], index['source_files']
assert index['dispatch_base'] == BASE and index['source_commit'] == SOURCE
assert len(artifacts) == index['artifact_count'] == 109
assert len(sources) == 5 and set(sources) <= set(artifacts)
assert len(index_bytes) == 31323 and index['index_self_excluded']
for name, row in artifacts.items():
    assert not Path(name).is_absolute() and '..' not in Path(name).parts
    assert name in sources or name in (index['plan_prefix']['path'], 'docs/evidence/task-6/controller-invoker-substage-report.md') or name.startswith('docs/evidence/task-6/controller-invoker-source-')
    data = (ROOT/name).read_bytes()
    info = (ROOT/name).lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    assert len(data) == row['bytes'] and sha(data) == row['sha256']
    assert info.st_blocks*512 == row['allocated_bytes']
    assert data == body(WORKER, name) == body(HEAD, name)
assert sum(r['bytes'] for r in artifacts.values()) == index['package_logical_bytes'] == 1696362
assert sum(r['allocated_bytes'] for r in artifacts.values()) == index['package_allocated_bytes'] == 1998848
assert sum(r['bytes'] for r in sources.values()) == 164942
assert set(git('diff', '--name-only', BASE, SOURCE).decode().splitlines()) == set(sources)
assert set(git('diff', '--name-only', BASE, WORKER).decode().splitlines()) == set(artifacts) | {index_name}
assert index_bytes == body(WORKER, index_name) == body(HEAD, index_name)
old_sizes = index['old_file_sizes_from_dispatch_git_blobs']
assert sum(old_sizes.values()) == 135398
for name, size in old_sizes.items():
    assert len(body(BASE, name)) == size
assert 1696362-135398 == index['incremental_logical_bytes_vs_dispatch_excluding_index'] == 1560964
plan = index['plan_prefix']['path']
old_plan, new_plan = body(BASE, plan), (ROOT/plan).read_bytes()
assert len(old_plan) == index['plan_prefix']['prefix_bytes'] == 22986
assert sha(old_plan) == index['plan_prefix']['prefix_sha256'] == '88f51ddbcc5d6ca026e9749e14ba1cdf9e52a797679d610f106f25c4d7aef123'
assert new_plan.startswith(old_plan) and len(new_plan)-len(old_plan) == 10550
report = 'docs/evidence/task-6/controller-invoker-substage-report.md'
assert (ROOT/report).read_bytes() == (ROOT/'.superpowers/sdd/2-warden-security-plan/task-6-controller-invoker-source-report.md').read_bytes()
root_changes = set(git('diff', '--name-only', WORKER, HEAD).decode().splitlines())
assert root_changes == {'docs/STATUS.md', 'docs/evidence/plan-review.md',
    'docs/evidence/task-6/controller-invoker-rulings.md', 'docs/evidence/task-6/controller-cli-material-proposal.md',
    'docs/evidence/task-6/controller-readonly-docker-api-proposal.md', 'docs/evidence/task-6/controller-readonly-docker-api-rulings.md'}
# Existing evidence is preserved by exact Git change coverage and the unchanged
# full plan prefix; old semantic evidence and old suites are not recrawled.

expected = [('red-01',3,3,0,1,1), ('green-01',118,4,0,1,2), ('red-02',2,1,1,1,2),
            ('green-02',121,4,0,1,2), ('green-03',121,0,0,0,2),
            ('green-04',1,0,0,0,2), ('cover-01',122,0,0,0,2)]
runs, baseline_sources = [], None
for stage, tests, failures, errors, exit_code, controller_count in expected:
    directory = 'docs/evidence/task-6/controller-invoker-source-'+stage
    baseline = load(directory+'/baseline.json')
    pre, post = load(directory+'/pre-source.json'), load(directory+'/post-source.json')
    pre_c, post_c = load(directory+'/pre-controller.json'), load(directory+'/post-controller.json')
    receipt, outer = load(directory+'/receipt.json'), load(directory+'/outer-tool-result.json')
    if baseline_sources is None:
        baseline_sources = baseline['sources']
        assert len(baseline_sources) == 150
        assert all(sha(body(BASE,n)) == h for n,h in baseline_sources.items())
    assert baseline['dispatch_base'] == BASE and baseline['sources'] == baseline_sources and baseline['controller_sources'] == {}
    assert len(pre) == receipt['source_files'] == 150 and pre == post
    assert len(pre_c) == receipt['controller_files'] == controller_count and pre_c == post_c
    assert set(pre_c) <= set(sources)-set(pre)
    assert all(pre[n] == h for n,h in baseline_sources.items() if n not in sources)
    combined = {**pre, **pre_c}
    changed = sorted(n for n,h in combined.items() if baseline_sources.get(n) != h)
    snapshot_root = ROOT/directory/'changed-source'
    snapshots = {str(p.relative_to(snapshot_root)):sha(p.read_bytes()) for p in snapshot_root.rglob('*') if p.is_file()}
    assert sorted(snapshots) == changed == sorted(receipt['changed_source_snapshots'])
    assert all(snapshots[n] == combined[n] for n in changed)
    assert (receipt['tests_run'],receipt['failures'],receipt['errors'],receipt['exit_code']) == (tests,failures,errors,exit_code)
    assert receipt['skipped'] == 0 and receipt['source_unchanged'] and receipt['live_cache_access'] is False
    assert receipt['limits'] == {'address_bytes':536870912,'cpu_seconds':30,'file_bytes':33554432,'wall_seconds':45}
    if 'initial' in outer:
        assert set(outer) in ({'initial'}, {'initial','final'})
        terminal = outer.get('final',outer['initial'])
        if 'final' in outer:
            assert type(outer['initial']['session_id']) is int and outer['initial']['output'] == ''
        assert json.loads(terminal['output']) == receipt
        outer_format = 'actual structured initial/final responses' if 'final' in outer else 'actual structured initial terminal response'
    else:
        assert stage == 'red-01' and outer['receipt'] == receipt and outer['chunk_id'] == 'bbe7ef'
        terminal = outer
        outer_format = 'normalized terminal metadata and receipt; not raw stdout'
    assert terminal['exit_code'] == exit_code
    output = (ROOT/directory/'output.txt').read_text()
    assert re.search(r'Ran '+str(tests)+r' tests? in ',output)
    if exit_code == 0:
        assert output.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$',output,re.M)) == tests
    else:
        assert output.count('\nFAIL: ') == failures and output.count('\nERROR: ') == errors
    wrapper = (ROOT/directory/'run.py').read_bytes()
    marker = b'# END DEADLINE PREFIX\n'
    prefix = wrapper.split(marker,1)[0]+marker
    assert sha(prefix) == receipt['tested_prefix_sha256'] == '7b46ff9acbebfc9d3cae6e9d5b80c0d2c7cdc0a082cbdb3a486021ff250a51aa'
    assert wrapper.rindex(b'finish_timer()') > wrapper.index(b'print(json.dumps(receipt')
    assert 'interpreter startup and essential timer bootstrap externally unbounded' in receipt['timing_scope']
    assert index['runs'][stage]['tests'] == tests and index['runs'][stage]['controller_files'] == controller_count
    if stage == 'cover-01':
        assert receipt['source_commit_at_launch'] == SOURCE
        assert all(sha(body(SOURCE,n)) == h == sha((ROOT/n).read_bytes()) for n,h in combined.items())
        assert sha((ROOT/directory/'pre-source.json').read_bytes()) == '003c3f304faf13b7e80985118ca00211d9eb4e78389a6f6832582c6356f9d980'
        assert sha((ROOT/directory/'pre-controller.json').read_bytes()) == 'a389ed447c1b100ea933e3de35510e7528b1ed2786c10b48dd335cf435c66b53'
        frozen = combined
    runs.append({'stage':stage,'tests':tests,'failures':failures,'errors':errors,'exit_code':exit_code,
                 'canonical_files':150,'controller_files':controller_count,'pre_post_equal':True,
                 'changed_snapshots':changed,'outer_format':outer_format,'terminal_chunk':terminal['chunk_id'],
                 'entry_to_receipt_seconds':receipt['whole_wall_until_receipt_seconds']})
assert sum(baseline_sources[n] == frozen[n] for n in baseline_sources) == 147
assert sha(('\n'.join(sorted(baseline_sources))+'\n').encode()) == 'f61b1c1e7613ee67e38bd9f31a6b023f34df39e4d805ef7f6f5bb9907aa7f079'
for name in sources:
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
        assert all(line.startswith(b'+') for line in lines[hunk+1:])
        data = b''.join(line[1:] for line in lines[hunk+1:])
        assert data == body(HEAD,name) == (ROOT/name).read_bytes()
    blocks.append((name,block,data))
assert {n for n,_,_ in blocks} == set(git('diff','--name-only',BASE,HEAD).decode().splitlines())
keepers = {}
for name,block,data in sorted(blocks,key=lambda row:(0 if row[0] in sources else 1 if '/controller-invoker-source-cover-01/changed-source/' in row[0] else 2,row[0])):
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
with VIEW.open('xb') as f: f.write(view)
result = {'status':'PASS','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'dispatch_base':BASE,'source':SOURCE,'worker_evidence':WORKER,'review_head':HEAD,
          'artifact_rows':109,'artifact_bytes_excluding_index':1696362,'index_bytes':31323,
          'package_bytes_including_index':1727685,'net_growth_including_index':1592287,
          'source_bytes':164942,'canonical_sources':150,'separate_controller_sources':2,'unchanged_canonical':147,
          'preserved_plan_prefix':{'bytes':22986,'sha256':sha(old_plan),'append_bytes':10550},
          'preservation':'Exact BASE-to-worker Git change set equals109 indexed artifacts plus index; only existing historical plan changes and its full old prefix is unchanged. No old semantic recrawl.',
          'root_coordinator_paths':sorted(root_changes),'runs':runs,
          'review_view':{'raw_path':str(PACKAGE.relative_to(ROOT)),'raw_bytes':len(raw),'raw_sha256':sha(raw),
                         'view_path':str(VIEW.relative_to(ROOT)),'view_bytes':len(view),'view_sha256':sha(view),
                         'raw_blocks':len(blocks),'retained_blocks':retained,'omitted_exact_duplicate_bodies':omitted},
          'scope':'Public/Git provenance only, no project code imported, test rerun, host/runtime/private-body/CLI/cloud operation. Fixture entry timing is not whole invocation or physical startup proof.',
          'diagnostic_note':'First root ad-hoc metadata inspection printed full plan/index metadata then KeyError0 by treating artifact mapping as list. Corrected inspection/proof uses mappings; no evidence or tests regenerated.',
          'raw_whitespace_note':'Two preserved historical unittest outputs have one trailing space each (green01 line53, green02 line56); source check passed. No raw history cleaned or approval bypass.'}
with OUT.open('x') as f: f.write(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':'PASS','artifacts':109,'runs':7,'frozen_tests':122,'raw_bytes':len(raw),
                  'view_bytes':len(view),'raw_blocks':len(blocks),'duplicate_blocks':len(omitted),'result':str(OUT.relative_to(ROOT))}))
