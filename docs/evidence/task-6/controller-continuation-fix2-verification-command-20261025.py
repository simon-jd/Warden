#!/usr/bin/env python3
"""Read-only Git/public evidence verification and duplicate rendering; no tests/cache."""
import datetime, hashlib, json, re, subprocess
from pathlib import Path
ROOT = Path(__file__).absolute().parents[3]
BASE = 'a51a923321ed4bd91936fc0afd84ed3eb2d92210'
DISPATCH = '1fb644b1a6b00165bb08e4447ba7550241b729f5'
SOURCE = '4c369be5aa5072a549ec34ba987a912646855d7e'
HEAD = 'abd3c570ab51c6cd82e4be59d0c01c8b58e8dad6'
OUT = ROOT/'docs/evidence/task-6/controller-continuation-fix2-verification-20261025.json'
PACKAGE = ROOT/'.superpowers/sdd/2-warden-security-plan/review-a51a923..abd3c57.diff'
VIEW = PACKAGE.with_name('review-a51a923..abd3c57-deduplicated-view.diff')
assert not OUT.exists() and not VIEW.exists()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(*args): return subprocess.check_output(['git', *args], cwd=ROOT)
def body(commit,name): return git('show',commit+':'+name)
def load(name): return json.loads((ROOT/name).read_bytes())
index_name='docs/evidence/task-6/continuation-fix2-artifact-sizes.json'
index=load(index_name)
assert index['dispatch_base']==DISPATCH and index['source_commit']==SOURCE
assert len(index['files'])==31
for row in index['files']+index['sources']:
    raw=(ROOT/row['path']).read_bytes()
    assert len(raw)==row['bytes'] and sha(raw)==row['sha256'] and raw==body(HEAD,row['path'])
report='docs/evidence/task-6/cache-continuation-substage-report.md'
old_report=body(DISPATCH,report); current_report=(ROOT/report).read_bytes()
assert current_report.startswith(old_report) and len(old_report)==index['historical_report_prefix_bytes']==12530
assert len(current_report)-len(old_report)==index['report_append_bytes']==7941
full_bytes=sum(row['bytes'] for row in index['files'])+(ROOT/index_name).stat().st_size
assert full_bytes==index['aggregate_full_evidence_bytes_including_index']==343793
assert full_bytes-len(old_report)==index['new_evidence_bytes_including_append_and_index']==331263
assert sum(row['bytes'] for row in index['sources'])==index['source_total_bytes']==55314
changed_names=git('diff','--name-only',DISPATCH,HEAD).decode().splitlines()
expected_names={row['path'] for row in index['files']+index['sources']}|{index_name}
assert set(changed_names)==expected_names
source_names=[row['path'] for row in index['sources']]
runs=[]; baseline_sources=None
for stage,expected in [('continuation-fix2-red-01',(4,1,4)),('continuation-fix2-green-02',(4,0,0)),('continuation-fix2-cover-03',(48,0,0))]:
    directory='docs/evidence/task-6/'+stage
    baseline=load(directory+'/baseline.json'); pre=load(directory+'/pre-source.json'); post=load(directory+'/post-source.json'); receipt=load(directory+'/receipt.json'); outer=load(directory+'/outer-tool-result.json')
    assert baseline['dispatch_base']==DISPATCH and pre==post and len(pre)==145
    if baseline_sources is None:
        baseline_sources=baseline['sources']; assert len(baseline_sources)==145
        assert all(sha(body(DISPATCH,n))==h for n,h in baseline_sources.items())
    assert baseline['sources']==baseline_sources and set(pre)==set(baseline_sources)
    assert all(pre[n]==h for n,h in baseline_sources.items() if n not in source_names)
    diff=sorted(n for n in pre if pre[n]!=baseline_sources[n])
    snapshots={str(p.relative_to(ROOT/directory/'changed-source')):sha(p.read_bytes()) for p in (ROOT/directory/'changed-source').rglob('*') if p.is_file()}
    assert sorted(snapshots)==diff==receipt['changed_source_snapshots'] and all(snapshots[n]==pre[n] for n in diff)
    assert (receipt['tests_run'],receipt['exit_code'],receipt['failures'])==expected and receipt['errors']==receipt['skipped']==0 and receipt['source_unchanged']
    assert receipt['limits']=={'address_bytes':536870912,'cpu_seconds':30,'file_bytes':33554432,'wall_seconds':45}
    if 'completion' in outer:
        assert set(outer)=={'initial','completion'} and outer['initial']['session_id']==44153 and outer['initial']['output']==''
        outer=outer['completion']
    assert outer['exit_code']==receipt['exit_code'] and json.loads(outer['output'])==receipt
    output=(ROOT/directory/'output.txt').read_text()
    assert re.search(r'Ran '+str(receipt['tests_run'])+r' tests in ',output)
    if receipt['exit_code']==0: assert output.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$',output,re.M))==receipt['tests_run']
    else: assert output.count('\nFAIL: ')==4 and 'FAILED (failures=4)' in output
    wrapper=(ROOT/directory/'run.py').read_text()
    assert 'os._exit(124)' in wrapper and wrapper.index('signal.alarm(0)')>wrapper.index('print(json.dumps(receipt')
    if stage.endswith('cover-03'):
        assert receipt['source_commit_at_launch']==SOURCE and all(sha(body(SOURCE,n))==h==sha((ROOT/n).read_bytes()) for n,h in pre.items())
    runs.append({'stage':stage,'tests':receipt['tests_run'],'exit_code':receipt['exit_code'],'failures':receipt['failures'],'source_files':145,'pre_post_sha256':sha((ROOT/directory/'pre-source.json').read_bytes()),'changed_snapshots':diff,'duration_seconds':receipt['duration_seconds'],'whole_wall_until_receipt_seconds':receipt['whole_wall_until_receipt_seconds'],'outer_exit_code':outer['exit_code']})
raw=PACKAGE.read_bytes(); parts=re.split(rb'(?=^diff --git )',raw,flags=re.M); blocks=[]
for block in parts[1:]:
    name=block.splitlines()[0].split(b' b/',1)[1].decode(); file_body=None
    if b'\nnew file mode ' in block:
        lines=block.splitlines(keepends=True); hunk=next(i for i,line in enumerate(lines) if line.startswith(b'@@ ')); assert all(line.startswith(b'+') for line in lines[hunk+1:])
        file_body=b''.join(line[1:] for line in lines[hunk+1:]); assert file_body==body(HEAD,name)==(ROOT/name).read_bytes()
    blocks.append((name,block,file_body))
keepers={}
for name,block,file_body in sorted(blocks,key=lambda row:(0 if '/continuation-fix2-cover-03/changed-source/' in row[0] else 1,row[0])):
    if file_body is not None: keepers.setdefault(sha(file_body),name)
retained=[]; omitted=[]; rendered=[parts[0]]
for name,block,file_body in blocks:
    keeper=keepers.get(sha(file_body)) if file_body is not None else name
    if name==keeper:
        rendered.append(block); retained.append({'path':name,'block_sha256':sha(block)})
    else:
        omitted.append({'path':name,'block_sha256':sha(block),'body_sha256':sha(file_body),'body_bytes':len(file_body),'identical_body_kept_at':keeper})
        rendered.append(('# Exact duplicate body: '+name+'\n# Kept verbatim at: '+keeper+'\n# SHA256: '+sha(file_body)+'\n# Full original diff and files remain intact.\n\n').encode())
assert all(any(row['path']==name for row in retained) for name in source_names)
view=b''.join(rendered); VIEW.write_bytes(view)
result={'status':'PASS','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'previous_review_head':BASE,'dispatch_base':DISPATCH,'source':SOURCE,'head':HEAD,'new_artifacts_including_index':31,'report_append_bytes':7941,'new_evidence_bytes':331263,'old_report_prefix_identical':True,'source_files':145,'unchanged_dependency_files':143,'runs':runs,'review_view':{'full_path':str(PACKAGE.relative_to(ROOT)),'full_bytes':len(raw),'full_sha256':sha(raw),'view_path':str(VIEW.relative_to(ROOT)),'view_bytes':len(view),'view_sha256':sha(view),'retained_blocks':retained,'omitted_exact_duplicate_bodies':omitted},'actuals':'No tests/cache/privatebody/host/cloud/identity operations; actual source gate and all operation/resource gates remain pending.'}
with OUT.open('x') as f:f.write(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':'PASS','runs':3,'frozen_tests':48,'full_bytes':len(raw),'view_bytes':len(view),'duplicate_blocks':len(omitted),'result':str(OUT.relative_to(ROOT))}))
