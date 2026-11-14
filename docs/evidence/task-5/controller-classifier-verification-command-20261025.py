"""Narrow frozen fixture source/evidence corroboration; never runs tests."""
import datetime,hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path('/home/postedism/Desktop/Warden')
SOURCE='6cedf69d7da82e7fd2cd80c69d5d9bfb5b0024aa'
BASE='b765fe109251ed7579386a70d5655c7e4edcccdd'
EVIDENCE='8319b458c6a01daa51409b2476376173bc875b99'
assert os.geteuid()==1000
os.chdir(ROOT)
sys.path.insert(0,str(ROOT/'scripts'))
import firecracker_recovery as r
def git(*args):return subprocess.check_output(['/usr/bin/git',*args])
assert git('rev-parse','HEAD').decode().strip()==EVIDENCE
directory=ROOT/'docs/evidence/task-5/classifier'/SOURCE
index=json.loads((directory/'index.json').read_bytes())
assert index['source_commit']==SOURCE and len(index['files'])==19
assert {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}==set(index['files'])|{'index.json'}
for name,meta in index['files'].items():
    raw=(directory/name).read_bytes()
    assert len(raw)==meta['bytes'] and hashlib.sha256(raw).hexdigest()==meta['sha256']
    assert raw==git('show',EVIDENCE+':'+str((directory/name).relative_to(ROOT)))
cover=json.loads((directory/'cover.json').read_bytes())
assert cover['source_head']==SOURCE and cover['exit_code']==0
assert cover['source_manifest_before']==cover['source_manifest_after']
assert set(git('diff','--name-only',BASE,SOURCE).decode().splitlines())==set(cover['source_manifest_before'])
for name,digest in cover['source_manifest_before'].items():
    raw=(ROOT/name).read_bytes()
    assert raw==git('show',SOURCE+':'+name)==(directory/'source'/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==digest
text=(directory/'cover.log').read_text()
assert len(re.findall(r'^--- PASS:',text,re.M))==6
assert len(re.findall(r'^ +--- PASS:',text,re.M))==53
assert not re.search(r'^\s*--- (FAIL|SKIP):',text,re.M)
assert cover['before']==cover['after']=={'containers':[],'images':[],'image_charge':0,'outstanding':5000000000}
assert cover['sysctls_before']==cover['sysctls_after']
with r.project_lock():
    scene=r.Scene(cleanup=True)
    try:
        scene.check(1000)
        raw=r.load(r.WORK/'inspect'/'result.json')
        assert hashlib.sha256(raw).hexdigest()=='55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
        inventory=r.helper.validate_inventory(raw,r.file_sha(r.MODULE))
        assert not r.scoped_ids('image',{'project':'warden'},r.docker)
        post=r.full_postflight(scene,0,inventory)
        assert r.current_charges()==5000000000
    finally:scene.close()
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':SOURCE,'base':BASE,'evidence':EVIDENCE,'source_files_verified':3,'indexed_new_artifacts_verified':len(index['files']),'frozen_cover_before_after_source_hashes_match':True,'recorded_frozen_tests':{'top_level_pass':6,'subtest_pass':53,'fail':0,'skip':0},'historical_red_green_pre_run_file_hashes_unavailable':True,'red_stub_snapshot_unavailable':True,'historical_provenance_not_reconstructed':True,'tests_rerun_by_controller':False,'ordinary_postflight':post,'original_scene_metadata_unchanged':True,'owned_images_and_containers':0,'Q_released':False,'fixture_authorship':'subagent /root/matrix_classifier, not human and not real attack evidence','actual_matrix_cells_run':0,'task5_complete':False,'goal_complete':False,'semantic_review':'independent classifier review pending'}
out=ROOT/'docs/evidence/task-5/controller-classifier-verification-20261025.json'
with out.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
