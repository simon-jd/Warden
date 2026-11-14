"""Controller hash corroboration and read-only post-code checkpoint; no tests."""
import datetime, hashlib, json, os, re, subprocess, sys
from pathlib import Path
ROOT=Path('/home/postedism/Desktop/Warden')
SOURCE='0da497136069bf045912f257f7c6d26c962f9d34'
BASE='f40934a5a3e6bc5f2d741120bcc5448ba996cd12'
EVIDENCE='df12df11de2e6d7a7f7f0d7187f6b48e6fd8a18d'
sys.path.insert(0,str(ROOT/'scripts'))
import firecracker_recovery as r
assert os.geteuid()==1000
os.chdir(ROOT)
def git(*args):return subprocess.check_output(['/usr/bin/git',*args])
assert git('rev-parse','HEAD').decode().strip()==EVIDENCE
directory=ROOT/'docs/evidence/task-4/round-5-b'/SOURCE
manifest=json.loads((directory/'source-verification.json').read_bytes())
changed=set(git('diff','--name-only',BASE,SOURCE).decode().splitlines())
assert changed==set(manifest['files']) and len(changed)==6
for group in ('files','unchanged_bindings'):
    for name,meta in manifest[group].items():
        raw=(ROOT/name).read_bytes()
        assert len(raw)==meta['bytes'] and hashlib.sha256(raw).hexdigest()==meta['sha256']
        assert raw==git('show',SOURCE+':'+name)
        if group=='unchanged_bindings':assert raw==git('show',BASE+':'+name)
index=json.loads((directory/'evidence-index.json').read_bytes())
assert len(index['files'])==14
assert {p.name for p in directory.iterdir()}==set(index['files'])|{'evidence-index.json'}
for name,meta in index['files'].items():
    raw=(directory/name).read_bytes()
    assert len(raw)==meta['bytes'] and hashlib.sha256(raw).hexdigest()==meta['sha256']
    assert raw==git('show',EVIDENCE+':'+str((directory/name).relative_to(ROOT)))
for name,passed,failed,skipped in [('red-behavior',1,2,0),('green',7,0,0),('cover',59,0,4)]:
    text=(directory/(name+'.log')).read_text()
    assert len(re.findall(r'^--- PASS:',text,re.M))==passed
    assert len(re.findall(r'^--- FAIL:',text,re.M))==failed
    assert len(re.findall(r'^--- SKIP:',text,re.M))==skipped
    receipt=json.loads((directory/(name+'.json')).read_bytes())
    assert receipt['after']=={'containers':[],'images':[],'image_charge':0,'outstanding':5000000000}
    if name=='cover':assert receipt['source_head']==SOURCE and receipt['exit_code']==0
with r.project_lock():
    scene=r.Scene(cleanup=True)
    try:
        scene.check(1000)
        raw=r.load(r.WORK/'inspect'/'result.json')
        assert hashlib.sha256(raw).hexdigest()=='55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
        inventory=r.helper.validate_inventory(raw,r.file_sha(r.MODULE))
        assert not r.scoped_ids('image',{'project':'warden'},r.docker)
        post=r.full_postflight(scene,0,inventory)
        assert r.current_charges()==5000000000 and post['released'] is False
    finally:scene.close()
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':SOURCE,'base':BASE,'evidence':EVIDENCE,'source_files_verified':len(changed),'unchanged_bindings_verified':len(manifest['unchanged_bindings']),'indexed_new_artifacts_verified':len(index['files']),'recorded_top_tests':{'behavior_red':{'pass':1,'fail':2},'green':{'pass':7},'committed_cover':{'pass':59,'live_skip':4}},'tests_rerun_by_controller':False,'semantic_review':'independent B review pending','ordinary_code_postflight':post,'original_scene_metadata_unchanged':True,'owned_images_and_containers':0,'old_recovery_operation_reexecuted':False,'Q_released':False,'new_boot_authorized':False,'task4_accepted':False,'goal_complete':False}
out=ROOT/'docs/evidence/task-4/controller-b-code-verification-20261025.json'
with out.open('x') as stream:stream.write(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
