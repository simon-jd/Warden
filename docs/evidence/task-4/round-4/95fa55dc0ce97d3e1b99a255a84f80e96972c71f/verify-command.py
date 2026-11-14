"""Read-only source/old-evidence verification; writes only this round's result."""
import hashlib,json,stat,subprocess
from pathlib import Path

root=Path('/home/postedism/Desktop/Warden')
source='95fa55dc0ce97d3e1b99a255a84f80e96972c71f'
parent='c0aac78'
out=root/'docs/evidence/task-4/round-4'/source
sha=lambda data:hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=root)
def original(path):return git('show',parent+':'+path)

manifest=json.loads((out/'source-manifest.json').read_text())
for group in ('files','unchanged_interfaces_and_profiles'):
    for name,expected in manifest[group].items():
        path=root/name;raw=path.read_bytes()
        assert sha(raw)==expected['sha256'],name
        assert oct(stat.S_IMODE(path.stat().st_mode))==expected['mode'],name
        assert raw==git('show',source+':'+name),name
git('diff','--exit-code',source,'--',*manifest['files'],*manifest['unchanged_interfaces_and_profiles'])

records=git('ls-tree','-r','--full-tree',parent,'docs/evidence/task-4').decode().splitlines()
for entry in records:
    meta,name=entry.split('\t',1);mode,kind,blob=meta.split();path=root/name
    assert path.read_bytes()==original(name),name
    assert mode==('100755' if path.stat().st_mode&0o111 else '100644'),name

indexes=[]
for entry in records:
    name=entry.split('\t',1)[1]
    if not name.endswith('/evidence-index.json'):continue
    path=root/name;data=json.loads(path.read_text())
    # Original index spans two source directories; later indexes are local.
    base=root/'docs/evidence/task-4' if name=='docs/evidence/task-4/55bd96828669c8e1536da321bcb87bae13afa6ea/evidence-index.json' else path.parent
    for filename,expected in data['files'].items():
        raw=(base/filename).read_bytes()
        assert sha(raw)==expected['sha256'],filename
        assert len(raw)==expected['bytes'],filename
    indexes.append({'index':name,'sha256':sha(path.read_bytes()),'entries_verified':len(data['files']),'all_match':True})

result={'source':source,'source_parent':git('rev-parse',parent).decode().strip(),'all_preexisting_tracked_task4_evidence_byte_and_mode_identical':True,'tracked_files_verified':len(records),'indexed_artifacts':indexes,'source_manifest_files_verified':len(manifest['files']),'unchanged_interface_files_verified':len(manifest['unchanged_interfaces_and_profiles'])}
path=out/'old-evidence-verification.json'
path.write_text(json.dumps(result,indent=2)+'\n');path.chmod(0o644)
print(json.dumps(result,indent=2))
