from pathlib import Path
import datetime,fcntl,hashlib,json,os,re,subprocess,sys,tarfile
root=Path('/home/postedism/Desktop/Warden');sys.path.insert(0,str(root/'scripts'))
from runtime_lab_docker import docker,scoped_ids,outstanding_bytes
source,phase=sys.argv[1:];assert re.fullmatch('[0-9a-f]{40}',source) and phase in ('mount-smoke','boot')
cache=root/'.cache/firecracker-code';folder=root/'docs/evidence/task-4/live'/source
lock=os.open(root/'.cache/warden-lab/docker.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    info=json.loads((cache/'package.json').read_text());assert info['source']==source
    assert subprocess.check_output(['git','log','-1','--format=%H','--','go.mod','go.sum','runtimes','scripts/firecracker_code.py','scripts/firecracker_lab.py'],cwd=root,text=True).strip()==source
    raw=(cache/'package.tar').read_bytes();assert len(raw)==info['tar_bytes']<=512000000 and hashlib.sha256(raw).hexdigest()==info['tar_sha256'];assert info['file_bytes']<=384000000
    verified={}
    with tarfile.open(cache/'package.tar','r:') as archive:
        seen=set();total=0
        for entry in archive:
            assert entry.name not in seen;seen.add(entry.name);assert len(seen)<=64
            if entry.isdir():continue
            assert entry.isfile() and entry.name.startswith('opt/warden/input/') and entry.size<=64*1024*1024
            data=archive.extractfile(entry).read();assert len(data)==entry.size;total+=len(data)
            name=entry.name.removeprefix('opt/warden/input/');verified[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            if name in info['manifest']['Artifacts']:assert verified[name]['sha256']==info['manifest']['Artifacts'][name]
            if name in ('lab','firecracker.test'):assert data==(cache/name).read_bytes()
            if name=='manifest.json':assert json.loads(data)==info['manifest']
        assert total==info['file_bytes']
    assert set(verified)=={'kernel','firecracker','jailer','lab','firecracker.test','agent.ext4','payload.ext4','manifest.json','provenance.json'}
    assert hashlib.sha256((cache/'agent').read_bytes()).hexdigest()==info['manifest']['AgentSHA']
    images=scoped_ids('image',{'project':'warden'},docker);containers=scoped_ids('container',{'project':'warden'},docker);outstanding=outstanding_bytes(root/'.cache/warden-lab')
    assert images==containers==[] and outstanding==0
    maximum_import_allowance=2*512000000+64000000;service=1256000000 if phase=='mount-smoke' else 5000000000
    preflight=json.loads(subprocess.check_output([sys.executable,'-B',str(root/'scripts/azure_guard.py'),'preflight','--additional-bytes',str(5000000000+maximum_import_allowance),'--service-memory-bytes',str(service),'--download-bytes','0'],text=True))
    result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':source,'phase':phase,'package':info,'independently_verified_files':verified,'owned_images_all':images,'owned_containers_all':containers,'outstanding_bytes':outstanding,'max_import_allowance_bytes':maximum_import_allowance,'prospective_outer_plus_host_allowance_bytes':service,'preflight':preflight,'vm_executed':False}
    with (folder/('package-verification-'+phase+'.json')).open('x') as out:json.dump(result,out,indent=2);out.write('\n')
    print(json.dumps({'package_tar_bytes':len(raw),'package_sha256':info['tar_sha256'],'verified_files':len(verified),'preflight':preflight,'own_objects':0,'outstanding':0}))
finally:os.close(lock)
