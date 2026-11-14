import datetime,json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/home/postedism/Desktop/Warden/scripts')
import firecracker_lab as lab
with lab.locked():
    images=lab.scoped_ids('image',{'project':'warden'},lab.docker)
    containers=lab.scoped_ids('container',{'project':'warden'},lab.docker)
    outstanding=lab.outstanding_bytes(lab.BASE)
    if images or containers or outstanding:raise RuntimeError('own resources or reservation remain')
    raw=subprocess.check_output([sys.executable,'-B',str(lab.ROOT/'scripts/azure_guard.py'),'preflight','--additional-bytes','0','--service-memory-bytes','1000000000','--download-bytes','0'],text=True)
    baseline=json.loads((lab.ROOT/'docs/evidence/task-4/controller-code-resource-checkpoint.json').read_text())['protected_sysctls']
    values={name:(Path('/proc/sys')/name).read_text().strip() for name in baseline}
    pins={}
    for name,pin in lab.MATERIALS.items():
        data=lab.bounded_input(lab.BASE/'firecracker-materials'/name,pin['size'])
        if lab.sha(data)!=pin['sha256']:raise RuntimeError('material changed')
        pins[name]={**pin,'observed_bytes':len(data),'observed_sha256':lab.sha(data)}
    sessions=[]
    for path in sorted(lab.BASE.glob('docker-firecracker-*')):
        sessions.append({'name':path.name,'charge':json.loads(lab.bounded_input(path/'charge.json',4096)),'files':sorted(p.name for p in path.iterdir())})
    print(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':subprocess.check_output(['git','rev-parse','HEAD'],cwd=lab.ROOT,text=True).strip(),'uid':os.getuid(),'host':os.uname().nodename,'kernel':os.uname().release,'docker_version':json.loads(lab.docker(['version','--format','{{json .}}'])),'owned_images_all':images,'owned_containers_all':containers,'outstanding_bytes':outstanding,'configured_resident_services_bytes':0,'host_allowance_bytes':1000000000,'preflight':json.loads(raw),'protected_sysctls':values,'protected_baseline_match':values==baseline,'materials':pins,'sessions':sessions,'vm_executed':False,'tenant_executed':False},indent=2))
