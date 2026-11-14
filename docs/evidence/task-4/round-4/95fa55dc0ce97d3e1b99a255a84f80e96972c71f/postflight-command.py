import datetime,json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/home/postedism/Desktop/Warden/scripts')
import firecracker_lab as lab
if os.getuid()!=1000:raise RuntimeError('ordinary UID1000 required')
with lab.locked():
 images=lab.scoped_ids('image',{'project':'warden'},lab.docker);containers=lab.scoped_ids('container',{'project':'warden'},lab.docker);outstanding=lab.outstanding_bytes(lab.BASE)
 if images or containers or outstanding:raise RuntimeError('own resources or charge remain')
 raw=subprocess.check_output([sys.executable,'-B',str(lab.ROOT/'scripts/azure_guard.py'),'preflight','--additional-bytes','0','--service-memory-bytes','1000000000','--download-bytes','0'],text=True)
 baseline=json.loads((lab.ROOT/'docs/evidence/task-4/controller-code-resource-checkpoint.json').read_text())['protected_sysctls']
 values={name:(Path('/proc/sys')/name).read_text().strip() for name in baseline}
 if values!=baseline:raise RuntimeError('protected host sysctls changed')
 print(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':subprocess.check_output(['git','rev-parse','HEAD'],cwd=lab.ROOT,text=True).strip(),'uid':os.getuid(),'preflight':json.loads(raw),'owned_images_all':images,'owned_containers_all':containers,'outstanding_bytes':outstanding,'configured_resident_services_bytes':0,'host_allowance_bytes':1000000000,'protected_sysctls':values,'protected_baseline_match':True,'bpf_or_device_policy_executed':False,'vm_executed':False,'tenant_executed':False,'prepare_or_abi_executed_this_round':False,'mount_smoke_or_remount_executed_this_round':False},indent=2))
