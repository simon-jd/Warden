import contextlib,datetime,hashlib,io,json,os,subprocess,sys
from pathlib import Path
ROOT=Path('/home/postedism/Desktop/Warden')
sys.path.insert(0,str(ROOT/'scripts'))
from runtime_lab_docker import docker,scoped_ids,outstanding_bytes
from azure_guard import preflight
os.umask(0o077)
if len(sys.argv)!=2 or sys.argv[1] not in ('red','green','cover'):raise RuntimeError('fixed evidence pass required')
name=sys.argv[1];mode='matrix-code'
source_paths=('attacks/matrix/classify.go','attacks/matrix/classify_test.go','scripts/firecracker_code.py')
def manifest():return {p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source_paths}
if name=='cover':
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()!='6cedf69d7da82e7fd2cd80c69d5d9bfb5b0024aa':
        raise RuntimeError('cover source head differs')
    if subprocess.check_output(['git','status','--porcelain','--',*source_paths],cwd=ROOT,text=True).strip():raise RuntimeError('source not frozen')
source_before=manifest()
output=ROOT/'.cache/task5-classifier'
keys=('vm/overcommit_memory','vm/panic_on_oom','kernel/panic','kernel/panic_on_oops','kernel/keys/root_maxkeys','kernel/keys/root_maxbytes')
def sysctls():return {k:(Path('/proc/sys')/k).read_text().strip() for k in keys}
def accounting():
    containers=scoped_ids('container',{'project':'warden'},docker)
    if containers:raise RuntimeError('Warden containers remain')
    charge=0;images=[]
    for identity in sorted(set(scoped_ids('image',{'project':'warden'},docker))):
        value=json.loads(docker(['image','inspect',identity]))[0]
        if value['Id']!=identity or value['Config'].get('Labels',{}).get('project')!='warden':raise RuntimeError('image identity differs')
        charge+=2*value['Size']+64000000;images.append({'id':identity,'size':value['Size']})
    reserve=outstanding_bytes(ROOT/'.cache/warden-lab')
    if reserve!=5000000000:raise RuntimeError('retained original Q differs')
    return {'containers':containers,'images':images,'image_charge':charge,'outstanding':reserve}
result={'mode':mode,'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'source_manifest_before':source_before,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'before':accounting(),'sysctls_before':sysctls()}
with (output/(name+'.log')).open('xb') as log:
    proc=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/firecracker_code.py'),mode],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=240)
result['exit_code']=proc.returncode
result['source_manifest_after']=manifest()
if result['source_manifest_after']!=source_before:raise RuntimeError('source changed during test')
result['after']=accounting();result['sysctls_after']=sysctls()
if result['sysctls_before']!=result['sysctls_after']:raise RuntimeError('protected sysctl changed')
receipt=io.StringIO()
with contextlib.redirect_stdout(receipt):preflight(result['after']['outstanding']+result['after']['image_charge'],1000000000,0)
result['ordinary_postflight']=json.loads(receipt.getvalue())
result['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (output/(name+'.json')).open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps({'pass':name,'exit_code':proc.returncode,'postflight':result['ordinary_postflight'],'sysctls_unchanged':True,'own_containers':0}))
