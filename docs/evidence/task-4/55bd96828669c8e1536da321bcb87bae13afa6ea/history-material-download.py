import hashlib,json,os,subprocess,sys,urllib.request
from pathlib import Path
ROOT=Path('/home/postedism/Desktop/Warden');sys.path.insert(0,str(ROOT/'scripts'))
from runtime_lab_docker import docker,scoped_ids,outstanding_bytes
from runtime_lab_paths import trusted_directory
os.umask(0o077)
if os.getuid()!=1000:raise RuntimeError('ordinary UID1000 required')
BASE='https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/'
KERNEL='https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261023-dd7c24b0d165-0/x86_64/vmlinux-6.18.54'
items=[('firecracker-v1.17.0-x86_64.tgz.sha256.txt',BASE+'firecracker-v1.17.0-x86_64.tgz.sha256.txt',97,'b89dea3edf551929f151b95d31168677ad2b8bb257d1d87a08470f7299749b7c'),('firecracker-v1.17.0-x86_64.tgz',BASE+'firecracker-v1.17.0-x86_64.tgz',7464385,'06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558'),('vmlinux-6.18.54',KERNEL,27893008,None),('vmlinux-6.18.54.config',KERNEL+'.config',101680,'7dbdc7445d01d3dd049b1e653534bde71266d59afaf9c1de50a8a6b8a8c138d0')]
base=ROOT/'.cache/warden-lab/firecracker-materials';base.mkdir(mode=0o700,exist_ok=True)
fd=trusted_directory(str(base),1000)
try:
 for name,url,size,expected in items:
  if scoped_ids('container',{'project':'warden'},docker):raise RuntimeError('other Warden container')
  external=0
  for identity in set(scoped_ids('image',{'project':'warden'},docker)):
   data=json.loads(docker(['image','inspect',identity]))[0]
   if data['Id']!=identity or data['Config'].get('Labels',{}).get('project')!='warden':raise RuntimeError('image identity')
   external+=2*data['Size']+64000000
  outstanding=outstanding_bytes(ROOT/'.cache/warden-lab')
  subprocess.run([sys.executable,'-B',str(ROOT/'scripts/azure_guard.py'),'preflight','--additional-bytes',str(5000000000+external+outstanding),'--service-memory-bytes','2000000000','--download-bytes',str(size)],check=True)
  dest=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
  count=0;h=hashlib.sha256()
  try:
   with urllib.request.urlopen(url,timeout=30) as response,os.fdopen(dest,'wb') as out:
    while chunk:=response.read(1048576):
     count+=len(chunk)
     if count>size:raise RuntimeError('material oversized')
     out.write(chunk);h.update(chunk)
    if count!=size or expected and h.hexdigest()!=expected:raise RuntimeError('material hash/size mismatch')
    out.flush();os.fsync(out.fileno())
   os.fsync(fd)
   if name.endswith('.sha256.txt'):
    if (base/name).read_text().split()[0]!='06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558':raise RuntimeError('publisher release checksum mismatch')
   print(json.dumps({'material':name,'url':url,'bytes':count,'sha256':h.hexdigest(),'provenance':'publisher release checksum verified' if expected else 'computed pin from fixed official CI URL, not a publisher checksum/signature'}),flush=True)
  except BaseException:
   try:os.close(dest)
   except OSError:pass
   os.unlink(name,dir_fd=fd);os.fsync(fd);raise
finally:os.close(fd)
