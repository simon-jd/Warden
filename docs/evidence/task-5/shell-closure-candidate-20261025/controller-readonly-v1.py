"""Inspect only fixed installed public materials; never execute a shell/payload."""
import datetime, hashlib, json, os, re, stat, subprocess
from pathlib import Path

ROOT=Path('/home/postedism/Desktop/Warden')
assert os.geteuid()==1000
def fixed(name,limit=4000000):
    parts=Path(name).parts
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
            s=os.fstat(fd)
            assert s.st_uid==0 and s.st_gid==0 and not s.st_mode&0o022
        filefd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            s=os.fstat(filefd)
            assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
            assert not s.st_mode&0o022 and s.st_size<=limit and not os.listxattr(filefd)
            raw=os.read(filefd,limit+1)
            assert len(raw)==s.st_size and os.fstat(filefd)==s
            assert os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)==s
            return {'path':name,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'nlink':s.st_nlink,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},raw
        finally:os.close(filefd)
    finally:os.close(fd)

readelf,raw=fixed('/usr/bin/x86_64-linux-gnu-readelf')
assert readelf['sha256']=='c857339616bbbfa5eba32733e22365048903fbaf6ed2126b897dd138bcb741fc'
query,_=fixed('/usr/bin/dpkg-query')
names=('/usr/bin/dash','/usr/lib/x86_64-linux-gnu/libc.so.6','/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')
materials={}
for name in names:
    meta,raw=fixed(name)
    assert raw[:4]==b'\x7fELF' and raw[4:6]==b'\x02\x01' and int.from_bytes(raw[18:20],'little')==62
    run=subprocess.run([readelf['path'],'-d',name],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},timeout=5)
    assert run.returncode==0 and not run.stderr and len(run.stdout)<=8192
    needed=re.findall(rb'\(NEEDED\).*?Shared library: \[([^\]]+)\]',run.stdout)
    meta['DT_NEEDED']=[x.decode('ascii') for x in needed]
    meta['dynamic_output_sha256']=hashlib.sha256(run.stdout).hexdigest()
    assert fixed(name)[0]=={k:v for k,v in meta.items() if k not in ('DT_NEEDED','dynamic_output_sha256')}
    materials[name]=meta
assert materials[names[0]]['sha256']=='c626229526bb58ec2d0f585f3c3ae1412e6f973b4353385042d11c38d8426917'
assert materials[names[0]]['DT_NEEDED']==['libc.so.6']
assert materials[names[1]]['DT_NEEDED']==['ld-linux-x86-64.so.2']
assert materials[names[2]]['DT_NEEDED']==[]
run=subprocess.run([query['path'],'-W','-f=${Package}\t${Version}\t${Architecture}\t${Status}\n','dash','libc6'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},timeout=5)
assert run.returncode==0 and not run.stderr and len(run.stdout)<=1024
licenses={}
for name in ('/usr/share/doc/dash/copyright','/usr/share/doc/libc6/copyright','/usr/share/common-licenses/GPL-2','/usr/share/common-licenses/LGPL-2.1'):
    licenses[name]=fixed(name,262144)[0]
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'fixed installed-material read-only ELF closure and package/license metadata; no material copied or executed','tools':{'readelf':readelf,'dpkg_query':query},'package_metadata':run.stdout.decode('ascii').splitlines(),'materials':materials,'public_material_bytes':sum(m['bytes'] for m in materials.values()),'license_notice_inputs':licenses,'interpreter_guest_path':'/lib64/ld-linux-x86-64.so.2','future_guest_materialization':'regular copies at exact loader/library paths; no symlinks implied','publisher_signature_verified':False,'dpkg_package_archive_hash_verified':False,'shell_executed':False,'guest_ABI_verified':False,'actual_32MiB_payload_fit_verified':False,'new_resource_created':False,'task5_matrix_cells_executed':0}
out=ROOT/'docs/evidence/task-5/shell-closure-candidate-20261025'
out.mkdir(mode=0o755)
with (out/'metadata.json').open('x') as stream:stream.write(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
