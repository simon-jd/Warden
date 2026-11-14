#!/usr/bin/env python3
"""Fixed, capless Task4 code/build profile. Never starts a microVM."""
import datetime,fcntl,json,os,secrets,subprocess,sys,stat
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'scripts'))
from runtime_lab_docker import docker,scoped_ids,outstanding_bytes,owned_inspect
from runtime_lab_paths import trusted_directory
os.umask(0o077)
if len(sys.argv)!=2 or sys.argv[1] not in ('code','build','tools','rootfs','diagnostics','matrix-code','identity-unit'):
    raise RuntimeError('fixed code/build/tools mode required')
mode=sys.argv[1]
basefd=trusted_directory(str(ROOT/'.cache/warden-lab'),os.getuid())
lockfd=os.open('docker.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=basefd)
os.close(basefd)
lockstat=os.fstat(lockfd)
if not stat.S_ISREG(lockstat.st_mode) or lockstat.st_uid!=os.getuid() or lockstat.st_nlink!=1 or stat.S_IMODE(lockstat.st_mode)!=0o600:raise RuntimeError('unsafe project lock')
fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
PIN='sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d'
if os.getuid()!=1000: raise RuntimeError('ordinary operator UID1000 required')
if scoped_ids('container',{'project':'warden'},docker): raise RuntimeError('other Warden container present')
external=0
for identity in set(scoped_ids('image',{'project':'warden'},docker)):
    data=json.loads(docker(['image','inspect',identity]))[0]
    if data['Id']!=identity or data['Config'].get('Labels',{}).get('project')!='warden': raise RuntimeError('unowned image')
    external+=2*data['Size']+64000000
outstanding=outstanding_bytes(ROOT/'.cache/warden-lab')
print(json.dumps({'image_id':PIN,'owned_image_charge':external,'outstanding':outstanding}),flush=True)
subprocess.run([sys.executable,'-B',str(ROOT/'scripts/azure_guard.py'),'preflight','--additional-bytes',str(512000000+external+outstanding),'--service-memory-bytes','3000000000','--download-bytes','0'],check=True)
cache=ROOT/'.cache/firecracker-code'
cache.mkdir(mode=0o700,exist_ok=True)
st=cache.lstat()
if st.st_uid!=1000 or st.st_mode&0o777!=0o700 or cache.is_symlink():raise RuntimeError('unsafe code cache')
labels={'project':'warden','owner':'codex-warden','session':secrets.token_hex(16),'task':mode if mode in ('matrix-code','identity-unit') else 'firecracker-code','ttl':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}
args=['container','create','--pull=never','--user=1000:1000','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--network=none','--ipc=private','--cgroupns=private','--memory=2000000000','--memory-swap=2000000000','--cpus=2','--pids-limit=256','--tmpfs=/tmp:rw,exec,nosuid,nodev,size=268435456','--log-driver=json-file','--log-opt=max-size=10m','--log-opt=max-file=1','--mount=type=bind,src='+str(ROOT)+',dst=/workspace,readonly','--mount=type=bind,src='+str(cache)+',dst=/workspace/.cache/firecracker-code','--workdir=/workspace']
for k,v in labels.items():args+=['--label',k+'='+v]
for k,v in {'GOMAXPROCS':'2','GOMEMLIMIT':'1500MiB','GOTOOLCHAIN':'local','GOPROXY':'off','GOCACHE':'/workspace/.cache/firecracker-code','GOMODCACHE':'/workspace/.cache/go-mod','HOME':'/tmp','GOPATH':'/tmp/go'}.items():args+=['--env',k+'='+v]
go='/workspace/.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin/go'
command='umask 0077; exec '+go+' test -p 1 -count=1 -v ./runtimes/firecracker/...'
if mode=='matrix-code':command='umask 0077; exec '+go+' test -p 1 -count=1 -v ./attacks/matrix'
if mode=='identity-unit':command='umask 0077; exec '+go+' test -p 1 -count=1 -v ./controlplane/internal/authn'
if mode=='diagnostics':command="umask 0077; exec "+go+" test -p 1 -count=1 -v -run '^TestVMMDiagnostic' ./runtimes/firecracker"
if mode=='rootfs':command='umask 0077; exec /workspace/.cache/firecracker-code/rootfs'
if mode=='tools':command='umask 0077; test -x /sbin/mke2fs && /sbin/mke2fs -V'
if mode=='build':
    command='umask 0077; export CGO_ENABLED=0; '+go+' build -p 1 -trimpath -o .cache/firecracker-code/agent ./runtimes/firecracker/cmd/agent && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/lab ./runtimes/firecracker/cmd/lab && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/rootfs ./runtimes/firecracker/cmd/rootfs && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/warden-probe ./runtimes/conformance/guest && '+go+' test -p 1 -c -o .cache/firecracker-code/firecracker.test ./runtimes/firecracker'
args += [PIN,'sh','-c',command]
code=1
try:
    identity=docker(args).strip()
    print(json.dumps({'container_id':identity,'labels':labels}),flush=True)
    config=owned_inspect('container',identity,labels,docker)
    host=config['HostConfig']
    if host['Memory']!=2000000000 or host['MemorySwap']!=2000000000 or host['NanoCpus']!=2000000000 or host['PidsLimit']!=256 or host['NetworkMode']!='none' or host.get('Privileged') or host.get('Devices') or host.get('DeviceCgroupRules') or host['ReadonlyRootfs'] is not True or host['CapDrop']!=['ALL'] or host.get('CapAdd'):
        raise RuntimeError('inspected code profile differs from fixed bounds')
    print(json.dumps({'inspected_host_config':host}),flush=True)
    code=subprocess.run(['docker','--host','unix:///var/run/docker.sock','start','-a',identity],timeout=180).returncode
finally:
    for identity in scoped_ids('container',labels,docker):
        owned_inspect('container',identity,labels,docker)
        docker(['container','rm','--force',identity])
        if identity in scoped_ids('container',labels,docker):raise RuntimeError('code container remains')
        print(json.dumps({'removed_container':identity}),flush=True)
sys.exit(code)
