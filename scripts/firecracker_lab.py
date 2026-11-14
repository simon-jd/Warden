#!/usr/bin/env python3
"""Fixed local Task4 preparation and actual (live KVM) lab modes.
No cloud, pulls, arbitrary commands, shared daemon workloads, or host changes.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
from runtime_lab_docker import docker, scoped_ids, owned_inspect, outstanding_bytes, record_charge, read_trusted, defer_signals
from runtime_lab_paths import trusted_directory, exclusive_file, NOFOLLOW_DIR
from firecracker_device_receipt import DeviceGate, POLICY_VERSION, POLICY_SHA

ROOT=Path(__file__).resolve().parent.parent
BASE=ROOT/'.cache/warden-lab'
CACHE=ROOT/'.cache/firecracker-code'
RESERVE=5000000000
CAPS=('CHOWN','DAC_OVERRIDE','SETUID','SETGID','SYS_CHROOT','MKNOD','SYS_ADMIN','KILL')
LIVE=('boot','conformance','snapshot','capacity-default','capacity-benchmark','capacity-pressure')
PRIVILEGED=LIVE+('device-policy',)
CI='https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261023-dd7c24b0d165-0/x86_64/'
RELEASE='https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/'
MATERIALS={
 'firecracker-v1.17.0-x86_64.tgz':dict(size=7464385,sha256='06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558',url=RELEASE+'firecracker-v1.17.0-x86_64.tgz',provenance='publisher-release-checksum'),
 'firecracker-v1.17.0-x86_64.tgz.sha256.txt':dict(size=97,sha256='b89dea3edf551929f151b95d31168677ad2b8bb257d1d87a08470f7299749b7c',url=RELEASE+'firecracker-v1.17.0-x86_64.tgz.sha256.txt',provenance='computed-pin'),
 'vmlinux-6.18.54':dict(size=27893008,sha256='da5e0041fb31fcc7337026da9e2b64fb7694b4eed760cc9b5e8fe54e52fa8188',url=CI+'vmlinux-6.18.54',provenance='computed-pin'),
 'vmlinux-6.18.54.config':dict(size=101680,sha256='7dbdc7445d01d3dd049b1e653534bde71266d59afaf9c1de50a8a6b8a8c138d0',url=CI+'vmlinux-6.18.54.config',provenance='computed-pin')}

def bounded_input(path,limit):
    parent=trusted_directory(str(path.parent),os.getuid())
    try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    finally:os.close(parent)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,os.getuid()) or st.st_mode&0o022 or st.st_size>limit:raise ValueError('unsafe or oversized fixed input')
        with os.fdopen(os.dup(fd),'rb') as source:raw=source.read(limit+1)
        if len(raw)>limit:raise ValueError('input grew beyond fixed bound')
        return raw
    finally:os.close(fd)

def sha(data):return hashlib.sha256(data).hexdigest()
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def validate_package_sizes(files,archive):
    if files<0 or archive<0 or files>384000000 or archive>512000000:raise ValueError('package files/tar exceed approved ceilings')

def validate_binding(bind,labels):
    session=labels.get('session')
    if type(session) is not str or not re.fullmatch('[0-9a-f]{32}',session) or type(bind) is not dict or set(bind)!={'source','device','inode','uid'} or bind['source']!=str(BASE/('docker-firecracker-'+session)/'live') or any(type(bind[k]) is not int or bind[k]<=0 for k in ('device','inode')) or type(bind['uid']) is not int or bind['uid']!=1000:raise ValueError('fixed owned live directory identity required')

def anchored_binding(path,fd):
    current=trusted_directory(str(path),1000)
    try:
        held,actual=os.fstat(fd),os.fstat(current)
        if not stat.S_ISDIR(held.st_mode) or held.st_uid!=1000 or stat.S_IMODE(held.st_mode)!=0o700 or (held.st_dev,held.st_ino,held.st_uid,held.st_mode)!=(actual.st_dev,actual.st_ino,actual.st_uid,actual.st_mode):raise ValueError('live path differs from original held FD')
        return {'source':str(path),'device':held.st_dev,'inode':held.st_ino,'uid':held.st_uid}
    finally:os.close(current)

def session_env(bind,host_mount_ns):
    if not re.fullmatch(r'mnt:\[[1-9][0-9]*\]',host_mount_ns):raise ValueError('original host mount namespace required')
    return ['--env=WARDEN_FC_SESSION_IDENTITY='+':'.join(str(bind[k]) for k in ('device','inode','uid')),'--env=WARDEN_FC_HOST_MOUNT_NS='+host_mount_ns]

def mount_smoke_args(image,bind,labels,host_mount_ns):
    validate_binding(bind,labels)
    if not re.fullmatch('sha256:[0-9a-f]{64}',image):raise ValueError('immutable smoke image required')
    args=['container','create','--pull=never','--user=1000:1000','--network=none','--ipc=private','--cgroupns=private','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256000000','--memory-swap=256000000','--cpus=1','--pids-limit=32','--tmpfs=/tmp:rw,nosuid,nodev,size=16m','--log-driver=json-file','--log-opt=max-size=1m','--log-opt=max-file=1','--mount=type=bind,src='+bind['source']+',dst=/opt/warden/session,readonly,bind-propagation=rprivate','--env=WARDEN_FC_MOUNT_SMOKE=controller-reviewed-ro-only']+session_env(bind,host_mount_ns)
    for key,value in labels.items():args+=['--label',key+'='+value]
    return args+[image,'mount-smoke']

def outer_pids(mode):
    # capacity-pressure alone: up to 160 VMs at about five pids each; on
    # 2026-11-10 its 101st VM did not start with 508 of 512 in use. The user
    # approved 1024 for that mode only (2026-11-13); the others keep 512.
    return 1024 if mode=='capacity-pressure' else 512

def live_args(mode,image,bind,labels,host_ns,host_mount_ns):
    validate_binding(bind,labels)
    if mode not in PRIVILEGED or not re.fullmatch('sha256:[0-9a-f]{64}',image) or not re.fullmatch(r'cgroup:\[\d+\]',host_ns) or not re.fullmatch(r'mnt:\[[1-9][0-9]*\]',host_mount_ns):raise ValueError('fixed reviewed mode, image and anchored bind required')
    memory=15000000000 if mode.startswith('capacity-') else 4000000000
    args=['container','create','--interactive','--pull=never','--network=none','--ipc=private','--cgroupns=private','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--security-opt=apparmor=unconfined','--security-opt=seccomp=unconfined','--device=/dev/kvm:/dev/kvm:rw','--memory='+str(memory),'--memory-swap='+str(memory),'--pids-limit='+str(outer_pids(mode)),'--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=64m','--tmpfs=/run:rw,nosuid,nodev,size=64m','--log-driver=json-file','--log-opt=max-size=10m','--log-opt=max-file=2','--stop-timeout=20','--mount=type=bind,src='+bind['source']+',dst=/opt/warden/session,readonly,bind-propagation=rprivate','--env=WARDEN_FC_REVIEWED=controller-reviewed','--env=WARDEN_FC_HOST_CGROUP_NS='+host_ns]+session_env(bind,host_mount_ns)
    args+=['--cap-add='+cap for cap in CAPS]
    for key,value in labels.items():args+=['--label',key+'='+value]
    return args+[image,mode]

@contextmanager
def locked():
    fd=trusted_directory(str(BASE),1000)
    lock=os.open('docker.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd);os.close(fd)
    st=os.fstat(lock)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=1000 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:os.close(lock);raise ValueError('unsafe project lock')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(lock)

def guard(additional,memory,own=None):
    containers=scoped_ids('container',{'project':'warden'},docker)
    for identity in containers:
        if own is None:raise ValueError('other Warden container present')
        owned_inspect('container',identity,own,docker)
    total=0
    for identity in set(scoped_ids('image',{'project':'warden'},docker)):
        data=json.loads(docker(['image','inspect',identity]))[0]
        if data['Id']!=identity or data['Config'].get('Labels',{}).get('project')!='warden':raise ValueError('image accounting identity mismatch')
        total+=2*data['Size']+64000000
    outstanding=outstanding_bytes(BASE)
    print(json.dumps({'owned_image_charge':total,'outstanding':outstanding,'additional':additional,'service_memory':memory}),flush=True)
    subprocess.run([sys.executable,'-B',str(ROOT/'scripts/azure_guard.py'),'preflight','--additional-bytes',str(total+outstanding+additional),'--service-memory-bytes',str(memory),'--download-bytes','0'],check=True)

def fresh_session():
    labels={'project':'warden','owner':'warden-lab','task':'firecracker','session':secrets.token_hex(16),'ttl':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}
    base=trusted_directory(str(BASE),1000);name='docker-firecracker-'+labels['session'];os.mkdir(name,0o700,dir_fd=base);os.fsync(base);os.close(base)
    return BASE/name,labels

def store(path,data,mode=0o600):
    parent=trusted_directory(str(path.parent),1000)
    try:
        fd=exclusive_file(parent,path.name,data)
        try:os.fchmod(fd,mode);os.fsync(fd)
        finally:os.close(fd)
        os.fsync(parent)
    finally:os.close(parent)

def remove_objects(labels):
    with defer_signals():
        for identity in scoped_ids('container',labels,docker):
            data=owned_inspect('container',identity,labels,docker)
            if data['State']['Running']:docker(['container','stop','--time=20',identity],timeout=30)
            print(docker(['container','logs',identity]),end='',flush=True)
            docker(['container','rm','--force',identity])
        if scoped_ids('container',labels,docker):raise RuntimeError('owned container still present')
        for identity in set(scoped_ids('image',labels,docker)):
            owned_inspect('image',identity,labels,docker);docker(['image','rm',identity])
        if scoped_ids('image',labels,docker):raise RuntimeError('owned image still present')

def operator_owned(path):
    """Every inode under path (links not followed) belongs to this operator."""
    uid=os.getuid()
    def fail(error):raise error
    try:
        if os.lstat(path).st_uid!=uid:return False
        for directory,dirs,files in os.walk(path,followlinks=False,onerror=fail):
            for name in dirs+files:
                if os.lstat(os.path.join(directory,name)).st_uid!=uid:return False
    except OSError:return False
    return True

def source_sha():
    paths=['go.mod','go.sum','runtimes','scripts/firecracker_code.py','scripts/firecracker_lab.py','scripts/firecracker_device_receipt.py','scripts/corpus_image.py','scripts/runtime_lab_docker.py','scripts/runtime_lab_paths.py','attacks']
    subprocess.run(['git','diff','--quiet','HEAD','--',*paths],cwd=ROOT,check=True)
    if subprocess.check_output(['git','ls-files','--others','--exclude-standard','--',*paths],cwd=ROOT).strip():raise ValueError('source must be committed before preparation')
    value=subprocess.check_output(['git','log','-1','--format=%H','--',*paths],cwd=ROOT,text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}',value):raise ValueError('source commit unavailable')
    return value

def add(tar,name,data,mode=0o444):
    entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=mode;tar.addfile(entry,io.BytesIO(data))

def fixed_materials():
    result={}
    for name,pin in MATERIALS.items():
        raw=bounded_input(BASE/'firecracker-materials'/name,pin['size'])
        if len(raw)!=pin['size'] or sha(raw)!=pin['sha256']:raise ValueError('material pin mismatch: '+name)
        result[name]=raw
    expected=(MATERIALS['firecracker-v1.17.0-x86_64.tgz']['sha256']+'  firecracker-v1.17.0-x86_64.tgz\n').encode()
    if result['firecracker-v1.17.0-x86_64.tgz.sha256.txt']!=expected:raise ValueError('publisher checksum exact entry mismatch')
    binaries={}
    with tarfile.open(fileobj=io.BytesIO(result['firecracker-v1.17.0-x86_64.tgz']),mode='r:gz') as tar:
        for name,bound in (('firecracker',32<<20),('jailer',8<<20)):
            member=tar.getmember('release-v1.17.0-x86_64/'+name+'-v1.17.0-x86_64')
            if not member.isfile() or member.size<=0 or member.size>bound:raise ValueError('invalid pinned release member')
            raw=tar.extractfile(member).read(bound+1)
            if len(raw)!=member.size:raise ValueError('release member size mismatch')
            # A scratch package requires the official binaries to be static.
            if raw[:6]!=b'\x7fELF\x02\x01':raise ValueError('x86_64 ELF required')
            phoff=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
            if any(struct.unpack_from('<I',raw,phoff+i*size)[0]==3 for i in range(count)):raise ValueError('dynamic release binary needs separate ABI proposal')
            binaries[name]=raw
    binaries['kernel']=result['vmlinux-6.18.54'];return binaries

def validate_loaded_binding(data,original,saved,diff_id):
    config=json.loads(original)['config']
    if saved!=original or data['RootFS']['Layers']!=[diff_id]:raise ValueError('loaded config bytes or diffID differ from owned manifest')
    if not re.fullmatch('sha256:[0-9a-f]{64}',data['Id']):raise ValueError('immutable Docker image ID required')
    for key in ('User','Entrypoint','Labels'):
        if data['Config'].get(key)!=config[key]:raise ValueError('loaded fixed probe configuration differs')

def payload_layer(probe,files):
    files={**files,'warden-probe':probe,'write-probe':b''}
    directories={'proc','dev','dev/pts','dev/shm','sys','etc'}
    for name in files:
        directories.update(str(p) for p in Path(name).parents if str(p)!='.')
    layer=io.BytesIO()
    with tarfile.open(fileobj=layer,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        for directory in sorted(directories):
            entry=tarfile.TarInfo(directory);entry.type=tarfile.DIRTYPE;entry.mode=0o755;tar.addfile(entry)
        for name,raw in sorted(files.items()):
            mode=0o666 if name=='write-probe' else (0o444 if name.startswith('usr/share/doc/') else 0o555)
            add(tar,name,raw,mode)
    return layer.getvalue()

def package_variant(without_corpus):
    # prepare --without-corpus builds no attack helper and packs no corpus,
    # helper or Task 5 shell closure; the default package keeps all of them.
    return 'without-corpus' if without_corpus else 'with-corpus'

def payload_inputs(without_corpus):
    if without_corpus:return {}
    from corpus_image import payload_files
    return payload_files(ROOT,helper=CACHE/'warden-attack')

def corpus_inputs(without_corpus):
    if without_corpus:return {}
    from runtime_lab_docker import corpus_files
    return corpus_files(ROOT)

def export_probe(output,labels,without_corpus=False):
    probe=bounded_input(CACHE/'warden-probe',16<<20)
    if len(probe)>16<<20:raise ValueError('probe oversized')
    layer=payload_layer(probe,payload_inputs(without_corpus));config=encode({'architecture':'amd64','os':'linux','config':{'User':'65534:65534','Entrypoint':['/warden-probe'],'Labels':labels},'rootfs':{'type':'layers','diff_ids':['sha256:'+sha(layer)]}})
    manifest=encode({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':'sha256:'+sha(config),'size':len(config)},'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+sha(layer),'size':len(layer)}]})
    config_id='sha256:'+sha(config);archive=output/'probe.tar'
    with tarfile.open(archive,'x',format=tarfile.USTAR_FORMAT) as tar:
        add(tar,'layer.tar',layer);add(tar,sha(config)+'.json',config);add(tar,'manifest.json',encode([{'Config':sha(config)+'.json','RepoTags':['warden-fc-probe:'+labels['session']],'Layers':['layer.tar']}]))
    store(output/'probe-oci-manifest.json',manifest)
    guard(0,2000000000);record_charge(output,reserve=RESERVE)
    complete=False
    try:
        guard(0,2000000000);docker(['image','load','--input',str(archive)],timeout=120)
        identities=list(set(scoped_ids('image',labels,docker)))
        if len(identities)!=1:raise ValueError('unique exact-labelled own loaded image required')
        image=identities[0];data=owned_inspect('image',image,labels,docker);image_data=data
        if data['Size']>32<<20:raise ValueError('owned probe image oversized')
        guard(0,2000000000)
        saved=output/'saved-probe.tar';docker(['image','save','--output',str(saved),image],timeout=120)
        with tarfile.open(fileobj=io.BytesIO(bounded_input(saved,64<<20))) as tar:
            member=tar.getmember('manifest.json')
            if not member.isfile() or member.size>65536:raise ValueError('saved image manifest oversized or special')
            saved_manifest=json.load(tar.extractfile(member))
            if len(saved_manifest)!=1:raise ValueError('saved image must have one config')
            name=saved_manifest[0]['Config']
            if name not in (sha(config)+'.json','blobs/sha256/'+sha(config)):raise ValueError('saved config digest path differs')
            member=tar.getmember(name)
            if not member.isfile() or member.size>65536:raise ValueError('saved config oversized or special')
            saved_config=tar.extractfile(member).read(65537)
        validate_loaded_binding(data,config,saved_config,'sha256:'+sha(layer))
        guard(0,2000000000)
        args=['container','create','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=64000000','--memory-swap=64000000','--pids-limit=16']
        for key,value in labels.items():args+=['--label',key+'='+value]
        cid=docker(args+[image,'uid']).strip();data=owned_inspect('container',cid,labels,docker)
        if data['State']['Status']!='created' or data['State']['Running'] or data['Image']!=image:raise ValueError('export container is not never-started owned config')
        export=output/'export.tar';docker(['container','export','--output',str(export),cid],timeout=60)
        raw=bounded_input(export,64<<20)
        if len(raw)>64<<20:raise ValueError('export oversized')
        store(CACHE/'export.tar',raw)
        provenance={'ImageDigest':'sha256:'+sha(manifest),'ImageConfigID':config_id,'DockerImageID':image,'DockerDescriptor':image_data.get('Descriptor'),'DiffID':'sha256:'+sha(layer),'ExportSHA':sha(raw),'ProbeSHA':sha(probe),'never_started':True}
        store(output/'export-provenance.json',encode(provenance));complete=True;return provenance
    finally:
        remove_objects(labels)
        if complete:record_charge(output,released=True,reserve=RESERVE)

def prepare(without_corpus=False):
    source=source_sha();variant=package_variant(without_corpus)
    subprocess.run([sys.executable,'-B',str(ROOT/'scripts/firecracker_code.py'),'build-without-corpus' if without_corpus else 'build'],check=True)
    with locked():
        guard(RESERVE,2000000000);output,labels=fresh_session();materials=fixed_materials()
        # These are exact local staging files, never SHA-bound public evidence.
        for name in ('export.tar','rootfs.json','agent.ext4','payload.ext4','package.tar','package.json'):
            path=CACHE/name
            if path.exists():
                st=path.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=1000 or st.st_nlink!=1:raise ValueError('unsafe old owned staging')
                path.unlink()
        staging=CACHE/'rootfs-staging'
        if staging.exists():
            if staging.is_symlink() or staging.stat().st_uid!=1000 or not shutil.rmtree.avoids_symlink_attacks:raise ValueError('unsafe old rootfs staging')
            parent=trusted_directory(str(CACHE),1000)
            try:shutil.rmtree('rootfs-staging',dir_fd=parent)
            finally:os.close(parent)
        provenance=export_probe(output,labels,without_corpus)
    subprocess.run([sys.executable,'-B',str(ROOT/'scripts/firecracker_code.py'),'rootfs'],check=True)
    with locked():
        guard(RESERVE,2000000000)
        if source_sha()!=source:raise ValueError('source changed during build')
        built=json.loads(bounded_input(CACHE/'rootfs.json',65536))
        if built['Export']['SHA256']!=provenance['ExportSHA']:raise ValueError('export provenance changed')
        if built['Export']['NormalizationVersion']!='warden-fc-docker-export-v1' or any(not re.fullmatch('[0-9a-f]{64}',built['Export'][key]) for key in ('NormalizedSHA256','NormalizationPolicySHA')):raise ValueError('normalization provenance missing')
        cache_key=sha(encode({'image':provenance['ImageDigest'],'export':built['Export'],'agent':sha(bounded_input(CACHE/'agent',16<<20)),'tools':built['Hashes'],'source':source}))
        cache_base=BASE/'firecracker-rootfs';cache_base.mkdir(mode=0o700,exist_ok=True)
        cache_parent=trusted_directory(str(cache_base),1000);os.mkdir(cache_key,0o700,dir_fd=cache_parent);os.fsync(cache_parent);os.close(cache_parent)
        cached=cache_base/cache_key
        for name in ('agent.ext4','payload.ext4'):
            contents=bounded_input(CACHE/name,64<<20)
            if len(contents)>64<<20 or sha(contents)!=built['Hashes'][name]:raise ValueError('ext4 cache provenance mismatch')
            store(cached/name,contents,0o400)
        store(cached/'provenance.json',encode({'source':source,'export':provenance,'build':built,'key':cache_key}))
        files={**materials}
        for name in ('agent.ext4','payload.ext4','lab','firecracker.test'):
            files[name]=bounded_input((cached if name.endswith('.ext4') else CACHE)/name,64<<20)
        agent=bounded_input(CACHE/'agent',16<<20)
        policy=sha(encode({'source':source,'network':'none','caps':CAPS,'device':'10:232 rw','default_workload_mib':512,'default_vm_mib':640,'retirement':'known original owner only','normalization':built['Export'],'device_policy_version':POLICY_VERSION,'device_policy_sha256':POLICY_SHA,'package_variant':variant}))
        manifest={'Version':1,'PackageVariant':variant,'SourceSHA':source,'ImageDigest':provenance['ImageDigest'],'ExportSHA':provenance['ExportSHA'],'NormalizedExportSHA':built['Export']['NormalizedSHA256'],'NormalizationVersion':built['Export']['NormalizationVersion'],'NormalizationPolicySHA':built['Export']['NormalizationPolicySHA'],'AgentSHA':sha(agent),'PolicySHA':policy,'DevicePolicyVersion':POLICY_VERSION,'DevicePolicySHA':POLICY_SHA,'Artifacts':{name:sha(files[name]) for name in ('kernel','firecracker','jailer','agent.ext4','payload.ext4')}}
        files.update(corpus_inputs(without_corpus))
        files['manifest.json']=encode(manifest);files['provenance.json']=encode({'source':source,'materials':MATERIALS,'export':provenance,'build':built})
        total=sum(map(len,files.values()));validate_package_sizes(total,0)
        archive=CACHE/'package.tar'
        with tarfile.open(archive,'x',format=tarfile.USTAR_FORMAT) as tar:
            for directory in ('proc','sys','sys/fs','sys/fs/cgroup','dev','tmp','run','opt','opt/warden','opt/warden/input','opt/warden/session'):
                entry=tarfile.TarInfo(directory);entry.type=tarfile.DIRTYPE;entry.mode=0o755;tar.addfile(entry)
            for directory in sorted({str(p) for name in files for p in Path('opt/warden/input/'+name).parents if str(p) not in ('.','opt','opt/warden','opt/warden/input')}):
                entry=tarfile.TarInfo(directory);entry.type=tarfile.DIRTYPE;entry.mode=0o755;tar.addfile(entry)
            for name,raw in sorted(files.items()):add(tar,'opt/warden/input/'+name,raw,0o555 if name in ('firecracker','jailer','lab','firecracker.test') else 0o444)
        raw=bounded_input(archive,512000000);validate_package_sizes(total,len(raw));archive.chmod(0o400)
        result={'source':source,'variant':variant,'file_bytes':total,'tar_bytes':len(raw),'tar_sha256':sha(raw),'manifest':manifest,'provenance':provenance,'build':built,'rootfs_cache_key':cache_key}
        store(CACHE/'package.json',encode(result));store(output/'package-result.json',encode(result));print(json.dumps(result),flush=True)
        guard(0,2000000000)

def inspect_session_bind(data,bind):
    h=data['HostConfig']
    want={'Type':'bind','Source':bind['source'],'Target':'/opt/warden/session','ReadOnly':True,'BindOptions':{'Propagation':'rprivate'}}
    if h.get('Binds') or h.get('VolumesFrom') or h.get('Mounts')!=[want]:raise ValueError('exact sole initial RO/rprivate bind required')
    mounts=data.get('Mounts')
    if type(mounts) is not list or len(mounts)!=1:raise ValueError('unique actual session mount required')
    m=mounts[0]
    if set(m)!={'Type','Source','Destination','Mode','RW','Propagation'} or m['Type']!='bind' or m['Source']!=bind['source'] or m['Destination']!='/opt/warden/session' or m['Mode'] not in ('','ro') or m['RW'] is not False or m['Propagation']!='rprivate':raise ValueError('actual initial bind differs')

def emit_inspected_bounds(data):
    # Fixed nonsecret bounds only, before refusal; never include Config.Env.
    diagnostic=json.dumps({'inspected_host_config':data['HostConfig'],'inspected_mounts':data.get('Mounts')})
    if len(diagnostic.encode())+1>16384:
        print(diagnostic.encode()[:16000].decode(errors='replace'),flush=True)
        raise ValueError('inspected bounds diagnostic exceeds fixed limit')
    print(diagnostic,flush=True)

def inspect_mount_smoke(data,bind):
    h=data['HostConfig'];emit_inspected_bounds(data)
    if data['Config']['User']!='1000:1000' or h['Memory']!=256000000 or h['MemorySwap']!=256000000 or h['NanoCpus']!=1000000000 or h['PidsLimit']!=32 or h['NetworkMode']!='none' or h['IpcMode']!='private' or h['CgroupnsMode']!='private' or h['PidMode'] or h.get('Privileged') or h.get('Devices') or h.get('DeviceCgroupRules') or h.get('DeviceRequests') or not h['ReadonlyRootfs'] or h['CapDrop']!=['ALL'] or h.get('CapAdd') or h['SecurityOpt']!=['no-new-privileges']:raise ValueError('inspected mount-smoke bounds differ')
    inspect_session_bind(data,bind)

def inspect_live(data,mode,bind):
    h=data['HostConfig'];memory=15000000000 if mode.startswith('capacity-') else 4000000000
    emit_inspected_bounds(data)
    caps=h.get('CapAdd')
    if type(caps) is not list or len(caps)!=len(CAPS) or any(type(cap) is not str for cap in caps) or set(caps)!={'CAP_'+cap for cap in CAPS}:raise ValueError('inspected capability names differ from exact eight-bit profile')
    if h.get('Privileged') or h['Memory']!=memory or h['MemorySwap']!=memory or h['PidsLimit']!=outer_pids(mode) or h['NanoCpus']!=2000000000 or h['NetworkMode']!='none' or h['IpcMode']!='private' or h['CgroupnsMode']!='private' or h['PidMode'] or not h['ReadonlyRootfs'] or h['CapDrop']!=['ALL'] or h.get('DeviceCgroupRules') or h.get('DeviceRequests'):raise ValueError('inspected outer bounds differ')
    if h['Devices']!=[{'PathOnHost':'/dev/kvm','PathInContainer':'/dev/kvm','CgroupPermissions':'rw'}]:raise ValueError('unexpected device access')
    inspect_session_bind(data,bind)
    c=data.get('Config',{})
    # create --interactive selects attached stdin and StdinOnce; container EOF
    # must follow the single ACK while start --attach keeps receiving output.
    if any(c.get(key) is not True for key in ('OpenStdin','StdinOnce','AttachStdin','AttachStdout','AttachStderr')) or c.get('Tty') is not False or c.get('Entrypoint')!=['/opt/warden/input/lab'] or c.get('Cmd')!=[mode] or c.get('User')!='':raise ValueError('fixed ACK+EOF trusted entrypoint required')
    if set(h['SecurityOpt'])!={'no-new-privileges','apparmor=unconfined','seccomp=unconfined'}:raise ValueError('unexpected security profile')

def execute(mode,other,without_corpus=False):
    with locked():
        memory=(16000000000 if mode.startswith('capacity-') else (5000000000 if mode in PRIVILEGED else (1256000000 if mode=='mount-smoke' else 3000000000)))+other
        guard(RESERVE,memory)
        package=json.loads(bounded_input(CACHE/'package.json',65536));raw=bounded_input(CACHE/'package.tar',512000000)
        if package['source']!=source_sha() or sha(raw)!=package['tar_sha256']:raise ValueError('reviewed source/package binding changed')
        variant=package_variant(without_corpus)
        if package.get('variant')!=variant or package.get('manifest',{}).get('PackageVariant')!=variant:raise ValueError('package variant differs from the requested '+variant+'; prepare with the same --without-corpus choice')
        validate_package_sizes(package['file_bytes'],len(raw));del raw;output,labels=fresh_session();record_charge(output,reserve=RESERVE);complete=False;livefd=None;device_gate=None
        try:
            guard(0,memory)
            command=['image','import','--change','ENTRYPOINT ["/opt/warden/input/lab"]']
            for key,value in labels.items():command+=['--change','LABEL '+key+'='+value]
            image=docker(command+[str(CACHE/'package.tar')],timeout=120).strip();data=owned_inspect('image',image,labels,docker)
            if data['Size']>512000000:raise ValueError('imported image exceeds 512MB')
            store(output/'identity.json',encode({'image':image,'labels':labels,'source':package['source'],'mode':mode,'image_bytes':data['Size']}));guard(0,memory)
            if mode in PRIVILEGED or mode=='mount-smoke':
                live=output/'live';live.mkdir(mode=0o700);livefd=trusted_directory(str(live),1000);bind=anchored_binding(live,livefd);original=os.fstat(livefd)
                host_mount_ns=os.readlink('/proc/self/ns/mnt')
                store(output/'session-binding.json',encode({'binding':bind,'host_mount_ns':host_mount_ns}))
            if mode in PRIVILEGED:
                st=os.lstat('/dev/kvm')
                if not stat.S_ISCHR(st.st_mode) or os.major(st.st_rdev)!=10 or os.minor(st.st_rdev)!=232:raise ValueError('exact local KVM missing')
                args=live_args(mode,image,bind,labels,os.readlink('/proc/self/ns/cgroup'),host_mount_ns)
            elif mode=='mount-smoke':args=mount_smoke_args(image,bind,labels,host_mount_ns)
            else:
                args=['container','create','--pull=never','--user=65534:65534','--network=none','--ipc=private','--cgroupns=private','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=2000000000','--memory-swap=2000000000','--cpus=2','--pids-limit=256','--tmpfs=/tmp:rw,nosuid,nodev,size=64m','--log-driver=json-file','--log-opt=max-size=10m','--log-opt=max-file=1']
                for key,value in labels.items():args+=['--label',key+'='+value]
                args+=[image,'abi']
            if livefd is not None and anchored_binding(live,livefd)!=bind:raise ValueError('session identity changed before create')
            cid=docker(args).strip();data=owned_inspect('container',cid,labels,docker)
            if mode in PRIVILEGED:inspect_live(data,mode,bind)
            elif mode=='mount-smoke':inspect_mount_smoke(data,bind)
            else:
                h=data['HostConfig']
                if data['Config']['User']!='65534:65534' or h['Memory']!=2000000000 or h['MemorySwap']!=2000000000 or h['NanoCpus']!=2000000000 or h['PidsLimit']!=256 or h['NetworkMode']!='none' or h['IpcMode']!='private' or h['CgroupnsMode']!='private' or h['PidMode'] or h.get('Privileged') or h.get('Devices') or h.get('DeviceCgroupRules') or h.get('DeviceRequests') or h.get('Mounts') or h.get('Binds') or not h['ReadonlyRootfs'] or h['CapDrop']!=['ALL'] or h.get('CapAdd') or h['SecurityOpt']!=['no-new-privileges']:raise ValueError('inspected ABI bounds differ')
                print(json.dumps({'inspected_abi_host_config':h}),flush=True)
            if livefd is not None and anchored_binding(live,livefd)!=bind:raise ValueError('session identity changed before start')
            if mode in PRIVILEGED:
                device_gate=DeviceGate(cid,image,lambda:owned_inspect('container',cid,labels,docker),lambda name,raw:store(output/name,raw))
                log=device_gate.run()
            else:log=docker(['container','start','--attach',cid],timeout=650)
            store(output/'run.log',log.encode());print(log,end='',flush=True)
            status=docker(['container','wait',cid]).strip()
            if livefd is not None and anchored_binding(live,livefd)!=bind:raise ValueError('session identity changed after outer exit')
            if mode in ('mount-smoke','device-policy'):
                observed=os.fstat(livefd)
                if status!='0' or (observed.st_mtime_ns,observed.st_ctime_ns)!=(original.st_mtime_ns,original.st_ctime_ns):raise RuntimeError('RO-only smoke failed or mutated session metadata')
            if mode in LIVE:
                if bounded_input(output/'live/node/retired',64)!=b'known-owner-retired\n':raise RuntimeError('known original owner retirement not proven')
            if status!='0':raise RuntimeError('actual mode failed: '+status)
            complete=True
        finally:
            cleaned=False
            try:
                try:
                    if device_gate is not None:store(output/'device-attach.log',bytes(device_gate.log))
                finally:remove_objects(labels)
                if device_gate is not None:device_gate.after_cleanup()
                cleaned=True
            finally:
                if livefd is not None:os.close(livefd)
                if device_gate is not None:device_gate.close()
                if cleaned and complete:record_charge(output,released=True,reserve=RESERVE)
                elif cleaned and operator_owned(output):
                    # The host has no sudo; a failed run that left nothing
                    # root-owned and no own object needs no manual recovery.
                    record_charge(output,released=True,reserve=RESERVE)
                    print('failed run cleaned: own containers/images removed, outer cgroup gone, session operator-owned; reservation released',flush=True)
        guard(0,other)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('prepare','abi','mount-smoke')+PRIVILEGED);parser.add_argument('--other-service-memory-bytes',type=int,required=True);parser.add_argument('--without-corpus',action='store_true',help='prepare a package without the attack helper, corpus or Task 5 files; actual modes then require that package');args=parser.parse_args()
    if os.getuid()!=1000 or args.other_service_memory_bytes<0:parser.error('ordinary UID1000 and nonnegative aggregate services required')
    if args.mode.startswith('capacity-') and args.other_service_memory_bytes:parser.error('capacity measurement requires zero other services')
    if args.mode=='prepare' and args.other_service_memory_bytes:parser.error('fixed build preparation requires zero other services')
    os.umask(0o077)
    info=json.loads(docker(['info','--format','{{json .}}']))
    if info['Name']!=os.uname().nodename or info['CgroupVersion']!='2' or any('rootless' in x for x in info['SecurityOptions']):raise ValueError('local rootful cgroup2 Docker required')
    if args.mode in PRIVILEGED and info.get('CgroupDriver')!='systemd':raise ValueError('fixed systemd own-scope receipt required')
    if args.mode=='prepare':prepare(True) if args.without_corpus else prepare()
    else:execute(args.mode,args.other_service_memory_bytes,args.without_corpus)
if __name__=='__main__':main()
