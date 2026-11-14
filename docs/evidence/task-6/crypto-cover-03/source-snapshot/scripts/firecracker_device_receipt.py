"""Fixed owned-outer receipt and exact cgroup-path disappearance, never host writes."""
import json,os,re,select,stat,subprocess,time
from runtime_lab_paths import trusted_directory,NOFOLLOW_DIR
POLICY_VERSION='warden-tun-deny-v1'
POLICY_SHA='bd958d0d3ab7193f91cb14013f9ce53ddd88c46ab6cba89337b7e4eeb6e74404'
ACK=b'WARDEN_DEVICE_RECEIPT_OK\n'

def parse_receipt(raw,host_cgroup_ns,host_mount_ns):
    if len(raw)>4096 or not raw.endswith(b'\n') or raw.count(b'\n')!=1:raise ValueError('bounded single receipt required')
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError('duplicate receipt key')
            out[k]=v
        return out
    r=json.loads(raw,object_pairs_hook=unique)
    if type(r) is not dict or set(r)!={'kind','pid','cgroup_ns','mount_ns','device','inode','mount_id','policy_version','policy_sha256'}:raise ValueError('receipt schema differs')
    if r['kind']!='warden-device-receipt-v1' or type(r['pid']) is not int or r['pid']!=1 or r['policy_version']!=POLICY_VERSION or r['policy_sha256']!=POLICY_SHA:raise ValueError('receipt identity differs')
    for k in ('device','inode','mount_id'):
        if type(r[k]) is not int or not 0<r[k]<2**64:raise ValueError('receipt numeric identity differs')
    for key,prefix,host in [('cgroup_ns','cgroup',host_cgroup_ns),('mount_ns','mnt',host_mount_ns)]:
        if type(r[key]) is not str or not re.fullmatch(prefix+r':\[[1-9][0-9]*\]',r[key]) or r[key]==host:raise ValueError('private namespace receipt required')
    return r

def validate_observation(cid,image,before,after,cgroup,status,start_before,start_after):
    if not re.fullmatch('[0-9a-f]{64}',cid) or not re.fullmatch('sha256:[0-9a-f]{64}',image):raise ValueError('exact immutable object identity required')
    pid=before['State']['Pid']
    for item in (before,after):
        if item['Id']!=cid or item['Image']!=image or item['State']['Running'] is not True or type(item['State']['Pid']) is not int or item['State']['Pid']!=pid or pid<=1:raise ValueError('owned running PID changed')
    if cgroup!='0::/system.slice/docker-'+cid+'.scope\n':raise ValueError('PID does not belong to exact own systemd scope')
    ns=[line.split(':',1)[1].split() for line in status.splitlines() if line.startswith('NSpid:')]
    if ns!=[[str(pid),'1']] or type(start_before) is not int or start_before<=0 or start_before!=start_after:raise ValueError('PID namespace/starttime mismatch')

def read_at(parent,name,limit):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    try:
        raw=os.read(fd,limit+1)
        if len(raw)>limit:raise ValueError('bounded process metadata exceeded')
        return raw.decode('ascii')
    finally:os.close(fd)

def starttime(raw,pid):
    head,sep,tail=raw.rpartition(')')
    if not sep or not head.startswith(str(pid)+' ('):raise ValueError('process stat identity differs')
    words=tail.split()
    if len(words)<20 or not words[19].isdigit():raise ValueError('invalid process starttime')
    return int(words[19])

def fd_identity(fd):
    s=os.fstat(fd)
    return s.st_dev,s.st_ino,s.st_uid

def read_line(fd,seconds=8):
    deadline=time.monotonic()+seconds;raw=bytearray()
    while len(raw)<4096:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([fd],[],[],remaining)[0]:raise TimeoutError('receipt deadline')
        chunk=os.read(fd,1)
        if not chunk:raise ValueError('EOF before receipt')
        raw+=chunk
        if chunk==b'\n':return bytes(raw)
    raise ValueError('receipt exceeds4KiB')

class OwnedCgroupReceipt:
    def __init__(self,parent,target,name):
        self.parent,self.target,self.name=parent,target,name
        self.parent_identity=fd_identity(parent);self.target_identity=fd_identity(target)
    def check_parent(self):
        if fd_identity(self.parent)!=self.parent_identity or fd_identity(self.target)!=self.target_identity:raise ValueError('held cgroup identity changed')
        fresh=trusted_directory('/sys/fs/cgroup/system.slice',0)
        try:
            if fd_identity(fresh)!=self.parent_identity:raise ValueError('cgroup parent pathname replaced')
        finally:os.close(fresh)
    def present(self):
        self.check_parent()
        s=os.stat(self.name,dir_fd=self.parent,follow_symlinks=False)
        if (s.st_dev,s.st_ino,s.st_uid)!=self.target_identity:raise ValueError('original cgroup entry changed before ACK')
    def absent(self):
        self.check_parent()
        try:os.stat(self.name,dir_fd=self.parent,follow_symlinks=False)
        except FileNotFoundError:return
        raise ValueError('original cgroup path remains or has replacement')
    def close(self):
        os.close(self.target);os.close(self.parent)

def capture_receipt(raw,cid,image,inspect):
    r=parse_receipt(raw,os.readlink('/proc/self/ns/cgroup'),os.readlink('/proc/self/ns/mnt'))
    before=inspect();pid=before['State']['Pid']
    if type(pid) is not int or pid<=1:raise ValueError('running own PID required')
    pidfd=os.pidfd_open(pid);proc=None;parent=None;target=None
    try:
        poll=select.poll();poll.register(pidfd,select.POLLIN)
        if poll.poll(0):raise ValueError('own PID already exited')
        base=trusted_directory('/proc',0)
        try:proc=os.open(str(pid),NOFOLLOW_DIR,dir_fd=base)
        finally:os.close(base)
        initial=starttime(read_at(proc,'stat',8192),pid)
        membership=read_at(proc,'cgroup',4096);status=read_at(proc,'status',16384)
        validate_observation(cid,image,before,before,membership,status,initial,initial)
        parent=trusted_directory('/sys/fs/cgroup/system.slice',0);name='docker-'+cid+'.scope'
        target=os.open(name,NOFOLLOW_DIR,dir_fd=parent)
        s=os.fstat(target)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or (s.st_dev,s.st_ino)!=(r['device'],r['inode']):raise ValueError('outer cgroup receipt does not match host FD')
        latest=starttime(read_at(proc,'stat',8192),pid)
        if read_at(proc,'cgroup',4096)!=membership or read_at(proc,'status',16384).split('NSpid:',1)[-1].splitlines()[0]!=status.split('NSpid:',1)[-1].splitlines()[0]:raise ValueError('own PID metadata changed')
        validate_observation(cid,image,before,inspect(),membership,status,initial,latest)
        if poll.poll(0):raise ValueError('own PID exited during capture')
        held=OwnedCgroupReceipt(parent,target,name);parent=target=None
        return held,{'outer':r,'container':cid,'image':image,'host_pid':pid,'host_starttime':initial,'host_cgroup':membership.strip(),'parent_identity':held.parent_identity,'target_identity':held.target_identity}
    finally:
        for fd in (target,parent,proc,pidfd):
            if fd is not None:os.close(fd)

class DeviceGate:
    def __init__(self,cid,image,inspect,save):
        self.cid,self.image,self.inspect,self.save=cid,image,inspect,save
        self.held=None;self.child=None;self.log=bytearray()
    def run(self):
        self.child=subprocess.Popen(['docker','--host','unix:///var/run/docker.sock','container','start','--attach','--interactive',self.cid],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
        raw=read_line(self.child.stdout.fileno());self.log+=raw
        self.held,receipt=capture_receipt(raw,self.cid,self.image,self.inspect)
        self.save('device-receipt.json',json.dumps(receipt,sort_keys=True).encode())
        self.held.present()
        if self.child.stdin.write(ACK)!=len(ACK):raise ValueError('short fixed ACK write')
        self.child.stdin.close()
        deadline=time.monotonic()+650
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.child.stdout],[],[],remaining)[0]:raise TimeoutError('owned outer deadline')
            raw=os.read(self.child.stdout.fileno(),4096)
            if not raw:break
            self.log+=raw
            if len(self.log)>1048576:raise ValueError('owned outer log ceiling')
        if self.child.wait(timeout=10)!=0:raise RuntimeError('owned device-policy outer failed')
        return bytes(self.log).decode('utf-8',errors='strict')
    def after_cleanup(self):
        if self.held is None:raise ValueError('no correlated outer cgroup receipt; reservation stays pending')
        self.held.absent()
        self.save('device-cgroup-absence.json',json.dumps({'container':self.cid,'target_identity':self.held.target_identity,'parent_identity':self.held.parent_identity,'exact_original_entry_absent':True,'meaning':'exact owned cgroup path removed; not synchronous kernel allocator GC'}).encode())
    def close(self):
        try:
            if self.child is not None:
                for pipe in (self.child.stdin,self.child.stdout):
                    if pipe is not None:pipe.close()
                self.child.wait(timeout=20) # own cleanup must end attach; no signal fallback
        finally:
            if self.held is not None:self.held.close()
