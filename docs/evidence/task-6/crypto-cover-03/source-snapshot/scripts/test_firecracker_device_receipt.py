import io,json,os,select,tempfile,threading,time,unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
import firecracker_device_receipt as gate

CID='a'*64
IMAGE='sha256:'+'b'*64

class PipeAttach:
    """Pinned Docker non-TTY lifetime model, not a daemon or Go execution.

    The daemon owns the container-input writer independently of client stdin.
    Output starts with only the receipt; success output requires ACK plus real
    pipe EOF. StdinOnce=false closes attach output but retains that writer.
    """
    def __init__(self,raw,stdin_once):
        read,write=os.pipe()
        self.container_input=os.fdopen(read,'rb',buffering=0)
        self.daemon_input=os.fdopen(write,'wb',buffering=0)
        read,write=os.pipe()
        self.stdout=os.fdopen(read,'rb',buffering=0)
        self.output=os.fdopen(write,'wb',buffering=0)
        self.output_lock=threading.Lock()
        self.output.write(raw)
        self.received=bytearray();self.saw_eof=False;self.accepted=False
        self.status=None;self.events=[]
        owner=self
        class Input:
            closed=False
            def write(self,data):return owner.daemon_input.write(data)
            def close(self):
                if self.closed:return
                self.closed=True;owner.events.append('client-input-closed')
                if stdin_once:
                    owner.daemon_input.close();owner.events.append('container-input-closed')
                else:owner.close_output()
        self.stdin=Input()
        self.worker=threading.Thread(target=self.receive,daemon=True)
        self.worker.start()
    def close_output(self):
        with self.output_lock:
            if not self.output.closed:self.output.close();self.events.append('output-closed')
    def receive(self):
        # This short test deadline models the unchanged Go 10s bounded receiver.
        expected=b'WARDEN_DEVICE_RECEIPT_OK\n';deadline=time.monotonic()+0.2
        try:
            while len(self.received)<len(expected)+1:
                remaining=deadline-time.monotonic()
                if remaining<=0 or not select.select([self.container_input],[],[],remaining)[0]:break
                chunk=self.container_input.read(len(expected)+1-len(self.received))
                if not chunk:self.saw_eof=True;break
                self.received+=chunk
            self.accepted=self.saw_eof and self.received==expected
            if self.accepted:
                self.events.append('ack-and-eof')
                with self.output_lock:
                    if not self.output.closed:self.output.write(b'fixture policy result after EOF\n')
            self.status=0 if self.accepted else 1
        finally:
            self.container_input.close();self.close_output()
    def wait(self,timeout):
        self.worker.join(timeout)
        if self.worker.is_alive():raise TimeoutError('finite attach fixture deadline')
        return self.status
    def close(self):
        self.stdin.close();self.wait(1)
        self.daemon_input.close();self.stdout.close()

class ReceiptTests(unittest.TestCase):
    def receipt(self):
        return dict(kind='warden-device-receipt-v1',pid=1,cgroup_ns='cgroup:[2]',mount_ns='mnt:[2]',device=7,inode=9,mount_id=11,policy_version='warden-tun-deny-v1',policy_sha256=gate.POLICY_SHA if hasattr(gate,'POLICY_SHA') else 'pending')
    def test_receipt_exact_schema_and_namespace(self):
        r=self.receipt();self.assertEqual(gate.parse_receipt(json.dumps(r).encode()+b'\n','cgroup:[1]','mnt:[1]'),r)
        for key,value in [('pid',True),('pid',2),('device',0),('inode','9'),('mount_id',0),('cgroup_ns','cgroup:[1]'),('mount_ns','mnt:[1]'),('policy_sha256','f'*64),('extra','x')]:
            bad=dict(r);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):gate.parse_receipt(json.dumps(bad).encode()+b'\n','cgroup:[1]','mnt:[1]')
        for raw in [b'',b'{}\n',b'x'*4097,json.dumps(r).encode()+b'\n{}\n']:
            with self.assertRaises(ValueError):gate.parse_receipt(raw,'cgroup:[1]','mnt:[1]')
    def test_owned_pid_cgroup_starttime_binding(self):
        before={'Id':CID,'Image':IMAGE,'State':{'Running':True,'Pid':42}}
        cg='0::/system.slice/docker-'+CID+'.scope\n';status='Name:\tlab\nNSpid:\t42\t1\n'
        gate.validate_observation(CID,IMAGE,before,before,cg,status,123,123)
        for kind in ('pid','image','stopped','path','nspid','reuse'):
            after=json.loads(json.dumps(before));c,s,start=cg,status,123
            if kind=='pid':after['State']['Pid']=43
            if kind=='image':after['Image']='sha256:'+'c'*64
            if kind=='stopped':after['State']['Running']=False
            if kind=='path':c='0::/system.slice/docker-'+('c'*64)+'.scope\n'
            if kind=='nspid':s='NSpid:\t42\t2\n'
            if kind=='reuse':start=124
            with self.subTest(kind=kind),self.assertRaises(ValueError):gate.validate_observation(CID,IMAGE,before,after,c,s,123,start)


    def test_bounded_pipe_eof_deadline_and_length(self):
        for raw in (b'{}\n',b'',b'x'*4096):
            r,w=os.pipe();os.write(w,raw);os.close(w)
            try:
                if raw==b'{}\n':self.assertEqual(gate.read_line(r),raw)
                else:
                    with self.assertRaises(ValueError):gate.read_line(r)
            finally:os.close(r)
        r,w=os.pipe()
        try:
            with self.assertRaises(TimeoutError):gate.read_line(r,0.001)
        finally:os.close(r);os.close(w)
    def test_real_held_cgroup_entry_absence_rejects_replacement(self):
        with tempfile.TemporaryDirectory(prefix='warden-receipt-') as root:
            parent=os.open(root,os.O_DIRECTORY);path=Path(root)/('docker-'+CID+'.scope');path.mkdir()
            target=os.open(path,os.O_DIRECTORY);held=gate.OwnedCgroupReceipt(parent,target,path.name)
            try:
                with patch.object(gate,'trusted_directory',side_effect=lambda *_:os.dup(parent)):
                    with self.assertRaises(ValueError):held.absent()
                    path.rmdir();held.absent()
                    path.mkdir()
                    with self.assertRaises(ValueError):held.absent()
                    path.rmdir();path.symlink_to('/tmp')
                    with self.assertRaises(ValueError):held.absent()
            finally:held.close()
    def test_fixed_transcript_ack_only_after_correlated_receipt(self):
        class Held:
            target_identity=(1,2,0);parent_identity=(1,3,0)
            def present(self):return None
            def absent(self):return None
            def close(self):return None
        raw=json.dumps(self.receipt()).encode()+b'\n'
        for stdin_once,failure in ((True,False),(False,False),(True,True)):
            with self.subTest(stdin_once=stdin_once,correlation_failure=failure):
                child=PipeAttach(raw,stdin_once);self.addCleanup(child.close)
                saved=[];runner=gate.DeviceGate(CID,IMAGE,lambda:None,lambda n,b:saved.append(n))
                with patch.object(gate.subprocess,'Popen',return_value=child) as launch,patch.object(gate,'capture_receipt',side_effect=ValueError('PID mismatch') if failure else None,return_value=(Held(),{})):
                    if failure:
                        with self.assertRaises(ValueError):runner.run()
                        with self.assertRaises(ValueError):runner.after_cleanup()
                    elif not stdin_once:
                        with self.assertRaises(RuntimeError):runner.run()
                        self.assertEqual(bytes(child.received),b'WARDEN_DEVICE_RECEIPT_OK\n')
                        self.assertFalse(child.saw_eof)
                        self.assertFalse(child.daemon_input.closed)
                        self.assertNotIn(b'fixture policy result',runner.log)
                    else:
                        log=runner.run()
                        self.assertIn('fixture policy result after EOF\n',log)
                        self.assertLess(child.events.index('ack-and-eof'),child.events.index('output-closed'))
                        runner.after_cleanup();self.assertIn('device-cgroup-absence.json',saved)
                    self.assertEqual(launch.call_args.args[0],['docker','--host','unix:///var/run/docker.sock','container','start','--attach','--interactive',CID])
                runner.close()
                if failure:self.assertEqual(bytes(child.received),b'')

    def test_inspected_stdin_lifetime_allows_ack_eof_and_rejects_daemon_hold(self):
        from test_firecracker_lab import lab,binding,bound_fixture,InspectedCapabilityTests
        data=bound_fixture(InspectedCapabilityTests.actual())
        with redirect_stdout(io.StringIO()):
            try:lab.inspect_live(data,'boot',binding())
            except ValueError as error:self.fail('ACK+EOF configuration rejected: '+str(error))
            data['Config']['StdinOnce']=False
            with self.assertRaises(ValueError):lab.inspect_live(data,'boot',binding())

    def test_fixed_transcript_refuses_wrong_extra_and_empty_ack(self):
        class Held:
            def present(self):pass
            def close(self):pass
        for raw in (b'wrong\n',b'WARDEN_DEVICE_RECEIPT_OK\nx',b''):
            with self.subTest(raw=raw):
                child=PipeAttach(json.dumps(self.receipt()).encode()+b'\n',True);self.addCleanup(child.close)
                runner=gate.DeviceGate(CID,IMAGE,lambda:None,lambda *_:None)
                with patch.object(gate.subprocess,'Popen',return_value=child),patch.object(gate,'capture_receipt',return_value=(Held(),{})),patch.object(gate,'ACK',raw):
                    with self.assertRaises(RuntimeError):runner.run()
                self.assertNotIn(b'fixture policy result',runner.log)
                self.assertFalse(child.accepted)
                runner.close()

if __name__=='__main__':unittest.main()
