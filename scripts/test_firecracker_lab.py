import io
import os
import tempfile
import copy
import json
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import patch
from contextlib import nullcontext
import firecracker_lab as lab

LABELS={'project':'warden','session':'a'*32}
def binding():
    return {'source':str(lab.BASE/('docker-firecracker-'+LABELS['session'])/'live'),'device':1,'inode':2,'uid':1000}

def bound_fixture(h):
    # Only capability/resource values come from the archived real inspection.
    # These new RO mount fields are policy fixtures, not new Docker observations.
    h=copy.deepcopy(h);b=binding()
    h['Mounts']=[{'Type':'bind','Source':b['source'],'Target':'/opt/warden/session','ReadOnly':True,'BindOptions':{'Propagation':'rprivate'}}]
    return {'Config':{'OpenStdin':True,'StdinOnce':True,'AttachStdin':True,'AttachStdout':True,'AttachStderr':True,'Tty':False,'Entrypoint':['/opt/warden/input/lab'],'Cmd':['boot'],'User':''},'HostConfig':h,'Mounts':[{'Type':'bind','Source':b['source'],'Destination':'/opt/warden/session','Mode':'ro','RW':False,'Propagation':'rprivate'}]}

class FirecrackerLabTests(unittest.TestCase):
    def test_live_profile_has_only_exact_kvm_and_eight_caps(self):
        args=lab.live_args('boot','sha256:'+'a'*64,binding(),LABELS,'cgroup:[123]','mnt:[321]')
        self.assertEqual([a for a in args if a.startswith('--device=')],['--device=/dev/kvm:/dev/kvm:rw'])
        self.assertEqual(set(a.removeprefix('--cap-add=') for a in args if a.startswith('--cap-add=')),set(lab.CAPS))
        self.assertEqual(len(lab.CAPS),8)
        self.assertNotIn('NET_ADMIN',lab.CAPS)
        self.assertIn('--memory=4000000000',args)
        self.assertIn('--memory-swap=4000000000',args)
        self.assertNotIn('--privileged',args)
        self.assertNotIn('--network=host',args)
    def test_capacity_leaves_exact_host_allowance(self):
        args=lab.live_args('capacity-default','sha256:'+'a'*64,binding(),LABELS,'cgroup:[123]','mnt:[321]')
        self.assertIn('--memory=15000000000',args)
        with self.assertRaises(ValueError):lab.live_args('shell','sha256:'+'a'*64,binding(),LABELS,'cgroup:[123]','mnt:[321]')
    def test_material_pin_distinguishes_computed_and_published(self):
        self.assertEqual(lab.MATERIALS['vmlinux-6.18.54']['provenance'],'computed-pin')
        self.assertEqual(lab.MATERIALS['vmlinux-6.18.54.config']['provenance'],'computed-pin')
        self.assertEqual(lab.MATERIALS['firecracker-v1.17.0-x86_64.tgz']['provenance'],'publisher-release-checksum')
    def test_package_limit_fails_before_archive_write(self):
        with self.assertRaises(ValueError):lab.validate_package_sizes(384000001,0)
        with self.assertRaises(ValueError):lab.validate_package_sizes(1,512000001)
        lab.validate_package_sizes(384000000,512000000)


class LoadedImageIdentityTests(unittest.TestCase):
    def test_descriptor_id_is_distinct_from_verified_config_id(self):
        config=lab.encode({'config':{'User':'65534:65534','Entrypoint':['/warden-probe'],'Labels':{'project':'warden'}}})
        image={'Id':'sha256:'+'a'*64,'RootFS':{'Layers':['sha256:'+'b'*64]},'Config':{'User':'65534:65534','Entrypoint':['/warden-probe'],'Labels':{'project':'warden'}}}
        lab.validate_loaded_binding(image,config,config,'sha256:'+'b'*64)
        with self.assertRaises(ValueError):lab.validate_loaded_binding(image,config,b'{}','sha256:'+'b'*64)
        with self.assertRaises(ValueError):lab.validate_loaded_binding(image,config,config,'sha256:'+'c'*64)

class InspectedCapabilityTests(unittest.TestCase):
    @staticmethod
    def actual():
        path=Path(__file__).resolve().parent.parent/'docs/evidence/task-4/live/135c3b866f07692ad846cc48c8c5bde0cf91ee33/create-inspect-only.json'
        return json.loads(path.read_text())['host_config']
    def check(self,h):
        with redirect_stdout(io.StringIO()):
            lab.inspect_live(bound_fixture(h),'boot',binding())
    def test_archived_actual_eight_prefixed_capabilities_pass(self):
        self.check(self.actual())
    def test_missing_extra_invalid_names_and_types_fail(self):
        actual=self.actual()['CapAdd']
        variants=[actual[:-1],actual+['CAP_NET_ADMIN'],actual[:-1]+[actual[0]],
                  actual[:-1]+['CAP_CAP_CHOWN'],actual[:-1]+['CHOWN'],
                  actual[:-1]+['cap_chown'],actual[:-1]+[' CAP_CHOWN'],
                  actual[:-1]+[None],actual[:-1]+[12],actual[:-1]+[{}],None,12,'CAP_CHOWN',{}]
        for caps in variants:
            with self.subTest(caps=caps):
                h=self.actual();h['CapAdd']=caps
                with self.assertRaises(ValueError):self.check(h)
    def test_raw_bounds_are_logged_before_rejection(self):
        h=self.actual();h['Memory']=4000000001
        output=io.StringIO()
        with redirect_stdout(output):
            with self.assertRaises(ValueError):lab.inspect_live({'HostConfig':h},'boot',binding())
        raw=json.loads(output.getvalue())
        self.assertEqual(raw['inspected_host_config'],h)
        self.assertLessEqual(len(output.getvalue().encode()),16384)
    def test_oversized_raw_bounds_fail_with_bounded_diagnostic(self):
        h=self.actual();h['Unexpected']='x'*20000
        output=io.StringIO()
        with redirect_stdout(output):
            with self.assertRaises(ValueError):lab.inspect_live({'HostConfig':h},'boot',binding())
        self.assertLessEqual(len(output.getvalue().encode()),16384)
    def test_other_deny_conditions_remain(self):
        for key,value in [('Privileged',True),('CapDrop',[]),('NetworkMode','host'),('Devices',[]),('ReadonlyRootfs',False)]:
            with self.subTest(key=key):
                h=self.actual();h[key]=value
                with self.assertRaises(ValueError):self.check(h)


class InitialReadonlyBindingTests(unittest.TestCase):
    def test_fixed_live_realpath_is_initial_readonly(self):
        labels={'session':'a'*32,'project':'warden'}
        path=str(lab.BASE/('docker-firecracker-'+labels['session'])/'live')
        args=lab.live_args('boot','sha256:'+'a'*64,binding(),labels,'cgroup:[123]','mnt:[321]')
        self.assertIn('--mount=type=bind,src='+path+',dst=/opt/warden/session,readonly,bind-propagation=rprivate',args)

    def test_arbitrary_source_and_identity_are_rejected(self):
        for key,value in [('source','/tmp/other'),('source',binding()['source']+'/../live'),('uid',0),('device',True),('inode',0)]:
            b=binding();b[key]=value
            with self.subTest(key=key,value=value):
                with self.assertRaises(ValueError):lab.mount_smoke_args('sha256:'+'a'*64,b,LABELS,'mnt:[321]')
    def test_real_held_fd_rejects_replacement_symlink_and_mode_change(self):
        self.assertEqual(os.getuid(),1000,'run ordinary host tests as UID1000')
        with tempfile.TemporaryDirectory(prefix='warden-fc-anchor-') as root:
            path=Path(root)/'live';path.mkdir(mode=0o700)
            fd=lab.trusted_directory(str(path),1000)
            try:
                observed=lab.anchored_binding(path,fd)
                self.assertEqual(observed['inode'],os.fstat(fd).st_ino)
                path.chmod(0o750)
                with self.assertRaises(ValueError):lab.anchored_binding(path,fd)
                path.chmod(0o700);old=Path(root)/'original';path.rename(old);path.mkdir(mode=0o700)
                with self.assertRaises(ValueError):lab.anchored_binding(path,fd)
                path.rmdir();path.symlink_to(old,target_is_directory=True)
                with self.assertRaises((ValueError,OSError)):lab.anchored_binding(path,fd)
                self.assertEqual(list(old.iterdir()),[])
            finally:os.close(fd)
    def test_inspection_rejects_rw_extra_mounts_alias_and_propagation(self):
        for kind in ('rw','source','shared','extra','hidden','host-rw'):
            d=bound_fixture(InspectedCapabilityTests.actual())
            if kind=='rw':d['Mounts'][0]['RW']=True
            if kind=='source':d['Mounts'][0]['Source']='/tmp/other'
            if kind=='shared':d['Mounts'][0]['Propagation']='shared'
            if kind=='extra':d['Mounts'].append(copy.deepcopy(d['Mounts'][0]))
            if kind=='hidden':d['HostConfig']['Binds']=['/tmp:/unexpected']
            if kind=='host-rw':d['HostConfig']['Mounts'][0]['ReadOnly']=False
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):lab.inspect_session_bind(d,binding())
    def test_smoke_is_fixed_capless_ro_only(self):
        args=lab.mount_smoke_args('sha256:'+'a'*64,binding(),LABELS,'mnt:[321]')
        for required in ('--user=1000:1000','--cap-drop=ALL','--read-only','--network=none','--memory=256000000','--memory-swap=256000000','--cpus=1','--pids-limit=32'):
            self.assertIn(required,args)
        self.assertFalse(any(a.startswith(('--cap-add','--device')) or 'unconfined' in a for a in args))
        self.assertEqual([a for a in args if a.startswith('--mount=')],['--mount=type=bind,src='+binding()['source']+',dst=/opt/warden/session,readonly,bind-propagation=rprivate'])
        self.assertEqual(args[-1],'mount-smoke')
        d=bound_fixture(InspectedCapabilityTests.actual());h=d['HostConfig']
        h.update(Memory=256000000,MemorySwap=256000000,NanoCpus=1000000000,PidsLimit=32,CapAdd=None,Devices=[],SecurityOpt=['no-new-privileges'])
        d['Config']={'User':'1000:1000'}
        with redirect_stdout(io.StringIO()):lab.inspect_mount_smoke(d,binding())
        for key,value in [('Memory',256000001),('PidsLimit',33),('Devices',[{}]),('CapAdd',['CAP_SYS_ADMIN']),('SecurityOpt',['no-new-privileges','seccomp=unconfined'])]:
            bad=copy.deepcopy(d);bad['HostConfig'][key]=value
            with self.subTest(key=key),redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):lab.inspect_mount_smoke(bad,binding())



class DevicePolicyModeTests(unittest.TestCase):
    def test_all_six_privileged_modes_require_interactive_fixed_entrypoint(self):
        self.assertEqual(set(lab.PRIVILEGED),{'boot','conformance','snapshot','capacity-default','capacity-benchmark','capacity-pressure','device-policy'})
        for mode in lab.PRIVILEGED:
            args=lab.live_args(mode,'sha256:'+'a'*64,binding(),LABELS,'cgroup:[123]','mnt:[321]')
            self.assertEqual(args.count('--interactive'),1)
            self.assertEqual(args[-1],mode)
            data=bound_fixture(InspectedCapabilityTests.actual());data['Config']['Cmd']=[mode]
            if mode.startswith('capacity-'):data['HostConfig']['Memory']=data['HostConfig']['MemorySwap']=15000000000
            if mode=='capacity-pressure':data['HostConfig']['PidsLimit']=1024
            with redirect_stdout(io.StringIO()):lab.inspect_live(data,mode,binding())
            for key,value in [('OpenStdin',False),('StdinOnce',False),('StdinOnce',None),('StdinOnce',1),('AttachStdin',False),('AttachStdout',False),('AttachStderr',False),('Tty',True),('Cmd',['shell']),('Entrypoint',['sh']),('User','1000')]:
                bad=copy.deepcopy(data);bad['Config'][key]=value
                with self.subTest(mode=mode,key=key),redirect_stdout(io.StringIO()),self.assertRaises(ValueError):lab.inspect_live(bad,mode,binding())
        self.assertNotIn('--interactive',lab.mount_smoke_args('sha256:'+'a'*64,binding(),LABELS,'mnt:[321]'))



class OuterPidsTests(unittest.TestCase):
    # On 2026-11-10 capacity-pressure's 101st VM did not start with 508 of the
    # outer's 512 pids in use; only that mode's outer gets 1024.
    def test_only_capacity_pressure_gets_the_raised_pid_limit(self):
        for mode in lab.PRIVILEGED:
            want=1024 if mode=='capacity-pressure' else 512
            args=lab.live_args(mode,'sha256:'+'a'*64,binding(),LABELS,'cgroup:[123]','mnt:[321]')
            self.assertEqual([a for a in args if a.startswith('--pids-limit=')],['--pids-limit=%d'%want],mode)
            data=bound_fixture(InspectedCapabilityTests.actual());data['Config']['Cmd']=[mode]
            if mode.startswith('capacity-'):data['HostConfig']['Memory']=data['HostConfig']['MemorySwap']=15000000000
            for pids in (512,1024,513,1023,2048,0,-1):
                data['HostConfig']['PidsLimit']=pids
                with self.subTest(mode=mode,pids=pids),redirect_stdout(io.StringIO()):
                    if pids==want:lab.inspect_live(data,mode,binding())
                    else:
                        with self.assertRaises(ValueError):lab.inspect_live(data,mode,binding())
        self.assertIn('--pids-limit=32',lab.mount_smoke_args('sha256:'+'a'*64,binding(),LABELS,'mnt:[321]'))



class PackageVariantTests(unittest.TestCase):
    """prepare --without-corpus: no attack helper build, no corpus, helper or
    Task 5 files in the package; the default package is unchanged."""
    def test_variant_names(self):
        self.assertEqual(lab.package_variant(False),'with-corpus')
        self.assertEqual(lab.package_variant(True),'without-corpus')
    def test_default_build_is_unchanged_and_the_corpus_free_one_skips_the_helper(self):
        import firecracker_code as code
        go='/go'
        original=('umask 0077; export CGO_ENABLED=0; '+go+' build -p 1 -trimpath -o .cache/firecracker-code/agent ./runtimes/firecracker/cmd/agent && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/lab ./runtimes/firecracker/cmd/lab && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/rootfs ./runtimes/firecracker/cmd/rootfs && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/warden-probe ./runtimes/conformance/guest && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/warden-attack ./attacks/cmd/warden-attack && '+go+' test -p 1 -c -o .cache/firecracker-code/firecracker.test ./runtimes/firecracker')
        self.assertEqual(code.build_command(go),original)
        free=code.build_command(go,corpus=False)
        self.assertEqual(free,original.replace(' && '+go+' build -p 1 -trimpath -o .cache/firecracker-code/warden-attack ./attacks/cmd/warden-attack',''))
        self.assertNotIn('warden-attack',free)
        self.assertNotIn('./attacks/',free)
        self.assertIn('build',code.MODES);self.assertIn('build-without-corpus',code.MODES)
    def test_corpus_inputs_are_not_touched_without_corpus(self):
        import corpus_image,runtime_lab_docker
        with patch.object(corpus_image,'payload_files',side_effect=AssertionError('payload_files called')) as payload,patch.object(runtime_lab_docker,'corpus_files',side_effect=AssertionError('corpus_files called')) as corpus:
            self.assertEqual(lab.payload_inputs(True),{})
            self.assertEqual(lab.corpus_inputs(True),{})
        payload.assert_not_called();corpus.assert_not_called()
        with patch.object(corpus_image,'payload_files',return_value={'bin/sh':b'sh'}) as payload,patch.object(runtime_lab_docker,'corpus_files',return_value={'corpus/x/run.sh':b'x'}) as corpus:
            self.assertEqual(lab.payload_inputs(False),{'bin/sh':b'sh'})
            self.assertEqual(lab.corpus_inputs(False),{'corpus/x/run.sh':b'x'})
        payload.assert_called_once_with(lab.ROOT,helper=lab.CACHE/'warden-attack');corpus.assert_called_once_with(lab.ROOT)
    def prepare(self,without_corpus):
        """Runs prepare() on fake build outputs; returns (build modes, export flags, receipt, package tar members, manifest)."""
        import tarfile as tf
        modes,exports=[],[]
        with tempfile.TemporaryDirectory(prefix='warden-variant-') as root:
            root=Path(root);os.chmod(root,0o700);cache=root/'code';cache.mkdir(mode=0o700);base=root/'lab';base.mkdir(mode=0o700)
            output=base/('docker-firecracker-'+LABELS['session']);output.mkdir(mode=0o700)
            files={'agent':b'agent','agent.ext4':b'agent-ext4','payload.ext4':b'payload-ext4','lab':b'lab','firecracker.test':b'test'}
            export={'SHA256':'e'*64,'NormalizationVersion':'warden-fc-docker-export-v1','NormalizedSHA256':'f'*64,'NormalizationPolicySHA':'1'*64}
            def run(args,check):
                self.assertTrue(check)
                if args[2].endswith('firecracker_code.py'):
                    modes.append(args[3])
                    if args[3]=='rootfs':
                        for name,raw in files.items():
                            (cache/name).write_bytes(raw);(cache/name).chmod(0o600)
                        (cache/'rootfs.json').write_bytes(lab.encode({'Export':export,'Hashes':{'agent.ext4':lab.sha(files['agent.ext4']),'payload.ext4':lab.sha(files['payload.ext4'])}}));(cache/'rootfs.json').chmod(0o600)
                return None
            def export_probe(out,labels,*rest):
                exports.append(rest)
                return {'ImageDigest':'sha256:'+'a'*64,'ExportSHA':'e'*64}
            materials={'kernel':b'kernel','firecracker':b'fc','jailer':b'jailer'}
            with patch.object(lab,'CACHE',cache),patch.object(lab,'BASE',base),patch.object(lab,'locked',return_value=nullcontext()),patch.object(lab,'guard'),patch.object(lab,'source_sha',return_value='c'*40),patch.object(lab.subprocess,'run',side_effect=run),patch.object(lab,'fresh_session',return_value=(output,dict(LABELS))),patch.object(lab,'fixed_materials',return_value=materials),patch.object(lab,'export_probe',side_effect=export_probe),patch('runtime_lab_docker.corpus_files',return_value={'corpus/fork-bomb/run.sh':b'x','corpus/fork-bomb/expect.yaml':b'y'}),redirect_stdout(io.StringIO()):
                # main() runs prepare under umask 0077; a caller's 0002 would
                # make the fake outputs group-writable, which bounded_input refuses.
                umask=os.umask(0o077)
                try:lab.prepare(without_corpus) if without_corpus else lab.prepare()
                finally:os.umask(umask)
            receipt=json.loads((cache/'package.json').read_text())
            with tf.open(cache/'package.tar') as tar:
                names=tar.getnames();manifest=json.load(tar.extractfile('opt/warden/input/manifest.json'))
            self.assertEqual(json.loads((output/'package-result.json').read_text()),receipt)
        return modes,exports,receipt,names,manifest
    def test_prepare_without_corpus_packs_no_corpus_and_records_its_variant(self):
        modes,exports,receipt,names,manifest=self.prepare(True)
        self.assertEqual(modes,['build-without-corpus','rootfs'])
        self.assertEqual(exports,[(True,)])
        self.assertFalse([n for n in names if n.startswith('opt/warden/input/corpus')],names)
        self.assertEqual(receipt['variant'],'without-corpus')
        self.assertEqual(receipt['manifest']['PackageVariant'],'without-corpus')
        self.assertEqual(manifest['PackageVariant'],'without-corpus')
        _,_,default,default_names,default_manifest=self.prepare(False)
        self.assertNotEqual(manifest['PolicySHA'],default_manifest['PolicySHA'])
    def test_default_prepare_still_packs_the_corpus(self):
        modes,exports,receipt,names,manifest=self.prepare(False)
        self.assertEqual(modes,['build','rootfs'])
        self.assertEqual(exports,[(False,)])
        self.assertIn('opt/warden/input/corpus/fork-bomb/run.sh',names)
        self.assertEqual(receipt['variant'],'with-corpus')
        self.assertEqual(manifest['PackageVariant'],'with-corpus')
    def test_execute_refuses_a_package_of_the_other_variant(self):
        for requested,stored in ((True,'with-corpus'),(False,'without-corpus'),(True,None),(False,None)):
            package={'source':'c'*40,'tar_sha256':lab.sha(b'package'),'file_bytes':7,'manifest':{'PackageVariant':stored}}
            if stored:package['variant']=stored
            def fixed_input(path,limit):
                return lab.encode(package) if path.name=='package.json' else b'package'
            with self.subTest(requested=requested,stored=stored),patch.object(lab,'locked',return_value=nullcontext()),patch.object(lab,'guard'),patch.object(lab,'source_sha',return_value='c'*40),patch.object(lab,'bounded_input',side_effect=fixed_input),patch.object(lab,'fresh_session',side_effect=AssertionError('session made for a package of the other variant')):
                with self.assertRaisesRegex(ValueError,'variant'):lab.execute('capacity-pressure',0,requested)
    def test_execute_refuses_a_receipt_whose_manifest_variant_differs(self):
        package={'source':'c'*40,'tar_sha256':lab.sha(b'package'),'file_bytes':7,'variant':'without-corpus','manifest':{'PackageVariant':'with-corpus'}}
        def fixed_input(path,limit):
            return lab.encode(package) if path.name=='package.json' else b'package'
        with patch.object(lab,'locked',return_value=nullcontext()),patch.object(lab,'guard'),patch.object(lab,'source_sha',return_value='c'*40),patch.object(lab,'bounded_input',side_effect=fixed_input),patch.object(lab,'fresh_session',side_effect=AssertionError('session made')):
            with self.assertRaisesRegex(ValueError,'variant'):lab.execute('capacity-pressure',0,True)
    def test_cli_takes_the_option_for_prepare_and_actual_modes(self):
        for argv,call in ((['prepare','--without-corpus'],'prepare'),(['capacity-pressure','--without-corpus'],'execute'),(['boot'],'execute')):
            info=lab.encode({'Name':os.uname().nodename,'CgroupVersion':'2','SecurityOptions':[],'CgroupDriver':'systemd'})
            with self.subTest(argv=argv),patch.object(lab.sys,'argv',['firecracker_lab.py',*argv,'--other-service-memory-bytes','0']),patch.object(lab.os,'getuid',return_value=1000),patch.object(lab,'docker',return_value=info),patch.object(lab,'prepare') as prepare,patch.object(lab,'execute') as execute,patch.object(lab.os,'umask'):
                lab.main()
                if call=='prepare':prepare.assert_called_once_with(True);execute.assert_not_called()
                else:execute.assert_called_once_with(argv[0],0,'--without-corpus' in argv);prepare.assert_not_called()



class DeviceReleaseTests(unittest.TestCase):
    def test_completed_outer_cannot_release_without_cgroup_absence(self):
        # Fake outer/PID proof, actual session/charge files. No Docker/device call.
        # A failed run releases its reservation only after the same verified
        # cleanup and when nothing in the session is left root-owned.
        for mode in ('device-policy','boot'):
            for completed,absence,operator in ((False,True,True),(False,True,False),(False,False,True),(True,False,True),(True,True,True)):
                with self.subTest(mode=mode,completed=completed,absence=absence,operator=operator),tempfile.TemporaryDirectory(prefix='warden-release-') as root:
                    base=Path(root);output=base/('docker-firecracker-'+LABELS['session']);output.mkdir(mode=0o700)
                    image='sha256:'+'a'*64;package={'source':'c'*40,'tar_sha256':lab.sha(b'package'),'file_bytes':7,'variant':'with-corpus','manifest':{'PackageVariant':'with-corpus'}}
                    labels=dict(LABELS);calls=[]
                    class FakeGate:
                        log=b'fake outer result'
                        def __init__(self,*args):pass
                        def run(self):
                            if not completed:raise RuntimeError('fixture ACK gate failed')
                            if mode=='boot':
                                node=output/'live/node';node.mkdir(mode=0o700);(node/'retired').write_bytes(b'known-owner-retired\n');(node/'retired').chmod(0o600)
                            return 'fake outer result'
                        def after_cleanup(self):
                            calls.append('absence')
                            if not absence:raise ValueError('original cgroup still present')
                        def close(self):calls.append('close')
                    original_input=lab.bounded_input
                    def fixed_input(path,limit):
                        if path.name=='package.json':return lab.encode(package)
                        if path.name=='package.tar':return b'package'
                        return original_input(path,limit)
                    def owned(kind,*args):
                        if kind=='image':return {'Size':100}
                        h=InspectedCapabilityTests.actual();h['Mounts'][0]['Source']=str(output/'live')
                        return {'HostConfig':h}
                    def docker(args,**kw):
                        if args[:2]==['image','import']:return image
                        if args[:2]==['container','create']:return 'd'*64
                        if args[:2]==['container','wait']:return '0'
                        raise AssertionError(args)
                    kvm=type('Stat',(),{'st_mode':0o20660,'st_rdev':os.makedev(10,232)})()
                    with patch.object(lab,'BASE',base),patch.object(lab,'locked',return_value=nullcontext()),patch.object(lab,'guard'),patch.object(lab,'source_sha',return_value='c'*40),patch.object(lab,'bounded_input',side_effect=fixed_input),patch.object(lab,'fresh_session',return_value=(output,labels)),patch.object(lab,'docker',side_effect=docker),patch.object(lab,'owned_inspect',side_effect=owned),patch.object(lab,'inspect_live'),patch.object(lab,'DeviceGate',FakeGate),patch.object(lab,'remove_objects',side_effect=lambda _:calls.append('remove')),patch.object(lab.os,'lstat',return_value=kvm),patch.object(lab,'operator_owned',return_value=operator),redirect_stdout(io.StringIO()):
                        if completed and absence:lab.execute(mode,0)
                        else:
                            with self.assertRaises(ValueError if completed or not absence else RuntimeError):lab.execute(mode,0)
                    self.assertEqual(json.loads((output/'charge.json').read_text())['released'],absence and (completed or operator))
                    self.assertEqual(calls,['remove','absence','close'])

class OperatorOwnedTests(unittest.TestCase):
    def test_walks_without_following_links(self):
        with tempfile.TemporaryDirectory(prefix='warden-owned-') as root:
            base=Path(root);(base/'live/node').mkdir(parents=True);(base/'live/node/runs').write_text('x')
            os.symlink('/',base/'live/node/escape')
            self.assertTrue(lab.operator_owned(base))
            real=os.lstat
            def foreign(path,*a,**k):
                st=real(path,*a,**k)
                if str(path).endswith('runs'):return os.stat_result((st.st_mode,st.st_ino,st.st_dev,st.st_nlink,0,0,st.st_size,0,0,0))
                return st
            with patch.object(lab.os,'lstat',side_effect=foreign):self.assertFalse(lab.operator_owned(base))

if __name__=='__main__':unittest.main()
