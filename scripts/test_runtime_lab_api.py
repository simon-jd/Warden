"""Breaks caught: private PG escape, stale target join, resource leak on failure."""
import importlib.util
import contextlib
import io
import json
import unittest
from unittest.mock import patch

SPEC=importlib.util.find_spec('runtime_lab_api')
if SPEC: import runtime_lab_api as api
CID='d'*64
LABELS={'project':'warden','owner':'warden-lab','session':'a'*32,'ttl':'test'}

class QuietTests(unittest.TestCase):
 def setUp(self):
  capture=contextlib.redirect_stdout(io.StringIO());capture.__enter__()
  self.addCleanup(capture.__exit__,None,None,None)

class ApiTopologyTests(QuietTests):
 def setUp(self):
  super().setUp()
  self.assertIsNotNone(SPEC,'private API/PG topology is missing')
 def test_owned_private_pg_is_removed_after_outer_failure(self):
  calls=[];exists=False
  def cli(args,**kw):
   nonlocal exists
   calls.append(args)
   if args[:2]==['image','inspect']:return json.dumps([{'Id':'sha256:'+'b'*64,'RepoDigests':[api.PG_IMAGE],'Size':432729433}])
   if args[:2]==['container','create']:exists=True;return CID
   if args[:2]==['container','inspect']:return json.dumps([self.record()])
   if args[:2]==['container','rm']:exists=False;return ''
   if args[:2]==['container','ls']:return CID if exists else ''
   if args[:2] in (['container','start'],['container','stop'],['container','exec']):return ''
   raise AssertionError(args)
  with self.assertRaisesRegex(RuntimeError,'outer failed'):
   with api.postgres(LABELS,cli) as target:
    self.assertEqual(target,CID)
    raise RuntimeError('outer failed')
  self.assertFalse(exists)
  create=next(x for x in calls if x[:2]==['container','create'])
  for option in ['--pull=never','--network=none','--read-only','--cap-drop=ALL','--user=70:70','--memory=536870912','--memory-swap=536870912','--pids-limit=128','--cpus=1']:
   self.assertIn(option,create)
  self.assertFalse(any(x.startswith(('--publish','-p=','--privileged','--mount','--volume')) for x in create))
  self.assertIn(['container','rm','--force',CID],calls)
 def record(self):
  return {'Id':CID,'Config':{'Labels':{**LABELS,'role':'postgres'}},'HostConfig':{'NetworkMode':'none','PidMode':'','IpcMode':'private','CgroupnsMode':'private','Privileged':False,'PortBindings':{}},'State':{'Running':True},'NetworkSettings':{'Ports':{},'SandboxID':'s'*64}}
 def test_host_unknown_and_stopped_targets_refused(self):
  for mutation in ['host','unowned','stopped','ports','missing']:
   record=self.record()
   if mutation=='host': record['HostConfig']['NetworkMode']='host'
   if mutation=='unowned':record['Config']['Labels']['session']='other'
   if mutation=='stopped':record['State']['Running']=False
   if mutation=='ports':record['HostConfig']['PortBindings']={'5432/tcp':[{'HostPort':'5432'}]}
   if mutation=='missing':record.pop('NetworkSettings')
   with self.subTest(mutation=mutation),self.assertRaises((RuntimeError,KeyError)):
    api.private_target(CID,LABELS,lambda *a,**k:json.dumps([record]))
 def test_wrong_cached_digest_never_creates(self):
  calls=[]
  def cli(args,**kw):
   calls.append(args);return json.dumps([{'Id':'sha256:'+'b'*64,'RepoDigests':['postgres@sha256:'+'f'*64],'Size':1}])
  with self.assertRaises(RuntimeError):api.cached_postgres(cli)
  self.assertEqual(len(calls),1)

class ApiOuterTests(QuietTests):
 def test_code_mode_is_capless_and_joins_only_verified_pg(self):
  import runtime_lab_docker as lab
  import tempfile
  from pathlib import Path
  calls=[];exists=False
  outer='e'*64
  def cli(args,**kw):
   nonlocal exists
   calls.append(args)
   if args[:2]==['container','inspect']:
    if args[-1]==CID:return json.dumps([ApiTopologyTests().record()])
    return json.dumps([{'Id':outer,'Config':{'Labels':{**LABELS,'role':'outer'}}}])
   if args[:2]==['container','create']:exists=True;return outer
   if args[:2]==['container','wait']:return '0'
   if args[:2]==['container','rm']:exists=False;return ''
   if args[:2]==['container','ls']:return outer if exists else ''
   if args[:2] in (['container','start'],['container','stop'],['container','logs']):return ''
   raise AssertionError(args)
  with tempfile.TemporaryDirectory() as tmp: lab.execute('sha256:'+'a'*64,Path(tmp),LABELS,'api-code',cli,pg_target=CID)
  create=next(x for x in calls if x[:2]==['container','create'])
  self.assertIn('--network=container:'+CID,create)
  self.assertIn('--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777',create)
  self.assertIn('--user=65534:65534',create)
  self.assertFalse(any('unconfined' in x or x.startswith(('--cap-add','--mount','--privileged')) for x in create))

class ApiChargeTests(QuietTests):
 def test_pg_cleanup_failure_keeps_charge_and_still_removes_owned_image(self):
  import runtime_lab_docker as lab
  import tempfile
  from pathlib import Path
  image='sha256:'+'b'*64; outer='e'*64; objects={};image_exists=False;calls=[]
  def cli(args,**kw):
   nonlocal image_exists
   calls.append(args)
   if args[:2]==['image','import']:image_exists=True;return image
   if args[:2]==['image','inspect']:
    if args[-1]==api.PG_IMAGE:return json.dumps([{'Id':'sha256:'+'f'*64,'RepoDigests':[api.PG_IMAGE],'Size':432729433}])
    return json.dumps([{'Id':image,'Config':{'Labels':LABELS}}])
   if args[:2]==['image','rm']:image_exists=False;return ''
   if args[:2]==['image','ls']:return image if image_exists and '--all' in args else ''
   if args[:2]==['container','create']:
    cid=CID if 'role=postgres' in args else outer
    objects[cid]=True;return cid
   if args[:2]==['container','inspect']:
    if args[-1]==CID:return json.dumps([ApiTopologyTests().record()])
    return json.dumps([{'Id':outer,'Config':{'Labels':{**LABELS,'role':'outer'}}}])
   if args[:2]==['container','wait']:return '0'
   if args[:2]==['container','rm']:
    if args[-1]==CID:raise RuntimeError('owned PG remove failed')
    objects.pop(args[-1]);return ''
   if args[:2]==['container','ls']:
    selectors=[x for x in args if x.startswith('id=')]
    return ' '.join(cid for cid in objects if not selectors or selectors==['id='+cid])
   if args[:2] in (['container','start'],['container','stop'],['container','exec'],['container','logs']):return ''
   raise AssertionError(args)
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);out=base/'docker-test';out.mkdir(mode=0o700)
   with self.assertRaisesRegex(RuntimeError,'PostgreSQL cleanup failed'):lab.image_session(out/'archive',out,LABELS,'api-code',cli)
   self.assertEqual(lab.outstanding_bytes(base),5000000000)
   self.assertFalse(image_exists)
   self.assertEqual(set(objects),{CID})

class EgressPostgresTests(QuietTests):
 def test_bridge_is_internal_unpublished_and_removed(self):
  network='warden-pg-'+LABELS['session']
  exists=False
  nets=set()
  calls=[]
  def cli(args,**kw):
   nonlocal exists
   calls.append(args)
   if args[:2]==['image','inspect']:return json.dumps([{'Id':'sha256:'+'b'*64,'RepoDigests':[api.PG_IMAGE],'Size':432729433}])
   if args[:2]==['network','create']:nets.add(args[-1]);return args[-1]
   if args[:2]==['network','rm']:nets.discard(args[-1]);return args[-1]
   if args[:2]==['container','create']:exists=True;return CID
   if args[:2]==['container','inspect']:return json.dumps([{'Id':CID,'Config':{'Labels':{**LABELS,'role':'postgres'}},'NetworkSettings':{'Networks':{network:{'IPAddress':'10.44.0.2'}}}}])
   if args[:2]==['container','rm']:exists=False;return ''
   if args[:2]==['container','ls']:return CID if exists else ''
   if args[:2] in (['container','start'],['container','stop'],['container','exec']):return ''
   raise AssertionError(args)
  with api.postgres_bridge(LABELS,cli) as target:
   self.assertEqual(target,{'network':network,'ip':'10.44.0.2'})
   self.assertIn(network,nets)
  self.assertFalse(exists)
  self.assertEqual(nets,set())
  create=next(x for x in calls if x[:2]==['container','create'])
  self.assertIn('--network='+network,create)
  self.assertNotIn('--network=none',create)
  self.assertIn('--internal',next(x for x in calls if x[:2]==['network','create']))
  self.assertFalse(any(x=='-p' or x.startswith('--publish') for x in create))
  self.assertIn('listen_addresses=*',create)
  self.assertNotIn('listen_addresses=127.0.0.1',create)
 def test_bridge_cleanup_runs_when_the_caller_fails(self):
  nets=set()
  exists=False
  def cli(args,**kw):
   nonlocal exists
   if args[:2]==['image','inspect']:return json.dumps([{'Id':'sha256:'+'b'*64,'RepoDigests':[api.PG_IMAGE],'Size':432729433}])
   if args[:2]==['network','create']:nets.add(args[-1]);return args[-1]
   if args[:2]==['network','rm']:nets.discard(args[-1]);return ''
   if args[:2]==['container','create']:exists=True;return CID
   if args[:2]==['container','inspect']:return json.dumps([{'Id':CID,'Config':{'Labels':{**LABELS,'role':'postgres'}},'NetworkSettings':{'Networks':{'warden-pg-'+LABELS['session']:{'IPAddress':'10.44.0.2'}}}}])
   if args[:2]==['container','rm']:exists=False;return ''
   if args[:2]==['container','ls']:return CID if exists else ''
   if args[:2] in (['container','start'],['container','stop'],['container','exec']):return ''
   raise AssertionError(args)
  with self.assertRaisesRegex(RuntimeError,'outer failed'):
   with api.postgres_bridge(LABELS,cli):
    raise RuntimeError('outer failed')
  self.assertFalse(exists)
  self.assertEqual(nets,set())
 def test_bridge_rejects_a_non_hex_session_before_creating_anything(self):
  def cli(args,**kw):raise AssertionError(args)
  with self.assertRaises(ValueError):
   with api.postgres_bridge({**LABELS,'session':'test-session'},cli):
    pass
