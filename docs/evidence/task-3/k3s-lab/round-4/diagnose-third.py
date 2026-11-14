import base64, collections, hashlib, http.client, io, json, os, re, socket, stat, sys, tarfile, urllib.parse
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[5] / "scripts"))
import k3s_lab_init as init
CID='57a48b46ee5477bf65fdb6ae60bf5b7766c652630c7f2549b3e1e013a696c360'
IMAGE='sha256:53914c90accfbe8f1e11b530a7ae42edc9d1a79e098a01d50d14f244b5991514'
LABELS={'owner':'codex-warden','project':'warden','session':'454fc203bfa3b1bb6296520028e6a1cd','ttl':'2026-10-24T18:35:22Z'}
OUTER='/home/postedism/Desktop/Warden/.cache/warden-lab/docker-'+LABELS['session']
CHILD='session-365b23ee00074b56'
PREFIX='/session/'+CHILD
class Local(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); self.sock.settimeout(15); self.sock.connect('/var/run/docker.sock')
def request(method,path,limit):
 c=Local('localhost'); c.request(method,path); r=c.getresponse(); status=r.status; headers=dict(r.getheaders()); body=r.read(limit+1); c.close()
 if len(body)>limit: raise ValueError('response-bound')
 return status,headers,body
def archivepath(path):return '/containers/'+CID+'/archive?path='+urllib.parse.quote(path,safe='')
def verify():
 s,h,b=request('GET','/containers/'+CID+'/json',262144)
 if s!=200: raise ValueError('inspect-status')
 d=json.loads(b); state=d['State']
 if not (d['Id']==CID and d['Image']==IMAGE and d['Config']['Labels']==LABELS and state['Status']=='exited' and state['Pid']==0 and not any(state[k] for k in ('Running','Paused','Restarting','OOMKilled','Dead')) and d['RestartCount']==0 and state['ExitCode']==2): raise ValueError('scene-drift')
 o=os.stat(OUTER,follow_symlinks=False); ch=os.stat(OUTER+'/'+CHILD,follow_symlinks=False)
 if not (stat.S_ISDIR(o.st_mode) and stat.S_IMODE(o.st_mode)==0o700 and (o.st_dev,o.st_ino,o.st_uid)==(66307,56011098,1000) and stat.S_ISDIR(ch.st_mode) and stat.S_IMODE(ch.st_mode)==0o700 and (ch.st_dev,ch.st_ino,ch.st_uid)==(66307,56011150,0)):raise ValueError('anchor-drift')
 return {'exact_stopped_identity':True,'outer_identity':True,'private_child_identity':True,'scope_absent':not os.path.lexists('/sys/fs/cgroup/system.slice/docker-'+CID+'.scope')}
def head(name):
 s,h,b=request('HEAD',archivepath(PREFIX+'/'+name),0)
 if s==404:return {'status':404}
 if s!=200:raise ValueError('head-status')
 v=json.loads(base64.b64decode(h['X-Docker-Container-Path-Stat']))
 if v['name']!=name or v.get('linkTarget'):raise ValueError('head-alias')
 return {'status':200,'bytes':v['size'],'mode':v['mode']}
def read(path,name,remaining):
 s,h,b=request('GET',archivepath(path),remaining+65536)
 if s==404:return None
 if s!=200:raise ValueError('archive-status')
 with tarfile.open(fileobj=io.BytesIO(b),mode='r:') as t:
  m=t.getmembers()
  if len(m)!=1 or not m[0].isreg() or m[0].name!=name or m[0].linkname or m[0].pax_headers or not 0<=m[0].size<=remaining:raise ValueError('archive-member')
  data=t.extractfile(m[0]).read(remaining+1)
  if len(data)!=m[0].size:raise ValueError('archive-size')
 return data
def classify(data):
 lines=data.decode('utf-8').splitlines();source=None;records=[]
 # Template matching only: these historical times and namespace names are
 # synthetic inputs. This failed scene has no actual Ready/namespace proof.
 start=int(datetime(2026,10,24,17,35,43,tzinfo=timezone.utc).timestamp())
 known_shutdown={
  'Shutdown request received: "kubelet exited: failed to run Kubelet: running with swap on is not supported, please disable swap or set --fail-swap-on flag to false"':'rejected-swap-shutdown',
  'Failed to migrate node-password secrets: context canceled':'rejected-shutdown-cancellation',
 }
 for line in lines:
  if line=='--- k3s ---':source='k3s';continue
  if line=='--- containerd ---':source='containerd';continue
  if not re.search(r'level=(warning|error|fatal)|[WEF]\d{4}\s',line):continue
  enum=None
  for fd in range(3,30):
   try:
    result=init.warning_lines(line,source=source,root=f'/proc/1/fd/{fd}/root',ready_window=(start,start+7),verified_namespaces=frozenset({'default','kube-system'}))
    if result:enum=result[0]['template'] if isinstance(result[0],dict) else 'safe-kernel-denial'
    break
   except ValueError:pass
  if enum is None:
   # JSON decoding is only in bounded memory and values never leave it.
   match=re.fullmatch(r'time="[^"\n]+" level=error msg=("(?:[^"\\]|\\.)*")',line)
   enum=known_shutdown.get(json.loads(match[1]),'rejected-unknown') if match else 'rejected-unknown'
  records.append({'template_enum':enum,'source':source,'sha256':hashlib.sha256(line.encode()).hexdigest()})
 return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'lines':len(lines),
         'template_counts':dict(collections.Counter(x['template_enum'] for x in records)),
         'records':records,'context':'synthetic-classification-only','ready_proven':False}
def main():
 result={'before':verify(),'head':{k:head(k) for k in ('root','state','io','containerd.toml','containerd.log','startup-private.log')}}
 remaining=32000000; logs={}
 for enum,path,name in [('snapshot',PREFIX+'/startup-private.log','startup-private.log'),('k3s',PREFIX+'/root/private.log','private.log'),('containerd',PREFIX+'/root/agent/containerd/containerd.log','containerd.log')]:
  data=read(path,name,remaining)
  if data is None:logs[enum]={'status':404}
  else:remaining-=len(data);logs[enum]=classify(data)
 result['logs']=logs;result['remaining_content_budget']=remaining;result['after']=verify()
 print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':
 try:main()
 except BaseException as e:print(json.dumps({'diagnostic_error':type(e).__name__}));raise SystemExit(2)
