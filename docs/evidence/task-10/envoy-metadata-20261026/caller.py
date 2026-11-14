import resource
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
resource.setrlimit(resource.RLIMIT_CPU,(15,15))
import os, sys, json, hashlib, time, signal, urllib.request, urllib.error
START=time.monotonic()
ROOT='/home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task10-envoy-metadata-20261026'
CAP=1048576
used=0
records=[]
status='FAILED'
error=None
summary={}
def alarm(signum, frame):
    raise TimeoutError('single operation deadline reached')
signal.signal(signal.SIGALRM, alarm)
signal.alarm(55)
def save(name, data):
    fd=os.open(os.path.join(ROOT,name),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(data)
def digest(data):
    return 'sha256:'+hashlib.sha256(data).hexdigest()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('redirect rejected; no alternate endpoint permitted')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def fetch(label,url,accept=None,token=None):
    global used
    if not url.startswith(('https://auth.docker.io/','https://registry-1.docker.io/')):
        raise RuntimeError('endpoint not authorized')
    req=urllib.request.Request(url,headers={'User-Agent':'warden-public-metadata/1'})
    if accept: req.add_header('Accept',accept)
    if token: req.add_header('Authorization','Bearer '+token)
    remain=55-(time.monotonic()-START)
    if remain<=0: raise TimeoutError('operation deadline')
    try:
        response=opener.open(req,timeout=min(12,remain))
    except urllib.error.HTTPError as e:
        response=e
    with response:
        length=response.headers.get('Content-Length')
        expected=int(length) if length is not None else None
        if expected is not None and (expected<0 or expected>CAP-used):
            raise RuntimeError(label+': Content-Length exceeds aggregate allowance')
        chunks=[]
        received=0
        while True:
            allowance=CAP-used
            if allowance<=0:
                if expected is not None and received==expected: break
                raise RuntimeError(label+': aggregate response cap reached')
            part=response.read(min(65536,allowance))
            if not part: break
            used+=len(part)
            received+=len(part)
            chunks.append(part)
        raw=b''.join(chunks)
        record={'label':label,'status':response.status,'bytes':len(raw),'sha256':digest(raw),'content_type':response.headers.get('Content-Type'),'content_length':length,'docker_content_digest':response.headers.get('Docker-Content-Digest')}
        records.append(record)
        if label!='auth': save(label+'.json',raw)
        if expected is not None and len(raw)!=expected: raise RuntimeError(label+': response length mismatch')
        if response.status!=200: raise RuntimeError(label+': HTTP '+str(response.status))
        if label!='auth' and record['docker_content_digest'] and record['docker_content_digest']!=digest(raw):
            raise RuntimeError(label+': Docker-Content-Digest mismatch')
        return raw
try:
    auth=fetch('auth','https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Aenvoyproxy%2Fenvoy%3Apull')
    auth_data=json.loads(auth)
    token=auth_data.get('token') or auth_data.get('access_token')
    if not isinstance(token,str) or not token: raise RuntimeError('public auth returned no bearer')
    del auth,auth_data
    base='https://registry-1.docker.io/v2/envoyproxy/envoy/'
    accepts='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
    raw_index=fetch('index',base+'manifests/v1.40.1',accepts,token)
    index=json.loads(raw_index)
    candidates=[m for m in index.get('manifests',[]) if m.get('platform',{}).get('os')=='linux' and m.get('platform',{}).get('architecture')=='amd64' and m.get('annotations',{}).get('vnd.docker.reference.type')!='attestation-manifest']
    if len(candidates)!=1: raise RuntimeError('expected exactly one Linux amd64 non-attestation descriptor')
    selected=candidates[0]
    md=selected.get('digest','')
    if len(md)!=71 or not md.startswith('sha256:') or any(c not in '0123456789abcdef' for c in md[7:]): raise RuntimeError('invalid manifest digest')
    raw_manifest=fetch('manifest',base+'manifests/'+md,'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json',token)
    if digest(raw_manifest)!=md or len(raw_manifest)!=selected.get('size'): raise RuntimeError('selected manifest digest/length mismatch')
    manifest=json.loads(raw_manifest)
    cfg=manifest['config']; cd=cfg.get('digest','')
    if len(cd)!=71 or not cd.startswith('sha256:') or any(c not in '0123456789abcdef' for c in cd[7:]): raise RuntimeError('invalid config digest')
    raw_config=fetch('config',base+'blobs/'+cd,None,token)
    del token
    if digest(raw_config)!=cd or len(raw_config)!=cfg.get('size'): raise RuntimeError('config digest/length mismatch')
    config=json.loads(raw_config)
    if config.get('os')!='linux' or config.get('architecture')!='amd64': raise RuntimeError('config platform mismatch')
    layers=[]
    for n,layer in enumerate(manifest.get('layers',[])):
        size=layer.get('size')
        if not isinstance(size,int) or size<0: raise RuntimeError('invalid compressed layer length')
        layers.append({'index':n,'digest':layer.get('digest'),'compressed_bytes':size,'media_type':layer.get('mediaType')})
    cc=config.get('config',{})
    labels=cc.get('Labels') or {}
    summary={'candidate':'docker.io/envoyproxy/envoy:v1.40.1','index_digest':digest(raw_index),'manifest_digest':md,'config_digest':cd,'platform':{'os':config.get('os'),'architecture':config.get('architecture')},'layers':layers,'compressed_layer_sum':sum(l['compressed_bytes'] for l in layers),'config_user':cc.get('User',''),'exposed_ports':cc.get('ExposedPorts',{}),'entrypoint':cc.get('Entrypoint'),'cmd':cc.get('Cmd'),'version_labels':{k:v for k,v in labels.items() if any(x in k.lower() for x in ('version','revision','created','source'))},'unpacked_expansion':'UNKNOWN','daemon_overhead':'UNKNOWN','runtime_filters_and_actual_uid':'UNVERIFIED; metadata only'}
    status='COMPLETE'
except Exception as exc:
    error=type(exc).__name__+': '+str(exc)
finally:
    signal.alarm(0)
    receipt={'status':status,'error':error,'aggregate_fetched_response_bytes_including_auth':used,'response_records':records,'summary':summary,'elapsed_seconds':round(time.monotonic()-START,6),'bounds':{'wall_seconds':60,'alarm_seconds':55,'address_space_bytes':268435456,'cpu_seconds':15,'response_bytes':1048576,'allocated_bytes':1572864},'no_layers_fetched':True,'no_execution_or_next_admission':True}
    save('receipt.json',(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode())
    note=('Task10 single public metadata operation: '+status+'\n'+('Failure: '+error+'\n' if error else '')+'Only official registry index, selected Linux amd64 manifest and config requested; public bearer was memory-only and never retained. No layer transfer, pull, image inspection/execution, source/index edits or next admission. Digest/length checks and declared metadata are in receipt.json. Unpacked expansion, daemon overhead, actual filter availability and runtime UID remain unverified. Trusted Cilium/runc network attachment, tenant/run identity enforcement and real bypass/cleanup acceptance remain OPEN. Prior Task10 proposal is unchanged.\n')
    if len(note.encode())>8192: raise RuntimeError('note cap')
    save('note.md',note.encode())
    allocation=sum(os.lstat(os.path.join(ROOT,n)).st_blocks*512 for n in os.listdir(ROOT))+os.lstat(ROOT).st_blocks*512
    if allocation>1572864: raise RuntimeError('allocated artifact cap exceeded')
    print(json.dumps({'status':status,'error':error,'elapsed_seconds':receipt['elapsed_seconds'],'aggregate_response_bytes':used,'allocated_bytes':allocation,'artifact':ROOT,'receipt_sha256':digest(open(os.path.join(ROOT,'receipt.json'),'rb').read()),'summary':summary},sort_keys=True))
    sys.exit(0 if status=='COMPLETE' else 1)
