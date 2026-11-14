#!/usr/bin/env python3
"""Build fixed OCI matrix image from pinned host shell and local Go attack helper."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
from corpus_image import payload_files
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'.cache/warden-lab'
def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def add(t,name,data,mode):
 h=tarfile.TarInfo(name);h.mode=mode;h.size=len(data);t.addfile(h,io.BytesIO(data))
def main():
 files=payload_files(ROOT)
 files['warden-probe']=(OUT/'warden-probe').read_bytes()
 files['write-probe']=b''
 layer=io.BytesIO()
 with tarfile.open(fileobj=layer,mode='w',format=tarfile.USTAR_FORMAT) as t:
  for name in ('bin','lib','lib/x86_64-linux-gnu','lib64','usr','usr/share','usr/share/doc','usr/share/doc/warden-corpus','proc','dev','dev/pts','dev/shm','sys'):
   h=tarfile.TarInfo(name);h.type=tarfile.DIRTYPE;h.mode=0o755;t.addfile(h)
  for name,data in sorted(files.items()):add(t,name,data,0o444 if name.endswith('copyright') else 0o666 if name=='write-probe' else 0o555)
 raw=layer.getvalue();ld=hashlib.sha256(raw).hexdigest()
 config=encode({'architecture':'amd64','os':'linux','config':{'User':'65534:65534','Entrypoint':['/warden-probe']},'rootfs':{'type':'layers','diff_ids':['sha256:'+ld]}});cd=hashlib.sha256(config).hexdigest()
 manifest=encode({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':'sha256:'+cd,'size':len(config)},'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+ld,'size':len(raw)}]});md=hashlib.sha256(manifest).hexdigest()
 name='warden-lab/corpus:matrix'
 index=encode({'schemaVersion':2,'manifests':[{'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':'sha256:'+md,'size':len(manifest),'platform':{'architecture':'amd64','os':'linux'},'annotations':{'org.opencontainers.image.ref.name':name}}]})
 with tarfile.open(OUT/'corpus.oci.tar','w') as t:
  add(t,'oci-layout',b'{"imageLayoutVersion":"1.0.0"}',0o644);add(t,'index.json',index,0o644)
  for digest,data in ((ld,raw),(cd,config),(md,manifest)):add(t,'blobs/sha256/'+digest,data,0o644)
 (OUT/'corpus-image-digest').write_text('sha256:'+md+'\n')
 (OUT/'corpus-image-name').write_text(name+'\n')
 print(name+'@sha256:'+md)
if __name__=='__main__':main()
