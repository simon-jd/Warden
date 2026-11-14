#!/usr/bin/env python3
"""Create a small, deterministic OCI archive without a Docker daemon."""
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / '.cache' / 'warden-lab'

def blob(data):
    return hashlib.sha256(data).hexdigest(), data

def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()

def add(tar, name, data, mode=0o644):
    item = tarfile.TarInfo(name)
    item.size = len(data)
    item.mode = mode
    tar.addfile(item, io.BytesIO(data))

def main():
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for directory in ['proc', 'dev', 'dev/pts', 'dev/shm', 'sys']:
            item = tarfile.TarInfo(directory)
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(item)
        add(tar, 'warden-probe', (OUT / 'warden-probe').read_bytes(), 0o555)
        add(tar, 'write-probe', b'', 0o666)
    layer_digest, layer_bytes = blob(layer.getvalue())
    config_digest, config = blob(encode({'architecture': 'amd64', 'os': 'linux', 'config': {'User': '65534:65534', 'Entrypoint': ['/warden-probe']}, 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + layer_digest]}}))
    manifest_digest, manifest = blob(encode({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': 'sha256:' + config_digest, 'size': len(config)}, 'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'digest': 'sha256:' + layer_digest, 'size': len(layer_bytes)}]}))
    name = 'warden-lab/probe:conformance'
    index = encode({'schemaVersion': 2, 'manifests': [{'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': 'sha256:' + manifest_digest, 'size': len(manifest), 'platform': {'architecture': 'amd64', 'os': 'linux'}, 'annotations': {'org.opencontainers.image.ref.name': name}}]})
    with tarfile.open(OUT / 'probe.oci.tar', 'w') as tar:
        add(tar, 'oci-layout', b'{"imageLayoutVersion":"1.0.0"}')
        add(tar, 'index.json', index)
        for digest, data in [(layer_digest, layer_bytes), (config_digest, config), (manifest_digest, manifest)]:
            add(tar, 'blobs/sha256/' + digest, data)
    (OUT / 'image-digest').write_text('sha256:' + manifest_digest + '\n')
    (OUT / 'image-name').write_text(name + '\n')
    print('OCI image ' + name + '@sha256:' + manifest_digest)

if __name__ == '__main__':
    main()
