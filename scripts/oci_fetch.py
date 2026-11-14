#!/usr/bin/env python3
"""Fetch one linux/amd64 image from a registry into an OCI layout archive.

The k3s lab node has no route out and imports images with `ctr images
import`, so lab images are fetched here instead of through the host's Docker
daemon (nothing lands in, or has to be removed from, the shared image store).
The reference must carry a digest. The index (or single manifest) must hash to
it, and every blob must match the digest and size its manifest gives, before
anything is written. The archive names the image with its tag
(io.containerd.image.name), so pods use it with imagePullPolicy: Never.

    oci_fetch.py REGISTRY/REPO:TAG@sha256:DIGEST OUT.tar
"""
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from collections import namedtuple

INDEX_TYPES = ('application/vnd.oci.image.index.v1+json',
               'application/vnd.docker.distribution.manifest.list.v2+json')
MANIFEST_TYPES = ('application/vnd.oci.image.manifest.v1+json',
                  'application/vnd.docker.distribution.manifest.v2+json')
ACCEPT = ', '.join(INDEX_TYPES + MANIFEST_TYPES)
MAX_JSON = 4 << 20

Ref = namedtuple('Ref', 'host repo tag digest name')


def parse_ref(ref):
    m = re.fullmatch(r'([a-z0-9.-]+(?::[0-9]+)?)/([a-z0-9._/-]+):([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})', ref)
    if not m:
        raise ValueError('want REGISTRY/REPO:TAG@sha256:DIGEST, got %r' % ref)
    host, repo, tag, digest = m.groups()
    name = '%s/%s:%s' % (host, repo, tag)
    if host == 'docker.io':
        host = 'registry-1.docker.io'
    return Ref(host, repo, tag, digest, name)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class Client:
    def __init__(self, base, repo):
        self.base, self.repo, self.token = base, repo, None

    def _open(self, url, headers):
        try:
            return _opener.open(urllib.request.Request(url, headers=headers), timeout=60)
        except urllib.error.HTTPError as e:
            return e

    def _auth(self, challenge):
        m = re.match(r'Bearer (.*)', challenge or '')
        if not m:
            raise ValueError('registry wants unsupported auth: %r' % challenge)
        params = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        query = {k: params[k] for k in ('service', 'scope') if k in params}
        query.setdefault('scope', 'repository:%s:pull' % self.repo)
        with self._open(params['realm'] + '?' + urllib.parse.urlencode(query), {}) as r:
            if r.status != 200:
                raise ValueError('token request failed: HTTP %d' % r.status)
            body = json.load(r)
        self.token = body.get('token') or body.get('access_token')

    def get(self, kind, ref, accept=None):
        """GET /v2/<repo>/<kind>/<ref>; redirects are followed without the token."""
        url = '%s/v2/%s/%s/%s' % (self.base, self.repo, kind, ref)
        for _ in range(2):
            headers = {'Accept': accept} if accept else {}
            if self.token:
                headers['Authorization'] = 'Bearer ' + self.token
            r = self._open(url, headers)
            if r.status == 401 and not self.token:
                self._auth(r.headers.get('WWW-Authenticate'))
                r.close()
                continue
            break
        hops = 0
        while r.status in (301, 302, 303, 307, 308) and hops < 5:
            location = urllib.parse.urljoin(url, r.headers['Location'])
            r.close()
            r, hops = self._open(location, {}), hops + 1
        if r.status != 200:
            r.close()
            raise ValueError('GET %s %s: HTTP %d' % (kind, ref, r.status))
        return r


def _read_verified(resp, digest, size=None, limit=None):
    h, out, n = hashlib.sha256(), io.BytesIO(), 0
    with resp:
        while chunk := resp.read(1 << 20):
            n += len(chunk)
            if (size is not None and n > size) or (limit is not None and n > limit):
                raise ValueError('%s: more bytes than expected' % digest)
            h.update(chunk)
            out.write(chunk)
    if 'sha256:' + h.hexdigest() != digest or (size is not None and n != size):
        raise ValueError('%s: content does not match its digest or size' % digest)
    return out.getvalue()


def _add(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size, info.mode = len(data), 0o644
    tar.addfile(info, io.BytesIO(data))


def fetch(ref, out, registry_url=None, platform=('linux', 'amd64')):
    r = parse_ref(ref)
    c = Client(registry_url or 'https://' + r.host, r.repo)
    top = c.get('manifests', r.digest, ACCEPT)
    media = top.headers.get('Content-Type', '').split(';')[0]
    top_bytes = _read_verified(top, r.digest, limit=MAX_JSON)
    doc = json.loads(top_bytes)
    media = doc.get('mediaType', media)
    blobs = {}
    if media in INDEX_TYPES:
        picks = [m for m in doc['manifests']
                 if (m.get('platform', {}).get('os'), m.get('platform', {}).get('architecture')) == platform
                 and not m.get('platform', {}).get('variant')]
        if len(picks) != 1:
            raise ValueError('%s: %d manifests for %s/%s' % (ref, len(picks), *platform))
        desc = picks[0]
        manifest = _read_verified(c.get('manifests', desc['digest'], ACCEPT), desc['digest'], desc['size'])
        mdigest, mtype = desc['digest'], desc['mediaType']
    elif media in MANIFEST_TYPES:
        manifest, mdigest, mtype = top_bytes, r.digest, media
    else:
        raise ValueError('%s: unsupported media type %r' % (ref, media))
    blobs[mdigest] = manifest
    m = json.loads(manifest)
    for d in [m['config']] + m['layers']:
        blobs[d['digest']] = _read_verified(c.get('blobs', d['digest']), d['digest'], d['size'])
    index = {'schemaVersion': 2, 'manifests': [{
        'mediaType': mtype, 'digest': mdigest, 'size': len(manifest),
        'platform': {'os': platform[0], 'architecture': platform[1]},
        'annotations': {'io.containerd.image.name': r.name, 'org.opencontainers.image.ref.name': r.tag}}]}
    tmp = out + '.tmp'
    with tarfile.open(tmp, 'w') as tar:
        _add(tar, 'oci-layout', b'{"imageLayoutVersion":"1.0.0"}')
        _add(tar, 'index.json', json.dumps(index, sort_keys=True).encode())
        for digest in sorted(blobs):
            _add(tar, 'blobs/sha256/' + digest.split(':', 1)[1], blobs[digest])
    os.replace(tmp, out)
    return {'name': r.name, 'index_digest': r.digest, 'manifest_digest': mdigest,
            'blobs': {d: len(b) for d, b in sorted(blobs.items())}}


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__.strip().splitlines()[-1].strip())
    print(json.dumps(fetch(argv[0], argv[1]), sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1:])
