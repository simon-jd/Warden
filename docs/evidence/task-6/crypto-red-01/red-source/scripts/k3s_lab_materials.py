"""Pinned official inputs; inspect archives in memory, never extract their links."""
import hashlib
import io
from pathlib import PurePosixPath
import posixpath
import re
import tarfile
from compression import zstd

PINS = {
    'k3s': {
        'version': 'v1.36.5+k3s1', 'bytes': 79077538,
        'sha256': 'd73847bcd3c5fccef0115b372e2f9a91f3032dc84bbf71518a4617565294d313',
        'url': 'https://github.com/k3s-io/k3s/releases/download/v1.36.5%2Bk3s1/k3s',
    },
    'gvisor.tar.bz2': {
        'version': 'release-20261019.0', 'bytes': 73621897,
        'sha256': '1298e8ed9c3fee900f00d2ea96ec2d79d80ed93f2175812f29b7e7da718041a3',
        'url': 'https://github.com/google/gvisor/releases/download/release-20261019.0/gvisor-x86_64.tar.bz2',
    },
}
EXPANDED_LIMIT = 900000000


def verify(data, pin):
    if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise ValueError('official input size or SHA256 mismatch')
    return data


def _name(name):
    if name.startswith('./'):
        name = name[2:]
    name = name.rstrip('/')
    if (not name or name.startswith('/') or '\\' in name or '\x00' in name
            or any(p in ('', '.', '..') for p in name.split('/'))):
        raise ValueError('unsafe archive path')
    return name


def regular_files(data, limit=EXPANDED_LIMIT):
    files, names, links = {}, set(), {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tar:
        for member in tar:
            name = _name(member.name)
            if name in names:
                raise ValueError('duplicate archive path')
            names.add(name)
            if member.isdir():
                continue
            if member.issym():
                target = member.linkname
                if target.startswith('/') or '\\' in target or '\x00' in target:
                    raise ValueError('unsafe archive alias')
                links[name] = _name(posixpath.normpath(str(PurePosixPath(name).parent / target)))
                continue
            if not member.isfile() or member.mode & 0o7000:
                raise ValueError('archive device, hardlink or privileged mode')
            total += member.size
            if total > limit or member.size < 0:
                raise ValueError('expanded material budget exceeded')
            files[name] = tar.extractfile(member).read()
    if any(target not in files for target in links.values()):
        raise ValueError('alias must reference a regular member directly')
    # Aliases are validated but deliberately never installed. The packager
    # copies only explicitly needed binaries under fixed names.
    return files


def embedded_k3s(binary):
    """Recover the hash-named embedded zstd asset without executing k3s."""
    hashes = set(re.findall(rb'([0-9a-f]{64})\.tar\.zst', binary))
    for match in re.finditer(re.escape(b'\x28\xb5\x2f\xfd'), binary):
        compressed = binary[match.start():]
        decoder = zstd.ZstdDecompressor()
        try:
            raw = decoder.decompress(compressed, EXPANDED_LIMIT + 1)
        except zstd.ZstdError:
            continue
        if not decoder.eof or len(raw) > EXPANDED_LIMIT:
            continue
        frame = compressed[:len(compressed) - len(decoder.unused_data)]
        if hashlib.sha256(frame).hexdigest().encode() in hashes:
            return regular_files(raw)
    raise ValueError('verified hash-named k3s payload not found')
