"""Pinned Ubuntu shell closure for the dedicated Task 5 matrix image."""
from pathlib import Path
import hashlib
import os
import stat

INPUTS = {
    'bin/sh': ('/usr/bin/dash', 129856, 'c626229526bb58ec2d0f585f3c3ae1412e6f973b4353385042d11c38d8426917'),
    'lib/x86_64-linux-gnu/libc.so.6': ('/usr/lib/x86_64-linux-gnu/libc.so.6', 2190608, '9941dc28e68bc5fd788d9cd024c69e68c791d63799e7538a97b6040dd9f50fb6'),
    'lib64/ld-linux-x86-64.so.2': ('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2', 254864, 'c0b20d6e1ced12abfe0b1ef2b5b68017950beaaea3df69eb6949d73e0ecf7b40'),
    'usr/share/doc/warden-corpus/dash-copyright': ('/usr/share/doc/dash/copyright', 3878, 'd98c53f281321baad38164aa9ae6e368a9253be6ec51bd26a759b5e72b326f4a'),
    'usr/share/doc/warden-corpus/libc6-copyright': ('/usr/share/doc/libc6/copyright', 53241, 'c31d10900fdb95d1889005145a2205bb75e3bc018d3ec8265b81364901748e09'),
}

def checked(path, size=None, digest=None):
    path = Path(path)
    st = path.stat(follow_symlinks=True)
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.getuid()) or st.st_mode & 0o022:
        raise ValueError(f'unsafe fixed shell material: {path}')
    data = path.read_bytes()
    if size is not None and (len(data) != size or hashlib.sha256(data).hexdigest() != digest):
        raise ValueError(f'fixed shell material changed: {path}')
    return data

def payload_files(root, helper=None):
    root = Path(root)
    helper = Path(helper) if helper else root / '.cache/warden-lab/warden-attack'
    files = {name: checked(path, size, digest) for name, (path, size, digest) in INPUTS.items()}
    files['warden-attack'] = checked(helper)
    if len(files['warden-attack']) > 16 << 20:
        raise ValueError('attack helper exceeds 16 MiB')
    return files
