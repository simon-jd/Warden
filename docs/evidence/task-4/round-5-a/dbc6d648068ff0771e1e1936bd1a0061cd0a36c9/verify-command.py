"""Public source/evidence integrity only. Never inventories the private scene."""
import hashlib
import json
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = 'dbc6d648068ff0771e1e1936bd1a0061cd0a36c9'
PARENT = 'ef7fd7b83bd9d7989c4246f6be1137868b2f9984'
RUNTIME = '95fa55dc0ce97d3e1b99a255a84f80e96972c71f'
OUT = ROOT / 'docs/evidence/task-4/round-5-a' / SOURCE


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


manifest = json.loads((OUT / 'source-manifest.json').read_text())
for group in ('files', 'unchanged_runtime_interfaces_and_profiles'):
    for name, wanted in manifest[group].items():
        path = ROOT / name
        raw = path.read_bytes()
        assert digest(raw) == wanted['sha256'] and len(raw) == wanted['bytes'], name
        assert oct(stat.S_IMODE(path.stat().st_mode)) == wanted['mode'], name
        assert raw == git('show', SOURCE + ':' + name), name
        if group.startswith('unchanged'):
            assert raw == git('show', RUNTIME + ':' + name), name

records = git('ls-tree', '-r', '--full-tree', PARENT, 'docs/evidence/task-4').decode().splitlines()
indexes = []
for record in records:
    metadata, name = record.split('\t')
    mode, kind, blob = metadata.split()
    path = ROOT / name
    raw = path.read_bytes()
    assert raw == git('show', PARENT + ':' + name), name
    assert mode == ('100755' if path.stat().st_mode & 0o111 else '100644'), name
    if not name.endswith('index.json'):
        continue
    value = json.loads(raw)
    base = ROOT / 'docs/evidence/task-4' if '/55bd96828669c8e1536da321bcb87bae13afa6ea/' in name else path.parent
    for relative, wanted in value['files'].items():
        entry = base / relative
        assert entry.resolve().is_relative_to(ROOT / 'docs/evidence/task-4'), relative
        data = entry.read_bytes()
        assert digest(data) == wanted['sha256'] and len(data) == wanted['bytes'], relative
    indexes.append({'path': name, 'sha256': digest(raw), 'entries_verified': len(value['files'])})

result = {'source': SOURCE, 'source_parent': PARENT, 'original_runtime_source': RUNTIME,
          'source_files_verified': len(manifest['files']),
          'unchanged_runtime_interface_profile_files_verified': len(manifest['unchanged_runtime_interfaces_and_profiles']),
          'old_tracked_task4_files_byte_and_mode_identical': len(records),
          'old_indexes_verified': indexes, 'all_match': True,
          'ordinary_guard_run': False, 'private_scene_read': False, 'docker_run': False}
path = OUT / 'old-evidence-verification.json'
path.write_text(json.dumps(result, indent=2) + '\n'); path.chmod(0o644)
print(json.dumps(result, indent=2))
