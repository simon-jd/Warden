"""Controller integrity checks only; no tests, Docker, or private scene reads."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = 'dbc6d648068ff0771e1e1936bd1a0061cd0a36c9'
EVIDENCE = '3b1c3f466ec13bc671acba7656362568d1d81550'
PARENT = 'ef7fd7b83bd9d7989c4246f6be1137868b2f9984'
RUNTIME = '95fa55dc0ce97d3e1b99a255a84f80e96972c71f'
FOLDER = ROOT / 'docs/evidence/task-4/round-5-a' / SOURCE


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


assert git('rev-parse', SOURCE + '^').decode().strip() == PARENT
assert git('rev-parse', EVIDENCE + '^').decode().strip() == SOURCE
manifest = json.loads((FOLDER / 'source-manifest.json').read_text())
assert manifest['source'] == SOURCE and manifest['runtime_source'] == RUNTIME
for group in ('files', 'unchanged_runtime_interfaces_and_profiles'):
    for name, wanted in manifest[group].items():
        path = ROOT / name
        raw = path.read_bytes()
        assert sha(raw) == wanted['sha256'] and len(raw) == wanted['bytes'], name
        assert oct(stat.S_IMODE(path.stat().st_mode)) == wanted['mode'], name
        assert raw == git('show', SOURCE + ':' + name), name
        if group.startswith('unchanged'):
            assert raw == git('show', RUNTIME + ':' + name), name

old = git('ls-tree', '-r', PARENT, 'docs/evidence/task-4').decode().splitlines()
old_permissions = {}
index_count = referenced = 0
for item in old:
    metadata, name = item.split('\t')
    raw = (ROOT / name).read_bytes()
    assert raw == git('show', PARENT + ':' + name), name
    permission = stat.S_IMODE((ROOT / name).stat().st_mode)
    old_permissions[oct(permission)] = old_permissions.get(oct(permission), 0) + 1
    assert metadata.split()[0] == ('100755' if permission & 0o111 else '100644'), name
    if not name.endswith('index.json'):
        continue
    index_count += 1
    value = json.loads(raw)
    base = ROOT / 'docs/evidence/task-4' if '/55bd96828669c8e1536da321bcb87bae13afa6ea/' in name else (ROOT / name).parent
    for relative, wanted in value['files'].items():
        path = base / relative
        assert path.resolve().is_relative_to(ROOT / 'docs/evidence/task-4')
        data = path.read_bytes()
        assert len(data) == wanted['bytes'] and sha(data) == wanted['sha256'], str(path)
        referenced += 1

index = json.loads((FOLDER / 'evidence-index.json').read_text())
for name, wanted in index['files'].items():
    path = FOLDER / name
    raw = path.read_bytes()
    assert len(raw) == wanted['bytes'] and sha(raw) == wanted['sha256'], name
    assert stat.S_IMODE(path.stat().st_mode) == 0o644, name
    assert raw == git('show', EVIDENCE + ':' + str(path.relative_to(ROOT))), name
assert (FOLDER / 'evidence-index.json').read_bytes() == git('show', EVIDENCE + ':' + str((FOLDER / 'evidence-index.json').relative_to(ROOT)))
report = (ROOT / '.superpowers/sdd/2-warden-security-plan/task-4-report.md').read_text()
section = report[report.index('# Task4 fix round5/5 — A implementation handoff'):]
paragraphs = [p for p in section.split('\n\n') if not p.startswith(('Evidence directory: ', 'Frozen A handoff: '))]
assert (FOLDER / 'README.md').read_text().strip() == '\n\n'.join(paragraphs).strip()
test_log = (FOLDER / 'python-tests.log').read_text()
assert test_log.count(' ... ok\n') == 25 and '\nRan 25 tests in 0.056s\n\nOK\n' in test_log

result = {
    'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'source': SOURCE, 'evidence': EVIDENCE, 'runtime_source_unchanged': RUNTIME,
    'source_files': len(manifest['files']),
    'unchanged_interface_profile_files': len(manifest['unchanged_runtime_interfaces_and_profiles']),
    'old_evidence_files': len(old), 'old_indexes': index_count,
    'old_evidence_mode_check': 'Git executable-bit mode; full historical Unix permissions not reconstructed from Git',
    'observed_old_evidence_permissions': old_permissions,
    'old_index_references': referenced, 'new_indexed_files': len(index['files']),
    'recorded_native_tests_pass': 25, 'tests_rerun': False,
    'readme_body_matches_report_except_two_explicit_provenance_paragraphs': True, 'all_match': True,
    'ordinary_guard_run': False, 'private_scene_read': False, 'docker_operation': False,
    'original_q_bytes': 5000000000, 'original_q_released': False,
    'actual_recovery': 'not_executed', 'task4_acceptance': 'open',
}
out = ROOT / 'docs/evidence/task-4/controller-round-5-a-verification.json'
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
with os.fdopen(fd, 'w') as stream:
    stream.write(json.dumps(result, indent=2) + '\n')
    stream.flush()
    os.fsync(stream.fileno())
print(json.dumps(result, sort_keys=True))
