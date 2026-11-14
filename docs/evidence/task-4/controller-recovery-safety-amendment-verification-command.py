"""Narrow controller provenance check; no tests, old-file crawl or live access."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = '8c8e9edf4a269effb155ae027b703cd9dc770836'
EVIDENCE = 'a08e22bd05aa31737825b5588fff39ce06d98676'
PARENT = 'ed65c4757a23678a0845d4184c32d1ab0f179d78'
A_SOURCE = 'dbc6d648068ff0771e1e1936bd1a0061cd0a36c9'
FOLDER = ROOT / 'docs/evidence/task-4/recovery-safety-amendment' / SOURCE


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


assert git('rev-parse', SOURCE + '^').decode().strip() == PARENT
assert git('rev-parse', EVIDENCE + '^').decode().strip() == SOURCE
m = json.loads((FOLDER / 'source-verification.json').read_text())
assert git('diff', '--name-only', PARENT, SOURCE).decode().splitlines() == sorted(m['changed_files'])
for name, wanted in m['changed_files'].items():
    path = ROOT / name
    raw = path.read_bytes()
    assert len(raw) == wanted['bytes'] and sha(raw) == wanted['sha256'], name
    assert stat.S_IMODE(path.stat().st_mode) == int(wanted['mode'], 8), name
    assert raw == git('show', SOURCE + ':' + name), name
for name, wanted in m['unchanged_source_bindings'].items():
    raw = (ROOT / name).read_bytes()
    assert len(raw) == wanted['bytes'] and sha(raw) == wanted['sha256'], name
    assert raw == git('show', A_SOURCE + ':' + name) == git('show', SOURCE + ':' + name), name
changed = set(m['host_functions_changed_or_added'])
host = 'scripts/firecracker_recovery.py'
def fixed(raw):
    return [ast.dump(n) for n in ast.parse(raw).body if not isinstance(n, ast.FunctionDef) or n.name not in changed]
assert fixed(git('show', PARENT + ':' + host)) == fixed((ROOT / host).read_bytes())
index = json.loads((FOLDER / 'evidence-index.json').read_text())
for name, wanted in index['files'].items():
    path = FOLDER / name
    raw = path.read_bytes()
    assert sha(raw) == wanted['sha256'] and len(raw) == wanted['bytes'], name
    assert stat.S_IMODE(path.stat().st_mode) == 0o644, name
    assert raw == git('show', EVIDENCE + ':' + str(path.relative_to(ROOT))), name
assert (FOLDER / 'evidence-index.json').read_bytes() == git('show', EVIDENCE + ':' + str((FOLDER / 'evidence-index.json').relative_to(ROOT)))
old = ROOT / 'docs/evidence/task-4/round-5-a' / A_SOURCE
assert (old / 'evidence-index.json').read_bytes() == git('show', PARENT + ':' + str((old / 'evidence-index.json').relative_to(ROOT)))
for name, wanted in json.loads((old / 'evidence-index.json').read_text())['files'].items():
    raw = (old / name).read_bytes()
    assert len(raw) == wanted['bytes'] and sha(raw) == wanted['sha256'], name
report = (ROOT / '.superpowers/sdd/2-warden-security-plan/task-4-report.md').read_text()
section = report[report.index('# Necessary recovery safety amendment — pending-operation settlement'):]
body = '\n\n'.join(p for p in section.split('\n\n') if not p.startswith(('Evidence directory: ', 'Frozen necessary-recovery safety amendment: ')))
assert body.strip() == (FOLDER / 'README.md').read_text().strip()
assert 'FAILED (failures=10)' in (FOLDER / 'history-pending-red.log').read_text()
green = (FOLDER / 'history-state-green.log').read_text()
assert green.count(' ... ok\n') == 4 and '\nOK\n' in green
cover = (FOLDER / 'python-tests.log').read_text()
assert cover.count(' ... ok\n') == 19 and 'Ran 19 tests in 0.065s\n\nOK\n' in cover
result = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'source': SOURCE, 'evidence': EVIDENCE, 'source_parent': PARENT,
          'changed_paths': list(m['changed_files']), 'unchanged_bindings': len(m['unchanged_source_bindings']),
          'unchanged_host_functions_AST': len(m['other_host_functions_AST_identical']),
          'other_top_level_AST_unchanged': True, 'old_A_indexed_files': 27,
          'new_indexed_files': len(index['files']), 'recorded_RED_failures': 10,
          'recorded_focused_PASS': 4, 'recorded_host_covering_PASS': 19,
          'report_body_matches': True, 'all_match': True,
          'tests_rerun': False, 'old_176_file_crawl_repeated': False,
          'ordinary_guard_run': False, 'private_scene_read': False, 'Docker_operation': False,
          'original_Q_released': False, 'original_Q_bytes': 5000000000, 'actual_recovery': 'not_executed'}
out = ROOT / 'docs/evidence/task-4/controller-recovery-safety-amendment-verification.json'
with os.fdopen(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), 'w') as stream:
    stream.write(json.dumps(result, indent=2) + '\n'); stream.flush(); os.fsync(stream.fileno())
print(json.dumps(result, sort_keys=True))
