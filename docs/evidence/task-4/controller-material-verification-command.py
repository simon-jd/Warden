"""Read-only narrow integrity verification, without rerunning product tests."""
from pathlib import Path
import hashlib
import json

root = Path('/home/postedism/Desktop/Warden')
folder = root / 'docs/evidence/task-4/recovery-material/05505bebb316a180c39e6e75f4a101e3c57224f1'
source = (folder / 'verify-command.py').read_text()
marker = "\npath = OUT / 'source-verification.json'"
assert source.count(marker) == 1
scope = {}
exec(compile(source.split(marker)[0], str(folder / 'verify-command.py'), 'exec'), scope)
result = scope['result']
index = json.loads((folder / 'evidence-index.json').read_bytes())
assert index['source'] == result['source'] == index['tested_source']
for name, item in index['files'].items():
    assert '/' not in name and name not in ('.', '..')
    raw = (folder / name).read_bytes()
    assert len(raw) == item['bytes']
    assert hashlib.sha256(raw).hexdigest() == item['sha256']
report = (root / '.superpowers/sdd/2-warden-security-plan/task-4-report.md').read_text()
assert '34PASS, exit0,0.111s' in report
assert (folder / 'python-tests.log').read_text().endswith('Ran 34 tests in 0.111s\n\nOK\n')
print(json.dumps({
    'source': result['source'],
    'source_paths': list(result['changed_files']),
    'changed_existing_functions': result['changed_existing_host_functions'],
    'added_functions': len(result['added_host_functions']),
    'unchanged_functions': len(result['unchanged_host_functions_AST']),
    'unchanged_bindings': len(result['unchanged_bindings']),
    'old_indexed_artifacts': sum(v['entries_verified'] for v in result['old_current_indexes'].values()),
    'new_indexed_artifacts': len(index['files']),
    'report_and_test_log_bound': True,
    'tests_or_actual_operations_rerun': False,
    'all_match': True,
}, indent=2))
