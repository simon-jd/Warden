"""I9-only source/fixture binding and immediate prior material index verification."""
import ast
import hashlib
import json
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = 'ba8cfaf6bffd7996f54bd50db9ccf453ff121022'
PARENT = 'ebd7496eb50d734cd9f137cbebea3036796cbc73'
FIX_BASE = '36c5856285c3b8b450b72004919e2d45e3bc5edc'
PRIOR = '05505bebb316a180c39e6e75f4a101e3c57224f1'
OUT = ROOT / 'docs/evidence/task-4/recovery-enumeration' / SOURCE
ALLOWED = ['docs/firecracker-recovery.md', 'scripts/firecracker_recovery.py',
           'scripts/test_firecracker_recovery.py']


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


assert git('rev-parse', SOURCE + '^').decode().strip() == PARENT
assert git('diff', '--name-only', PARENT, SOURCE).decode().splitlines() == ALLOWED
files = {}
for name in ALLOWED:
    path = ROOT / name; raw = path.read_bytes()
    assert raw == git('show', SOURCE + ':' + name)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    files[name] = {'sha256': digest(raw), 'bytes': len(raw), 'mode': '0644'}

host = 'scripts/firecracker_recovery.py'
before = ast.parse(git('show', PARENT + ':' + host))
after = ast.parse((ROOT / host).read_bytes())
fixed_before = [n for n in before.body if not isinstance(n, ast.FunctionDef) or n.name != 'select_stdlib']
fixed_after = [n for n in after.body if not isinstance(n, ast.FunctionDef) or n.name != 'select_stdlib']
assert [ast.dump(n) for n in fixed_before] == [ast.dump(n) for n in fixed_after]
unchanged_functions = [n.name for n in fixed_after if isinstance(n, ast.FunctionDef)]

test = 'scripts/test_firecracker_recovery.py'
tests_before = ast.parse(git('show', PARENT + ':' + test))
tests_after = ast.parse((ROOT / test).read_bytes())
old_class = next(n for n in tests_before.body if isinstance(n, ast.ClassDef) and n.name == 'MaterialPolicyTests')
new_class = next(n for n in tests_after.body if isinstance(n, ast.ClassDef) and n.name == 'MaterialPolicyTests')
added = {'nofollow_enumeration_guard', 'test_enumeration_never_implicitly_follows_omitted_link_targets',
         'test_nofollow_enumeration_refuses_unknown_links_and_types_and_keeps_directory_exclusions',
         'test_nofollow_enumeration_rejects_directory_replacement_before_descent'}
assert [ast.dump(n) for n in old_class.body] == [ast.dump(n) for n in new_class.body if n.name not in added]
assert {n.name for n in new_class.body} - {n.name for n in old_class.body} == added
tests_before.body.remove(old_class); tests_after.body.remove(new_class)
assert ast.dump(tests_before) == ast.dump(tests_after)

bindings = ['scripts/firecracker_recovery_init.py', 'scripts/test_firecracker_recovery_init.py',
            'scripts/firecracker_lab.py', 'scripts/firecracker_device_receipt.py',
            'scripts/firecracker_code.py', 'scripts/runtime_lab_docker.py',
            'scripts/runtime_lab_paths.py', 'scripts/azure_guard.py', 'scripts/k3s_lab.py',
            'runtimes/firecracker/driver.go', 'runtimes/firecracker/identity.go',
            'runtimes/firecracker/vm.go', 'runtimes/firecracker/process.go', 'runtimes/gate/gate.go']
unchanged = {}
for name in bindings:
    raw = (ROOT / name).read_bytes()
    assert raw == git('show', PRIOR + ':' + name) == git('show', SOURCE + ':' + name), name
    unchanged[name] = {'sha256': digest(raw), 'bytes': len(raw)}

index_name = 'docs/evidence/task-4/recovery-material/' + PRIOR + '/evidence-index.json'
index_path = ROOT / index_name; index_raw = index_path.read_bytes()
assert index_raw == git('show', PARENT + ':' + index_name)
index = json.loads(index_raw)
for name, item in index['files'].items():
    path = index_path.parent / name; raw = path.read_bytes()
    assert len(raw) == item['bytes'] and digest(raw) == item['sha256'], name
    assert raw == git('show', PARENT + ':' + str(path.relative_to(ROOT))), name

result = {'source': SOURCE, 'source_parent': PARENT, 'fix_base': FIX_BASE,
          'prior_material_source': PRIOR, 'changed_paths_exactly_allowed': True,
          'changed_files': files, 'changed_host_function_only': 'select_stdlib',
          'unchanged_host_functions_AST': unchanged_functions, 'other_top_level_AST_unchanged': True,
          'added_material_fixture_methods': sorted(added), 'all_other_test_AST_unchanged': True,
          'unchanged_bindings': unchanged,
          'immediate_prior_index': {'path': index_name, 'sha256': digest(index_raw),
                                    'artifacts_verified': len(index['files']), 'all_match': True},
          'older_15_or_176_artifact_crawl_repeated': False,
          'other_host_operation_helper_Go_Task3_tests_repeated': False,
          'actual_system_scan_ABI_package_Docker_live_or_VM': False}
path = OUT / 'source-verification.json'
path.write_text(json.dumps(result, indent=2) + '\n'); path.chmod(0o644)
print(json.dumps({'source': SOURCE, 'changed_host_function_only': 'select_stdlib',
                  'unchanged_host_functions': len(unchanged_functions),
                  'all_other_test_AST_unchanged': True, 'unchanged_bindings': len(bindings),
                  'immediate_prior_index_artifacts': len(index['files']), 'all_match': True}, indent=2))
