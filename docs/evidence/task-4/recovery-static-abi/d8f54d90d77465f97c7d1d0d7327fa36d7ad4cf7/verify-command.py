"""Exact parser amendment provenance; no ABI execution or historical crawl."""
import ast
import hashlib
import json
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = 'd8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7'
PARENT = '1493f522be2ec95d34591f4f6d59796a21a3e059'
FIX_BASE = '9aa87b2c5bf6b485cdb0ea6f182153edbf4835e0'
PRIOR = 'ba8cfaf6bffd7996f54bd50db9ccf453ff121022'
OUT = ROOT / 'docs/evidence/task-4/recovery-static-abi' / SOURCE
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
old_parser = next(n for n in before.body if isinstance(n, ast.FunctionDef) and n.name == 'dependencies')
new_parser = next(n for n in after.body if isinstance(n, ast.FunctionDef) and n.name == 'dependencies')
expected = ast.parse("if stdout.strip() == b'statically linked' and not stderr: return set()")
assert ast.dump(new_parser.body[2]) == ast.dump(expected.body[0])
new_parser.body.pop(2)
assert ast.dump(before) == ast.dump(after)
unchanged_functions = [n.name for n in after.body if isinstance(n, ast.FunctionDef) and n.name != 'dependencies']

test = 'scripts/test_firecracker_recovery.py'
tests_before = ast.parse(git('show', PARENT + ':' + test))
tests_after = ast.parse((ROOT / test).read_bytes())
old_boundary = next(n for n in tests_before.body if isinstance(n, ast.ClassDef) and n.name == 'BoundaryTests')
new_class = next(n for n in tests_after.body if isinstance(n, ast.ClassDef) and n.name == 'DependencyParserTests')
existing_name = 'test_abi_dependency_output_is_closed_and_missing_library_stops'
moved = next(n for n in old_boundary.body if n.name == existing_name)
assert ast.dump(moved) == ast.dump(next(n for n in new_class.body if n.name == existing_name))
old_boundary.body.remove(moved); tests_after.body.remove(new_class)
assert ast.dump(tests_before) == ast.dump(tests_after)
assert len(new_class.body) == 5

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

index_name = 'docs/evidence/task-4/recovery-enumeration/' + PRIOR + '/evidence-index.json'
index_path = ROOT / index_name; index_raw = index_path.read_bytes()
assert index_raw == git('show', PARENT + ':' + index_name)
index = json.loads(index_raw)
for name, item in index['files'].items():
    path = index_path.parent / name; raw = path.read_bytes()
    assert len(raw) == item['bytes'] and digest(raw) == item['sha256'], name
    assert raw == git('show', PARENT + ':' + str(path.relative_to(ROOT))), name

diagnostic_name = 'docs/evidence/task-4/public-abi-diagnostic-v1.json'
diagnostic_raw = (ROOT / diagnostic_name).read_bytes()
assert diagnostic_raw == git('show', PARENT + ':' + diagnostic_name)
refusal = json.loads(diagnostic_raw)['first_dependency_refusal']
observed = b'\tstatically linked\n'
assert refusal['exit_code'] == 0 and refusal['stdout_addresses_redacted'].encode() == observed
assert refusal['stdout_bytes'] == len(observed) and refusal['stdout_sha256'] == digest(observed)
assert refusal['stderr_bytes'] == 0 and refusal['stderr_addresses_redacted'] == ''
assert refusal['stderr_sha256'] == digest(b'')

result = {'source': SOURCE, 'source_parent': PARENT, 'fix_base': FIX_BASE,
          'prior_source': PRIOR, 'changed_paths_exactly_allowed': True, 'changed_files': files,
          'production_delta_only': 'one exact successful-static branch in dependencies',
          'all_other_host_AST_unchanged': True, 'unchanged_host_functions': unchanged_functions,
          'existing_parser_test_relocated_AST_identical': True, 'all_other_test_AST_unchanged': True,
          'unchanged_bindings': unchanged,
          'immediate_prior_source_index': {'path': index_name, 'sha256': digest(index_raw),
                                           'artifacts_verified': len(index['files']), 'all_match': True},
          'actual_diagnostic_binding': {'path': diagnostic_name, 'sha256': digest(diagnostic_raw),
                                         'fixture_matches_exact_observed_bytes': True},
          'older_11_15_176_crawls_repeated': False, 'other_suites_repeated': False,
          'implementer_actual_ABI_ldd_closure_package_Docker_scene_or_VM': False}
path = OUT / 'source-verification.json'
path.write_text(json.dumps(result, indent=2) + '\n'); path.chmod(0o644)
print(json.dumps({'source': SOURCE, 'production_delta_only': 'one exact branch in dependencies',
                  'unchanged_host_functions': len(unchanged_functions), 'unchanged_bindings': len(bindings),
                  'immediate_prior_source_index_artifacts': len(index['files']),
                  'exact_diagnostic_bytes_match': True, 'all_match': True}, indent=2))
