"""Narrow committed-source/material verification; no live or runtime probe."""
import ast
import hashlib
import json
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = '05505bebb316a180c39e6e75f4a101e3c57224f1'
PARENT = '0af30b0fae2f844651d37b996c455782b11bdaa2'
FIX_BASE = '96b20165e1bf1ba24e71e11b5487a9cc637692c0'
PREDECESSOR = '8c8e9edf4a269effb155ae027b703cd9dc770836'
OUT = ROOT / 'docs/evidence/task-4/recovery-material' / SOURCE
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
    assert raw == git('show', SOURCE + ':' + name), name
    assert stat.S_IMODE(path.stat().st_mode) == 0o644, name
    files[name] = {'sha256': digest(raw), 'bytes': len(raw), 'mode': '0644'}

host = 'scripts/firecracker_recovery.py'
before = ast.parse(git('show', PARENT + ':' + host))
after = ast.parse((ROOT / host).read_bytes())
old_functions = {n.name: n for n in before.body if isinstance(n, ast.FunctionDef)}
new_functions = {n.name: n for n in after.body if isinstance(n, ast.FunctionDef)}
changed = {'build_archive', 'runtime_inputs', 'new_phase', 'execute_phase', 'main'}
added = {'public_directory', 'open_public', 'held_hash', 'select_stdlib', 'host_abi',
         'directory_shape', 'private_snapshot', 'validate_admission', 'predecessor',
         'operation_document', 'operation_read', 'phase_binding', 'bound_account'}
assert set(new_functions) - set(old_functions) == added
assert not set(old_functions) - set(new_functions)
assert {n for n in old_functions if ast.dump(old_functions[n]) != ast.dump(new_functions[n])} == changed
unchanged_functions = sorted(set(old_functions) - changed)
assert {'validate_phase_state', 'state_read', 'cleanup_phase', 'admitted', 'account',
        'create_args', 'inspect_profile', 'full_postflight', 'bounded_command'} <= set(unchanged_functions)
changed_constants = {'WORK', 'PREDECESSOR_WORK', 'PREDECESSOR_SOURCE', 'PREDECESSOR_HELPER',
                     'MATERIAL_POLICY', 'PYTHON', 'STDLIB', 'STDLIB_NAME', 'SYSCONFIG_ALIAS',
                     'SYSCONFIG_TARGET', 'LINKS', 'DEVELOPMENT_OBJECT', 'OBJECT_HEADER',
                     'OBJECT_HEADER_SHA', 'OMITTED', 'INPUT_GID', 'HOST_ABI_CHECK'}


def fixed_nodes(tree):
    for node in tree.body:
        if isinstance(node, ast.FunctionDef): continue
        if isinstance(node, ast.ClassDef) and node.name == 'RuntimeMaterial': continue
        if isinstance(node, ast.Assign) and all(isinstance(n, ast.Name) and n.id in changed_constants for n in node.targets): continue
        yield ast.dump(node)


assert list(fixed_nodes(before)) == list(fixed_nodes(after))
bindings = ['scripts/firecracker_recovery_init.py', 'scripts/test_firecracker_recovery_init.py',
            'scripts/firecracker_lab.py', 'scripts/firecracker_device_receipt.py',
            'scripts/firecracker_code.py', 'scripts/runtime_lab_docker.py',
            'scripts/runtime_lab_paths.py', 'scripts/azure_guard.py', 'scripts/k3s_lab.py',
            'runtimes/firecracker/driver.go', 'runtimes/firecracker/identity.go',
            'runtimes/firecracker/vm.go', 'runtimes/firecracker/process.go', 'runtimes/gate/gate.go']
unchanged = {}
for name in bindings:
    raw = (ROOT / name).read_bytes()
    assert raw == git('show', PREDECESSOR + ':' + name) == git('show', SOURCE + ':' + name), name
    unchanged[name] = {'sha256': digest(raw), 'bytes': len(raw)}

indexes = {}
for scope in ('recovery-live', 'recovery-safety-amendment'):
    name = 'docs/evidence/task-4/' + scope + '/' + PREDECESSOR + '/evidence-index.json'
    path = ROOT / name; raw = path.read_bytes()
    assert raw == git('show', PARENT + ':' + name)
    value = json.loads(raw)
    observed_modes = {}
    for child, item in value['files'].items():
        artifact = path.parent / child; data = artifact.read_bytes()
        assert len(data) == item['bytes'] and digest(data) == item['sha256'], child
        assert data == git('show', PARENT + ':' + str(artifact.relative_to(ROOT))), child
        observed_modes[child] = format(stat.S_IMODE(artifact.stat().st_mode), '04o')
    indexes[name] = {'sha256': digest(raw), 'entries_verified': len(value['files']),
                     'observed_modes_not_normalized': observed_modes, 'all_match': True}

result = {'source': SOURCE, 'source_parent': PARENT, 'fix_base': FIX_BASE,
          'predecessor_source': PREDECESSOR, 'changed_paths_exactly_allowed': True,
          'changed_files': files, 'changed_existing_host_functions': sorted(changed),
          'added_host_functions': sorted(added), 'added_class': 'RuntimeMaterial',
          'unchanged_host_functions_AST': unchanged_functions,
          'changed_or_added_constants': sorted(changed_constants), 'other_top_level_AST_unchanged': True,
          'unchanged_bindings': unchanged, 'old_current_indexes': indexes,
          'historical_176_file_crawl_repeated': False, 'helper_suite_repeated': False,
          'actual_material_ABI_Docker_live_recovery_or_Go_executed': False}
path = OUT / 'source-verification.json'
path.write_text(json.dumps(result, indent=2) + '\n'); path.chmod(0o644)
print(json.dumps({'source': SOURCE, 'changed_paths': ALLOWED, 'changed_existing_functions': sorted(changed),
                  'added_functions': len(added), 'unchanged_host_functions': len(unchanged_functions),
                  'unchanged_bindings': len(bindings), 'old_current_indexes': len(indexes),
                  'old_indexed_artifacts': sum(v['entries_verified'] for v in indexes.values()),
                  'all_match': True, 'actual_operations_executed': False}, indent=2))
