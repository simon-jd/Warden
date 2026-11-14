"""Read only this delta, fixed interfaces and the immediate prior evidence index."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
SOURCE = '0c7dedbf38499ee991f879e93e43b9f5df9bb7f4'
PARENT = '05110d80665c2bb9dab8d8affdb3604f5bc8bf95'
FIX_BASE = '2b86368b294b8621c91204bf5449066b12e83cc1'
FILES = ['docs/firecracker-recovery.md', 'scripts/firecracker_recovery.py', 'scripts/test_firecracker_recovery.py']
BINDINGS = ['scripts/firecracker_recovery_init.py', 'scripts/test_firecracker_recovery_init.py',
            'scripts/firecracker_lab.py', 'scripts/firecracker_device_receipt.py', 'scripts/firecracker_code.py',
            'scripts/runtime_lab_docker.py', 'scripts/runtime_lab_paths.py', 'scripts/azure_guard.py',
            'scripts/k3s_lab.py', 'runtimes/firecracker/driver.go', 'runtimes/firecracker/identity.go',
            'runtimes/firecracker/vm.go', 'runtimes/firecracker/process.go', 'runtimes/gate/gate.go']


def git(*args): return subprocess.check_output(['git', *args], cwd=ROOT)
def blob(commit, path): return git('show', commit + ':' + path)
def digest(raw): return hashlib.sha256(raw).hexdigest()
def dump(node): return ast.dump(node, include_attributes=False)
def definitions(tree):
    return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
def same_binding(path):
    raw = (ROOT / path).read_bytes()
    assert raw == blob(PARENT, path) == blob(SOURCE, path), path
    return {'bytes': len(raw), 'sha256': digest(raw)}


assert git('rev-parse', SOURCE + '^').decode().strip() == PARENT
assert sorted(git('diff', '--name-only', PARENT, SOURCE).decode().splitlines()) == FILES
source_files = {}
for path in FILES:
    raw = (ROOT / path).read_bytes()
    assert raw == blob(SOURCE, path)
    assert (ROOT / path).stat().st_mode & 0o7777 == 0o644
    source_files[path] = {'bytes': len(raw), 'sha256': digest(raw), 'mode': '0644'}
host = 'scripts/firecracker_recovery.py'
old, new = ast.parse(blob(PARENT, host)), ast.parse(blob(SOURCE, host))
a, b = definitions(old), definitions(new)
changed = sorted(name for name in a if dump(a[name]) != dump(b[name]))
added = sorted(set(b) - set(a))
assert changed == ['execute_phase', 'operation_document', 'operation_read']
assert added == ['histories', 'second_operation_document', 'second_predecessor']
assert not set(a) - set(b)
# Everything outside these three existing functions, three additions and the
# fixed WORK/SECOND_WORK/SECOND_SOURCE declarations must be AST-identical.
fixed = {'WORK', 'SECOND_WORK', 'SECOND_SOURCE'}
def unchanged_nodes(tree):
    return [dump(n) for n in tree.body
            if not (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in changed + added)
            and not (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in fixed for t in n.targets))]
assert unchanged_nodes(old) == unchanged_nodes(new)
constants = {n.targets[0].id: n.value for n in new.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id in fixed}
for name, expression in {'WORK': "SCENE / 'recovery-a-py314-static-v1'",
                         'SECOND_WORK': "SCENE / 'recovery-a-py314-v1'",
                         'SECOND_SOURCE': "'ba8cfaf6bffd7996f54bd50db9ccf453ff121022'"}.items():
    assert dump(constants[name]) == dump(ast.parse(expression, mode='eval').body)
# The workflow delta is exactly the one history-reader call replacement.
workflow = copy.deepcopy(b['execute_phase'])
changes = 0
for node in ast.walk(workflow):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'histories':
        node.func.id = 'predecessor'; changes += 1
assert changes == 1 and dump(workflow) == dump(a['execute_phase'])
for name in ('predecessor', 'validate_phase_state', 'cleanup_phase', 'dependencies', 'runtime_inputs',
             'select_stdlib', 'build_archive', 'create_args', 'inspect_profile', 'account', 'admitted',
             'full_postflight', 'new_phase', 'phase_binding', 'bound_account', 'main'):
    assert dump(a[name]) == dump(b[name]), name
unchanged_functions = [name for name in a if name not in changed and isinstance(a[name], ast.FunctionDef)]
unchanged_classes = [name for name in a if name not in changed and isinstance(a[name], ast.ClassDef)]
tests = 'scripts/test_firecracker_recovery.py'
test_old, test_new = ast.parse(blob(PARENT, tests)), ast.parse(blob(SOURCE, tests))
ta, tb = definitions(test_old), definitions(test_new)
assert sorted(name for name in ta if dump(ta[name]) != dump(tb[name])) == ['OperationBindingTests', 'WorkflowTests']
assert set(tb) - set(ta) == {'HistoryBindingTests'}
affected = {'HistoryBindingTests', 'OperationBindingTests', 'WorkflowTests'}
assert [dump(n) for n in test_old.body if not isinstance(n, ast.ClassDef) or n.name not in affected] == [
    dump(n) for n in test_new.body if not isinstance(n, ast.ClassDef) or n.name not in affected]
counts = {name: sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_') for n in tb[name].body)
          for name in sorted(affected)}
assert sum(counts.values()) == 19
bindings = {path: same_binding(path) for path in BINDINGS}
prior_dir = 'docs/evidence/task-4/recovery-static-abi/d8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7'
index_path = prior_dir + '/evidence-index.json'
index_binding = same_binding(index_path)
index = json.loads((ROOT / index_path).read_bytes())
assert index['source'] == index['tested_source'] == 'd8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7'
assert set(index['files']) == {'README.md', 'history-static-green.log', 'history-static-red.log',
                              'python-tests.log', 'source-verification.json', 'source-verification.log', 'verify-command.py'}
for name, expected in index['files'].items():
    assert same_binding(prior_dir + '/' + name) == expected
public = {path: same_binding('docs/evidence/task-4/' + path) for path in (
    'controller-third-recovery-rulings.md', 'public-abi-closure-v2.json', 'public-package-preflight-v2.json')}
result = {'source': SOURCE, 'tested_source': SOURCE, 'parent': PARENT, 'fix_base': FIX_BASE,
          'source_files': source_files, 'changed_existing': changed, 'added_functions': added,
          'unchanged_functions': unchanged_functions, 'unchanged_classes': unchanged_classes,
          'other_ast_unchanged': True, 'workflow_delta': 'one predecessor() to histories() call',
          'affected_class_tests': counts, 'other_test_ast_unchanged': True, 'bindings': bindings,
          'immediate_prior_index': {'path': index_path, **index_binding, 'artifacts_verified': 7,
                                    'older_indices_followed': 0}, 'public_ruling_prerequisites': public,
          'no_actual_scene_or_material_execution': True}
(OUT / 'source-verification.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print('PASS: exactly 3 source files; 3 existing functions changed / 3 fixed functions added.')
print('PASS: ' + str(len(unchanged_functions)) + ' functions / ' + str(len(unchanged_classes)) +
      ' classes and remaining AST unchanged; first validator, I8, materials, ABI, profiles and guards preserved.')
print('PASS: only affected history/operation/workflow tests; 14 fixed bindings unchanged.')
print('PASS: immediate prior source index and 7 artifacts only; 3 named public prerequisites unchanged.')
