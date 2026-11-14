"""Narrow safety-amendment source binding; no old evidence crawl or live access."""
import ast
import hashlib
import json
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
SOURCE = '8c8e9edf4a269effb155ae027b703cd9dc770836'
PARENT = 'ed65c4757a23678a0845d4184c32d1ab0f179d78'
FIX_BASE = '078329de70abb59bfdce20840d52dac30482a374'
ORIGINAL_A = 'dbc6d648068ff0771e1e1936bd1a0061cd0a36c9'
OUT = ROOT / 'docs/evidence/task-4/recovery-safety-amendment' / SOURCE
ALLOWED = ['docs/firecracker-recovery.md', 'scripts/firecracker_recovery.py',
           'scripts/test_firecracker_recovery.py']


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


assert git('diff', '--name-only', PARENT, SOURCE).decode().splitlines() == ALLOWED
assert git('rev-parse', SOURCE + '^').decode().strip() == PARENT
files = {}
for name in ALLOWED:
    path = ROOT / name
    raw = path.read_bytes()
    assert raw == git('show', SOURCE + ':' + name), name
    assert stat.S_IMODE(path.stat().st_mode) == 0o644, name
    files[name] = {'sha256': digest(raw), 'bytes': len(raw), 'mode': '0644'}

host = 'scripts/firecracker_recovery.py'
before = ast.parse(git('show', PARENT + ':' + host))
after = ast.parse((ROOT / host).read_bytes())
changed = {'state_read', 'cleanup_phase', 'validate_phase_state'}
before_fixed = [n for n in before.body if not isinstance(n, ast.FunctionDef) or n.name not in changed]
after_fixed = [n for n in after.body if not isinstance(n, ast.FunctionDef) or n.name not in changed]
assert [ast.dump(n) for n in before_fixed] == [ast.dump(n) for n in after_fixed]
functions = [n.name for n in after_fixed if isinstance(n, ast.FunctionDef)]

bindings = ['scripts/firecracker_recovery_init.py', 'scripts/test_firecracker_recovery_init.py',
            'scripts/firecracker_lab.py', 'scripts/firecracker_device_receipt.py',
            'scripts/firecracker_code.py', 'scripts/runtime_lab_docker.py',
            'scripts/runtime_lab_paths.py', 'scripts/azure_guard.py', 'scripts/k3s_lab.py',
            'runtimes/firecracker/driver.go', 'runtimes/firecracker/identity.go',
            'runtimes/firecracker/vm.go', 'runtimes/firecracker/process.go', 'runtimes/gate/gate.go']
unchanged = {}
for name in bindings:
    raw = (ROOT / name).read_bytes()
    assert raw == git('show', ORIGINAL_A + ':' + name), name
    assert raw == git('show', SOURCE + ':' + name), name
    unchanged[name] = {'sha256': digest(raw), 'bytes': len(raw)}

result = {'source': SOURCE, 'source_parent': PARENT, 'fix_base': FIX_BASE,
          'original_A_source': ORIGINAL_A, 'changed_paths_exactly_allowed': True,
          'changed_files': files, 'host_functions_changed_or_added': sorted(changed),
          'other_host_functions_AST_identical': functions,
          'all_other_host_top_level_AST_identical': True,
          'unchanged_source_bindings': unchanged,
          'old_176_file_integrity_crawl_repeated': False,
          'helper_suite_repeated': False, 'actual_recovery_or_Docker_operations': False}
path = OUT / 'source-verification.json'
path.write_text(json.dumps(result, indent=2) + '\n'); path.chmod(0o644)
print(json.dumps({'source': SOURCE, 'changed_paths': ALLOWED,
                  'unchanged_host_functions': len(functions), 'unchanged_bindings': len(bindings),
                  'all_match': True, 'historical_integrity_crawl_repeated': False}, indent=2))
