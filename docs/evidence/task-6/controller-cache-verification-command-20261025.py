"""Read-only frozen-source/fixture corroboration; no cache operation or tests."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
BASE = '0a18e1aa54619097cfc90fa0488ddb3e2269ac25'
SOURCE = '7be15fa29aafc7cf84dcd488dbf8aadc22ae2655'
EVIDENCE = '3f417651b257d91ea892b8cf0ffbcf45778adfd8'
NEW_SOURCE = {'scripts/identity_cache.py', 'scripts/test_identity_cache.py'}


def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args])


assert git('rev-parse', 'HEAD').decode().strip() == EVIDENCE
assert set(git('diff', '--name-only', BASE, SOURCE).decode().splitlines()) == NEW_SOURCE
directory = ROOT / 'docs/evidence/task-6'
cover = directory / 'cache-cover-06'
before = json.loads((cover / 'pre-source.json').read_bytes())
assert before == json.loads((cover / 'post-source.json').read_bytes())
assert len(before) == 139
for name, digest in before.items():
    raw = (ROOT / name).read_bytes()
    assert raw == git('show', SOURCE + ':' + name)
    assert hashlib.sha256(raw).hexdigest() == digest
receipt = json.loads((cover / 'receipt.json').read_bytes())
assert receipt['source_commit'] == SOURCE
assert receipt['exit_code'] == 0 and receipt['source_unchanged'] is True
assert receipt['source_files'] == 139 and receipt['fixture_only'] is True
log = (cover / 'output.txt').read_text()
assert len(re.findall(r'^test_.* \.\.\. ok$', log, re.M)) == 26
assert '\nRan 26 tests in ' in log and log.rstrip().endswith('OK')
assert not re.search(r'\.\.\. (FAIL|ERROR|skipped)', log)
names = [name for name in git('diff', '--name-only', SOURCE, EVIDENCE).decode().splitlines()]
assert len(names) == 26 and all(name.startswith('docs/evidence/task-6/') for name in names)
artifacts = {}
for name in names:
    raw = (ROOT / name).read_bytes()
    assert raw == git('show', EVIDENCE + ':' + name)
    artifacts[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
result = {
    'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'base': BASE, 'source': SOURCE, 'evidence': EVIDENCE,
    'new_source_files': sorted(NEW_SOURCE),
    'frozen_pre_post_commit_workspace_source_files_verified': len(before),
    'artifacts': artifacts,
    'final_fixture_tests_pass': 26,
    'fixture_authorship': 'subagent /root/identity, not human or actual cache execution',
    'tests_rerun_by_controller': False,
    'historical_setup_api_and_cover_failures_preserved': True,
    'whole_main_fixture_actual_ancestor_admission_not_proved': True,
    'actual_cache_operation_executed': False,
    'semantic_source_review': 'pending independent reviewer',
    'Q_released': False, 'task6_complete': False, 'goal_complete': False,
}
out = directory / 'controller-cache-verification-20261025.json'
with out.open('x') as stream:
    stream.write(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: value for key, value in result.items() if key != 'artifacts'}, sort_keys=True))
