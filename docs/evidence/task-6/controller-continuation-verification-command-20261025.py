#!/usr/bin/env python3
"""Read frozen public evidence/Git bodies only; never opens cache or runs tests."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).absolute().parents[3]
BASE = '333dfa155ed1670ebceff3c20fb0228c365f17d3'
SOURCE = '93051e37849f6bfeb8416ef3883f65034f6dff09'
HEAD = 'a51a923321ed4bd91936fc0afd84ed3eb2d92210'
OUT = ROOT / 'docs/evidence/task-6/controller-continuation-verification-20261025.json'
PACKAGE = ROOT / '.superpowers/sdd/2-warden-security-plan/review-333dfa1..a51a923.diff'
VIEW = PACKAGE.with_name('review-333dfa1..a51a923-deduplicated-view.diff')
assert not OUT.exists() and not VIEW.exists()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

def body(commit, name):
    return git('show', commit + ':' + name)

def load(name):
    return json.loads((ROOT / name).read_bytes())

source_names = ['scripts/identity_cache_continue.py', 'scripts/test_identity_cache_continue.py']
changed = git('diff', '--name-status', BASE, HEAD).decode().splitlines()
assert all(row.startswith('A\t') for row in changed)
paths = [row.split('\t')[1] for row in changed]
assert sorted(p for p in paths if not p.startswith('docs/evidence/')) == source_names
artifacts = load('docs/evidence/task-6/continuation-artifact-sizes.json')
assert len(artifacts['evidence_except_this_manifest']) + 1 == 68
for name, recorded in {**artifacts['source'], **artifacts['evidence_except_this_manifest']}.items():
    raw = (ROOT / name).read_bytes()
    assert len(raw) == recorded['bytes'] and sha(raw) == recorded['sha256']
    assert raw == body(HEAD, name)
artifact_names = list(artifacts['evidence_except_this_manifest']) + ['docs/evidence/task-6/continuation-artifact-sizes.json']
assert sorted(artifact_names) == sorted(p for p in paths if p.startswith('docs/evidence/'))
assert sum((ROOT / n).stat().st_size for n in artifact_names) == artifacts['evidence_bytes_including_this_manifest'] == 737675
assert sum((ROOT / n).stat().st_size for n in source_names) == artifacts['source_bytes'] == 51050
stages = ['continuation-red-01', 'continuation-fixture-02', 'continuation-red-03', 'continuation-fixture-04', 'continuation-fixture-05', 'continuation-cover-06', 'continuation-cover-07']
expected = [(1, 1, 0, 1), (14, 0, 0, 0), (36, 1, 2, 0), (42, 0, 0, 0), (44, 0, 0, 0), (44, 0, 0, 0), (44, 0, 0, 0)]
base_sources = None
runs = []
for stage, expectation in zip(stages, expected):
    directory = 'docs/evidence/task-6/' + stage
    baseline = load(directory + '/baseline.json')
    pre = load(directory + '/pre-source.json')
    post = load(directory + '/post-source.json')
    receipt = load(directory + '/receipt.json')
    assert pre == post and baseline['dispatch_base'] == BASE
    if base_sources is None:
        base_sources = baseline['sources']
        assert len(base_sources) == 143
        assert all(sha(body(BASE, n)) == h for n, h in base_sources.items())
    assert baseline['sources'] == base_sources
    assert all(pre[n] == h for n, h in base_sources.items())
    difference = sorted(n for n in pre if base_sources.get(n) != pre[n])
    snapshots = {str(n.relative_to(ROOT / directory / 'changed-source')): sha(n.read_bytes()) for n in (ROOT / directory / 'changed-source').rglob('*') if n.is_file()}
    assert sorted(snapshots) == difference == receipt['changed_source_snapshots']
    assert all(snapshots[n] == pre[n] for n in difference)
    actual = (receipt['tests_run'], receipt['exit_code'], receipt['failures'], receipt['errors'])
    assert actual == expectation and receipt['source_unchanged'] and receipt['skipped'] == 0
    assert receipt['limits'] == {'address_bytes': 536870912, 'cpu_seconds': 30, 'file_bytes': 33554432, 'wall_seconds': 45}
    assert receipt['source_files'] == len(pre) == (144 if stage == 'continuation-red-01' else 145)
    output = (ROOT / directory / 'output.txt').read_text()
    assert re.search(r'Ran ' + str(receipt['tests_run']) + r' tests? in ', output)
    if receipt['exit_code'] == 0:
        assert output.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$', output, re.M)) == receipt['tests_run']
    if stage == 'continuation-red-01':
        assert "ModuleNotFoundError: No module named 'identity_cache_continue'" in output
    if stage == 'continuation-red-03':
        assert output.count('\nFAIL: ') == 2 and 'FAILED (failures=2)' in output
    if stage in ('continuation-cover-06', 'continuation-cover-07'):
        assert receipt['source_commit_at_launch'] == SOURCE
        assert all(sha(body(SOURCE, n)) == h == sha((ROOT / n).read_bytes()) for n, h in pre.items())
    runs.append({'stage': stage, 'tests': receipt['tests_run'], 'exit_code': receipt['exit_code'], 'failures': receipt['failures'], 'errors': receipt['errors'], 'source_files': len(pre), 'changed_snapshots': difference, 'pre_post_sha256': sha((ROOT / directory / 'pre-source.json').read_bytes()), 'duration_seconds': receipt['duration_seconds']})
outer = load('docs/evidence/task-6/continuation-cover-07/outer-tool-result.json')
assert outer['exit_code'] == 0 and json.loads(outer['output']) == load('docs/evidence/task-6/continuation-cover-07/receipt.json')
wrapper07 = (ROOT / 'docs/evidence/task-6/continuation-cover-07/run.py').read_text()
assert 'os._exit(124)' in wrapper07 and wrapper07.index('signal.alarm(0)') > wrapper07.index('print(json.dumps(receipt')
raw = PACKAGE.read_bytes()
parts = re.split(rb'(?=^diff --git )', raw, flags=re.M)
assert len(parts) == 71
blocks = []
for block in parts[1:]:
    name = block.splitlines()[0].split(b' b/', 1)[1].decode()
    assert name in paths and b'new file mode ' in block
    lines = block.splitlines(keepends=True)
    hunk = next(i for i, line in enumerate(lines) if line.startswith(b'@@ '))
    assert all(line.startswith(b'+') for line in lines[hunk + 1:])
    file_body = b''.join(line[1:] for line in lines[hunk + 1:])
    assert file_body == body(HEAD, name) == (ROOT / name).read_bytes()
    blocks.append((name, block, file_body))

def priority(name):
    if name in source_names:
        return (0, name)
    if name.endswith('/run.py') and '/continuation-red-01/' in name:
        return (1, name)
    if name.endswith('/pre-source.json') and '/continuation-cover-07/' in name:
        return (1, name)
    return (2, name)
keepers = {}
for name, block, file_body in sorted(blocks, key=lambda row: priority(row[0])):
    keepers.setdefault(sha(file_body), name)
retained = []
omitted = []
view_parts = [parts[0]]
for name, block, file_body in blocks:
    keeper = keepers[sha(file_body)]
    if keeper == name:
        view_parts.append(block)
        retained.append({'path': name, 'block_sha256': sha(block), 'body_sha256': sha(file_body)})
    else:
        omitted.append({'path': name, 'block_sha256': sha(block), 'body_sha256': sha(file_body), 'bytes': len(file_body), 'identical_body_kept_at': keeper})
        view_parts.append(('# Exact duplicate body: ' + name + '\n# Kept verbatim at: ' + keeper + '\n# SHA256: ' + sha(file_body) + '\n# Original full diff and evidence remain intact.\n\n').encode())
assert all(any(row['path'] == name for row in retained) for name in source_names)
view = b''.join(view_parts)
VIEW.write_bytes(view)
result = {'status': 'PASS', 'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'base': BASE, 'source': SOURCE, 'head': HEAD, 'source_files_changed': source_names, 'base_sources_verified_against_git': len(base_sources), 'artifact_files': 68, 'evidence_bytes': 737675, 'source_bytes': 51050, 'runs': runs, 'corrected_outer_exit_code': 0, 'review_view': {'full_package': str(PACKAGE.relative_to(ROOT)), 'full_bytes': len(raw), 'full_sha256': sha(raw), 'view_path': str(VIEW.relative_to(ROOT)), 'view_bytes': len(view), 'view_sha256': sha(view), 'retained_blocks': retained, 'omitted_exact_duplicate_bodies': omitted}, 'limits': 'No tests/cache/privatebody/host/cloud/identity operations; all actual resource and checkpoint facts remain unverified future gates.'}
with OUT.open('x') as f:
    f.write(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status': 'PASS', 'artifacts': 68, 'runs': 7, 'final_tests': 44, 'full_package_bytes': len(raw), 'view_bytes': len(view), 'duplicate_blocks': len(omitted), 'result': str(OUT.relative_to(ROOT))}))
