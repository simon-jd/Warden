#!/usr/bin/env python3
"""Verify frozen public recorder evidence and render exact body duplicates only."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).absolute().parents[3]
BASE = '86d8d1424f77113722a826b1e9cecda7da26d67b'
SOURCE = '835600b611b631502b158b5037b8078921277f10'
HEAD = 'e9acbe412e699da32a0546de7e98527ba87eae83'
OUT = ROOT/'docs/evidence/task-6/controller-operations-verification-20261025.json'
PACKAGE = ROOT/'.superpowers/sdd/2-warden-security-plan/review-86d8d14..e9acbe4.diff'
VIEW = PACKAGE.with_name('review-86d8d14..e9acbe4-deduplicated-view.diff')
assert not OUT.exists() and not VIEW.exists()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

def body(commit, name):
    return git('show', commit+':'+name)

def load(name):
    return json.loads((ROOT/name).read_bytes())

index_name = 'docs/evidence/task-6/controller-operations-artifact-sizes.json'
index = load(index_name)
assert index['dispatch_base'] == BASE and index['source_commit'] == SOURCE
assert len(index['artifacts']) == index['artifact_count_excluding_index'] == 85
assert len(index['source_files']) == 4
assert len({r['path'] for r in index['artifacts']+index['source_files']}) == 89
for row in index['artifacts']+index['source_files']:
    data = (ROOT/row['path']).read_bytes()
    assert len(data) == row['bytes'] and sha(data) == row['sha256']
    assert data == body(HEAD, row['path'])
assert sum(r['bytes'] for r in index['artifacts']) == index['artifact_bytes_excluding_index'] == 1041287
assert (ROOT/index_name).stat().st_size == index['index_bytes'] == 19321
assert index['artifact_bytes_excluding_index']+index['index_bytes'] == index['total_evidence_bytes_including_index'] == 1060608
assert sum(r['bytes'] for r in index['source_files']) == index['source_bytes'] == 98685
names = [r['path'] for r in index['source_files']]
assert set(git('diff', '--name-only', BASE, SOURCE).decode().splitlines()) == set(names)
assert all(stat.S_IMODE((ROOT/n).stat().st_mode) == 0o644 for n in names)
expected_changes = {r['path'] for r in index['artifacts']+index['source_files']} | {index_name}
assert set(git('diff', '--name-only', BASE, HEAD).decode().splitlines()) == expected_changes
report = 'docs/evidence/task-6/continuation-controller-operations-substage-report.md'
assert (ROOT/report).read_bytes() == (ROOT/'.superpowers/sdd/2-warden-security-plan/task-6-continuation-controller-operations-report.md').read_bytes()

expected = [
    ('red-01', 1, 0, 1, 1, 146),
    ('fixture-02', 44, 8, 19, 1, 149),
    ('red-03', 48, 1, 1, 1, 149),
    ('fixture-04', 59, 0, 0, 0, 149),
    ('red-05', 67, 1, 0, 1, 149),
    ('green-06', 68, 0, 0, 0, 149),
    ('cover-07', 68, 0, 0, 0, 149),
]
runs = []
base_sources = None
for stage, tests, failures, errors, exit_code, count in expected:
    directory = 'docs/evidence/task-6/controller-operations-'+stage
    baseline = load(directory+'/baseline.json')
    pre = load(directory+'/pre-source.json')
    post = load(directory+'/post-source.json')
    receipt = load(directory+'/receipt.json')
    outer = load(directory+'/outer-tool-result.json')
    if base_sources is None:
        base_sources = baseline['sources']
        assert len(base_sources) == 145
        assert all(sha(body(BASE, n)) == h for n, h in base_sources.items())
    assert baseline['dispatch_base'] == BASE and baseline['sources'] == base_sources
    assert pre == post and len(pre) == receipt['source_files'] == count
    assert all(pre[n] == h for n, h in base_sources.items())
    diff = sorted(n for n, h in pre.items() if base_sources.get(n) != h)
    snapshot_root = ROOT/directory/'changed-source'
    snapshots = {str(p.relative_to(snapshot_root)): sha(p.read_bytes())
                 for p in snapshot_root.rglob('*') if p.is_file()}
    assert sorted(snapshots) == diff == receipt['changed_source_snapshots']
    assert all(snapshots[n] == pre[n] for n in diff)
    assert (receipt['tests_run'], receipt['failures'], receipt['errors'], receipt['exit_code']) == (tests, failures, errors, exit_code)
    assert receipt['skipped'] == 0 and receipt['source_unchanged'] and receipt['live_cache_access'] is False
    assert receipt['limits'] == {'address_bytes': 536870912, 'cpu_seconds': 30,
                                 'file_bytes': 33554432, 'wall_seconds': 45}
    if 'completion' in outer:
        assert set(outer) == {'initial', 'completion'}
        assert type(outer['initial']['session_id']) is int and outer['initial']['output'] == ''
        outer = outer['completion']
    assert outer['exit_code'] == exit_code and json.loads(outer['output']) == receipt
    output = (ROOT/directory/'output.txt').read_text()
    assert re.search(r'Ran '+str(tests)+r' tests? in ', output)
    if exit_code == 0:
        assert output.rstrip().endswith('OK')
        assert len(re.findall(r'^test_.* \.\.\. ok$', output, re.M)) == tests
    else:
        assert output.count('\nFAIL: ') == failures and output.count('\nERROR: ') == errors
    wrapper = (ROOT/directory/'run.py').read_text()
    assert 'os._exit(124)' in wrapper
    assert wrapper.index('signal.alarm(0)') > wrapper.index('print(json.dumps(receipt')
    if stage == 'cover-07':
        assert receipt['source_commit_at_launch'] == SOURCE
        assert all(sha(body(SOURCE, n)) == h == sha((ROOT/n).read_bytes()) for n, h in pre.items())
    runs.append({'stage': stage, 'tests': tests, 'failures': failures, 'errors': errors,
                 'exit_code': exit_code, 'source_files': count, 'source_pre_post_equal': True,
                 'changed_snapshots': diff, 'outer_exit_code': outer['exit_code'],
                 'duration_seconds': receipt['duration_seconds'],
                 'whole_wall_until_receipt_seconds': receipt['whole_wall_until_receipt_seconds']})

raw = PACKAGE.read_bytes()
parts = re.split(rb'(?=^diff --git )', raw, flags=re.M)
blocks = []
for block in parts[1:]:
    name = block.splitlines()[0].split(b' b/', 1)[1].decode()
    assert b'\nnew file mode ' in block
    lines = block.splitlines(keepends=True)
    hunk = next(i for i, line in enumerate(lines) if line.startswith(b'@@ '))
    assert all(line.startswith(b'+') for line in lines[hunk+1:])
    data = b''.join(line[1:] for line in lines[hunk+1:])
    assert data == body(HEAD, name) == (ROOT/name).read_bytes()
    blocks.append((name, block, data))
assert len(blocks) == 90
keepers = {}
for name, block, data in sorted(blocks, key=lambda row: (0 if row[0] in names else 1, row[0])):
    keepers.setdefault(sha(data), name)
rendered = [parts[0]]
retained, omitted = [], []
for name, block, data in blocks:
    keeper = keepers[sha(data)]
    if name == keeper:
        rendered.append(block)
        retained.append({'path': name, 'block_sha256': sha(block)})
    else:
        omitted.append({'path': name, 'block_sha256': sha(block), 'body_sha256': sha(data),
                        'body_bytes': len(data), 'identical_body_kept_at': keeper})
        rendered.append(('# Exact duplicate body: '+name+'\n# Kept verbatim at: '+keeper+
                         '\n# SHA256: '+sha(data)+'\n# Full original diff and files remain intact.\n\n').encode())
assert all(any(r['path'] == n for r in retained) for n in names)
view = b''.join(rendered)
with VIEW.open('xb') as f:
    f.write(view)
result = {
    'status': 'PASS', 'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'dispatch_base': BASE, 'source': SOURCE, 'head': HEAD,
    'artifacts_excluding_index': 85, 'evidence_bytes_including_index': 1060608,
    'canonical_new_source_bytes': 98685, 'unchanged_base_sources': 145,
    'frozen_source_files': 149, 'runs': runs,
    'review_view': {'full_path': str(PACKAGE.relative_to(ROOT)), 'full_bytes': len(raw),
                    'full_sha256': sha(raw), 'view_path': str(VIEW.relative_to(ROOT)),
                    'view_bytes': len(view), 'view_sha256': sha(view),
                    'retained_blocks': retained, 'omitted_exact_duplicate_bodies': omitted},
    'limits': 'Public/Git bytes and generated fixture records corroborated only; no tests, imported project modules, private cache bodies, host probes, Docker, Go or cloud operation.',
    'actual_gate': 'Outer invoker/startup-envelope/tool integration and live owned-child/resource proof unimplemented/unverified; no actual admission.',
    'diagnostic_note': 'An earlier ad-hoc index summary used old files/sources field names and raised KeyError after printing; this verifier uses this stage artifacts/source_files schema. No test or artifact was regenerated.',
}
with OUT.open('x') as f:
    f.write(json.dumps(result, sort_keys=True, indent=2)+'\n')
print(json.dumps({'status': 'PASS', 'artifacts': 85, 'runs': 7, 'frozen_tests': 68,
                  'full_bytes': len(raw), 'view_bytes': len(view), 'duplicate_blocks': len(omitted),
                  'result': str(OUT.relative_to(ROOT))}))
