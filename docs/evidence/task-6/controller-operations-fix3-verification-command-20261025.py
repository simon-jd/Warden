#!/usr/bin/env python3
"""Corroborate fix3 public/Git evidence; never import or execute project source."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).absolute().parents[3]
BASE = 'e9acbe412e699da32a0546de7e98527ba87eae83'
DISPATCH = 'b7682d02eb7d78712f819adca38da07dae0b694f'
SOURCE = '61477c02d3bb482af9d0cf3233312e5c53dcca4c'
HEAD = 'a10aac39a20f420ee546bfaa1b170336224fef4c'
OUT = ROOT/'docs/evidence/task-6/controller-operations-fix3-verification-20261025.json'
PACKAGE = ROOT/'.superpowers/sdd/2-warden-security-plan/review-e9acbe4..a10aac3.diff'
VIEW = PACKAGE.with_name('review-e9acbe4..a10aac3-deduplicated-view.diff')
assert not OUT.exists() and not VIEW.exists()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

def body(commit, name):
    return git('show', commit+':'+name)

def load(name):
    return json.loads((ROOT/name).read_bytes())

index_name = 'docs/evidence/task-6/controller-operations-fix3-artifact-sizes.json'
index = load(index_name)
assert index['dispatch_base'] == DISPATCH and index['source_commit'] == SOURCE
assert len(index['artifacts']) == index['artifact_count_excluding_index'] == 51
assert len(index['source_files']) == 5
names = [r['path'] for r in index['source_files']]
prefixes = {}
for row in index['artifacts']+index['source_files']:
    data = (ROOT/row['path']).read_bytes()
    assert len(data) == row['bytes'] and sha(data) == row['sha256'] and data == body(HEAD, row['path'])
    if 'unchanged_prefix' in row:
        old = body(BASE, row['path'])
        assert len(old) == row['unchanged_prefix']['bytes'] and sha(old) == row['unchanged_prefix']['sha256']
        assert data.startswith(old)
        assert len(data)-len(old) == row['new_append_bytes'] and sha(data[len(old):]) == row['new_append_sha256']
        prefixes[row['path']] = {'bytes': len(old), 'sha256': sha(old), 'append_bytes': len(data)-len(old)}
assert sum(r['bytes'] for r in index['artifacts']) == index['artifact_bytes_excluding_index'] == 736740
assert (ROOT/index_name).stat().st_size == index['index_bytes'] == 13259
assert index['artifact_bytes_excluding_index']+index['index_bytes'] == index['total_package_evidence_bytes_including_index'] == 749999
assert sum(r['bytes'] for r in prefixes.values()) == index['historical_document_prefix_bytes'] == 29783
assert 749999-29783 == index['new_evidence_bytes_including_index'] == 720216
assert sum(r['bytes'] for r in index['source_files']) == index['source_bytes'] == 117958
assert index['source_net_growth_bytes'] == 19273
assert set(git('diff', '--name-only', DISPATCH, SOURCE).decode().splitlines()) == set(names)
stage_changes = set(git('diff', '--name-only', DISPATCH, HEAD).decode().splitlines())
assert stage_changes == {r['path'] for r in index['artifacts']+index['source_files']} | {index_name}
report = 'docs/evidence/task-6/continuation-controller-operations-substage-report.md'
assert (ROOT/report).read_bytes() == (ROOT/'.superpowers/sdd/2-warden-security-plan/task-6-continuation-controller-operations-report.md').read_bytes()
old_index_name = 'docs/evidence/task-6/controller-operations-artifact-sizes.json'
assert (ROOT/old_index_name).read_bytes() == body(BASE, old_index_name) == body(HEAD, old_index_name)
old_rows = json.loads(body(BASE, old_index_name))['artifacts']
assert {r['path'] for r in old_rows} & stage_changes == set(prefixes)
# Old unique artifacts were already verified at their frozen HEAD. Git change
# coverage and exact document prefixes establish preservation without recrawling.

expected = [('red-01', 74, 4, 4, 1, 149), ('green-02', 83, 0, 0, 0, 150),
            ('green-03', 84, 0, 0, 0, 150), ('cover-04', 84, 0, 0, 0, 150)]
runs, base_sources = [], None
for stage, tests, failures, errors, exit_code, count in expected:
    directory = 'docs/evidence/task-6/controller-operations-fix3-'+stage
    baseline = load(directory+'/baseline.json')
    pre = load(directory+'/pre-source.json')
    post = load(directory+'/post-source.json')
    receipt = load(directory+'/receipt.json')
    outer = load(directory+'/outer-tool-result.json')
    if base_sources is None:
        base_sources = baseline['sources']
        assert len(base_sources) == 149
        assert all(sha(body(DISPATCH, n)) == h for n, h in base_sources.items())
    assert baseline['dispatch_base'] == DISPATCH and baseline['sources'] == base_sources
    assert pre == post and len(pre) == receipt['source_files'] == count
    assert all(pre[n] == h for n, h in base_sources.items() if n not in names)
    diff = sorted(n for n, h in pre.items() if base_sources.get(n) != h)
    snapshot_root = ROOT/directory/'changed-source'
    snapshots = {str(p.relative_to(snapshot_root)): sha(p.read_bytes()) for p in snapshot_root.rglob('*') if p.is_file()}
    assert sorted(snapshots) == diff == receipt['changed_source_snapshots']
    assert all(snapshots[n] == pre[n] for n in diff)
    assert (receipt['tests_run'], receipt['failures'], receipt['errors'], receipt['exit_code']) == (tests, failures, errors, exit_code)
    assert receipt['skipped'] == 0 and receipt['source_unchanged'] and receipt['live_cache_access'] is False
    assert receipt['limits'] == {'address_bytes': 536870912, 'cpu_seconds': 30, 'file_bytes': 33554432, 'wall_seconds': 45}
    if 'final' in outer:
        assert set(outer) == {'initial', 'final'} and type(outer['initial']['session_id']) is int
        assert outer['initial']['output'] == (SOURCE+'\n' if stage == 'cover-04' else '')
        terminal = outer['final']
        assert json.loads(terminal['output']) == receipt
        outer_format = 'initial_and_final_tool_output'
    else:
        assert stage == 'red-01' and outer['receipt'] == receipt and outer['chunk_id'] == '21cb17'
        terminal = outer
        outer_format = 'structured_terminal_metadata_and_receipt; raw stdout not stored here'
    assert terminal['exit_code'] == exit_code
    output = (ROOT/directory/'output.txt').read_text()
    assert re.search(r'Ran '+str(tests)+r' tests? in ', output)
    if exit_code == 0:
        assert output.rstrip().endswith('OK') and len(re.findall(r'^test_.* \.\.\. ok$', output, re.M)) == tests
    else:
        assert output.count('\nFAIL: ') == failures and output.count('\nERROR: ') == errors
    wrapper = (ROOT/directory/'run.py').read_bytes()
    marker = b'# END DEADLINE PREFIX\n'
    prefix = wrapper.split(marker, 1)[0]+marker
    assert sha(prefix) == receipt['tested_prefix_sha256'] == '7b46ff9acbebfc9d3cae6e9d5b80c0d2c7cdc0a082cbdb3a486021ff250a51aa'
    assert b'signal.setitimer(signal.ITIMER_REAL, remaining())' in prefix and b'os._exit(124)' in prefix
    assert wrapper.rindex(b'finish_timer()') > wrapper.index(b'print(json.dumps(receipt')
    assert 'interpreter startup and essential timer bootstrap externally unbounded' in receipt['timing_scope']
    if stage == 'cover-04':
        assert receipt['source_commit_at_launch'] == SOURCE
        assert all(sha(body(SOURCE, n)) == h == sha((ROOT/n).read_bytes()) for n, h in pre.items())
    runs.append({'stage': stage, 'tests': tests, 'failures': failures, 'errors': errors,
                 'exit_code': exit_code, 'source_files': count, 'source_pre_post_equal': True,
                 'changed_snapshots': diff, 'outer_format': outer_format,
                 'outer_exit_code': terminal['exit_code'], 'tested_prefix_sha256': sha(prefix),
                 'duration_seconds': receipt['duration_seconds'], 'entry_to_receipt_seconds': receipt['whole_wall_until_receipt_seconds']})

raw = PACKAGE.read_bytes()
parts = re.split(rb'(?=^diff --git )', raw, flags=re.M)
blocks = []
for block in parts[1:]:
    name = block.splitlines()[0].split(b' b/', 1)[1].decode()
    data = None
    if b'\nnew file mode ' in block:
        lines = block.splitlines(keepends=True)
        hunk = next(i for i, line in enumerate(lines) if line.startswith(b'@@ '))
        assert all(line.startswith(b'+') for line in lines[hunk+1:])
        data = b''.join(line[1:] for line in lines[hunk+1:])
        assert data == body(HEAD, name) == (ROOT/name).read_bytes()
    blocks.append((name, block, data))
keepers = {}
for name, block, data in sorted(blocks, key=lambda row: (0 if row[0] in names else 1 if '/controller-operations-fix3-cover-04/changed-source/' in row[0] else 2, row[0])):
    if data is not None:
        keepers.setdefault(sha(data), name)
retained, omitted, rendered = [], [], [parts[0]]
for name, block, data in blocks:
    keeper = keepers[sha(data)] if data is not None else name
    if name == keeper:
        rendered.append(block)
        retained.append({'path': name, 'block_sha256': sha(block)})
    else:
        omitted.append({'path': name, 'block_sha256': sha(block), 'body_sha256': sha(data),
                        'body_bytes': len(data), 'identical_body_kept_at': keeper})
        rendered.append(('# Exact duplicate body: '+name+'\n# Kept verbatim at: '+keeper+'\n# SHA256: '+sha(data)+'\n# Raw full package and all files remain intact.\n\n').encode())
assert all(any(r['path'] == n for r in retained) for n in names)
view = b''.join(rendered)
with VIEW.open('xb') as f:
    f.write(view)
result = {'status': 'PASS', 'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'previous_review_head': BASE, 'dispatch_base': DISPATCH, 'source': SOURCE, 'head': HEAD,
          'new_artifact_rows': 51, 'old_85_artifacts_preservation': 'Git changes affect only exact preserved report/plan prefixes; original index unchanged; no old semantic recrawl.',
          'historical_prefixes': prefixes, 'new_evidence_bytes': 720216, 'source_bytes': 117958,
          'unchanged_old_sources': 145, 'frozen_source_count': 150, 'runs': runs,
          'review_view': {'full_path': str(PACKAGE.relative_to(ROOT)), 'full_bytes': len(raw), 'full_sha256': sha(raw),
                          'view_path': str(VIEW.relative_to(ROOT)), 'view_bytes': len(view), 'view_sha256': sha(view),
                          'raw_blocks': len(blocks), 'retained_blocks': retained, 'omitted_exact_duplicate_bodies': omitted},
          'limits': 'Only public/Git byte provenance; no test, imported project source, native probe, private cache body, Docker, Go or cloud operation. Earliest measurable fixture timing only; actual caller/CLI/child/resource gates unverified.',
          'whitespace_note': 'Implementer preserved three exact raw historical artifacts excluded from its final whitespace check; current canonical source check passed. No approval rejection or test result was overwritten.'}
with OUT.open('x') as f:
    f.write(json.dumps(result, sort_keys=True, indent=2)+'\n')
print(json.dumps({'status': 'PASS', 'artifacts': 51, 'runs': 4, 'frozen_tests': 84,
                  'full_bytes': len(raw), 'view_bytes': len(view), 'duplicate_blocks': len(omitted),
                  'result': str(OUT.relative_to(ROOT))}))
