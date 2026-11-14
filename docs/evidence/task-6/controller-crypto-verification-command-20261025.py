"""Frozen source/evidence corroboration and lossless duplicate-copy review view; no tests."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path('/home/postedism/Desktop/Warden')
BASE = 'c43c74f63062e5c1bae7f30893ab37dc5d9d6f06'
SOURCE = '6d02de4062c0ee1e5d62825df0ea670d54672b5e'
HEAD = 'f4dd9dc75fbabce7b6d7d79eba5d8428f483a1ae'
CHANGED = {'controlplane/internal/authn/verifier.go', 'controlplane/internal/authn/jwks.go',
           'controlplane/internal/authn/verifier_test.go', 'scripts/firecracker_code.py'}


def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


assert git('rev-parse', 'HEAD').decode().strip() == HEAD
assert set(git('diff', '--name-only', BASE, SOURCE).decode().splitlines()) == CHANGED
folder = ROOT / 'docs/evidence/task-6'
artifacts = {}
new = git('diff', '--name-only', SOURCE, HEAD).decode().splitlines()
assert len(new) == 458 and all(name.startswith('docs/evidence/task-6/crypto') for name in new)
for name in new:
    raw = (ROOT / name).read_bytes()
    assert raw == git('show', HEAD + ':' + name)
    artifacts[name] = {'bytes': len(raw), 'sha256': sha(raw)}
stages = {}
for stage, snapshot, count, exit_code in [('crypto-red-01', 'red-source', 141, 1),
                                          ('crypto-unit-02', 'source-snapshot', 143, 0),
                                          ('crypto-cover-03', 'source-snapshot', 143, 0)]:
    path = folder / stage
    manifest = json.loads((path / 'pre-source.json').read_bytes())
    assert manifest == json.loads((path / 'post-source.json').read_bytes()) and len(manifest) == count
    for name, digest in manifest.items():
        raw = (path / snapshot / name).read_bytes()
        assert sha(raw) == digest
        if stage == 'crypto-cover-03':
            assert raw == (ROOT / name).read_bytes() == git('show', SOURCE + ':' + name)
    receipt = json.loads((path / 'receipt.json').read_bytes())
    assert receipt['exit_code'] == exit_code and receipt['source_unchanged'] is True
    assert json.loads((path / 'pre-sysctls.json').read_bytes()) == json.loads((path / 'post-sysctls.json').read_bytes())
    post = json.loads((path / 'postguard.json').read_bytes())
    assert post['exit_code'] == 0 and post['outstanding_bytes'] == 5000000000
    assert post['owned_containers'] == post['owned_images'] == [] and post['owned_image_charge'] == 0
    stages[stage] = {'source_files': count, 'exit_code': exit_code,
                     'snapshot_matches_prospective_pre_post': True, 'known_objects_empty_Q5GB_retained': True}
log = (folder / 'crypto-cover-03/output.txt').read_text()
assert len(re.findall(r'^--- PASS:', log, re.M)) == 15
assert len(re.findall(r'^ +--- PASS:', log, re.M)) == 32
assert not re.search(r'^\s*--- (FAIL|SKIP):', log, re.M)
full = ROOT / '.superpowers/sdd/2-warden-security-plan/review-c43c74f..f4dd9dc.diff'
raw = full.read_bytes()
parts = re.split(rb'(?=^diff --git )', raw, flags=re.M)
view = [b'# Duplicate-copy-aware review view; full canonical range remains available.\n', parts[0]]
omitted = {}
for block in parts[1:]:
    match = re.match(rb'diff --git a/(\S+) b/(\S+)\n', block)
    assert match and match.group(1) == match.group(2)
    name = match.group(1).decode()
    suffix = None
    for marker in ('/source-snapshot/', '/red-source/'):
        if marker in name:
            suffix = name.split(marker, 1)[1]
            break
    if suffix is not None and suffix not in CHANGED:
        body = (ROOT / name).read_bytes()
        assert body == git('show', BASE + ':' + suffix) == git('show', SOURCE + ':' + suffix)
        omitted[name] = {'canonical_path': suffix, 'canonical_commits': [BASE, SOURCE],
                         'body_bytes': len(body), 'body_sha256': sha(body), 'full_diff_block_sha256': sha(block)}
        view.append(block.split(b'\n', 1)[0] + b'\n')
        view.append(('UNCHANGED HISTORICAL SOURCE COPY ONLY: ' + json.dumps(omitted[name], sort_keys=True) + '\n').encode())
    else:
        view.append(block)
destination = full.with_name('review-c43c74f..f4dd9dc-duplicate-copy-view.diff')
compressed = b''.join(view)
with destination.open('xb') as stream:
    stream.write(compressed)
record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'base': BASE, 'source': SOURCE, 'evidence': HEAD,
          'source_files_changed': sorted(CHANGED), 'stages': stages, 'final_top_pass': 15, 'final_sub_pass': 32,
          'frozen_source_files_verified': 143, 'new_artifacts': artifacts,
          'full_review_package': {'bytes': len(raw), 'sha256': sha(raw)},
          'duplicate_copy_view': {'bytes': len(compressed), 'sha256': sha(compressed), 'omitted_exact_copies': omitted},
          'all_canonical_product_diff_and_changed_scope_snapshots_preserved': True,
          'no_evidence_deleted_or_rewritten': True, 'tests_rerun_by_controller': False,
          'actual_resource_postflight_not_performed_by_this_verifier': True,
          'semantic_security_review': 'pending independent reviewer',
          'fixture_authorship': 'subagent /root/identity, not human or real Entra',
          'Q_released': False, 'task6_complete': False, 'goal_complete': False}
out = folder / 'controller-crypto-verification-20261025.json'
with out.open('x') as stream:
    stream.write(json.dumps(record, indent=2) + '\n')
print(json.dumps({'artifacts': len(artifacts), 'frozen_sources': 143, 'tests': [15, 32],
                  'full_package_bytes': len(raw), 'view_bytes': len(compressed), 'unchanged_copy_bodies_hash_only': len(omitted)}))
