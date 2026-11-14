"""Read-only fixed-scene corroboration after the already completed postflight."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path('/home/postedism/Desktop/Warden')
sys.path.insert(0, str(ROOT / 'scripts'))
import firecracker_recovery as r

assert os.geteuid() == 1000
source = '0c7dedbf38499ee991f879e93e43b9f5df9bb7f4'
assert r.source_sha() == source
with r.project_lock():
    scene = r.Scene(cleanup=True)
    try:
        scene.check(1000)
        bindings = [r.phase_binding(mode, source) for mode in r.MODES]
        assert bindings[0] == bindings[1]
        states = [r.state_read(mode, source) for mode in r.MODES]
        assert all(s['step'] == 'complete' and s['settled'] and s['success'] and not s['released'] for s in states)
        for s in states:
            for kind in ('container', 'image'):
                assert not r.scoped_ids(kind, s['labels'], r.docker)
            r.helper_absent(s['cid'])
        raw = r.load(r.WORK / 'inspect' / 'result.json')
        inventory = r.helper.validate_inventory(raw, r.file_sha(r.MODULE))
        receipt = r.validate_result('restore-traversal', r.load(r.WORK / 'restore-traversal' / 'result.json'), r.file_sha(r.MODULE), inventory)
        r.restored_metadata(inventory['entries'])
        containers = r.scoped_ids('container', {'project': 'warden'}, r.docker)
        images = r.scoped_ids('image', {'project': 'warden'}, r.docker)
        assert not containers and not images
        post = r.helper.strict_json(r.load(r.WORK / 'ordinary-full-postflight.json', 65536))
        assert post['protected_baseline_match'] and post['released'] is False
        assert post['reserved_bytes'] == 5000000000
        assert post['original_owner_retirement'] == 'cleanup_pending'
        assert post['creation_outcome'] == 'unknown' and post['never_reopen'] is True
        assert r.current_charges() == 5000000000
        original = ROOT / 'docs/evidence/task-4/recovery-live' / source
        command_meta = {}
        for mode in ('restore-traversal', 'postflight'):
            meta = json.loads((original / (mode + '-meta.json')).read_bytes())
            log = (original / (mode + '.log')).read_bytes()
            assert meta['exit_code'] == 0 and meta['source'] == source
            assert len(log) == meta['log_bytes'] and hashlib.sha256(log).hexdigest() == meta['log_sha256']
            command_meta[mode] = meta
        result = {
            'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source': source, 'helper_sha256': r.file_sha(r.MODULE),
            'original_live_uid': os.fstat(scene.live).st_uid,
            'all_original_regular_metadata_unchanged': True,
            'directory_only_owner_restoration': True,
            'inventory_entries': len(inventory['entries']),
            'inventory_digest': inventory['digest'],
            'private_inventory_sha256': hashlib.sha256(raw).hexdigest(),
            'history_sha256': bindings[0]['history_sha256'],
            'both_phases_complete_success_settled': True,
            'original_and_both_helper_cgroups_absent': True,
            'owned_containers': containers, 'owned_images': images,
            'ordinary_postflight_saved_record': post,
            'original_Q_bytes': 5000000000, 'original_Q_released': False,
            'helper_retained_envelope_bytes': 0,
            'scene_file_bodies_read': False,
            'new_guest_boot_or_tenant_execution': False,
            'task4_accepted': False, 'overall_project_complete': False,
            'command_metadata': command_meta,
        }
        scene.check(1000)
    finally:
        scene.close()
out = ROOT / 'docs/evidence/task-4/recovery-resume-20261025/restored-audit.json'
with out.open('x') as stream:
    stream.write(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, sort_keys=True))
