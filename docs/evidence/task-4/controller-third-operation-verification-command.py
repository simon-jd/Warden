"""Read-only current dual-history delta/index check, no tests or actual."""
from pathlib import Path
import json,hashlib
root=Path('/home/postedism/Desktop/Warden')
folder=root/'docs/evidence/task-4/recovery-third-operation/0c7dedbf38499ee991f879e93e43b9f5df9bb7f4'
command=folder/'verify-command.py'
source=command.read_text();marker="\n(OUT / 'source-verification.json').write_text"
assert source.count(marker)==1
scope={'__file__':str(command)}
exec(compile(source.split(marker)[0],str(command),'exec'),scope)
result=scope['result'];index=json.loads((folder/'evidence-index.json').read_bytes())
assert index['source']==index['tested_source']==result['source']
for name,item in index['files'].items():
 assert '/' not in name and name not in ('.','..')
 raw=(folder/name).read_bytes()
 assert len(raw)==item['bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256']
assert (folder/'python-tests.log').read_text().endswith('Ran 19 tests in 0.147s\n\nOK\n')
print(json.dumps({'source':result['source'],'changed_existing':result['changed_existing'],
 'added_functions':result['added_functions'],'unchanged_functions':len(result['unchanged_functions']),
 'unchanged_classes':len(result['unchanged_classes']),'unchanged_bindings':len(result['bindings']),
 'affected_class_tests':result['affected_class_tests'],
 'prior_artifacts_verified':result['immediate_prior_index']['artifacts_verified'],
 'new_artifacts_verified':len(index['files']),'tests_or_actual_operations_rerun':False,'all_match':True},indent=2))
