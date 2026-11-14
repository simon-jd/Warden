"""Narrow read-only I9 binding check; no test or actual operation."""
from pathlib import Path
import hashlib, json
root=Path('/home/postedism/Desktop/Warden')
folder=root/'docs/evidence/task-4/recovery-enumeration/ba8cfaf6bffd7996f54bd50db9ccf453ff121022'
source=(folder/'verify-command.py').read_text()
marker="\npath = OUT / 'source-verification.json'"
assert source.count(marker)==1
scope={}
exec(compile(source.split(marker)[0],str(folder/'verify-command.py'),'exec'),scope)
result=scope['result']
index=json.loads((folder/'evidence-index.json').read_bytes())
assert index['source']==index['tested_source']==result['source']
for name,item in index['files'].items():
    assert '/' not in name and name not in ('.','..')
    raw=(folder/name).read_bytes()
    assert len(raw)==item['bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256']
assert (folder/'python-tests.log').read_text().endswith('Ran 12 tests in 0.034s\n\nOK\n')
print(json.dumps({'source':result['source'],'changed_host_function_only':result['changed_host_function_only'],
 'unchanged_host_functions':len(result['unchanged_host_functions_AST']),
 'unchanged_bindings':len(result['unchanged_bindings']),
 'prior_index_artifacts':result['immediate_prior_index']['artifacts_verified'],
 'new_index_artifacts':len(index['files']),'tests_or_actual_operations_rerun':False,'all_match':True},indent=2))
