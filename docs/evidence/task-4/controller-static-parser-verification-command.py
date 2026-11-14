"""Read-only exact parser/source/index binding; no product test or ABI."""
from pathlib import Path
import json,hashlib
root=Path('/home/postedism/Desktop/Warden')
folder=root/'docs/evidence/task-4/recovery-static-abi/d8f54d90d77465f97c7d1d0d7327fa36d7ad4cf7'
source=(folder/'verify-command.py').read_text()
marker="\npath = OUT / 'source-verification.json'"
assert source.count(marker)==1
scope={}
exec(compile(source.split(marker)[0],str(folder/'verify-command.py'),'exec'),scope)
result=scope['result']
index=json.loads((folder/'evidence-index.json').read_bytes())
for name,item in index['files'].items():
 assert '/' not in name and name not in ('.','..')
 raw=(folder/name).read_bytes()
 assert len(raw)==item['bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256']
assert (folder/'python-tests.log').read_text().endswith('Ran 5 tests in 0.001s\n\nOK\n')
print(json.dumps({'source':result['source'],'production_delta_only':result['production_delta_only'],
 'unchanged_host_functions':len(result['unchanged_host_functions']),
 'unchanged_bindings':len(result['unchanged_bindings']),
 'prior_index_artifacts':result['immediate_prior_source_index']['artifacts_verified'],
 'new_index_artifacts':len(index['files']),'exact_diagnostic_bytes_match':True,
 'tests_or_actual_operations_rerun':False,'all_match':True},indent=2))
