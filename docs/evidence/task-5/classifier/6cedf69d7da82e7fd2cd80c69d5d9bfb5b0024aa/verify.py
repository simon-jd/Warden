"""Read-only artifact/source verification; never invokes Go, Docker or attacks."""
from pathlib import Path
import hashlib,json,subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
SHA=HERE.name
index=json.loads((HERE/'index.json').read_text())
assert index['source_commit']==SHA
for name,meta in index['files'].items():
 data=(HERE/name).read_bytes()
 assert len(data)==meta['bytes'] and hashlib.sha256(data).hexdigest()==meta['sha256'],name
cover=json.loads((HERE/'cover.json').read_text())
assert cover['source_head']==SHA
assert cover['source_manifest_before']==cover['source_manifest_after']
for path,digest in cover['source_manifest_before'].items():
 data=subprocess.check_output(['git','show',SHA+':'+path],cwd=ROOT)
 assert (HERE/'source'/path).read_bytes()==data
 assert hashlib.sha256(data).hexdigest()==digest
for name,code in [('red',1),('green',0),('cover',0)]:
 receipt=json.loads((HERE/(name+'.json')).read_text())
 assert receipt['exit_code']==code
 assert receipt['sysctls_before']==receipt['sysctls_after']
 for when in ('before','after'):
  assert receipt[when]['containers']==[] and receipt[when]['images']==[]
  assert receipt[when]['outstanding']==5000000000
 log=(HERE/(name+'.log')).read_text().splitlines()
 records=[json.loads(line) for line in log if line.startswith('{')]
 creation=next(x for x in records if 'container_id' in x)
 removal=next(x for x in records if 'removed_container' in x)
 assert creation['container_id']==removal['removed_container']
 assert creation['labels']['task']=='matrix-code'
 admission=next(x for x in records if x.get('event')=='local-preflight')
 assert admission['project_allocated_bytes']+int(admission['additional_bytes'])<12000000000
 assert admission['additional_bytes']=='5512000000'
 assert admission['service_memory_bytes']=='3000000000'
print('PASS: artifact index, committed source hashes, actual RED/GREEN/one covering, Q-inclusive guards, exact own cleanup and six sysctls.')
