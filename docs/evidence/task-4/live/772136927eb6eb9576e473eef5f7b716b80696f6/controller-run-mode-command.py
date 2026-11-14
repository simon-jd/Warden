from pathlib import Path
import datetime,hashlib,json,os,re,subprocess,sys,time
root=Path('/home/postedism/Desktop/Warden');os.chdir(root);os.umask(0o077)
source,mode,stem=sys.argv[1:]
assert os.getuid()==1000 and re.fullmatch('[0-9a-f]{40}',source)
flags={'prepare':[],'mount-smoke':['--reviewed-mount-profile'],'boot':['--reviewed-live-profile']}
assert mode in flags and re.fullmatch(r'(prepare|mount-smoke|boot)-(first|second|third)',stem)
assert subprocess.check_output(['git','log','-1','--format=%H','--','go.mod','go.sum','runtimes','scripts/firecracker_code.py','scripts/firecracker_lab.py'],text=True).strip()==source
folder=root/'docs/evidence/task-4/live'/source;folder.mkdir(parents=True,exist_ok=True)
body=Path(__file__).read_bytes();archive=folder/'controller-run-mode-command.py'
if archive.exists():assert archive.read_bytes()==body
else:
    with archive.open('xb') as out:out.write(body)
cmd=['python3','-B','scripts/firecracker_lab.py',mode,'--other-service-memory-bytes','0',*flags[mode]]
start=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic();print('Controller reviewed source '+source+' '+mode+' started',flush=True)
with (folder/(stem+'.log')).open('xb') as out:
    result=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT);out.flush();os.fsync(out.fileno())
raw=(folder/(stem+'.log')).read_bytes();meta={'source':source,'review':'docs/evidence/task-4/review-code-round-2.md','command':cmd,'uid':os.getuid(),'start_utc':start,'end_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-t,'exit_code':result.returncode,'log_bytes':len(raw),'log_sha256':hashlib.sha256(raw).hexdigest(),'scope':mode+' controller gate only; result does not imply other unexecuted acceptance gates'}
with (folder/(stem+'.json')).open('x') as out:json.dump(meta,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
print(json.dumps(meta),flush=True);sys.exit(result.returncode)
