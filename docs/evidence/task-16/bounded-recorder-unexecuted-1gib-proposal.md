# Exact single recorder adjustment — root FULLREAD approval required

Old red.log/red.json and original recorder proposal/rulings remain unchanged. The first invocation consumed one of THREE total profile invocations and was infrastructure failure, not RED. Exactly TWO remain: literal PHASE red-assertions with current unchanged stubs, then literal frozen-green after genuine RED, implementation and source freeze. The latter is both GREEN and the one frozen same-source ./vuln cover; no fourth invocation. One correction only, no compatibility/cap search. 1GiB CLI compatibility is UNPROVEN. Further infra/unknown/overflow failure stops the batch.

Changes to old body: cleanenv exec prefix per root; two remaining exclusive phase filenames; recorder softAS256MiB/hardAS1GiB; fixed single-thread preexec sets profile/inherited CLI AS soft+hard1GiB; metadata lists separate ceilings and conservative5e9 resident reserve; prelaunch read-only MemAvailable>=5e9 gate. Existing profile still refuses any other project container and retains original3GB guard, fresh R+ALLQ+own-image+512MB accounting, lock, labels and cleanup. Parent256MiB+profile1GiB+oneCLI1GiB+container2GB ceilings conservatively covered by5GB; this is a reserve/bound, not measured peak RSS. Other wall240/work235/CPU20/FSIZE4MiB/log2MiB/polls48x<=5s/body semantics unchanged. No extra Docker operation, inherited credentials, nativeGo, service or cleanup. Existing uncertainty about missing independent Docker State terminal observation remains.

Each call executes exactly this body, replacing only PHASE's red-assertions literal with frozen-green for the final call. Actual exec shell /bin/bash, loginfalse/ttyfalse, cwd project, require_escalated ordinaryUID1000, yield1000/max3000; original-session empty polls<=10s/max3000. Unknown external/timeout stops without replay. No tests executed under this adjustment yet.

```sh
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -B - <<'PY'
import datetime, hashlib, json, os, resource, selectors, signal, subprocess, time
from pathlib import Path
PHASE = 'red-assertions'
ROOT = Path('/home/postedism/Desktop/Warden')
OUT = ROOT / 'docs/evidence/task-16'
EXPECTED = {'vm/overcommit_memory':'1', 'vm/panic_on_oom':'0',
            'kernel/panic':'10', 'kernel/panic_on_oops':'1',
            'kernel/keys/root_maxkeys':'1000000', 'kernel/keys/root_maxbytes':'25000000'}
FILES = ('vuln/prioritize.go','vuln/feeds.go','vuln/sla.go','vuln/prioritize_test.go','scripts/firecracker_code.py')
os.umask(0o077)
resource.setrlimit(resource.RLIMIT_CPU,(20,20))
resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,1024*1024*1024))
resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024*1024,4*1024*1024))
started=time.monotonic()
def profile_limits():
    resource.setrlimit(resource.RLIMIT_AS,(1024*1024*1024,1024*1024*1024))
mem_available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
if mem_available<5000000000: raise RuntimeError('MemAvailable below conservative 5GB reserve; no profile launched')
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sysctls(): return {k:Path('/proc/sys',k).read_text().strip() for k in EXPECTED}
def hashes(): return {k:hashlib.sha256((ROOT/k).read_bytes()).hexdigest() for k in FILES}
meta={'phase':PHASE,'started':stamp(),'command':['/usr/bin/python3','-B',str(ROOT/'scripts/firecracker_code.py'),'vuln-unit'],
      'limits':{'wall_s':240,'cpu_s':20,'parent_as_soft_bytes':268435456,'parent_as_hard_bytes':1073741824,'profile_cli_as_bytes':1073741824,'resident_reserve_bytes':5000000000,'fsize_bytes':4194304,'log_bytes':2097152,'polls':48,'poll_max_s':5},
      'mem_available_before':mem_available,'owned_resident_policy':'existing profile refuses every other project-labeled container before guard/create','sysctls_before':sysctls(),'source_before':hashes(),'terminal_known':False,'cleanup_independent_observation':False}
if meta['sysctls_before']!=EXPECTED: raise RuntimeError('protected sysctl baseline mismatch; no profile launched')
OUT.mkdir(parents=True,exist_ok=True)
flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
logfd=os.open(OUT/(PHASE+'.log'),flags,0o600)
metafd=os.open(OUT/(PHASE+'.json'),flags,0o600)
p=None
sel=selectors.DefaultSelector()
class Stop(Exception): pass
def deadline(signum,frame):
    if p is not None and p.poll() is None:
        try: os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError: pass
    os.write(2,b'240s outer deadline: terminal/cleanup and final metadata unknown; STOP\n')
    os._exit(124)
signal.signal(signal.SIGALRM,deadline)
signal.setitimer(signal.ITIMER_REAL,max(0.001,240-(time.monotonic()-started)))
try:
    p=subprocess.Popen(meta['command'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=profile_limits,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    os.set_blocking(p.stdout.fileno(),False)
    sel.register(p.stdout,selectors.EVENT_READ)
    total=0
    for poll in range(48):
        meta['polls_used']=poll+1
        remaining=235-(time.monotonic()-started)
        if remaining<=0: raise Stop('wall deadline')
        ready=sel.select(min(5,remaining))
        if ready:
            chunk=os.read(p.stdout.fileno(),65536)
            if chunk:
                if total+len(chunk)>2097152: raise Stop('combined log limit; output incomplete')
                view=memoryview(chunk)
                while view: view=view[os.write(logfd,view):]
                total+=len(chunk)
            else:
                sel.unregister(p.stdout)
                break
        elif p.poll() is not None:
            continue
    else:
        raise Stop('finite poll limit; terminal/cleanup unknown')
    rc=p.wait(timeout=min(5,max(0.001,240-(time.monotonic()-started))))
    meta.update(returncode=rc,terminal_known=True,log_bytes=total)
except BaseException as exc:
    meta['failure']=type(exc).__name__+': '+str(exc)
    if p is not None and p.poll() is None:
        os.killpg(p.pid,signal.SIGKILL)
        try: meta['native_kill_returncode']=p.wait(timeout=1)
        except subprocess.TimeoutExpired: meta['native_kill_returncode']='unknown'
finally:
    sel.close()
    if p is not None and p.stdout is not None: p.stdout.close()
    meta['finished']=stamp()
    meta['elapsed_s']=time.monotonic()-started
    meta['sysctls_after']=sysctls()
    meta['sysctls_unchanged']=meta['sysctls_after']==meta['sysctls_before']
    meta['source_after']=hashes()
    meta['source_unchanged']=meta['source_after']==meta['source_before']
    os.fsync(logfd)
    os.close(logfd)
    raw=(json.dumps(meta,indent=2,sort_keys=True)+'\n').encode()
    view=memoryview(raw)
    while view: view=view[os.write(metafd,view):]
    os.fsync(metafd)
    os.close(metafd)
signal.setitimer(signal.ITIMER_REAL,0)
print(json.dumps(meta,sort_keys=True))
if not meta['terminal_known'] or not meta['sysctls_unchanged'] or not meta['source_unchanged']: raise SystemExit(125)
raise SystemExit(meta['returncode'])
PY
```
