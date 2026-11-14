# Task14 first RED caller (INERT)
BASE798bf98da93cd17d557d43efae0c60b44791fadf. Source: respond/actions.go2059B, executor.go1688B, executor_test.go4900B. Only original three tests; stub ErrNotImplemented. No Go yet.
Root FULLREAD/freezes inputs/body, grants actual permission, then same-dispatch unchanged scripts/azure_guard.py preflight --additional-bytes 6073741824 --service-memory-bytes 11000000000 --download-bytes 0 known0/raw fresh R; require R+Q5GB+1073741824<=12GB. No scene/cache scan here.
Prospective python3 -B stdin, cwd Warden, external90s (work75/cleanup10/kill5), yield<=1000ms/poll<=60s; root retains exact tool events. CPU60/AS4GiB/FSIZE256MiB perprocess, not aggregate. GOMEMLIMIT768MiB/GOMAX2/-p1 cooperative, not RSS quota; new2GB+old9GB<=16GB. New disk1073741824 includes source/cache/tmp/evidence; sampled namespace limit is not quota, can overshoot. Output combined64KiB separate from compile-file256MiB. Any timeout/resource/compile/unknown STOP; preserve raw prefix if overflow. Retain namespace for root; kill only own group.
Static Go-root reads: src/cmd/internal/telemetry/{telemetry.go,counter/counter.go}; src/cmd/vendor/golang.org/x/telemetry/{start.go,counter/counter.go,internal/telemetry/dir.go}; src/cmd/go/internal/telemetrycmd/telemetry.go; src/os/file.go. GOTELEMETRY non-settable; TEST_TELEMETRY_DIR + mode off disables counters/sidecar; XDG_CONFIG_HOME + mode off redirects defaults. HOME unchanged. No Go env/version/Docker/download.
Run only after external gate and explicit admission:
```python
import hashlib,json,os,pathlib,resource,selectors,signal,stat,subprocess,sys,time
W=pathlib.Path("/home/postedism/Desktop/Warden")
G=W/".cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64"
N=W/".cache/task14-first-red-20261025-a"
F={
"respond/actions.go":"8f9b25aa2824017c0ddb8b3a5acbe2f5c6e2a88aafff67e6ddac87b141259006",
"respond/executor.go":"1fd4224c4e5b6d04cbd9e1c4d16b2d3dcbf7baf5e08bfc6cfd01a9bf75913685",
"respond/executor_test.go":"d104aff34a26fe593d7955ddf0267590d8b3ecb0d966ae39a22c42ca60aecbe3",
"go.mod":"bad0afe37cbccb1da689ac5cff6dfd7edf741a977bcfa0d9d56928b91c6fa3aa",
"go.sum":"cf5570603c6b110aad01b4a6c8f99874f62a1f8394a5d109bb7b06b1b5efbaa0"}
def hashes():
 return {k:hashlib.sha256((W/k).read_bytes()).hexdigest() for k in F}
def mem():
 for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
  if line.startswith("MemAvailable:"): return int(line.split()[1])*1024
 raise RuntimeError("MemAvailable absent")
def usage():
 total=0
 for root,dirs,files in os.walk(N,followlinks=False):
  for name in dirs+files:
   try: s=os.lstat(os.path.join(root,name))
   except FileNotFoundError: continue
   if stat.S_ISLNK(s.st_mode): raise RuntimeError("namespace symlink")
   total+=s.st_blocks*512
 return total
assert os.getuid()==1000 and os.geteuid()==1000
assert mem()>=2000000000 and not os.path.lexists(N)
assert hashes()==F
assert sorted(p.name for p in (W/"respond").iterdir())==["actions.go","executor.go","executor_test.go"]
assert (G/"VERSION").read_text()=="go1.26.10\ntime 2026-10-19T22:20:36Z\n"
for rel in ["bin/go","pkg/tool/linux_amd64/compile"]:
 s=os.lstat(G/rel)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_mode&0o111
os.umask(0o077)
N.mkdir()
for part in ["cache","tmp","gopath","modcache","config/go/telemetry","telemetry"]:
 (N/part).mkdir(parents=True,exist_ok=True)
for part in ["config/go/telemetry/mode","telemetry/mode"]:
 (N/part).write_text("off\n")
env=os.environ.copy()
for k in list(env):
 if k.startswith("GO") or k in ["CGO_ENABLED","TEST_TELEMETRY_DIR"]:
  del env[k]
env.update({
"GOROOT":str(G),"GOENV":"off","GOWORK":"off","GOTOOLCHAIN":"local",
"GOPROXY":"off","GOSUMDB":"off","GOVCS":"*:off","CGO_ENABLED":"0",
"GOOS":"linux","GOARCH":"amd64","GOMAXPROCS":"2","GOMEMLIMIT":"768MiB",
"GOCACHE":str(N/"cache"),"GOTMPDIR":str(N/"tmp"),"TMPDIR":str(N/"tmp"),
"GOPATH":str(N/"gopath"),"GOMODCACHE":str(N/"modcache"),
"XDG_CONFIG_HOME":str(N/"config"),"TEST_TELEMETRY_DIR":str(N/"telemetry"),
"PATH":"/usr/bin:/bin"})
names=["TestPlaybookIdempotentPerAlert","TestDestructiveRequiresApproval","TestDryRunMakesNoChanges"]
argv=[str(G/"bin/go"),"test","-mod=readonly","-buildvcs=false","-vet=off","-p=1",
"-parallel=1","-count=1","-timeout=20s","-run","^("+"|".join(names)+")$","-v","./respond"]
(N/"request.json").write_text(json.dumps({"argv":argv,"cwd":str(W),"env_overrides":{
k:env[k] for k in env if k.startswith("GO") or k in ["CGO_ENABLED","TMPDIR","XDG_CONFIG_HOME","TEST_TELEMETRY_DIR","PATH"]},
"hashes":F,"limits":{"work":75,"cleanup":10,"kill":5,"cpu_perprocess":60,
"as_perprocess":4294967296,"file_perprocess":268435456,"output_combined":65536},
"pre_mem_available":mem()},sort_keys=True))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(60,60))
resource.setrlimit(resource.RLIMIT_AS,(4294967296,4294967296))
resource.setrlimit(resource.RLIMIT_FSIZE,(268435456,268435456))
start=time.monotonic()
p=None
sel=selectors.DefaultSelector()
files={}
reason=""
seen=0
try:
 for label in ["stdout","stderr"]: files[label]=open(N/(label+".raw"),"xb",buffering=0)
 p=subprocess.Popen(argv,cwd=W,env=env,stdin=subprocess.DEVNULL,
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 for pipe,label in [(p.stdout,"stdout"),(p.stderr,"stderr")]:
  os.set_blocking(pipe.fileno(),False)
  sel.register(pipe,selectors.EVENT_READ,label)
 while sel.get_map():
  if time.monotonic()-start>=75: reason="work_timeout"; break
  if usage()>900000000: reason="namespace_disk_stop"; break
  if mem()<2000000000: reason="MemAvailable_stop"; break
  for key,_ in sel.select(0.1):
   data=os.read(key.fileobj.fileno(),8192)
   if not data:
    sel.unregister(key.fileobj); key.fileobj.close(); continue
   keep=data[:max(0,65536-seen)]
   files[key.data].write(keep)
   seen+=len(keep)
   if len(keep)!=len(data): reason="output_truncated"; break
  if reason: break
 if not reason:
  try: p.wait(timeout=max(0.01,75-(time.monotonic()-start)))
  except subprocess.TimeoutExpired: reason="work_timeout"
except BaseException as e:
 reason="caller_exception:"+type(e).__name__
finally:
 sel.close()
 if p is not None:
  try:
   os.killpg(p.pid,0)
   os.killpg(p.pid,signal.SIGTERM)
   until=time.monotonic()+10
   while time.monotonic()<until:
    p.poll()
    try: os.killpg(p.pid,0)
    except ProcessLookupError: break
    time.sleep(0.05)
   try: os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError: pass
   try: p.wait(timeout=5)
   except subprocess.TimeoutExpired: reason="cleanup_unknown"
  except ProcessLookupError:
   p.wait(timeout=1)
 for f in files.values(): f.close()
def group_absent():
 if p is None: return True
 try: os.killpg(p.pid,0); return False
 except ProcessLookupError: return True
try:
 after=hashes()
 out=(N/"stdout.raw").read_bytes()
 err=(N/"stderr.raw").read_bytes()
 gone=group_absent()
 if after!=F: reason="source_changed"
 if not gone: reason="process_group_unknown"
 disk=usage()
 if disk>1073000000: reason="disk_budget_unknown"
 candidate=(not reason and p is not None and p.returncode==1 and not err
  and all(("--- FAIL: "+n+" ").encode() in out for n in names)
  and out.count(b"RED_REQUIRED")==3
  and out.count(b"respond executor not implemented")==3
  and b"[build failed]" not in out and b"--- SKIP:" not in out)
 r=resource.getrusage(resource.RUSAGE_CHILDREN)
 status={"decision":"STOP_FOR_ROOT","candidate_semantic_red":candidate,
  "go_returncode":None if p is None else p.returncode,"reason":reason,
  "raw_stdout_bytes":len(out),"raw_stderr_bytes":len(err),
  "post_hashes":after,"post_mem_available":mem(),"namespace_allocated_bytes":disk,
  "own_group_absent":gone,"elapsed_seconds":time.monotonic()-start,
  "children_cpu_seconds":r.ru_utime+r.ru_stime,"max_single_child_rss_kib":r.ru_maxrss}
 (N/"status.json").write_text(json.dumps(status,sort_keys=True))
 print(json.dumps(status,sort_keys=True))
except BaseException as e:
 print(json.dumps({"decision":"STOP_UNKNOWN","error":type(e).__name__}))
 sys.exit(2)
sys.exit(1 if candidate else 2)
```
STOP for root raw review; no GREEN/rerun. Close/journal/approval/adapters/live acceptance remain OPEN.
