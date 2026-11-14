# Task14 formatter command (INERT)
Static implementation and tests are written; no Go/tests/formatter have run since accepted first RED. Please admit at most this one formatting operation before cover freeze. No test/GREEN is included. The five frozen files/hashes are below. Fixed cached bin/gofmt is UID1000 regular non-symlink executable, 3110743B (static metadata only). Its fixed src/cmd/gofmt/gofmt.go uses counter.Open; existing TEST_TELEMETRY_DIR/mode off prevents HOME writes. The standard -w path briefly creates same-directory <source>.<random> backup files and removes them on success (read writeFile/backupFile statically); these transient formatter backups need inclusion in this exact operation, not new product files. On any error stop, retain output/backups, no retry.

Prospective native command: timeout --signal=TERM --kill-after=1s 9s python3 -B - with this stdin, workdir /home/postedism/Desktop/Warden; total10s INCLUDING kill grace. The Python process execs the sole gofmt, so no Python-owned child group/reaping protocol. CPU10s/AS4GiB/FSIZE65536 perprocess, GOMAXPROCS2/GOMEMLIMIT512MiB cooperative. Each source is currently<19KiB; stdout/stderr each max64KiB via same FSIZE (distinct files). New namespace protects raw output/config, source backup peak<256KiB; count it in existing full1GiB reserve. No HOME or umask changes. Root retains actual request/result and afterwards reads the 2 raw files and exact five source hashes. No fresh Go env/version, no Go cache, services/network/download/Git.
```python
import hashlib,os,pathlib,resource,stat
W=pathlib.Path("/home/postedism/Desktop/Warden")
G=W/".cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64"
N=W/".cache/task14-format-20261025-a"
F={
"respond/actions.go":"6bd24e83b1f7a0bdeae023d82d752cb32085d2f5b325643b876625b3a517b04e",
"respond/executor.go":"a6a4a701f5b3aed26bea9a99ba5f8edadb49715c60bac96b08474d0506743581",
"respond/ledger.go":"f9bb1cc5f0018a99a16e3a997febe7afa883ec8aad33a4efbf086ad670e6e644",
"respond/executor_test.go":"e557d744fd96fba4de532e350ca6a36358e1b3ed2836cdf52447b86fa701adfc",
"respond/ledger_test.go":"115959fc251fca12db48e02179d3e6151589668346b6edb09c79f2e4dd879e07"}
assert os.getuid()==1000 and os.geteuid()==1000 and not os.path.lexists(N)
assert {k:hashlib.sha256((W/k).read_bytes()).hexdigest() for k in F}==F
s=os.lstat(G/"bin/gofmt")
assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_mode&0o111
N.mkdir(mode=0o700)
for part in ["telemetry","config/go/telemetry"]:
 (N/part).mkdir(parents=True,exist_ok=True)
 (N/part/"mode").write_text("off\n")
env=os.environ.copy()
for k in list(env):
 if k.startswith("GO") or k=="TEST_TELEMETRY_DIR": del env[k]
env.update({"GOROOT":str(G),"GOENV":"off","GOTOOLCHAIN":"local","GOPROXY":"off",
"GOSUMDB":"off","GOMAXPROCS":"2","GOMEMLIMIT":"512MiB",
"TEST_TELEMETRY_DIR":str(N/"telemetry"),"XDG_CONFIG_HOME":str(N/"config"),
"TMPDIR":str(N),"PATH":"/usr/bin:/bin"})
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
resource.setrlimit(resource.RLIMIT_AS,(4294967296,4294967296))
resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536))
for fd,name in [(1,"stdout.raw"),(2,"stderr.raw")]:
 out=os.open(N/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 os.dup2(out,fd)
 os.close(out)
os.execve(str(G/"bin/gofmt"),[str(G/"bin/gofmt"),"-w",*F],env)
```
