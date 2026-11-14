# Task 15 fix 1/5: affected scan cover caller (inert)

Preparation only. Root must fully read this exact body and perform a fresh
external guard before the sole run. This caller selects **only the 13 top-level
`AssessScanTests` methods**; it does not rerun the four unchanged renderer
tests, the old 15-test batch, Docker, Grype, Go, Kyverno, or another task.
The new severity `Unknown` positive control now reaches its assertion.

Fresh-base HEAD: `26405c9a0aed8ae53889a831e2ba94cc37d2944f`.
Six authorized changed paths total 44,608 bytes are frozen below; no other
SOURCE was edited. The two policy files, renderer, and old test/evidence
archives remain unchanged.

| Frozen SOURCE input | Bytes | SHA-256 |
| --- | ---: | --- |
| `controlplane/Dockerfile` | 801 | `ccc26e9888ccb042a1d95d17c26ab0194134388c119c0b0ba8faac4f34d42cc9` |
| `.dockerignore` | 257 | `eaa6f1331a6f1c3ea3b886b15022f9bf5d23d674fe0b089b8f6932f9d5d11de9` |
| `.github/workflows/build.yml` | 7612 | `5a45bbea80b358c4c8fc8467f683a006e6cb9b696dcbb77927bb376734a06427` |
| `scripts/supplychain.py` | 16426 | `237cac53e63b83bada908cffb9703a1492f3c06794516f8629d5527377320c28` |
| `scripts/test_supplychain.py` | 13828 | `18981ab88c94af6c3244e77472dea4c5ff9332aa53b6141013685977643a7b51` |
| `policies/kyverno/README.md` | 5684 | `83409c4076ed8618817b01734b66cd40d619e8cda95ce9e2179a7796571dd6f7` |

Static Docker dependency closure: the real `controlplane/cmd/warden-api`
imports local control-plane packages; its scheduler and run packages import
`warden/runtimes`, `warden/runtimes/gate`, and `warden/runtimes/runc`. The runc
package imports `warden/policies/seccomp`, whose `policy.go` embeds
`default.json`; control-plane store also embeds its two SQL migrations.
The `.dockerignore` and Dockerfile now allow/copy precisely the needed
`runtimes/runtime.go`, gate, runc, and seccomp source subtrees alongside the
existing control-plane tree, while excluding tests and unrelated runtime
implementations. This is a static import/COPY check, **not** a Docker build.

The Grype profile is based on fixed v0.121.0
[`options.Grype` JSON tags](https://github.com/anchore/grype/blob/v0.121.0/cmd/grype/cli/options/grype.go)
and [`runGrype` matcher wiring](https://github.com/anchore/grype/blob/v0.121.0/cmd/grype/cli/commands/root.go).
The workflow uses documented `GRYPE_INCLUDE_MATCHER_SUPPRESSIONS=true`,
while the existing kernel-header CLI flag remains on. The assessor requires
all relevant fields and correct types, permits only empty filtering lists
(Go nil JSON null or []), rejects disabled suppression disclosure and
nonempty ignored matches. The fixed
[`severity.go`](https://github.com/anchore/grype/blob/v0.121.0/grype/vulnerability/severity.go)
recognizes legitimate Unknown separately from malformed values.

Execute once from `/home/postedism/Desktop/Warden` after root's own fresh
budget guard. Atomic `mkdir` must prove
`/tmp/warden-task15-fix1-cover-237cac53-18981ab8` was absent. Preserve
the new namespace and every output on failure; do not retry or clean it.
Whole 89 s TERM plus 1 s KILL contains Python setup, tests, and status
output; internal alarm 88 s. AS 1 GiB, CPU 45 s, FSIZE 32 MiB per file,
CORE 0, NOFILE 64. Full new disk budget is 256 MiB plus conservative
128 KiB for the **three** retained Task 15 `/tmp` trees, with Q5GB untouched:
fresh R + 5,000,000,000 + 268,435,456 + 131,072 <= 12,000,000,000 B.
Root must verify retained actual allocation remains under that conservative
allowance. Old UNKNOWN 9,000,000,000 B + new 1 GiB = 10,073,741,824 B
under the 16 GB service ceiling. No stale R, old PID/RSS/scene scan,
HOME/umask edit, new child process, network, binary mode change, service,
cloud, host, GPU, registry, or publication action.

```bash
/usr/bin/timeout --signal=TERM --kill-after=1s 89s /usr/bin/python3 -I -B - <<'PY'
import hashlib
import importlib.util
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import unittest

signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("caller deadline")))
signal.setitimer(signal.ITIMER_REAL, 88)
resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
resource.setrlimit(resource.RLIMIT_FSIZE, (32 << 20, 32 << 20))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
if os.getuid() != 1000 or Path.cwd() != Path('/home/postedism/Desktop/Warden'):
    raise SystemExit('wrong UID or cwd')
parent = Path('/tmp')
pst = parent.lstat()
if not stat.S_ISDIR(pst.st_mode) or pst.st_uid != 0 or not pst.st_mode & stat.S_ISVTX:
    raise SystemExit('unsafe /tmp')
frozen = {
    'controlplane/Dockerfile': (801, 'ccc26e9888ccb042a1d95d17c26ab0194134388c119c0b0ba8faac4f34d42cc9'),
    '.dockerignore': (257, 'eaa6f1331a6f1c3ea3b886b15022f9bf5d23d674fe0b089b8f6932f9d5d11de9'),
    '.github/workflows/build.yml': (7612, '5a45bbea80b358c4c8fc8467f683a006e6cb9b696dcbb77927bb376734a06427'),
    'scripts/supplychain.py': (16426, '237cac53e63b83bada908cffb9703a1492f3c06794516f8629d5527377320c28'),
    'scripts/test_supplychain.py': (13828, '18981ab88c94af6c3244e77472dea4c5ff9332aa53b6141013685977643a7b51'),
    'policies/kyverno/README.md': (5684, '83409c4076ed8618817b01734b66cd40d619e8cda95ce9e2179a7796571dd6f7'),
}
for name, (size, digest) in frozen.items():
    path = Path(name)
    for ancestor in (path.parent, *path.parents):
        if ancestor == Path('.'):
            continue
        ast = ancestor.lstat()
        if not stat.S_ISDIR(ast.st_mode) or ast.st_uid != 1000:
            raise SystemExit('unsafe input parent: ' + name)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 1000 or st.st_size != size:
        raise SystemExit('changed input: ' + name)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit('changed input hash: ' + name)
n = parent / 'warden-task15-fix1-cover-237cac53-18981ab8'
os.mkdir(n, 0o700)
os.chmod(n, 0o700)  # Only the new owned namespace; inherited umask untouched.
nst = n.lstat()
if not stat.S_ISDIR(nst.st_mode) or nst.st_uid != 1000 or stat.S_IMODE(nst.st_mode) != 0o700:
    raise SystemExit('new namespace owner/mode mismatch; preserve it')
ndir = os.open(n, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
def new_file(name):
    return os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=ndir), 'w', encoding='utf-8')
with new_file('status.txt') as status:
    status.write('STARTED; Docker/CI/Kyverno/crypto UNRUN\n')
    status.flush()
    try:
        with new_file('unittest.txt') as log:
            spec = importlib.util.spec_from_file_location(
                'task15_fix1_scan_tests', str(Path('scripts/test_supplychain.py').resolve()))
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.AssessScanTests)
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
            green = result.testsRun == 13 and result.wasSuccessful() and not result.skipped
            status.write(f'tests={result.testsRun} failures={len(result.failures)} errors={len(result.errors)} skips={len(result.skipped)}\n')
            status.write('AFFECTED LOCAL SCAN GREEN; crypto UNRUN\n' if green else 'AFFECTED COVER FAILED; stop\n')
            status.flush()
    except BaseException as exc:
        status.write('ERROR; stop; ' + type(exc).__name__ + '\n')
        status.flush()
        raise
os.close(ndir)
raise SystemExit(0 if green else 2)
PY
```

Expected result: 13 genuine scan tests pass, zero failures/errors/skips.
This is local parsing/decision coverage only, not Docker build, signature
verification, the three original real cases, or acceptance of Task 15.
