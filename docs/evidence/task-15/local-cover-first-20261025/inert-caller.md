# Task15 single local semantic cover — inert, root admission required

SOURCE owner froze only ten allowed new paths at BASE
`6f8af6e6d672feb25d254729aa99c7ffe82bf4e7`; no tests, formatter, CLI,
build, stage or commit has been run. The separate first RED archive remains
unchanged. Before running this exact caller, root must read it and perform a
fresh external guard. New disk maximum is 256 MiB total (64 MiB source,
128 MiB temporary, 64 MiB output); include the *retained first-RED /tmp
namespace* separately in existing occupancy, keep Q=5 GB untouched, and
verify old R plus Q plus new <=12 GB. New resident cap is 1 GiB plus old
UNKNOWN 9 GB <=16 GB. No old PID/RSS/scene scan or retry. The command does
not run Go/Kyverno, use the downloaded CLI, alter HOME/umask, start a service
or child process, or publish. It is local JSON/stdlib semantic coverage,
not a cryptographic acceptance test.

| Frozen input | Bytes | SHA-256 |
| --- | ---: | --- |
| `controlplane/Dockerfile` | 647 | `8c6adcae98dbd9b8197ea4554dd09a101e079f9b581d29a91994ed4d09b8bf95` |
| `.dockerignore` | 51 | `9e346865f8214e263743827f2da07ce83ee385dd4e489976c65309a5c8b27397` |
| `.github/workflows/build.yml` | 7559 | `29c091f6af58b0ef8a3f1ffc361c92b6ba6b418271038ca34d29a340d14e75bd` |
| `scripts/supplychain.py` | 15169 | `22c7197f10e8aba303d8e316cd9cec6219c8b4f4071ef1bd7f00c7902ea0b88f` |
| `scripts/test_supplychain.py` | 10466 | `968f62dec23e4e5e39f9e85d5b80f8c3a3fc5575b1b3ec214a10f83a7587af63` |
| `policies/kyverno/README.md` | 5223 | `98c64f2204d98ec54aad8b51f78b51dfb39cfa1700a738667e20fc49a8365c4a` |
| `policies/kyverno/verify-images.yaml` | 650 | `9b0b0a606cc9db0f1e065d896ef8919b6a2e5cfbd93f8ba8e723e6dc3ec66165` |
| `policies/kyverno/block-kev.yaml` | 600 | `c40f729e6a64e39449afdf4cd4fcaf699ccde6cbf80f8d6d65b30f6a98059005` |
| `policies/kyverno/tests/kyverno-test.yaml` | 1019 | `b2f91bc96247c0920591e81d9d09d09afe063ec68f9354353b03f50093845095` |
| `policies/kyverno/tests/resources.yaml` | 942 | `331955e3152d9a0b28eea960ba32463e09207ebd1475a83ab955740d8febcc62` |

Run once from `/home/postedism/Desktop/Warden` only after root's
separate fresh guard. Whole 89s TERM + 1s KILL includes Python setup,
test execution and status output. A pre-existing namespace means stop,
preserve it, and do not retry. All failures preserve the new namespace
and any written output.

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
    'controlplane/Dockerfile': (647, '8c6adcae98dbd9b8197ea4554dd09a101e079f9b581d29a91994ed4d09b8bf95'),
    '.dockerignore': (51, '9e346865f8214e263743827f2da07ce83ee385dd4e489976c65309a5c8b27397'),
    '.github/workflows/build.yml': (7559, '29c091f6af58b0ef8a3f1ffc361c92b6ba6b418271038ca34d29a340d14e75bd'),
    'scripts/supplychain.py': (15169, '22c7197f10e8aba303d8e316cd9cec6219c8b4f4071ef1bd7f00c7902ea0b88f'),
    'scripts/test_supplychain.py': (10466, '968f62dec23e4e5e39f9e85d5b80f8c3a3fc5575b1b3ec214a10f83a7587af63'),
    'policies/kyverno/README.md': (5223, '98c64f2204d98ec54aad8b51f78b51dfb39cfa1700a738667e20fc49a8365c4a'),
    'policies/kyverno/verify-images.yaml': (650, '9b0b0a606cc9db0f1e065d896ef8919b6a2e5cfbd93f8ba8e723e6dc3ec66165'),
    'policies/kyverno/block-kev.yaml': (600, 'c40f729e6a64e39449afdf4cd4fcaf699ccde6cbf80f8d6d65b30f6a98059005'),
    'policies/kyverno/tests/kyverno-test.yaml': (1019, 'b2f91bc96247c0920591e81d9d09d09afe063ec68f9354353b03f50093845095'),
    'policies/kyverno/tests/resources.yaml': (942, '331955e3152d9a0b28eea960ba32463e09207ebd1475a83ab955740d8febcc62'),
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
n = parent / 'warden-task15-green-22c7197f-968f62de'
os.mkdir(n, 0o700)
os.chmod(n, 0o700)  # Only the newly owned namespace; inherited umask unchanged.
nst = n.lstat()
if not stat.S_ISDIR(nst.st_mode) or nst.st_uid != 1000 or stat.S_IMODE(nst.st_mode) != 0o700:
    raise SystemExit('new namespace owner/mode mismatch; preserve it')
ndir = os.open(n, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
def new_file(name):
    return os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=ndir), 'w', encoding='utf-8')
with new_file('status.txt') as status, new_file('unittest.txt') as log:
    status.write('STARTED; real crypto cases UNRUN\n')
    status.flush()
    try:
        spec = importlib.util.spec_from_file_location(
            'task15_supplychain_tests', str(Path('scripts/test_supplychain.py').resolve()))
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        green = result.testsRun == 15 and result.wasSuccessful() and not result.skipped
        status.write(f'tests={result.testsRun} failures={len(result.failures)} errors={len(result.errors)} skips={len(result.skipped)}\n')
        status.write('LOCAL SEMANTIC GREEN; crypto UNRUN\n' if green else 'LOCAL COVER FAILED; stop\n')
        status.flush()
    except BaseException as exc:
        status.write('ERROR; stop; ' + type(exc).__name__ + '\n')
        status.flush()
        raise
os.close(ndir)
raise SystemExit(0 if green else 2)
PY
```

Expected only: 15 genuine stdlib tests passing, zero failures/errors/skips.
Exit 0 is **local semantic coverage**, not the original three
signature/provenance/KEV password acceptance cases. The verified CLI
execution remains closed until credential/cache write paths, genuine
registry artifacts, trust roots and the original three-case manifests
are separately admitted. No cleanup removes any failed evidence.
