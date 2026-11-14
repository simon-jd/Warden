# Task 15 fix 1/5: two-regression semantic RED caller (inert)

This is preparation only. SOURCE/index owner has **not** run tests, a guard,
Grype, Docker, Go, Kyverno, a formatter, or any download. Root must fully read
the body and independently approve a fresh external guard before its one run.
The fixed Grype v0.121.0 profile fixture uses the JSON tags in
[`options/grype.go`](https://github.com/anchore/grype/blob/v0.121.0/cmd/grype/cli/options/grype.go),
including `include-matcher-suppressions`, whose default is false. Severity
`Unknown` is valid in pinned
[`severity.go`](https://github.com/anchore/grype/blob/v0.121.0/grype/vulnerability/severity.go).

Fresh-base HEAD: `26405c9a0aed8ae53889a831e2ba94cc37d2944f`.
The only changed runtime input is the test file; production is still the old
behavior so two business assertions should genuinely fail. The selected
suite contains **only**
`AssessScanTests.test_actual_grype_configuration_must_prove_unfiltered_scan`
and `AssessScanTests.test_severity_must_be_valid_before_release_decision`.
The old fifteen tests, renderer, old RED/GREEN archives, CLI, and build are not
run. `Unknown` is a positive control in the second test for the future cover.

| Frozen input | Bytes | SHA-256 |
| --- | ---: | --- |
| `scripts/supplychain.py` | 15169 | `22c7197f10e8aba303d8e316cd9cec6219c8b4f4071ef1bd7f00c7902ea0b88f` |
| `scripts/test_supplychain.py` | 13828 | `18981ab88c94af6c3244e77472dea4c5ff9332aa53b6141013685977643a7b51` |

Run once from `/home/postedism/Desktop/Warden`. The atomic `mkdir` must prove
`/tmp/warden-task15-fix1-red-18981ab8-22c7197f` did not exist. Keep the
new namespace and all files on failure; no retry or cleanup. The entire
caller is bounded by 89 s TERM plus 1 s KILL, with Python's internal 88 s
alarm. AS 1 GiB, CPU 45 s, individual FSIZE 32 MiB, CORE 0, NOFILE 64.
The full new disk allowance is 256 MiB, plus conservative 128 KiB for the
two already retained Task 15 `/tmp` trees and untouched Q=5,000,000,000 B:
fresh R + Q + 268,435,456 + 131,072 <= 12,000,000,000 B. Reserve the old
UNKNOWN 9,000,000,000 B plus new 1 GiB = 10,073,741,824 B under the 16 GB
service ceiling. Do not use stale R or scan old PIDs/RSS/scene. No HOME,
umask, binary mode, network, child process, service, cloud, host, GPU,
registry, or publication action.

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
    'scripts/supplychain.py': (15169, '22c7197f10e8aba303d8e316cd9cec6219c8b4f4071ef1bd7f00c7902ea0b88f'),
    'scripts/test_supplychain.py': (13828, '18981ab88c94af6c3244e77472dea4c5ff9332aa53b6141013685977643a7b51'),
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
n = parent / 'warden-task15-fix1-red-18981ab8-22c7197f'
os.mkdir(n, 0o700)
os.chmod(n, 0o700)  # Newly owned namespace only; inherited umask untouched.
nst = n.lstat()
if not stat.S_ISDIR(nst.st_mode) or nst.st_uid != 1000 or stat.S_IMODE(nst.st_mode) != 0o700:
    raise SystemExit('new namespace owner/mode mismatch; preserve it')
ndir = os.open(n, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
def new_file(name):
    return os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=ndir), 'w', encoding='utf-8')
with new_file('status.txt') as status:
    status.write('STARTED; real crypto cases UNRUN\n')
    status.flush()
    try:
        with new_file('unittest.txt') as log:
            spec = importlib.util.spec_from_file_location(
                'task15_fix1_tests', str(Path('scripts/test_supplychain.py').resolve()))
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            names = (
                'test_actual_grype_configuration_must_prove_unfiltered_scan',
                'test_severity_must_be_valid_before_release_decision',
            )
            suite = unittest.TestSuite(module.AssessScanTests(name) for name in names)
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
            failures = {test._testMethodName for test, _ in result.failures}
            expected = (result.testsRun == 2 and failures == set(names)
                        and len(result.failures) == 2 and not result.errors
                        and not result.skipped)
            status.write(f'tests={result.testsRun} failures={len(result.failures)} errors={len(result.errors)} skips={len(result.skipped)}\n')
            status.write('EXPECTED I2/I3 SEMANTIC RED; crypto UNRUN\n' if expected else 'UNEXPECTED RESULT; stop\n')
            status.flush()
    except BaseException as exc:
        status.write('ERROR; stop; ' + type(exc).__name__ + '\n')
        status.flush()
        raise
os.close(ndir)
raise SystemExit(0 if expected else 2)
PY
```

Expected observation is two assertion failures, zero errors/skips, with
the new profile test listing unsafe configurations the old assessor accepted
and the severity test listing malformed values it accepted. The caller's
exit 0 means that **RED was observed**, not that security admission passed.
