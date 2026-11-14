# Task15 first semantic RED caller — inert, do not execute yet

Fresh BASE `6f8af6e6d672feb25d254729aa99c7ffe82bf4e7`; only the two new `scripts/` inputs belong to this step. Frozen bytes/SHA-256:

The synthetic JSON field locations follow pinned Grype v0.121.0 primary [Document](https://github.com/anchore/grype/blob/v0.121.0/grype/presenter/models/document.go), [source](https://github.com/anchore/grype/blob/v0.121.0/grype/presenter/models/source.go), [descriptor](https://github.com/anchore/grype/blob/v0.121.0/grype/presenter/models/descriptor.go), and [vulnerability metadata](https://github.com/anchore/grype/blob/v0.121.0/grype/presenter/models/vulnerability_metadata.go). `descriptor.db` is an opaque `any`; the synthetic marker proves neither a real DB structure nor KEV source freshness. Resolve those before GREEN/release logic.

| input | bytes | SHA-256 |
| --- | ---: | --- |
| `scripts/supplychain.py` | 3062 | `9ffe58a919687766824e2974a096086a661af91e5e0c3f0aad89f35c36b88756` |
| `scripts/test_supplychain.py` | 4835 | `b5d6dcbd1861319934c18a95f304872e3b21005915ff2c455cdac8b0f7dc7b24` |

Root must first read this caller and separately admit a fresh resource guard. Complete new disk allowance is 256 MiB (source 64 + temp 128 + output 64), *additional* Q 5 GB remains reserved; old R about 5.03 GB plus Q plus 256 MiB is below 12 GB only if fresh measurements confirm. New resident allowance 1 GiB plus old UNKNOWN 9 GB stays below 16 GB, also subject to fresh guard. No old PID/RSS/scene scan, no Q release. This command is not authorized to run by this note. It invokes only Python stdlib tests of these two files; no Go/Kyverno, download, package install, executable-mode change, HOME/umask change, service, cloud, or publication. The two files are synthetic local semantics, not the three real cryptographic admissions.

Run once only from `/home/postedism/Desktop/Warden`, after root's fresh guard. Whole caller including setup/status is bounded by 89 seconds plus 1 second kill grace. Its sole new namespace is an exact never-created private `/tmp` name; if it already exists, stop with no retry or deletion. All acquired output is preserved on failure or timeout.

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
pstat = parent.lstat()
if not stat.S_ISDIR(pstat.st_mode) or pstat.st_uid != 0 or not pstat.st_mode & stat.S_ISVTX:
    raise SystemExit('unsafe /tmp parent')
frozen = {
    'scripts/supplychain.py': ('9ffe58a919687766824e2974a096086a661af91e5e0c3f0aad89f35c36b88756', 3062),
    'scripts/test_supplychain.py': ('b5d6dcbd1861319934c18a95f304872e3b21005915ff2c455cdac8b0f7dc7b24', 4835),
}
for name, (expected_hash, expected_size) in frozen.items():
    path = Path(name)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 1000 or st.st_size != expected_size:
        raise SystemExit('changed input: ' + name)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
        raise SystemExit('changed input hash: ' + name)
n = parent / 'warden-task15-first-red-9ffe58a9-b5d6dcbd'
os.mkdir(n, 0o700)  # O_EXCL semantics; preexisting path raises and is untouched.
os.chmod(n, 0o700)  # Only our just-created namespace; inherited umask is unchanged.
nst = n.lstat()
if not stat.S_ISDIR(nst.st_mode) or nst.st_uid != 1000 or stat.S_IMODE(nst.st_mode) != 0o700:
    raise SystemExit('new namespace owner/mode mismatch; preserve it')
ndir = os.open(n, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
def new_file(name):
    return os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=ndir), 'w', encoding='utf-8')
with new_file('status.txt') as status, new_file('unittest.txt') as log:
    status.write('STARTED; no acceptance claim\n')
    status.flush()
    try:
        spec = importlib.util.spec_from_file_location('task15_supplychain_tests', str(Path('scripts/test_supplychain.py').resolve()))
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        failed = {case.id().split('.')[-1] for case, _ in result.failures}
        expected = {
            'test_valid_binding_covers_every_image_and_exact_identity',
            'test_fixable_critical_blocks_unfiltered_scan',
            'test_not_fixed_kev_still_blocks',
            'test_related_kev_cve_is_not_lost',
        }
        red = result.testsRun == 8 and not result.errors and failed == expected
        status.write(f'tests={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}\n')
        status.write('SEMANTIC RED; real crypto cases UNRUN\n' if red else 'UNEXPECTED RESULT; stop\n')
        status.flush()
    except BaseException as exc:
        status.write('ERROR; stop; ' + type(exc).__name__ + '\n')
        status.flush()
        raise
os.close(ndir)
raise SystemExit(1 if red else 2)
PY
```

Expected result is eight tests, four ordinary assertion failures and zero errors; exit 1 means only that local semantic RED occurred. Any other result, timeout, stale inputs, or unsafe namespace stops the phase. The first RED gives no signature, provenance, database freshness, or cluster admission PASS. No cleanup deletes `n`; root decides the next step after inspecting status and output.
