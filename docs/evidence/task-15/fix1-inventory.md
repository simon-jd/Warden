# Task 15 fix 1/5 actual-byte inventory

Base: `26405c9a0aed8ae53889a831e2ba94cc37d2944f`. Fix1 SOURCE commit: `0fefe2627e7c765fd8cc055fad0b1e30e2388897`.
SOURCE: 6 paths, 44608 bytes. Raw fix1 evidence: 14 unchanged paths, 83029 bytes.

| SOURCE path | Bytes | SHA-256 |
| --- | ---: | --- |
| `controlplane/Dockerfile` | 801 | `ccc26e9888ccb042a1d95d17c26ab0194134388c119c0b0ba8faac4f34d42cc9` |
| `.dockerignore` | 257 | `eaa6f1331a6f1c3ea3b886b15022f9bf5d23d674fe0b089b8f6932f9d5d11de9` |
| `.github/workflows/build.yml` | 7612 | `5a45bbea80b358c4c8fc8467f683a006e6cb9b696dcbb77927bb376734a06427` |
| `scripts/supplychain.py` | 16426 | `237cac53e63b83bada908cffb9703a1492f3c06794516f8629d5527377320c28` |
| `scripts/test_supplychain.py` | 13828 | `18981ab88c94af6c3244e77472dea4c5ff9332aa53b6141013685977643a7b51` |
| `policies/kyverno/README.md` | 5684 | `83409c4076ed8618817b01734b66cd40d619e8cda95ce9e2179a7796571dd6f7` |

| Raw evidence path | Bytes | SHA-256 |
| --- | ---: | --- |
| `docs/evidence/task-15/fix1-red-first-20261025/command.py.txt` | 3820 | `9816cf4947e25c16daf1312a7d2315bc4d482f615e78f5b9c164e377146823e6` |
| `docs/evidence/task-15/fix1-red-first-20261025/inert-caller.md` | 6540 | `2d4c1abfe57b009bbfbaaa5b98f5729477908555e93705d5daf070af53f701d3` |
| `docs/evidence/task-15/fix1-red-first-20261025/native-events.json` | 13233 | `3bc09eca4a27f86efaf1a58c1d5a72a128d654cb07514ef3d9931ef8fb43e342` |
| `docs/evidence/task-15/fix1-red-first-20261025/postread.json` | 532 | `186757698065e552f2b2132ffbdf27df177b8127356008325c3da03da84ad899` |
| `docs/evidence/task-15/fix1-red-first-20261025/status.txt` | 111 | `3993f48fc726cc1ef9f43db60f1d780a63edffef17a255e813e6f5467d0e27a7` |
| `docs/evidence/task-15/fix1-red-first-20261025/supplychain.py.txt` | 15169 | `22c7197f10e8aba303d8e316cd9cec6219c8b4f4071ef1bd7f00c7902ea0b88f` |
| `docs/evidence/task-15/fix1-red-first-20261025/test_supplychain.py.txt` | 13828 | `18981ab88c94af6c3244e77472dea4c5ff9332aa53b6141013685977643a7b51` |
| `docs/evidence/task-15/fix1-red-first-20261025/unittest.txt` | 2656 | `fbf771a2947530c94bc40d98689973080738b9a3bd28855f8cb77c4a79e92f90` |
| `docs/evidence/task-15/fix1-cover-first-20261025/command.py.txt` | 3895 | `c994addf992706a8ff72589880e934f086876e5ba16c492997dfa11d89620e51` |
| `docs/evidence/task-15/fix1-cover-first-20261025/inert-caller.md` | 7960 | `ccb29b0f560c80b304c5950a55fc7fcd0d9e467601865b8f15bdb046f47a930b` |
| `docs/evidence/task-15/fix1-cover-first-20261025/native-events.json` | 12737 | `613555c919a0de459205bda4cfc3955d86b32f447ba11e104049a4abef618418` |
| `docs/evidence/task-15/fix1-cover-first-20261025/postread.json` | 586 | `8bc77e7a9362220b430ac88c5a425990e0511424dd9832e262ffc2045a7c102b` |
| `docs/evidence/task-15/fix1-cover-first-20261025/status.txt` | 117 | `eb21a45d63eed79ea13840b1e0ed44902b43a5544c7723164d633d1785304c58` |
| `docs/evidence/task-15/fix1-cover-first-20261025/unittest.txt` | 1845 | `6882676be90b43ac2042a3761595d13f91a4a0f8c2e632dfdf3903ff10aec078` |

The first RED (8 tests, 4 semantic failures), prior 15-test local cover, and first independent review remain in their earlier commits. This inventory records only the fix1 frozen SOURCE and the two new root-authorized raw directories; no raw file was rewritten.
