# Task 15 frozen source and raw evidence inventory

Base: `6f8af6e6d672feb25d254729aa99c7ffe82bf4e7`. SOURCE commit: `75a141d22f57160e5d6d758ae468152430e82ec0`. Source total: 10 paths, 42,326 bytes. The cover caller checked these same bytes and hashes before loading the tests.

| SOURCE path | Bytes | SHA-256 |
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

The following 14 files are the first RED and first local cover originals. The source author did not rewrite them. Paths below are relative to `docs/evidence/task-15/`.

| Raw evidence path | Bytes | SHA-256 |
| --- | ---: | --- |
| `semantic-red-first-20261025/command.py.txt` | 3514 | `26d6280ec0540a712b627198e28a37fadc1e69c0a57dc47dd27591c2a686dca2` |
| `semantic-red-first-20261025/inert-caller.md` | 6200 | `1ed8188115a57edcf2b96a771e26112f0488cfe7e0822c99e4fba7a00f232fe7` |
| `semantic-red-first-20261025/native-events.json` | 5724 | `9dfd1bfa6a84055ae376a1fc75a0032f763e8c8e2bc7cd850587a6b282cfdf23` |
| `semantic-red-first-20261025/postread.json` | 533 | `63d5b8c5841d4a857ee318413d2abf01bf01da85f2fd7449a6e906bc1be4d872` |
| `semantic-red-first-20261025/status.txt` | 95 | `448c1d9cfcf7726c3131359d25ed8983085d4a997acc454176c7c21dd127fd37` |
| `semantic-red-first-20261025/supplychain.py.txt` | 3062 | `9ffe58a919687766824e2974a096086a661af91e5e0c3f0aad89f35c36b88756` |
| `semantic-red-first-20261025/test_supplychain.py.txt` | 4835 | `b5d6dcbd1861319934c18a95f304872e3b21005915ff2c455cdac8b0f7dc7b24` |
| `semantic-red-first-20261025/unittest.txt` | 3554 | `ef99a38fb210bea63899fdeb614b222340b3b53e45a236abefaa48cb35fa17af` |
| `local-cover-first-20261025/command.py.txt` | 4279 | `c0f022e8f37ef1a9813d5c7466ea0166cdf617ac33da3756a08525c99d6f86b7` |
| `local-cover-first-20261025/inert-caller.md` | 7158 | `bb9512d2f009a20b339a3979a8c257de47a365d95d40754913462459e08c1e8e` |
| `local-cover-first-20261025/native-events.json` | 8279 | `bfd6b356253653f88b323cac87f3fb18e1b14618a53ceafc58dc146e93010e0e` |
| `local-cover-first-20261025/postread.json` | 555 | `8274303b13c90dd11349c1bb85f6c42a5deb99e6c8f472dcd7374d4c16dbc4d9` |
| `local-cover-first-20261025/status.txt` | 105 | `e46a66672f03757499cd35a2c88022b54374de917be170a462d8ae11f2a63a9b` |
| `local-cover-first-20261025/unittest.txt` | 2149 | `fd470a777bf7fd1fcae835b443724db77972fcb0256f9c7b7d84d07443f33ff8` |
