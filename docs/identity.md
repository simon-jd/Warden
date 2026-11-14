# 身份：Entra OIDC 与 SCIM（Task 6）

2026-11-10（太平洋时间，UTC 已是 11-11）在 home-ubuntu 上对真实 Entra 租户（东北大学的组织目录，用户不是管理员）实测。下面每个数字都来自 [evidence/task-6/](evidence/task-6/) 里已提交的文件；租户 ID 写成 `<tenant-id>`，用户对象 ID 写成 `<user-oid>`，令牌、用户名、SCIM 令牌和数据库密码都已替换，写盘前脚本会检查有没有残留（包括任何像 JWT 的字符串）。

## 结论

- **OIDC：通过（两次 17/17，过期令牌 4/4）。** Entra 给 `warden-lab-api` 签发的真实 v2 委托令牌（Azure CLI 以用户身份申请 `warden.access`），由本仓库构建的 `warden-api` 用租户真实的 issuer 和 JWKS 验证，Postgres 18 是临时容器：已开通的用户 `POST /v1/runs` 得 201，`GET` 读回 200（`queued`）。没有令牌、未开通的用户、别的资源（Azure Resource Manager）的令牌、改过 payload 或签名的令牌、`alg=none`、过期的真实令牌、受众是别的应用的 Warden，全部 401。
- **分配 / 取消分配（Entra 侧）：** 应用要求分配（`app_role_assignment_required`）。分配前 Entra 拒绝签发（AADSTS50105）；分配后第一次拿到令牌用了 51.2 s，再次分配用了 8.7 s。取消分配后 12.5 s 起 Entra 不再签发新令牌。
- **取消分配不会传到 Warden：** 取消分配前签发的令牌在 Warden 上一直有效（当时还剩 4417 s，约 74 min），因为没有 SCIM，Warden 的目录里这个用户仍是 active。手工通过 Warden 自己的 SCIM 端点停用后，下一次请求就是 401（47 ms 内，含 PATCH 本身）。所以“在 IdP 里取消分配，控制面同步变化”这一项 **没有达到**：缺的正是 Entra 开通服务。
- **SCIM（Entra 开通服务）：不做（最终）。** 只做了只读检查：程序化配置开通要 `Synchronization.ReadWrite.All`，需要管理员同意；Azure CLI 拿不到这个 scope（AADSTS65002）；用户的令牌读自己服务主体的同步作业也是 401。用户 2026-11-11 决定不做真实 SCIM：之前试过，学校账号注册不了。所以上一条“控制面同步变化”这一项保持没达到。详见下文“SCIM”。

## 应用注册

定义在 [identity/terraform/idp.tf](../identity/terraform/idp.tf)，用 `.tools/` 里的 terraform 1.17.1（zip 的 SHA-256 来自 HashiCorp 签名的 SHA256SUMS，签名用主钥 `C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F` 验过）和锁定的 `hashicorp/azuread` 3.10.0 创建与删除；state 放在 `.cache`（不进 git）。`make test-terraform` 跑 `fmt -check` 和 `validate`：每次 terraform 调用都在新的网络命名空间里（`bwrap --unshare-net`：只有回环 lo，bwrap 会把它启用，地址 127.0.0.1/8；没有别的网卡，[记录](evidence/task-6/bwrap-netns-lo-20261112.txt)），provider 只从 `.cache/terraform/plugins` 取（`-plugin-dir`，不回退到 registry，按锁文件核对哈希），缓存里没有就失败并提示先联网跑一次 `make terraform-plugins`（[记录](evidence/task-6/test-terraform-offline-20261112.txt)：通过；缺 provider 时失败；同样的命名空间里去 registry 的 init 连 DNS 都失败）。2026-11-10 的版本把第一次 `-plugin-dir` init 的输出丢掉，失败就静默改成联网 init，`env -i` 又让失效代理挡不住 terraform，所以那时说的“离线”没有证明，当时是否用到联网回退也没有记录；`scripts/test_idp_tf.py`（在 `make test` 里）检查下面这些性质，并核对 scope 名和 `authn` 的 `requiredScope` 一致。

| 设置 | 值 | 为什么 |
|---|---|---|
| `sign_in_audience` | `AzureADMyOrg` | 验证器只认一个租户 |
| `api.requested_access_token_version` | 2 | 这样 iss 才是 `https://login.microsoftonline.com/<tenant-id>/v2.0`、`ver` 是 `2.0`、`aud` 是 client ID（GUID）——验证器只接受这种 |
| 委托 scope | `warden.access`（User 类型，固定 ID `eb84a779-…`） | 验证器要求 `scp` 含 `warden.access` |
| identifier URI | `api://<client_id>` | 客户端申请 `api://<client_id>/warden.access` |
| 预授权客户端 | Azure CLI `04b07795-8ddb-461a-bbee-02f9e1bf7b46`（变量，lab 默认） | 不弹同意页就能以用户身份拿令牌 |
| 凭证 | 无密码、无证书、无联合凭证 | API 只验令牌，从不以自己的身份调用 Entra |
| 服务主体 | `app_role_assignment_required = true` | 只有被分配的用户能拿到令牌 |
| 名称 / 标签 / 所有者 | `warden-lab-api`；`project=warden`、`owner=warden-lab`、`ttl=2026-11-11T06:00:00Z`、`est_usd_per_hour=0`；所有者只有用户本人 | 用户定的 lab 规则 |

验证器需要的 `oid`、`sub`、`scp` 是委托令牌的默认声明，没有配置可选声明。实测令牌的声明名：`aio aud azp azpacr exp iat iss name nbf oid preferred_username rh scp sid sub tid uti ver xms_ftd`，头部只有 `alg=RS256`、`kid`、`typ=JWT`，签名 256 字节。`exp − iat` 不是固定值：这次用到两个令牌，run 1、取消分配和过期测试里的旧令牌是同一个（`iat` 01:12:56Z），5055 s；run 2 和过期测试里作对照的新令牌是另一个（`iat` 02:33:09Z），4080 s。`iat`/`nbf` 比实际签发早 5 分钟（第一次拿到令牌是 01:17:56.8Z，`iat` 是 01:12:56Z）。

建过的 Entra 对象（只有这两个；`identifier URI` 和预授权是应用对象的属性；创建、读回和删除的原始输出在 [entra-objects-20261110.txt](evidence/task-6/entra-objects-20261110.txt)，删除时间是 Graph 回收站里的 `deletedDateTime`）：

| 对象 | 对象 ID | 创建（UTC） | 删除（UTC） |
|---|---|---|---|
| 应用 `warden-lab-api`（client ID `00000000-0000-0000-0000-000000000001`） | `00000000-0000-0000-0000-000000000002` | 2026-11-11T01:16:38Z | 2026-11-11T02:39:16Z |
| 服务主体 `warden-lab-api` | `00000000-0000-0000-0000-000000000003` | 2026-11-11T01:16:40Z | 2026-11-11T02:38:55Z |

用户本人对该服务主体的分配建过两次、删过一次，最后随服务主体一起删除（分配 ID 是用户对象 ID 的编码，不写出来）。没有分配过别人。

## OIDC 实测

驱动脚本 [scripts/entra_oidc_live.py](../scripts/entra_oidc_live.py)：从当前源码构建 `warden-api`，起临时 `postgres:18-alpine`（与 `scripts/test-postgres.sh` 相同的限制，结束即删），用 `WARDEN_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0`、`WARDEN_OIDC_AUDIENCE=<client_id>`、`WARDEN_OIDC_JWKS_URL=…/discovery/v2.0/keys` 和一个一次性的 `WARDEN_SCIM_TOKEN_DIGESTS` 启动。用户是脚本用这个静态 SCIM 令牌通过 Warden 的 `/scim/v2/Users` 手工开通的（`externalId` = 令牌里的 `oid`），**不是 Entra 开通服务做的**。

[run 1](evidence/task-6/entra-oidc-live-20261110-run1.json)（JSON 记的源码是 `47dd091`、没有改动，但那时驱动脚本 `entra_oidc_live.py` 还没提交，`7795d87` 在 run 1 结束 36 s 后才提交；脚本当时只看已跟踪文件，见 [provenance](evidence/task-6/entra-provenance-20261112.txt)，`b64ff73` 起连未跟踪文件一起记录；01:18Z，17/17 通过）：

| 请求 | 期望 | 结果 | 耗时 |
|---|---|---|---|
| 不带 Authorization 的 POST /v1/runs | 401 | 401 | 0.38 ms |
| 真实令牌，用户还没开通（第一次请求，含从 Entra 拉 JWKS） | 401 | 401 | 369 ms |
| SCIM POST，`externalId` = oid | 201 | 201 | 5.79 ms |
| 真实令牌 POST /v1/runs | 201 | 201 | 2.58 ms |
| 真实令牌 GET /v1/runs/{id} | 200，`queued` | 200，`queued` | 0.58 ms |
| 同一个 Idempotency-Key 再 POST | 201，同一个 run_id | 201，同一个 | 0.62 ms |
| Azure Resource Manager 的真实令牌（v1，`aud=https://management.azure.com/`） | 401 | 401 | 0.54 ms |
| 改 payload（exp +1 h，原签名） | 401 | 401 | 0.50 ms |
| 改签名一个 bit | 401 | 401 | 0.40 ms |
| `alg=none`，无签名 | 401 | 401 | 0.26 ms |
| 不是 JWT | 401 | 401 | 0.18 ms |
| 手工 SCIM PATCH `active=false` 后用真实令牌 | 401 | 401（第一次轮询） | 2.07 ms |
| PATCH `active=true` 后 | 200 | 200 | 0.48 ms |
| 同一个令牌发给受众是另一个应用（随机 GUID）的 Warden | 401 | 401 | 0.21 ms |

[run 2](evidence/task-6/entra-oidc-live-20261110-run2.json)（源码 `6283e49`，02:38Z，另一个令牌，`iat` 02:33:09Z）同样 17/17 通过；拉 JWKS 的第一次请求 438 ms，手工停用到 401 是 5.75 ms。

[过期令牌](evidence/task-6/entra-oidc-expired-20261110-run1.json)（02:38Z，4/4 通过）：run 1 保存的令牌（`exp` 02:37:11Z，权限 0600，只在 `.cache`）过期 57 s 后发给新起的 `warden-api` → 401；同一个用户的新令牌作对照 → POST 201、GET 200。保存的令牌文件随后删除。

两次 run 和过期测试里，令牌头部的 `kid` 都是同一个（`xH9DJH3N086Ags8JL6IQzeQh1p8`），所以没有遇到 Entra 真实的签名密钥轮换；轮换路径仍只有本地 JWKS 的单测（`TestVerify_JWKSRotation`）。

## 分配与取消分配

都是用户本人，通过 Graph `servicePrincipals/{id}/appRoleAssignedTo`（默认角色 `00000000-…`）。新令牌是否能签发，用 [scripts/entra_token_probe.py](../scripts/entra_token_probe.py) 测：它用 Azure CLI 自带的 MSAL，把 CLI 的令牌缓存只读载入内存，`force_refresh=True` 每次真的向 Entra 要一次令牌（`az account get-access-token` 会返回缓存里的旧令牌，测不出变化）；不写回 `~/.azure`，只输出成功与否、AADSTS 码和耗时。

- 分配前（01:16:56Z）：`az account get-access-token --scope api://<client_id>/warden.access` 返回 AADSTS50105（用户没有被分配，原文在同一个文件里）。
- [第一次分配](evidence/task-6/entra-assign-20261110.txt)：Graph 01:17:05.9Z 建好分配；`az` 每 2 s 重试，01:17:56.8Z 第 23 次拿到令牌，**51.2 s**（分辨率约 2–3 s，每次 `az` 调用本身也要时间）。
- [取消分配 run 1](evidence/task-6/entra-unassign-20261110-run1.json)（01:23Z，8/8 通过；源码 `7795d87` 加未提交的改动：unassign 模式和 `entra_token_probe.py` 都是 run 之后在 `6890dbd` 才提交的）：01:23:15.1Z 删除分配（调用 508 ms）。之后每 3 s 一次：9.5 s 时仍能签发，**12.5 s 起连续 3 次 AADSTS50105**。同一时间，取消分配前签发的令牌在 Warden 上每次都是 200，之后也是 200（还剩 4417 s）。手工 SCIM 停用后 47 ms 内 401。重新分配后 **8.7 s**（第 4 次）又能拿到令牌。这个 JSON 里两个检查的 `ms` 字段其实是秒：“Entra refuses new tokens…”的 12.51 和 “fresh token from Entra after assigning again” 的 8.7（文件不改；脚本 `ab96af3` 起写毫秒）。
- 探测的判定（2026-11-12 起，`fb33cc1`）：只有 Entra 回答 AADSTS50105 算拒绝；探测进程崩溃、超时、没有输出 JSON、令牌缓存不可用或别的错误都算不确定，既不算进“连续 3 次拒绝”，也不打断它。之前崩溃的探测会被当成拒绝；提交的这次运行 7 个样本都有结论（4 次拿到令牌、3 次 AADSTS50105），不受影响。过期测试现在还要求旧令牌和对照令牌是同一个用户（`0dc2eba`；提交的那次 `same_user` 是 true）。

这说明：Entra 的分配只管“能不能拿到新令牌”。已经签发的访问令牌在自己的 `exp` 之前一直有效（这次的两个令牌，有效期分别是 5055 s 和 4080 s，约 84 和 68 分钟），Warden 不会知道用户被取消分配；只有 SCIM 停用（`TenantVerifier` 每次请求都查 `scim_users`，没有会话缓存）才能立刻拒绝。

## SCIM：Entra 开通服务为什么没做成

只读检查的原始输出在 [entra-scim-probe-20261110.txt](evidence/task-6/entra-scim-probe-20261110.txt)，只碰了用户自己的对象和自己的令牌，没有列举目录、用户或组。

1. **配置开通需要管理员同意的权限。** Graph 的同步 API（建作业、写 secret、改映射、按需开通）的委托权限是 `Synchronization.ReadWrite.All`，Graph 权限参考里 AdminConsentRequired 为 Yes；文档列出的角色是 Application Administrator、Cloud Application Administrator。用户的 Graph 令牌（Azure CLI）里没有任何 `Synchronization.*` scope，`wids` 里也没有这些角色。用这个令牌读用户**自己的**服务主体：`GET …/synchronization/jobs`、`…/synchronization/templates`（v1.0 和 beta）都是 `401 Unauthorized`。
2. **Azure CLI 拿不到这个 scope。** `az account get-access-token --scope https://graph.microsoft.com/Synchronization.ReadWrite.All` 返回 AADSTS65002：“Consent between first party application '04b07795-…' and first party resource '00000003-…' must be configured via preauthorization”。换成用户自己注册的客户端，这个 scope 也要管理员同意。按约定，这一步到此停止，没有尝试绕过。
3. **许可不是障碍。** Entra 许可表（2026-11-10 取）里 “Automated user provisioning to SaaS apps” Free 就有（组开通才要 P1）；用户本人还有 M365 A5 学生版里的 `AAD_PREMIUM`、`AAD_PREMIUM_P2`。
4. **还缺公网 HTTPS 端点。** 开通服务从 AzureActiveDirectory 服务标签的 IP 段访问 SCIM 端点，只接受 TLS 1.2 和文档列出的密码套件（或者在 Windows 服务器上装开通代理，要 Hybrid Identity Administrator）。本机 `warden-api` 只监听 127.0.0.1。因为第 1 条已经挡住，本次没有建任何公网端点，也没有建 Azure 资源。
5. **属性映射要改。** Entra 对非库应用的默认用户映射是 `mailNickname → externalId`；Warden 要求 `externalId` 是对象 ID（与令牌的 `oid` 对上），要改成 `objectId → externalId`，否则 POST 会被 400 拒绝。
6. 文档说企业应用的所有者可以管理开通（在 Entra 管理中心里）。那条路只能在门户网页里走，本次没有做：需要用户本人在浏览器里操作，也没有验证这个租户是否允许非管理员用 “Create your own application” 建非库应用。

**用户 2026-11-11 的决定：不做真实 SCIM。** 用户之前试过，学校账号注册不了，所以下面几条路都不走；这是最终状态，不是待定问题。下面保留当时列的选项，只作记录。

当时列的选项：

- 请学校的目录管理员给一个 `warden-lab-` 客户端应用的 `Synchronization.ReadWrite.All` 做管理员同意，或者在这个实验应用的范围内给用户 Cloud Application Administrator。之后可以全部脚本化：从 Custom 模板（`8adf8e6e-67b2-4cf2-a259-e3dc5476c621`，`supportedProvisioningTypes: sync`）实例化 `warden-lab-scim`，建 `scim` 作业，写 tenant URL 和 secret token（Warden 只存 SHA-256），映射 `objectId → externalId`，只分配用户本人，按需开通，再取消分配，测到建用户、停用和 401 的时间。
- 或者用户本人以所有者身份在 Entra 管理中心配置开通，配一个临时公网端点并计时。
- 或者注册 Okta Integrator 免费账号（[AZURE-BUDGET.md](../AZURE-BUDGET.md) 2.10 已列），用 Okta 的 SCIM 开通。

三条都还需要一个临时的公网 HTTPS 端点（例如 Container Apps 消耗计划，开之前按 AZURE-BUDGET 记台账；或者临时隧道），测完拆掉。开通服务的周期是 40 分钟，测时间要用按需开通。

## 复现

```bash
make tools && make terraform-plugins && make test-terraform   # terraform-plugins 联网，只要一次：make tools 不带 azuread provider，test-terraform 不联网
TF="env -i PATH=/usr/bin:/bin HOME=$HOME TF_DATA_DIR=$PWD/.cache/tf TF_PLUGIN_CACHE_DIR=$PWD/.cache/terraform/plugins .tools/terraform/terraform -chdir=identity/terraform"
$TF init -lockfile=readonly -plugin-dir=$PWD/.cache/terraform/plugins -backend-config=path=$PWD/.cache/idp.tfstate
$TF apply -var ttl=<UTC>          # 输出 oidc_audience、scope 和两个对象 ID
# 用 Graph appRoleAssignedTo 把自己分配给服务主体，然后：
python3 -I -B scripts/entra_oidc_live.py run --audience <client_id> --out <json> --keep-token .cache/<file>
python3 -I -B scripts/entra_oidc_live.py unassign --audience <client_id> --sp-object-id <sp> --out <json>
python3 -I -B scripts/entra_oidc_live.py expired --audience <client_id> --keep-token .cache/<file> --out <json>   # 令牌过期后
$TF destroy -var ttl=<UTC>
az ad app list --show-mine --query "[?starts_with(displayName,'warden-lab-')]"
```

## 清理

- 02:38:50–02:39:37Z `terraform destroy`：4 个资源（应用、服务主体，以及作为应用属性的 identifier URI 和预授权）全部删除，用户的分配随服务主体一起删除。之后 `az ad app show` / `az ad sp show` 都返回 “does not exist”，`az ad app list --show-mine` 里没有 `warden-lab-` 开头的应用（只剩别的项目的一个应用，没有动）。两个对象先留在 Entra 回收站里；2026-11-12 23:23Z 按对象 ID 永久删除（删前按 ID 读回收站条目、确认名字以 `warden-lab-` 开头，删后再读是 Not Found；[记录](evidence/task-14/entra-recycle-bin-purge-20261112.txt)）。
- 没有建任何 Azure 资源：会话开始（01:04Z）和结束（02:40Z）各跑一次 `scripts/azure_reaper.sh`，两次都是 `group-absent`（`rg-warden-lab` 不存在），[台账](azure-spend.md)不变（$0.00）。Entra 应用注册不收费。
- 临时 Postgres 容器（标签 `warden.test=task6`）每次结束即删，证据里 `postgres.removed` 为 true；`warden-api` 进程都已退出；保存的令牌已删除。
