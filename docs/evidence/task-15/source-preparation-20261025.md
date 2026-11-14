# Task15 源码前准备（inert）

仅写此 ignored 文件；无产品/Git/index、CLI/测试/下载/服务/云操作。材料 caller 已完成；N 中 CLI 265,805,986B / SHA-256 `dd492a230e3f7c68235efbf925932cdb34cefbabbd4436d932c3287d9450eea8`，0600、未执行；不重下/改权。三例 **UNRUN**，Task15/Goal OPEN.

## 固定源码与写路径

Kyverno v1.19.2 `cmd/cli/kubectl-kyverno/main.go` 正常启动只建命令/配置日志；`commands/test/command.go` 接本地目录、`--registry`、`--require-tests`，summary 把 Skip 计入 passed；`commands/test/test.go` 设置 registry access、fake client，invalid policy 可 skip；`processor/policy_processor.go` 调 `VerifyAndPatchImages` 且禁其 image verification cache。退出0不等于验签。

固定 Kyverno v1.19.2 `go.mod` 锁 SDK `5a61cbc9e077`、go-containerregistry `v0.21.8`、Cosign/v3 `v3.1.2`、Sigstore `v1.10.9`、client-go `v0.36.3`。SDK `extensions/registryclient/client.go` 默认 `authn.DefaultKeychain`；[keychain](https://github.com/google/go-containerregistry/blob/v0.21.8/pkg/authn/keychain.go) 先查 `$HOME/.docker/config.json`，再可查 `DOCKER_CONFIG`、`REGISTRY_AUTH_FILE`、XDG Podman auth/credential helper。`--registry` 不隔离宿主凭据。`pkg/sigstoretuf/sigstoretuf.go` 与 `pkg/image/verifiers/cpol/cosign/cosign.go` 使 keyless/attestation 读 TUF/Fulcio/Rekor/CTLog；[Sigstore TUF v1.10.9](https://github.com/sigstore/sigstore/blob/v1.10.9/pkg/tuf/client.go) 默认写 `$HOME/.sigstore/root`，`TUF_ROOT` 换根、`SIGSTORE_NO_CACHE=true` 用内存（`NewFromEnv` 仍尝试读私有 root 的 `remote.json`）。client-go v0.36.3 `tools/clientcmd/loader.go` 查 `KUBECONFIG`/`HOME/.kube/config`。Cosign/OCI 余下写位置未闭包，CLI 禁运行。

未来 CLI caller 须 `env -i`、私有 N/cwd；传 `HOME=N/home`、`DOCKER_CONFIG=N/docker`（空 `{}`）、`REGISTRY_AUTH_FILE=N/containers/auth.json`（空）、`XDG_CONFIG_HOME=N/config`、`XDG_RUNTIME_DIR=N/run`、`XDG_CACHE_HOME=N/cache`、`XDG_DATA_HOME=N/data`、`TMPDIR=N/tmp`、`TUF_ROOT=N/tuf`、`SIGSTORE_NO_CACHE=true`、`KUBECONFIG=N/empty-kubeconfig`、最小 PATH。不继承代理/云/registry env；不用 Git URL、secret/KMS ref。CLI 写路径/网络未闭包前不运行；registry 另裁。变量/mock、第三方镜像、`--registry` 标志不算 PASS；逐 rule 核零 Skip/Error。

## 最小 SOURCE 路径及原任务闭包

- `controlplane/Dockerfile`：真实入口 `controlplane/cmd/warden-api/main.go`，锁 Go/基础镜像 digest、非 root；现有 guest Dockerfile 不适用。`.github/workflows/build.yml`：仅受保护 GitHub context 提供真实 `repository/ref`、OCI 目标和权限；默认缺任一绑定即停止发布/签名。build/push 取 registry 返回的**同一不可变 digest**；Syft CycloneDX SBOM 并签 attestation；Grype 对同 digest 作**未过滤完整** JSON 扫描并独立 gate 可修复 critical；受信 workflow 签完整漏洞 attestation、Cosign keyless 签镜像；`slsa-github-generator` v2.1.0 container workflow 生成同 digest provenance。action/tool 固定 revision、最小权限、失败不签；generator 与 build workflow 身份分验。
- `scripts/supplychain.py` 与 `scripts/test_supplychain.py`：唯一生产 `render`/`assess_scan` 逻辑和调用**同函数/CLI**的本地测试，无新 controller。render 对 repository/ref/image repo/digest 逐项严格校验，缺身份默认失败；本地只验格式；真实身份靠 GitHub/OIDC。assess_scan 吃 Grype v0.121.0 未过滤 JSON，要求完整 `matches`、空 `ignoredMatches`、同 digest image source、版本/DB/KEV 源与新鲜度；从**同份**完整结果提取 fixable critical 与 direct/related KEV CVE，保留原报告 hash/所有 findings。缺/旧 DB、未知结构、过滤痕迹或 digest 不符均失败；不信自报 `kev:false`。真实 DB 字段待核。
- `policies/kyverno/verify-images.yaml`、`block-kev.yaml`：Warden 受控准入范围内 `imageReferences: ['*']`，堵别的 image 路径绕过；未绑定模板身份 `UNBOUND` 必拒绝。render 后签名规则精确 GitHub OIDC workflow issuer/subject、Rekor 和 digest；独立 SLSA generator builder/subject；漏洞规则要求同 digest、受信 workflow 完整扫描 attestation、可信 DB/KEV 来源且无 KEV。`policies/kyverno/tests/kyverno-test.yaml`、`resources.yaml`：原三条真实 digest manifest（未签名拒绝、本仓库签名+provenance 放行、KEV 拒绝）和错误身份/缺证明/旁路负例；未绑定保持 UNRUN。

JSON primary：[Grype v0.121.0 `Document`](https://github.com/anchore/grype/blob/v0.121.0/grype/presenter/models/document.go) 的 `matches`/`ignoredMatches`/`source`/`descriptor`；`Match` 的 direct/related；`Vulnerability` 与 `KnownExploited` 的 severity/CVE/`fix.state`/versions；`FixState` 定义 fixed/not-fixed/unknown/wont-fix。`source.type=sbom-file` 不自证 image digest，CI 应直接扫描同 digest image 并核 `source.target.repoDigests`。DB/KEV 元数据待核。Task12 PyYAML 仅解析。

## 首 RED 与预算

首 SOURCE caller 写生产 `render`/`assess_scan` **非空语义 stub**（`NotImplementedError`）及调用它们的测试；root 全文读 inert caller/fresh BASE 后才准 RED，再 GREEN 同命令复验。用例：未绑定/错 digest 拒绝；synthetic 绑定仅验配置格式/全 image 覆盖；未过滤 JSON 的 fixed critical 阻断、**not-fixed KEV 仍拒绝**、related CVE、ignoredMatches/DB 缺失失败。GREEN 仅本地语义；三条密码用例 UNRUN。CI/policy/manifest 同 Task15 补齐。

纯源码新增≤256MiB（源码64+临时128+输出64），内存≤1GiB。另裁 CLI 新增≤1GiB：binary 副本254MiB+临时副本254+TUF/registry128+XDG/TMP128+policy/结果128+日志/证据128+目录4=1024MiB；内存≤2GiB，旧 UNKNOWN9GB+新2GiB≈11.15GB<16GB。R≈5.03GB+Q5GB+新1GiB≈11.10GB<12GB **仅规划**；每 caller fresh 门禁，不扫旧 PID/RSS/scene、不清 Q。CLI 写路径未闭包前不执行；全 build/DB 峰值仍拒。无 host k3s/iptables/sudo/GPU、云、发布，Task6/BP/Task16 额度不变。
