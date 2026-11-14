# Task 3 k3s lab 的后续：结束检查（2026-11-10，home-ubuntu）

这次在 Task 3 的 worktree 里做了等 Kubernetes lab 的几项后续工作。各项的证据：

| 项目 | 结果 | 证据 |
|---|---|---|
| Task 10 的 Cilium 部分（默认拒绝、出口代理） | **停止**：装 Cilium 时宿主内核多加载了 4 个模块（STATUS 阻塞 11） | [task-10/cilium-k3s-20261110](../../task-10/cilium-k3s-20261110/README.md) |
| Task 14 的 Cilium 部分（quarantine 切断已建立的连接） | 没测，同样卡在阻塞 11；1 s 的要求不变 | 同上，[time-to-contain.md](../../time-to-contain.md) |
| Task 7 本机部分 | `TestControlPlaneTokenIsShortLived` 先 FAIL，改了控制面的 pod 配置后 PASS；`TestSandboxSAHasNoBindings` 先 FAIL，改了测试（接受默认的 issuer 发现绑定、修正对照）后 PASS，系统没有改；`deny-metadata.yaml` 没应用，`TestSandboxCannotReachMetadata` 没写（阻塞 11）；Entra 联合没做（阻塞 12） | [task-7/identity-k3s-20261110](../../task-7/identity-k3s-20261110/README.md) |
| 阻塞 10（kind 上的 Service/DNS） | 解决：inotify 512/524288 下 kube-proxy 正常，ClusterIP 和 DNS 都能用 | [task-14/kind-service-dns-20261110](../../task-14/kind-service-dns-20261110/README.md) |

提交：`a7515aa`、`0fea0c1`、`1a92833`、`87ab637`、`c748a9d`、`86289ca`，还有带这个目录的提交。

## make test / make check（源码 `86289ca`，工作区干净）

都在 worktree 里跑，经过 `.cache/mk.sh`（只多加了 `-buildvcs=false`）。
- `make test` **通过**（[make-test.log](make-test.log)）：
  - Go 28 个包 ok。比 Task 3 时多一个，是 `runtimes/conformance`，现在有了 Task 7 的离线测试。
  - Python 测试：`scripts/` 188 个 OK；`detect/report` 和背压 helper 37 个 OK（live 1 个 skip）；pySigma 和 OpenSearch helper 14 个 OK（live 2 个 skip）。
  - Vector：38 个 `vector test` 用例 passed，背压配置 validate 通过。
- `make check` **通过**（[make-check.log](make-check.log)）。

## 结束检查（[postflight.txt](postflight.txt)，18:32:06 PST）

- 没有 `project=warden` 或 `warden` 开头的容器、网络、镜像。kind 集群只剩 `materialflow`，不是这个项目的，没有动过。
- 宿主 inotify 是 512 / 524288，模块列表哈希 `9e93ec2d…`。这个值是 Cilium 那次以后的，之后没有再变。
- 根分区剩 99G（94%）。worktree 915 MB。
- 主 checkout 里两处有意留下的改动还在，没有动过：`scripts/firecracker_code.py`（M）、`detect/tests/backpressure_test.sh`（??）。
- load average 1.95、3.76、3.84。
