# 复审修复第 1 轮最后的普通 make test、make check（2026-11-12，worktree `cloud-identity`）

在这个 worktree 里，普通的 `make test`、`make check` 原来跑不了，所以这个分支之前都通过未跟踪的 `.cache/mk.sh` 调 make。两个原因都已经在 `implementation/warden` 上修过，这里移植过来：

- [1-buildvcs.red.log](1-buildvcs.red.log)：`52f10a2` 的 Makefile。worktree 的 `.git` 是文件，Go 的 VCS 标记只认 `.git` 目录，一直找到空的 `~/.git`，git 退出 128，`go list` 什么也没列出，`make test` 和 `make check` 都变成对 `.` 跑，失败。修复 `0a6fe50`：`276a734` 的 Makefile 部分（每个 go 命令加 `-buildvcs=false`，`go list` 失败或为空时停下），去掉本分支没有的 `test-gvisor`、`test-identity` 两段，`test-azure-respond` 也加上。
- [2-socket-path.red.log](2-socket-path.red.log)：Makefile 修好后，`runtimes/firecracker` 的两个 API 测试在 `.cache/test-tmp` 下建 unix socket，路径超过 `sun_path`（`bind: invalid argument`）。修复 `e1e8642`：原样 cherry-pick `a229a70`（socket 放在 `/tmp` 下新建的 0700 目录里）。
- [make-test.log](make-test.log)、[make-check.log](make-check.log)：在 `e1e8642` 上直接跑 `make test`、`make check`（make 在 `taskset -c 0-7,16-31` 下），开头记了 head 和 `git status --short`（干净，跑完也干净）。都通过：Go 26 个包 ok；`scripts/` 的 unittest 235 个、`detect/report` + 背压 helper 37 个（1 个 skip）、pySigma + OpenSearch helper 14 个（2 个 skip）都 OK，38 个 `vector test` 用例 passed；`make check` 的 go vet、gofmt、shellcheck 都没有报告。
