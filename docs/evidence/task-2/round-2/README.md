# Task2 core 修复 round 2 / 5

日期：2026-10-23。FIX_BASE：`2456e06`。修复实现SHA：**`2c27f783536ce9c6b9954885948fcd01418deae1`**。

本轮只修独立lab runner收尾；**不执行特权runner、不启动containerd、不操作真实cgroup、不创建Azure资源**。真实七项guest与scheduler接线继续未验收。

## 问题与修复

旧finally将cgroup.kill、daemon terminate/kill/wait、subtree验证和数据删除放在同一try；kill写入OSError会跳过daemon回收，随后关闭anchored目录FD而daemon仍存活。

现在`cleanup_owned`逐项best effort：kill-control、检查/终止自有Popen daemon、wait与force-kill/reap、subtree验证分别执行；错误按阶段汇总为`CleanupError.failures`。只有**daemon已reap且subtree空得到验证**时才删除cgroup/本次daemon数据；删除cgroup失败也保留数据。无法取得已创建cgroup的descriptor视为未验证，保留现场。finally的各自有FD close也独立尝试，保留所有错误而不覆盖早先错误。信号只作用于本runner返回的Popen对象，不搜索或终止其他进程。

## 真实故障注入与RED/GREEN

Focused测试`OwnedCleanupTests.test_kill_write_failure_still_reaps_daemon_and_preserves_unknown_state`：

- 所有文件位于temp目录，真实Session类管理root/state/io sentinel。
- 将模拟cgroup.kill放为目录，真实os.open写调用产生IsADirectoryError；cgroup.events缺失产生FileNotFoundError，代表subtree状态未知。
- 只启动自己的无害Python子进程，它输出READY后阻塞读取stdin；不是daemon、容器或攻击guest。
- 对旧逻辑的机械抽取运行：子进程仍存活，出现明确RED。测试finally始终kill/wait自己的child，RED本身不留子进程。
- 修复后检查Popen.poll非None，且真正os.waitpid报ChildProcessError，独立证明child已被回收。检查两阶段错误均被聚合，root/state/io sentinel和未验证cgroup目录均保留。

命令：

```bash
python3 -B scripts/test_runtime_lab_cleanup.py
```

[red-cleanup.txt](red-cleanup.txt)：FAIL `cgroup.kill failure skipped owned daemon termination/reap`。
[green-cleanup.txt](green-cleanup.txt)：1测试通过，含上述实际waitpid与数据保留断言。

## 回归与边界

```bash
python3 -B -m unittest discover -s scripts -p 'test_runtime_lab_*.py' -v
```

[python-regression.txt](python-regression.txt)：**9项通过**（新增cleanup故障测试＋原8项路径guard测试）。为获得真实host文件owner而绕过sandbox的/tmp uid65534映射，运行命令使用require_escalated；进程仍普通uid，仅临时文件及自己的无害child，无sudo/root runner/真实cgroup/daemon操作。

Python AST、bash wrapper语法及`git diff --check`通过。本轮不改Go代码或依赖，未重复上一轮Go全suite race/vet与govulncheck；已有证据保留。本轮root runner完整执行仍未进行，不能把temp文件故障测试写为真实kernel验收。
