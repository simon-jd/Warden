"""One admitted continuation child; real approval pins intentionally absent."""
if __name__ == '__main__':
    raise SystemExit('use sole identity_cache_control entry')
EXPECTED_APPROVAL_SHA256 = None
EXPECTED_APPROVAL_BYTES = None

def require_approval_pins():
    import re
    if (type(EXPECTED_APPROVAL_SHA256) is not str or
            not re.fullmatch('[0-9a-f]{64}', EXPECTED_APPROVAL_SHA256) or
            type(EXPECTED_APPROVAL_BYTES) is not int or not 0 < EXPECTED_APPROVAL_BYTES <= 65536):
        raise ValueError('actual_approval_pin_absent')


def run(control):
    require_approval_pins()  # Before private reads, command launch or process creation.
    c, api = control, control.api
    pre_record, _ = c.preparation()
    approval = api.read(api.ROOT / api.PUBLIC / 'cache-continuation-checkpoint-approval-20261025.json')
    api.require(api.sha(approval.data) == EXPECTED_APPROVAL_SHA256 and
                len(approval.data) == EXPECTED_APPROVAL_BYTES, 'approval_pin_mismatch')
    c.records.append(approval)
    # -B prevents writes, not reads of bytecode. Refuse unchecked project bytecode.
    api.absent(api.ROOT / 'scripts/__pycache__')
    launch = c.launch(pre_record)
    parent = api.directory(api.ROOT / api.PUBLIC)
    fd = None
    owner = api.OwnedProcess(c.deadline)
    try:
        name = api.PREFIX + 'continue.log'
        fd = api.os.open(name, api.os.O_WRONLY | api.os.O_CREAT | api.os.O_EXCL |
                         api.os.O_NOFOLLOW | api.os.O_CLOEXEC, 0o600, dir_fd=parent)
        created = api.os.fstat(fd)
        api.require(created.st_uid == created.st_gid == 1000 and created.st_nlink == 1 and
                    api.stat.S_IMODE(created.st_mode) == 0o600, 'log_identity')
        def sink(chunk):
            offset = 0
            while offset < len(chunk):
                n = api.os.write(fd, chunk[offset:])
                api.require(n > 0, 'log_write_progress')
                offset += n
        c.recheck()
        cutoffs = [c.deadline.start + n for n in (580, 585, 590)]
        outcome = owner.run(api.CHILD, cutoffs, sink, api.child_limits)
        api.os.fsync(fd)
        final = api.os.fstat(fd)
        api.require(api.meta(final)[:6] == api.meta(created)[:6] and final.st_size == outcome['log_bytes'] and
                    api.meta(api.os.stat(name, dir_fd=parent, follow_symlinks=False)) == api.meta(final), 'log_changed')
        api.os.fsync(parent)
        # Empty logs are valid; verify using held FD/path metadata, hash nonempty logs.
        if final.st_size:
            readback = api.read(api.ROOT / api.PUBLIC / name, api.LOG_LIMIT)
            api.require(api.meta(readback.info) == api.meta(final) and
                        api.sha(readback.data) == outcome['log_sha256'], 'log_readback')
        api.require(api.meta(api.os.fstat(fd)) == api.meta(final) and
                    api.meta(api.os.stat(name, dir_fd=parent, follow_symlinks=False)) == api.meta(final), 'log_replaced')
        receipt = c.receipt(launch, outcome)
        c.deadline.check()
        print(api.raw({'state': 'child-terminal-postflight-pending', 'receipt': receipt.proof()}).decode(),
              end='', flush=True)
        c.deadline.check()
        return 0 if outcome['exit_code'] == 0 and not outcome['timed_out'] and not outcome['overflow'] else 1
    except BaseException:
        owner.signal(api.signal.SIGKILL)
        # Pending never asserts terminal, even when an exception follows a poll.
        if c.deadline.now() < c.deadline.end:
            try:
                api.durable('continue-pending.json', {'version': 1, 'state': 'unknown-retain',
                            'launch_sha256': api.sha(launch.data), 'spawn_pending': owner.spawn_pending,
                            'owned_pid': None if owner.proc is None else owner.proc.pid, 'Q_released': False})
            except BaseException:
                pass
        raise
    finally:
        if fd is not None:
            api.os.close(fd)
        api.os.close(parent)

