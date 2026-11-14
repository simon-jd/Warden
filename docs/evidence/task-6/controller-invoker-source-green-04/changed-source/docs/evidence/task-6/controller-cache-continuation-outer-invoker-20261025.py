"""Passive fixed supervisor; only verified sole bootstrap may call run."""
if __name__ == '__main__':
    raise SystemExit('use identity_cache_control supervise MODE')


def validate_target(control, mode, outcome):
    api = control.api
    api.require(outcome['terminal'] is True and not outcome['timed_out'] and not outcome['overflow'] and
                type(outcome['exit_code']) is int and outcome['exit_code'] in (0, 1), 'recorder_terminal_unknown')
    if mode in ('capture', 'continue'):
        launch = control.public(mode + '-launch.json')
        launch_value = control.launch_binding(launch)
        receipt = control.public(mode + '-receipt.json')
        value, result = control.receipt_value(launch, receipt)
        good = result['exit_code'] == 0 and not result['timed_out'] and not result['overflow']
        api.require(outcome['exit_code'] == (0 if good else 1), 'recorder_receipt_disagreement')
        api.require(launch_value['deadline_envelope'] == control.envelope_record.proof(), 'recorder_envelope')
        claim_proof = launch_value['deadline_claim']
        result_proof = {'launch_sha256': api.sha(launch.data), 'receipt_sha256': api.sha(receipt.data),
                        'child_terminal': True, 'child_exit_code': None if mode == 'capture' else result['exit_code']}
    else:
        record = control.public(mode + '.json')
        value = api.strict(record.data)
        if mode.endswith('-preprobe'):
            api.schema(value, ('version', 'stage', 'state', 'admission_sha256', 'source_commit', 'source_hashes',
                               'clock_identity', 'observed_monotonic_ns', 'utc', 'facts', 'Q_released',
                               'deadline_envelope', 'deadline_claim'))
            api.require(value['state'] == 'preprobe-complete' and value['stage'] == control.stage and
                        value['admission_sha256'] == api.sha(control.admission_record.data) and
                        value['source_commit'] == control.admission['source_commit'] and
                        api.raw(value['source_hashes']) == api.raw(control.admission['source_hashes']) and
                        api.raw(value['clock_identity']) == api.raw(control.admission['clock_identity']) and
                        outcome['exit_code'] == 0, 'probe_binding')
            api.integer(value['observed_monotonic_ns'])
        else:
            api.schema(value, ('version', 'stage', 'state', 'facts', 'private_proof', 'receipt_sha256',
                               'approval_created', 'Q_released', 'new3GB_admitted', 'deadline_envelope', 'deadline_claim'))
            api.require(value['stage'] == control.stage and value['approval_created'] is False and
                        value['new3GB_admitted'] is False and value['state'] ==
                        ('postflight-success' if outcome['exit_code'] == 0 else 'incomplete'), 'probe_binding')
            api.digest(value['receipt_sha256'])
        api.require(type(value['version']) is int and value['version'] == 1 and value['Q_released'] is False and
                    api.raw(value['deadline_envelope']) == api.raw(control.envelope_record.proof()), 'probe_envelope')
        claim_proof = value['deadline_claim']
        result_proof = {'probe_sha256': api.sha(record.data), 'owned_cli_terminal': True}
    control.history_deadline(mode, control.envelope_record.proof(), claim_proof)
    control.recheck()
    return claim_proof, result_proof


def run(control, mode):
    api, deadline = control.api, control.deadline
    api.require(mode in api.MODES and mode.split('-')[0] == control.stage, 'fixed_supervisor_mode')
    control.clock()
    timing = api.timing_from_birth(api.OwnClock().sample(), deadline.entry_monotonic_ns)
    seconds = api.mode_policy(mode)['wall_seconds']
    start = timing['budget_start_monotonic_lower_ns'] / api.NS
    api.require(start <= deadline.start and start + seconds <= deadline.end, 'supervisor_cannot_extend')
    deadline.start, deadline.end = start, start + seconds
    deadline.guard = api.ClockBudget(timing, seconds)
    deadline.check()
    deadline.arm()
    control.recheck()
    # Fixed no-retry names are checked before any operation intent/log or Popen.
    for suffix in (mode + '-deadline.json', mode + '-deadline-accepted.json',
                   mode + '-supervisor.json', mode + '-supervisor.log'):
        api.absent(api.ROOT / api.PUBLIC / (api.PREFIX + suffix))
    outputs = (mode + '.json',) if '-' in mode else (mode + '-launch.json', mode + '-receipt.json')
    for suffix in outputs:
        api.absent(api.ROOT / api.PUBLIC / (api.PREFIX + suffix))
    deadline.check()
    envelope = api.durable(mode + '-deadline.json', api.envelope_value(control, mode, timing))
    control.envelope_record, control.envelope_mode = envelope, mode
    control.records.append(envelope)
    control.recheck()
    parent = api.directory(api.ROOT / api.PUBLIC)
    fd = None
    owner = api.OwnedProcess(deadline)
    try:
        name = api.PREFIX + mode + '-supervisor.log'
        deadline.check()
        fd = api.os.open(name, api.os.O_WRONLY | api.os.O_CREAT | api.os.O_EXCL |
                         api.os.O_NOFOLLOW | api.os.O_CLOEXEC, 0o600, dir_fd=parent)
        created = api.os.fstat(fd)
        api.require(created.st_uid == created.st_gid == 1000 and created.st_nlink == 1 and
                    api.stat.S_ISREG(created.st_mode) and api.stat.S_IMODE(created.st_mode) == 0o600,
                    'supervisor_log_identity')
        def sink(chunk):
            offset = 0
            while offset < len(chunk):
                deadline.check()
                count = api.os.write(fd, chunk[offset:])
                api.require(count > 0, 'supervisor_log_progress')
                offset += count
        cutoffs = [deadline.start + seconds for seconds in api.outer_cutoffs(mode)]
        control.recheck()
        outcome = owner.run(api.target_command(mode), cutoffs, sink, lambda: api.target_limits(mode))
        deadline.check()
        claim, proof = validate_target(control, mode, outcome)
        api.os.fsync(fd)
        final = api.os.fstat(fd)
        api.require(api.meta(final)[:6] == api.meta(created)[:6] and final.st_size == outcome['log_bytes'] and
                    api.meta(api.os.stat(name, dir_fd=parent, follow_symlinks=False)) == api.meta(final),
                    'supervisor_log_changed')
        api.os.fsync(parent)
        if final.st_size:
            readback = api.read(api.ROOT / api.PUBLIC / name, api.LOG_LIMIT)
            api.require(api.meta(readback.info) == api.meta(final) and
                        api.sha(readback.data) == outcome['log_sha256'], 'supervisor_log_readback')
        api.require(api.meta(api.os.fstat(fd)) == api.meta(final) and
                    api.meta(api.os.stat(name, dir_fd=parent, follow_symlinks=False)) == api.meta(final),
                    'supervisor_log_replaced')
        control.recheck()
        record = api.durable(mode + '-supervisor.json', {
            'version': 1, 'mode': mode, 'state': 'recorder-terminal-tool-reconciliation-pending',
            'command': api.target_command(mode), 'source_commit': control.admission['source_commit'],
            'invoker': control.invoker_record.proof(), 'envelope': envelope.proof(), 'claim': claim,
            'outcome': outcome, 'target_proof': proof, 'clock_identity': control.admission['clock_identity'],
            'budget_start_monotonic_lower_ns': timing['budget_start_monotonic_lower_ns'],
            'outer_entry_monotonic_ns': timing['outer_entry_monotonic_ns'],
            'observed_monotonic_ns': api.time.monotonic_ns(), 'last_clock_sample': deadline.guard.last,
            'controller_outer_result_created': False, 'Q_released': False})
        control.records.append(record)
        control.recheck()
        print(api.raw({'state': 'tool-reconciliation-pending', 'record': record.proof()}).decode(),
              end='', flush=True)
        deadline.check()
        return outcome['exit_code']
    except BaseException:
        owner.signal(api.signal.SIGKILL)
        # A known recorder exit cannot close an unknown nested child's state.
        # Retain envelope/claim/log/partial receipt; no success/fallback/retry.
        raise
    finally:
        if fd is not None:
            api.os.close(fd)
        api.os.close(parent)
