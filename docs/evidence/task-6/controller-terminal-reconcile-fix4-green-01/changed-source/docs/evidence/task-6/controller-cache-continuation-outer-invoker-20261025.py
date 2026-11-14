"""Passive fixed supervisor; only verified sole bootstrap may call run."""
if __name__ == '__main__':
    raise SystemExit('use identity_cache_control supervise MODE')


def validate_target(control, mode, outcome, historical_envelope=None):
    api = control.api
    envelope_record = control.envelope_record if historical_envelope is None else historical_envelope
    api.require(outcome['terminal'] is True and not outcome['timed_out'] and not outcome['overflow'] and
                type(outcome['exit_code']) is int and outcome['exit_code'] in (0, 1), 'recorder_terminal_unknown')
    if mode in ('capture', 'continue'):
        launch = control.public(mode + '-launch.json')
        launch_value = control.launch_binding(launch)
        receipt = control.public(mode + '-receipt.json')
        value, result = control.receipt_value(launch, receipt)
        good = result['exit_code'] == 0 and not result['timed_out'] and not result['overflow']
        api.require(outcome['exit_code'] == (0 if good else 1), 'recorder_receipt_disagreement')
        api.require(api.raw(launch_value['deadline_envelope']) == api.raw(envelope_record.proof()), 'recorder_envelope')
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
            api.require(type(value['facts']) is dict and type(value['utc']) is str, 'probe_value_types')
        else:
            api.schema(value, ('version', 'stage', 'state', 'facts', 'private_proof', 'receipt_sha256',
                               'approval_created', 'Q_released', 'new3GB_admitted', 'deadline_envelope', 'deadline_claim'))
            api.require(value['stage'] == control.stage and value['approval_created'] is False and
                        value['new3GB_admitted'] is False and value['state'] ==
                        ('postflight-success' if outcome['exit_code'] == 0 else 'incomplete'), 'probe_binding')
            api.digest(value['receipt_sha256'])
            api.require(type(value['facts']) is dict and type(value['private_proof']) is dict, 'probe_value_types')
        api.require(type(value['version']) is int and value['version'] == 1 and value['Q_released'] is False and
                    api.raw(value['deadline_envelope']) == api.raw(envelope_record.proof()), 'probe_envelope')
        claim_proof = value['deadline_claim']
        result_proof = {'probe_sha256': api.sha(record.data), 'owned_cli_terminal': True}
    control.history_deadline(mode, envelope_record.proof(), claim_proof)
    control.recheck()
    return claim_proof, result_proof


def root_request(mode):
    return {'cmd': 'exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B '
                   'scripts/identity_cache_control.py supervise ' + mode,
            'workdir': '/home/postedism/Desktop/Warden', 'shell': '/bin/bash', 'login': False,
            'tty': False, 'yield_time_ms': 1000, 'max_output_tokens': 2000,
            'sandbox_permissions': 'require_escalated',
            'justification': '以项目普通UID1000运行已审查的Warden固定控制器步骤；不使用sudo或修改宿主网络。'}


def tool_chain(api, mode, events, terminal_index):
    api.require(mode in api.MODES and type(events) is list and 1 <= len(events) <= 32,
                'bounded_tool_chain')
    api.require(api.integer(terminal_index) == len(events) - 1, 'last_tool_terminal')
    session = None
    for index, event in enumerate(events):
        api.schema(event, ('seq', 'tool', 'request', 'response'))
        api.require(api.integer(event['seq']) == index, 'tool_sequence')
        expected = root_request(mode) if index == 0 else {
            'session_id': session, 'chars': '', 'yield_time_ms': 45000, 'max_output_tokens': 2000}
        api.require(event['tool'] == ('exec_command' if index == 0 else 'write_stdin') and
                    api.raw(event['request']) == api.raw(expected), 'fixed_tool_request')
        response = event['response']
        required = {'output', 'wall_time_seconds'}
        optional = {'chunk_id', 'original_token_count', 'exit_code', 'session_id'}
        api.require(type(response) is dict and required <= response.keys() <= required | optional,
                    'tool_response_keys')
        api.require(type(response['output']) is str and len(response['output'].encode()) <= 65536,
                    'tool_output_bound')
        wall = response['wall_time_seconds']
        api.require(type(wall) in (int, float) and 0 <= wall < float('inf'), 'tool_wait_number')
        if 'chunk_id' in response:
            api.require(type(response['chunk_id']) is str and 0 < len(response['chunk_id']) <= 128,
                        'tool_chunk_id')
        if 'original_token_count' in response:
            api.require(api.integer(response['original_token_count']) <= 2000, 'tool_truncation')
        final = index == len(events) - 1
        if final:
            api.require('session_id' not in response and type(response.get('exit_code')) is int and
                        response['exit_code'] in (0, 1), 'known_tool_terminal')
        else:
            api.require('exit_code' not in response and 'session_id' in response, 'tool_running_shape')
            current = api.integer(response['session_id'], 1)
            api.require(session is None or current == session, 'tool_session_changed')
            session = current
    return events[-1]['response']['exit_code']


def proof_matches(api, record, value):
    api.schema(value, ('sha256', 'bytes', 'metadata'))
    api.digest(value['sha256'])
    api.integer(value['bytes'])
    api.require(type(value['metadata']) is list and len(value['metadata']) == 10 and
                all(type(x) is int for x in value['metadata']) and
                api.raw(value) == api.raw(record.proof()), 'terminal_proof_changed')


def supervisor_log(control, mode):
    # Only these six public logs may be empty; generic source/private read stays strict.
    api = control.api
    api.require(mode in api.MODES, 'fixed_supervisor_log')
    path = api.ROOT / api.PUBLIC / (api.PREFIX + mode + '-supervisor.log')
    parent = api.directory(path.parent)
    fd = None
    try:
        info = api.os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        api.require(api.stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 1000 and
                    info.st_nlink == 1 and api.stat.S_IMODE(info.st_mode) == 0o600 and
                    info.st_dev == api.os.fstat(parent).st_dev and 0 <= info.st_size <= api.LOG_LIMIT,
                    'supervisor_log_trust')
        fd = api.os.open(path.name, api.FILE_FLAGS, dir_fd=parent)
        api.require(api.meta(api.os.fstat(fd)) == api.meta(info), 'supervisor_log_open')
        chunks, size = [], 0
        while size <= api.LOG_LIMIT:
            control.deadline.check()
            chunk = api.os.read(fd, min(65536, api.LOG_LIMIT + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        data = b''.join(chunks)
        api.require(len(data) == info.st_size and api.meta(api.os.fstat(fd)) == api.meta(info) ==
                    api.meta(api.os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'supervisor_log_read')
        class LogRecord(api.Record):
            def recheck(self):
                other = supervisor_log(control, mode)
                api.require(other.data == self.data and api.meta(other.info) == api.meta(self.info),
                            'supervisor_log_changed')
        return LogRecord(path, data, info, api.LOG_LIMIT)
    finally:
        if fd is not None:
            api.os.close(fd)
        api.os.close(parent)


def history(control, mode):
    api = control.api
    api.require(mode in api.MODES and mode.split('-')[0] == control.stage, 'terminal_mode')
    control.clock()
    envelope, ev = control.envelope(mode)
    claim = control.public(mode + '-deadline-accepted.json')
    _, accepted = control.history_deadline(mode, envelope.proof(), claim.proof())
    supervisor = control.public(mode + '-supervisor.json')
    sv = api.strict(supervisor.data)
    api.schema(sv, ('version', 'mode', 'state', 'command', 'source_commit', 'invoker', 'envelope', 'claim',
                    'outcome', 'target_proof', 'clock_identity', 'budget_start_monotonic_lower_ns',
                    'outer_entry_monotonic_ns', 'observed_monotonic_ns', 'last_clock_sample',
                    'controller_outer_result_created', 'Q_released'))
    api.require(type(sv['version']) is int and sv['version'] == 1 and sv['mode'] == mode and
                sv['state'] == 'recorder-terminal-tool-reconciliation-pending' and
                sv['command'] == api.target_command(mode) and sv['source_commit'] == ev['source_commit'] and
                api.raw(sv['clock_identity']) == api.raw(ev['clock_identity']) and
                sv['controller_outer_result_created'] is False and sv['Q_released'] is False,
                'supervisor_identity')
    for key, record in (('invoker', control.invoker_record), ('envelope', envelope), ('claim', claim)):
        proof_matches(api, record, sv[key])
    for key in ('budget_start_monotonic_lower_ns', 'outer_entry_monotonic_ns'):
        api.require(api.integer(sv[key]) == ev['timing'][key], 'supervisor_timing_binding')
    outcome = sv['outcome']
    api.schema(outcome, ('terminal', 'exit_code', 'timed_out', 'overflow', 'log_bytes', 'log_sha256'))
    api.require(outcome['terminal'] is True and outcome['timed_out'] is False and outcome['overflow'] is False and
                type(outcome['exit_code']) is int and outcome['exit_code'] in (0, 1), 'supervisor_outcome_unknown')
    api.require(api.integer(outcome['log_bytes']) <= api.LOG_LIMIT, 'supervisor_log_bound')
    api.digest(outcome['log_sha256'])
    log = supervisor_log(control, mode)
    control.records.append(log)
    api.require(len(log.data) == outcome['log_bytes'] and api.sha(log.data) == outcome['log_sha256'],
                'supervisor_log_digest')
    target_claim, target = validate_target(control, mode, outcome, envelope)
    api.require(api.raw(target_claim) == api.raw(claim.proof()) and api.raw(target) == api.raw(sv['target_proof']),
                'supervisor_target_proof')
    raw_record = control.public(mode + '-root-tool.json')
    api.require(api.stat.S_IMODE(raw_record.info.st_mode) in (0o600, 0o644), 'root_record_mode')
    rv = api.strict(raw_record.data)
    api.schema(rv, ('version', 'origin', 'mode', 'stage', 'source_commit', 'source_manifest_sha256',
                    'admission', 'invoker', 'envelope', 'claim', 'supervisor', 'clock_identity',
                    'events', 'terminal_event_index', 'root_assertion'))
    api.require(type(rv['version']) is int and rv['version'] == 1 and rv['mode'] == mode and
                rv['stage'] == control.stage and rv['origin'] == 'root-controller-actual-tool' and
                rv['root_assertion'] == 'awaited-terminal-before-record-before-reconcile' and
                rv['source_commit'] == ev['source_commit'] and
                rv['source_manifest_sha256'] == ev['source_manifest_sha256'] and
                api.raw(rv['clock_identity']) == api.raw(ev['clock_identity']), 'root_tool_binding')
    for key, record in (('admission', control.admission_record), ('invoker', control.invoker_record),
                        ('envelope', envelope), ('claim', claim), ('supervisor', supervisor)):
        proof_matches(api, record, rv[key])
    code = tool_chain(api, mode, rv['events'], rv['terminal_event_index'])
    api.require(code == outcome['exit_code'], 'tool_supervisor_exit')
    stamps = [accepted['target_entry_monotonic_ns'], api.integer(sv['observed_monotonic_ns'])]
    if mode in ('capture', 'continue'):
        launch = control.public(mode + '-launch.json')
        receipt = control.public(mode + '-receipt.json')
        lv = control.launch_binding(launch)
        rvalue, _ = control.receipt_value(launch, receipt)
        stamps.extend((api.integer(lv['entry_monotonic_ns']), api.integer(rvalue['ended_monotonic_ns'])))
        result = None
    else:
        result = control.public(mode + '.json')
        pv = api.strict(result.data)
        if mode.endswith('-preprobe'):
            stamps.append(api.integer(pv['observed_monotonic_ns']))
        else:
            # Validate the operation's complete terminal chain before trusting postflight history.
            operation_success, _ = control.outer_gate()
            api.require(code == (0 if operation_success else 1), 'postflight_operation_outcome')
            receipt = control.public(control.stage + '-receipt.json')
            api.require(pv['receipt_sha256'] == api.sha(receipt.data), 'postflight_receipt_binding')
    control.recheck()
    return {'envelope': envelope, 'ev': ev, 'claim': claim, 'supervisor': supervisor, 'sv': sv,
            'root': raw_record, 'code': code, 'target': target, 'stamps': stamps, 'result': result}


def terminal_timing(api, hist, timing):
    api.schema(timing, ('start_lower_ns', 'terminal_upper_ns', 'entry_boot_ns', 'entry_after_ns',
                        'verified_sample', 'metadata_end_ns'))
    for key in ('start_lower_ns', 'terminal_upper_ns', 'entry_boot_ns', 'entry_after_ns', 'metadata_end_ns'):
        api.integer(timing[key])
    ev, sv = hist['ev'], hist['sv']
    origin = ev['timing']['sample']
    last, current = sv['last_clock_sample'], timing['verified_sample']
    api.validate_sample(origin)
    api.validate_sample(last)
    api.validate_sample(current)
    m0, u, b, a = (timing[k] for k in ('start_lower_ns', 'terminal_upper_ns', 'entry_boot_ns', 'entry_after_ns'))
    api.require(m0 == ev['timing']['budget_start_monotonic_lower_ns'] and
                0 <= u - m0 <= ev['wall_seconds'] * api.NS and
                0 <= b - origin['birth_boot_lower_ns'] <= ev['wall_seconds'] * api.NS and
                0 <= a - u <= 100000000, 'independent_terminal_bound')
    api.require(last['pid'] == origin['pid'] and last['birth_ticks'] == origin['birth_ticks'] and
                last['namespace'] == current['namespace'] == origin['namespace'] and
                origin['monotonic_after_ns'] <= last['monotonic_before_ns'] <= last['monotonic_after_ns'] <=
                sv['observed_monotonic_ns'] <= u <= a <= current['monotonic_before_ns'] and
                origin['boottime_ns'] <= last['boottime_ns'] <= b <= current['boottime_ns'] and
                all(type(x) is int and x <= u for x in hist['stamps']), 'terminal_clock_order')
    samples = (origin, last, current)
    lo = max([b - a] + [s['boottime_ns'] - s['monotonic_after_ns'] for s in samples])
    hi = min([b - u] + [s['boottime_ns'] - s['monotonic_before_ns'] for s in samples])
    api.require(lo <= hi, 'terminal_clock_offset')
    own = api.timing_from_birth(current, u)
    api.require(current['monotonic_after_ns'] <= timing['metadata_end_ns'] <=
                own['budget_start_monotonic_lower_ns'] + 30 * api.NS, 'metadata_elapsed')


def marker_value(control, mode, hist, result, timing):
    return {'version': 1, 'mode': mode, 'stage': control.stage,
            'state': 'known-success' if hist['code'] == 0 else 'known-failure',
            'source_commit': hist['ev']['source_commit'],
            'source_manifest_sha256': hist['ev']['source_manifest_sha256'],
            'admission': control.admission_record.proof(), 'invoker': control.invoker_record.proof(),
            'envelope': hist['envelope'].proof(), 'claim': hist['claim'].proof(),
            'root_tool': hist['root'].proof(), 'supervisor': hist['supervisor'].proof(),
            'result': result.proof(), 'clock_identity': hist['ev']['clock_identity'], 'timing': timing,
            'tool_exit_code': hist['code'], 'child_exit_code': hist['target'].get('child_exit_code'), 'Q_released': False}


def outer_value(control, mode, hist, upper):
    return {'version': 1, 'stage': control.stage, 'producer': 'controller-tool-result', 'terminal': True,
            'exit_code': hist['code'], 'child_terminal': True,
            'child_exit_code': hist['target']['child_exit_code'],
            'launch_sha256': hist['target']['launch_sha256'], 'receipt_sha256': hist['target']['receipt_sha256'],
            'source_commit': hist['ev']['source_commit'],
            'outer_invoker_sha256': control.admission['outer_invoker_sha256'],
            'command': control.api.target_command(mode), 'clock_identity': hist['ev']['clock_identity'],
            'started_monotonic_ns': hist['ev']['timing']['budget_start_monotonic_lower_ns'],
            'ended_monotonic_ns': upper}


def validate_terminal(control, mode):
    api = control.api
    api.require(mode in api.MODES and mode.split('-')[0] == control.stage, 'terminal_mode')
    record = control.public(mode + '-terminal.json')
    api.require(len(record.data) <= 16384 and api.stat.S_IMODE(record.info.st_mode) == 0o600, 'terminal_marker_trust')
    value = api.strict(record.data)
    api.require(type(value) is dict and 'timing' in value, 'terminal_marker_schema')
    hist = history(control, mode)
    terminal_timing(api, hist, value['timing'])
    if mode in ('capture', 'continue'):
        result = control.public(mode + '-outer-result.json')
        api.require(api.raw(api.strict(result.data)) == api.raw(outer_value(control, mode, hist,
                    value['timing']['terminal_upper_ns'])), 'terminal_outer_binding')
        control.outer_value()
    else:
        result = hist['result']
    api.require(api.raw(value) == api.raw(marker_value(control, mode, hist, result, value['timing'])),
                'terminal_marker_binding')
    control.recheck()
    return record, value


def reconcile(control, mode, entry):
    api, deadline = control.api, control.deadline
    api.require(mode in api.MODES and mode.split('-')[0] == control.stage, 'terminal_mode')
    api.require(type(entry) is tuple and len(entry) == 3 and all(type(x) is int for x in entry),
                'reconcile_entry_samples')
    u, b, a = entry
    api.require(u == deadline.entry_monotonic_ns and 0 <= a - u <= 100000000, 'reconcile_entry_bracket')
    control.clock()
    own_sample = api.OwnClock().sample()
    own = api.timing_from_birth(own_sample, u)
    start = own['budget_start_monotonic_lower_ns'] / api.NS
    api.require(start <= deadline.start and start + 30 <= deadline.end, 'metadata_cannot_extend')
    deadline.start, deadline.end = start, start + 30
    deadline.guard = api.ClockBudget(own, 30)
    deadline.check()
    deadline.arm()
    api.absent(api.ROOT / api.PUBLIC / (api.PREFIX + mode + '-terminal.json'))
    if mode in ('capture', 'continue'):
        api.absent(api.ROOT / api.PUBLIC / (api.PREFIX + mode + '-outer-result.json'))
    hist = history(control, mode)
    timing = {'start_lower_ns': hist['ev']['timing']['budget_start_monotonic_lower_ns'],
              'terminal_upper_ns': u, 'entry_boot_ns': b, 'entry_after_ns': a,
              'verified_sample': own_sample, 'metadata_end_ns': api.time.monotonic_ns()}
    terminal_timing(api, hist, timing)
    control.recheck()
    if mode in ('capture', 'continue'):
        result = api.durable(mode + '-outer-result.json', outer_value(control, mode, hist, u))
        control.records.append(result)
        control.recheck()
    else:
        result = hist['result']
    timing['metadata_end_ns'] = api.time.monotonic_ns()
    terminal_timing(api, hist, timing)
    control.recheck()
    marker = api.durable(mode + '-terminal.json', marker_value(control, mode, hist, result, timing))
    control.records.append(marker)
    control.recheck()
    # No claim that this pre-exit output proves our own tool terminal.
    print(api.raw({'state': 'reconcile-terminal-pending', 'marker': marker.proof()}).decode(), end='', flush=True)
    control.recheck()
    deadline.check()
    return 0


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
