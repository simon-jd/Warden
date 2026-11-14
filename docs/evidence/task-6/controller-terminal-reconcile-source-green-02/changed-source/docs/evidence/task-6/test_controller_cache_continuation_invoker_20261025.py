"""Generated invoker fixtures only; no real proc, process, clock identity or binary."""
import json
from pathlib import Path
import resource
import unittest
from unittest import mock

import identity_cache_observe as api

ROOT = Path(__file__).absolute().parents[3]


class InvokerTests(unittest.TestCase):
    def test_preparation_requires_independent_terminal_marker(self):
        fixture = original.ControllerTests(methodName='runTest')
        fixture.real_terminal = True
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.put(fixture.invoker, (ROOT / 'docs/evidence/task-6' / api.INVOKER_NAME).read_bytes())
        c = fixture.controller()
        fixture.preprobe(c)
        with self.assertRaises((ValueError, FileNotFoundError)):
            c.preparation()
        self.assertFalse(fixture.path('capture-launch.json').exists())

    def test_outer_gate_requires_independent_terminal_marker(self):
        fixture = original.ControllerTests(methodName='runTest')
        fixture.real_terminal = True
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.put(fixture.invoker, (ROOT / 'docs/evidence/task-6' / api.INVOKER_NAME).read_bytes())
        c = fixture.controller()
        path = fixture.path('capture-preprobe-terminal.json')
        fixture.put(path, b'{"generated_setup_only":true}\n')
        with mock.patch.object(c, 'terminal_gate', return_value=api.read(path)):
            fixture.public_terminal(c)
        with self.assertRaises((ValueError, FileNotFoundError)):
            c.outer_gate()

    def test_supervisor_filesize_inheritance_does_not_cap_capture(self):
        policy = {'cpu_seconds': 10, 'cpu_hard_seconds': 540, 'address_bytes': 134217728,
                  'address_hard_bytes': 536870912, 'file_bytes': 1048576, 'file_hard_bytes': 33554432}
        state = {kind: (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
                 for kind in (resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_FSIZE)}
        with (mock.patch.object(resource, 'getrlimit', side_effect=lambda kind: state[kind]),
              mock.patch.object(resource, 'setrlimit', side_effect=lambda kind, value: state.update({kind: value})),
              mock.patch.object(api.os, 'umask'), mock.patch.object(api.signal, 'signal')):
            api.limits(policy)
        self.assertEqual(state[resource.RLIMIT_FSIZE], (1048576, 33554432))

    def test_deadline_checks_both_clocks_before_phase_work(self):
        deadline = api.Deadline(100, 600)
        deadline.guard = mock.Mock()
        deadline.guard.check.side_effect = ValueError('generated BOOTTIME phase exhausted')
        with mock.patch.object(deadline, 'now', return_value=101):
            with self.assertRaisesRegex(ValueError, 'BOOTTIME'):
                deadline.check(180)
        deadline.guard.check.assert_called_once_with(180)

    def test_fixed_passive_invoker_exists(self):
        self.assertTrue((ROOT / 'docs/evidence/task-6/controller-cache-continuation-outer-invoker-20261025.py').is_file())



# No inheritance from the old TestCase: it is a generated fixture factory only.
import contextlib
import io
import os
import signal
import types
import identity_cache_control as bootstrap
import test_identity_cache_control as original


def sample(second=100, boot=None, **changes):
    value = {'pid': 123, 'hz': 100, 'birth_ticks': 10001, 'birth_boot_lower_ns': 100 * api.NS,
             'namespace': [1, 2], 'monotonic_before_ns': int(second * api.NS),
             'boottime_ns': int((second if boot is None else boot) * api.NS),
             'monotonic_after_ns': int(second * api.NS)}
    value.update(changes)
    return value


class ClockTests(unittest.TestCase):
    def timing(self):
        return api.timing_from_birth(sample(), 100 * api.NS)

    def test_boottime_sample_between_monotonic_bracket_is_valid(self):
        value = sample(monotonic_before_ns=100 * api.NS, boottime_ns=100 * api.NS + 100,
                       monotonic_after_ns=100 * api.NS + 200)
        api.validate_sample(value)
        self.assertLessEqual(api.timing_from_birth(value, 100 * api.NS)['budget_start_monotonic_lower_ns'],
                             100 * api.NS)

    def test_tick_lower_bound_and_delayed_entry_are_distinct(self):
        fields = ['0'] * 50
        fields[19] = '10001'
        self.assertEqual(api.parse_birth('123 (name ) with spaces) ' + ' '.join(fields), 123, 100),
                         (10001, 100 * api.NS))
        timing = api.timing_from_birth(sample(120), 119 * api.NS)
        self.assertEqual(timing['budget_start_monotonic_lower_ns'], 100 * api.NS)
        self.assertEqual(timing['outer_entry_monotonic_ns'], 119 * api.NS)
        with self.assertRaisesRegex(ValueError, 'linux_tick_contract'):
            api.parse_birth('unused', 123, 1000)

    def test_strict_samples_reject_boolean_reversed_namespace_and_ticks(self):
        for changes in ({'pid': True}, {'hz': 1000}, {'birth_ticks': 0}, {'namespace': [True, 2]},
                        {'monotonic_before_ns': 101 * api.NS}, {'boottime_ns': 99 * api.NS}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                api.validate_sample(sample(**changes))
        with self.assertRaisesRegex(ValueError, 'conservative_start_order'):
            api.timing_from_birth(sample(), 99 * api.NS)

    def test_own_sampler_uses_only_fixed_fake_inputs(self):
        fields = ['0'] * 50
        fields[19] = '10001'
        calls = []
        def proc(path):
            calls.append(path)
            return ('monotonic 0 0\nboottime 0 0\n' if path.endswith('timens_offsets')
                    else '123 (fixture) ' + ' '.join(fields))
        info = types.SimpleNamespace(implementation='clock_gettime(CLOCK_MONOTONIC)',
                                     monotonic=True, adjustable=False, resolution=1e-9)
        with (mock.patch.object(api, 'own_proc_text', side_effect=proc),
              mock.patch.object(api.os, 'stat', return_value=types.SimpleNamespace(st_dev=1, st_ino=2)) as stat,
              mock.patch.object(api.os, 'getpid', return_value=123),
              mock.patch.object(api.os, 'sysconf', return_value=100),
              mock.patch.object(api.time, 'get_clock_info', return_value=info),
              mock.patch.object(api.time, 'clock_gettime_ns', return_value=100 * api.NS)):
            self.assertEqual(api.OwnClock().sample(), sample())
        self.assertEqual(calls, ['/proc/self/timens_offsets', '/proc/self/stat'])
        self.assertEqual([c.args[0] for c in stat.call_args_list],
                         ['/proc/self/ns/time', '/proc/self/ns/time_for_children'])
        with mock.patch.object(api.os, 'open') as opener, self.assertRaisesRegex(ValueError, 'own_proc_only'):
            api.own_proc_text('/proc/other/stat')
        opener.assert_not_called()

    def test_nonzero_namespace_offset_refuses_before_stat(self):
        info = types.SimpleNamespace(implementation='clock_gettime(CLOCK_MONOTONIC)',
                                     monotonic=True, adjustable=False, resolution=1e-9)
        with (mock.patch.object(api, 'own_proc_text', return_value='monotonic 1 0\nboottime 0 0\n'),
              mock.patch.object(api.time, 'get_clock_info', return_value=info), mock.patch.object(api.os, 'stat') as stat):
            with self.assertRaisesRegex(ValueError, 'time_namespace_offsets'):
                api.OwnClock().sample()
            stat.assert_not_called()

    def test_suspend_at_each_phase_refuses_without_synthetic_now(self):
        for phase in (101, 179, 184, 189, 699):
            with self.subTest(phase=phase):
                clock = mock.Mock()
                clock.sample.return_value = sample(phase, phase + 10)
                guard = api.ClockBudget(self.timing(), 600, clock)
                with self.assertRaisesRegex(ValueError, 'clock_offset_changed'):
                    guard.check(700)
                self.assertEqual(clock.sample.return_value['monotonic_after_ns'], phase * api.NS)

    def test_namespace_change_reversal_and_identity_change_refuse(self):
        for changed in (sample(101, namespace=[1, 3]), sample(99), sample(101, pid=124)):
            with self.subTest(changed=changed):
                clock = mock.Mock()
                clock.sample.side_effect = [sample(), changed]
                guard = api.ClockBudget(self.timing(), 600, clock)
                guard.check(700)
                with self.assertRaises(ValueError):
                    guard.check(700)

    def test_boottime_phase_bound_with_overlapping_uncertainty(self):
        origin = sample(monotonic_before_ns=100 * api.NS - 1000000, boottime_ns=100 * api.NS)
        timing = api.timing_from_birth(origin, 100 * api.NS)
        clock = mock.Mock()
        # Offset intervals still overlap, but BOOTTIME independently reaches phase end.
        clock.sample.return_value = sample(179.9995, 180)
        guard = api.ClockBudget(timing, 600, clock)
        self.assertTrue(guard.reached(179.999))

    def test_target_preexec_real_callbacks_in_fake_kernel_all_six(self):
        r = resource
        for mode in api.MODES:
            with self.subTest(mode=mode):
                state = {k: (r.RLIM_INFINITY, r.RLIM_INFINITY)
                         for k in (r.RLIMIT_CPU, r.RLIMIT_AS, r.RLIMIT_FSIZE)}
                active = state
                def setlimit(kind, pair):
                    hard = active[kind][1]
                    if pair[0] > pair[1] or (hard != r.RLIM_INFINITY and pair[1] > hard):
                        raise ValueError('fake kernel hard raise')
                    active[kind] = pair
                with (mock.patch.object(r, 'getrlimit', side_effect=lambda k: active[k]),
                      mock.patch.object(r, 'setrlimit', side_effect=setlimit),
                      mock.patch.object(api.os, 'umask'), mock.patch.object(api.signal, 'signal')):
                    api.limits(api.SUPERVISOR_POLICY)
                    saved = dict(state)
                    active = dict(state)
                    api.target_limits(mode)
                    api.limits(api.mode_policy(mode))
                    self.assertEqual(state, saved)
                    self.assertEqual(saved[r.RLIMIT_FSIZE], (1048576, 33554432))
                    self.assertEqual(saved[r.RLIMIT_CPU], (10, 540))
                    self.assertEqual(saved[r.RLIMIT_AS], (134217728, 536870912))
                    self.assertEqual(active[r.RLIMIT_AS][0], api.mode_policy(mode)['address_bytes'])
                    if mode == 'continue':
                        api.child_limits()
                        self.assertEqual(active[r.RLIMIT_AS], (536870912, 536870912))

    def test_target_insufficient_hard_limit_changes_nothing(self):
        with (mock.patch.object(resource, 'getrlimit', return_value=(1, 1)),
              mock.patch.object(resource, 'setrlimit') as setter):
            with self.assertRaisesRegex(ValueError, 'target_inherited_hard_ceiling'):
                api.target_limits('capture')
            setter.assert_not_called()


class GeneratedInvokerTests(unittest.TestCase):
    def setUp(self):
        self.f = original.ControllerTests(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.put(self.f.invoker, (ROOT / 'docs/evidence/task-6' / api.INVOKER_NAME).read_bytes())
        self.f.stack.enter_context(mock.patch.object(api.OwnClock, 'sample', side_effect=lambda: sample(self.f.deadline.current)))
        self.f.stack.enter_context(mock.patch.object(api.time, 'monotonic_ns', side_effect=lambda: int(self.f.deadline.current * api.NS)))

    def controller(self, stage='capture', seconds=600):
        self.f.deadline = original.FakeDeadline(seconds)
        self.f.admission(stage)
        c = api.Controller(stage, self.f.deadline)
        c.api = api
        return c

    def envelope(self, c, mode):
        timing = api.timing_from_birth(sample(), 100 * api.NS)
        return api.durable(mode + '-deadline.json', api.envelope_value(c, mode, timing))

    def test_real_adoption_consumes_once_and_preserves_earlier_origin(self):
        c = self.controller()
        self.envelope(c, 'capture')
        self.f.deadline.start = 105
        self.f.deadline.entry_monotonic_ns = 105 * api.NS
        self.f.deadline.current = 106
        c.adopt_envelope('capture')
        self.assertEqual((c.deadline.start, c.deadline.end), (100, 190))
        self.assertEqual(api.strict(c.claim_record.data)['target_entry_monotonic_ns'], 105 * api.NS)
        fresh = api.Controller('capture', original.FakeDeadline(600))
        with self.assertRaises(FileExistsError):
            fresh.adopt_envelope('capture')
        self.assertFalse(self.f.path('capture-launch.json').exists())
        api.subprocess.Popen.assert_not_called()

    def test_all_six_fixed_envelopes_bind_exact_commands_and_schedules(self):
        c = self.controller()
        for mode in api.MODES:
            c.stage = mode.split('-')[0]  # Pure value generation; not an admitted Controller.
            value = api.envelope_value(c, mode, api.timing_from_birth(sample(), 100 * api.NS))
            self.assertEqual(value['command'], ['python3', '-B', 'scripts/identity_cache_control.py', mode])
            self.assertEqual(value['outer_cutoffs'], [80, 85, 90] if mode == 'capture' else
                             [590, 595, 600] if mode == 'continue' else [170, 175, 180])
            self.assertLessEqual(len(api.raw(value)), 4096)
        with self.assertRaises(ValueError):
            api.target_command('material')

    def test_missing_mismatched_or_extended_envelope_never_claims(self):
        c = self.controller()
        with self.assertRaises(FileNotFoundError):
            c.adopt_envelope('capture')
        record = self.envelope(c, 'capture')
        value = api.strict(record.data)
        value['outer_cutoffs'][0] += 1
        self.f.put(record.path, api.raw(value))
        with self.assertRaisesRegex(ValueError, 'envelope_binding'):
            c.adopt_envelope('capture')
        self.assertFalse(self.f.path('capture-deadline-accepted.json').exists())

    def test_expired_target_budget_refuses_before_claim(self):
        c = self.controller()
        self.envelope(c, 'capture')
        c.deadline.current = 191
        with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
            c.adopt_envelope('capture')
        self.assertFalse(self.f.path('capture-deadline-accepted.json').exists())
        api.subprocess.Popen.assert_not_called()

    def test_continue_real_verified_none_pins_refuse_before_claim(self):
        body = (ROOT / 'scripts/identity_cache_maintenance.py').read_bytes()
        self.f.put(self.f.root / 'scripts/identity_cache_maintenance.py', body)
        self.f.hashes['scripts/identity_cache_maintenance.py'] = api.sha(body)
        c = self.controller('continue')
        self.envelope(c, 'continue')
        with self.assertRaisesRegex(ValueError, 'actual_approval_pin_absent'):
            c.adopt_envelope('continue')
        self.assertFalse(self.f.path('continue-deadline-accepted.json').exists())
        self.assertFalse(self.f.path('continue-launch.json').exists())
        api.subprocess.Popen.assert_not_called()

    def test_claim_fsync_failure_retains_partial_and_refuses_retry(self):
        c = self.controller()
        self.envelope(c, 'capture')
        with mock.patch.object(os, 'fsync', side_effect=OSError('generated fsync')):
            with self.assertRaises(OSError):
                c.adopt_envelope('capture')
        path = self.f.path('capture-deadline-accepted.json')
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            c.adopt_envelope('capture')
        self.assertEqual(path.read_bytes(), before)

    def proof_mutation(self, target, replace):
        c = self.controller()
        self.envelope(c, 'capture')
        c.adopt_envelope('capture')
        path = self.f.path('capture-deadline' + ('-accepted' if target == 'claim' else '') + '.json')
        body = path.read_bytes()
        if replace:
            new = path.with_suffix('.replacement')
            self.f.put(new, body)
            new.replace(path)
        else:
            self.f.put(path, body.replace(b'"version":1', b'"version":2'))
        fresh = api.Controller('capture', self.f.deadline)
        with self.assertRaises(ValueError):
            fresh.history_deadline('capture', c.envelope_record.proof(), c.claim_record.proof())
        with self.assertRaises(ValueError):
            c.require_envelope('capture')
        api.subprocess.Popen.assert_not_called()

    def test_envelope_same_bytes_inode_replacement_refuses(self):
        self.proof_mutation('envelope', True)

    def test_claim_same_bytes_inode_replacement_refuses(self):
        self.proof_mutation('claim', True)

    def test_envelope_in_place_alteration_refuses(self):
        self.proof_mutation('envelope', False)

    def test_claim_in_place_alteration_refuses(self):
        self.proof_mutation('claim', False)

    def test_passive_module_refuses_direct_execution(self):
        with self.assertRaisesRegex(SystemExit, 'use identity_cache_control'):
            exec(compile(self.f.invoker.read_bytes(), str(self.f.invoker), 'exec'), {'__name__': '__main__'})
        api.subprocess.Popen.assert_not_called()

    def test_invoker_changed_after_admission_cannot_compile(self):
        c = self.controller()
        body = self.f.invoker.read_bytes()
        new = self.f.invoker.with_suffix('.replacement')
        self.f.put(new, body)
        new.replace(self.f.invoker)
        with self.assertRaises(ValueError):
            c.load_invoker()
        api.subprocess.Popen.assert_not_called()

    def run_supervisor(self, *, delay=0, finish=100, chunks=(b'fixture output', b''), mutate=None):
        c = self.controller(seconds=180)
        invoker = c.load_invoker()
        owner, proc, signals = self.f.fake_run(finish=finish, chunks=chunks, delay=delay)
        spawn = api.subprocess.Popen.side_effect
        def child(*args, **kwargs):
            result = spawn(*args, **kwargs)
            self.assertTrue(self.f.path('capture-preprobe-deadline.json').exists())
            self.assertTrue(callable(kwargs['preexec_fn']))
            self.f.preprobe(c)  # Generated target result + exact claim, no real child.
            if mutate:
                mutate(c)
            return result
        api.subprocess.Popen.side_effect = child
        with mock.patch.object(api, 'OwnedProcess', return_value=owner), contextlib.redirect_stdout(io.StringIO()):
            result = invoker.run(c, 'capture-preprobe')
        return c, owner, signals, result

    def test_eof_observed_after_drain_cutoff_remains_unknown(self):
        owner, _, _ = self.f.fake_run(finish=100, chunks=(b'',), clock_step=4)
        with self.assertRaises(api.UnknownChild):
            owner.run(api.target_command('capture-preprobe'), [101, 102, 103], lambda _: None)

    def test_supervise_all_six_modes_share_single_verified_loader(self):
        import sys
        for mode in api.MODES:
            with self.subTest(mode=mode):
                module = mock.Mock()
                module.Controller.return_value.load_invoker.return_value.run.return_value = 0
                with (mock.patch.object(sys, 'argv', ['identity_cache_control.py', 'supervise', mode]),
                      mock.patch.object(bootstrap, 'load_control', return_value=module) as loader,
                      mock.patch.object(bootstrap.time, 'monotonic', return_value=bootstrap.ENTRY),
                      mock.patch.object(api.signal, 'signal'), mock.patch.object(api.signal, 'setitimer')):
                    self.assertEqual(bootstrap.main(), 0)
                    loader.assert_called_once_with()
                    module.limits.assert_called_once_with(module.SUPERVISOR_POLICY)
                    module.Controller.return_value.load_invoker.return_value.run.assert_called_once_with(
                        module.Controller.return_value, mode)
                    module.Controller.return_value.adopt_envelope.assert_not_called()
                    module.probe_entry.assert_not_called()

    def test_full_fake_supervisor_stream_terminal_proof_and_no_outer_authority(self):
        c, owner, signals, result = self.run_supervisor()
        self.assertEqual(result, 0)
        value = api.strict(self.f.path('capture-preprobe-supervisor.json').read_bytes())
        self.assertEqual(value['state'], 'recorder-terminal-tool-reconciliation-pending')
        self.assertEqual(value['claim'], c.public('capture-preprobe-deadline-accepted.json').proof())
        self.assertFalse(value['controller_outer_result_created'])
        self.assertEqual(value['outcome']['log_bytes'], len(b'fixture output'))
        self.assertFalse(self.f.path('capture-outer-result.json').exists())
        self.assertEqual(signals, [])
        args, kwargs = self.f.spawn_args
        self.assertEqual(args[0], api.target_command('capture-preprobe'))
        self.assertEqual(kwargs['env'], api.ENV)

    def test_delayed_spawn_past_run_cutoff_never_writes_supervisor_success(self):
        with self.assertRaisesRegex(ValueError, 'recorder_terminal_unknown'):
            self.run_supervisor(delay=171, chunks=(b'',))
        self.assertTrue(self.f.path('capture-preprobe-deadline.json').exists())
        self.assertFalse(self.f.path('capture-preprobe-supervisor.json').exists())

    def test_supervisor_overflow_retains_bounded_log_without_success(self):
        with self.assertRaisesRegex(ValueError, 'recorder_terminal_unknown'):
            self.run_supervisor(chunks=(b'x' * (api.LOG_LIMIT + 1), b''))
        self.assertEqual(self.f.path('capture-preprobe-supervisor.log').stat().st_size, api.LOG_LIMIT)
        self.assertFalse(self.f.path('capture-preprobe-supervisor.json').exists())

    def test_startup_exhausted_before_any_envelope_or_spawn(self):
        c = self.controller(seconds=90)
        c.deadline.start = 191
        c.deadline.end = 281
        c.deadline.entry_monotonic_ns = 191 * api.NS
        c.deadline.current = 191
        with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
            c.load_invoker().run(c, 'capture')
        self.assertFalse(self.f.path('capture-deadline.json').exists())
        api.subprocess.Popen.assert_not_called()

    def test_unknown_spawn_retains_envelope_and_no_retry(self):
        c = self.controller(seconds=180)
        invoker = c.load_invoker()
        with mock.patch.object(api.subprocess, 'Popen', side_effect=OSError('generated spawn uncertainty')) as spawn:
            with self.assertRaises(api.UnknownChild):
                invoker.run(c, 'capture-preprobe')
            self.assertEqual(spawn.call_count, 1)
            with self.assertRaises(FileExistsError):
                invoker.run(c, 'capture-preprobe')
            self.assertEqual(spawn.call_count, 1)
        self.assertTrue(self.f.path('capture-preprobe-deadline.json').exists())
        self.assertFalse(self.f.path('capture-preprobe-supervisor.json').exists())

    def test_replaced_claim_in_fake_target_rejected_by_normal_result(self):
        def mutate(c):
            path = self.f.path('capture-preprobe-deadline-accepted.json')
            new = path.with_suffix('.replacement')
            self.f.put(new, path.read_bytes())
            new.replace(path)
        with self.assertRaises(ValueError):
            self.run_supervisor(mutate=mutate)
        self.assertFalse(self.f.path('capture-preprobe-supervisor.json').exists())

    def test_suspend_during_final_log_fsync_never_creates_success(self):
        sync = os.fsync
        def suspended(fd):
            result = sync(fd)
            if os.fstat(fd).st_size == len(b'fixture output'):
                api.OwnClock.sample.side_effect = lambda: sample(self.f.deadline.current, self.f.deadline.current + 10)
            return result
        with mock.patch.object(os, 'fsync', side_effect=suspended):
            with self.assertRaisesRegex(ValueError, 'clock_offset_changed'):
                self.run_supervisor()
        self.assertFalse(self.f.path('capture-preprobe-supervisor.json').exists())

    def test_late_final_output_cannot_return_success(self):
        class Late(io.StringIO):
            def flush(inner):
                self.f.deadline.current = 281
        c = self.controller(seconds=180)
        invoker = c.load_invoker()
        owner, _, _ = self.f.fake_run(chunks=(b'',))
        spawn = api.subprocess.Popen.side_effect
        def child(*args, **kwargs):
            result = spawn(*args, **kwargs)
            self.f.preprobe(c)
            return result
        api.subprocess.Popen.side_effect = child
        with mock.patch.object(api, 'OwnedProcess', return_value=owner), contextlib.redirect_stdout(Late()):
            with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
                invoker.run(c, 'capture-preprobe')
        self.assertTrue(self.f.path('capture-preprobe-supervisor.json').exists())
        self.assertFalse(self.f.path('capture-outer-result.json').exists())

    def test_normal_operation_receipts_require_recorder_exit_agreement(self):
        for stage in ('capture', 'continue'):
            with self.subTest(stage=stage):
                c = self.f.controller(stage)
                self.f.public_terminal(c)  # Generated independent outer record, never live authority.
                invoker = c.load_invoker()
                outcome = {'terminal': True, 'exit_code': 0, 'timed_out': False, 'overflow': False}
                claim, proof = invoker.validate_target(c, stage, outcome)
                self.assertEqual(claim, c.claim_record.proof())
                self.assertTrue(proof['child_terminal'])
                self.assertEqual(proof['child_exit_code'], None if stage == 'capture' else 0)
                with self.assertRaisesRegex(ValueError, 'recorder_receipt_disagreement'):
                    invoker.validate_target(c, stage, {**outcome, 'exit_code': 1})

    def test_forced_recorder_exit_does_not_prove_nested_terminal(self):
        c = self.controller('continue')
        self.f.bind(c, 'continue')
        invoker = c.load_invoker()
        with self.assertRaisesRegex(ValueError, 'recorder_terminal_unknown'):
            invoker.validate_target(c, 'continue', {'terminal': True, 'exit_code': -9,
                                                   'timed_out': True, 'overflow': False})
        self.assertFalse(self.f.path('continue-outer-result.json').exists())

    def test_outer_result_started_must_equal_conservative_origin(self):
        c = self.f.controller()
        outer = self.f.public_terminal(c)
        outer['started_monotonic_ns'] += 1
        self.f.put(self.f.path('capture-outer-result.json'), api.raw(outer))
        with self.assertRaisesRegex(ValueError, 'outer_budget_origin'):
            c.outer_gate()


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.f = original.ControllerTests(methodName='runTest')
        self.f.real_terminal = True
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.put(self.f.invoker, (ROOT / 'docs/evidence/task-6' / api.INVOKER_NAME).read_bytes())
        self.f.stack.enter_context(mock.patch.object(api.OwnClock, 'sample',
            side_effect=AssertionError('own host clock forbidden outside explicit generated sample')))
        self.f.stack.enter_context(mock.patch.object(api, 'own_proc_text',
            side_effect=AssertionError('real proc forbidden')))

    def c(self, stage='capture', at=100, seconds=600):
        self.f.deadline = original.FakeDeadline(seconds)
        self.f.deadline.start = self.f.deadline.current = at
        self.f.deadline.end = at + seconds
        self.f.deadline.entry_monotonic_ns = int(at * api.NS)
        if not self.f.path(stage + '-admission.json').exists():
            self.f.admission(stage)
        result = api.Controller(stage, self.f.deadline)
        result.api = api
        return result

    def generated_history(self, mode='capture-preprobe', code=0, log=b''):
        c = self.c(mode.split('-')[0])
        self.f.bind(c, mode)
        if mode.endswith('-preprobe'):
            self.f.preprobe(c)
        elif mode in ('capture', 'continue'):
            self.generated_history(mode + '-preprobe')
            self.reconcile_mode(mode + '-preprobe', 101)
            self.f.deadline = c.deadline
            c.deadline.current = 102
            pre, _ = c.preparation()
            launch = c.launch(pre)
            result = {'terminal': True, 'exit_code': code, 'timed_out': False, 'overflow': False}
            if mode == 'continue':
                result.update(log_bytes=0, log_sha256=api.sha(b''))
            c.receipt(launch, result)
        else:
            self.generated_history(c.stage, code)
            self.reconcile_mode(c.stage, 103)
            self.f.deadline = c.deadline
            self.f.put(self.f.path(mode + '.json'), api.raw({
                'version': 1, 'stage': c.stage, 'state': 'postflight-success' if code == 0 else 'incomplete',
                'facts': {}, 'private_proof': {}, 'receipt_sha256': api.sha(self.f.path(c.stage + '-receipt.json').read_bytes()),
                'approval_created': False, 'Q_released': False, 'new3GB_admitted': False,
                'deadline_envelope': c.envelope_record.proof(), 'deadline_claim': c.claim_record.proof()}))
        inv = c.load_invoker()
        outcome = {'terminal': True, 'exit_code': code, 'timed_out': False, 'overflow': False,
                   'log_bytes': len(log), 'log_sha256': api.sha(log)}
        claim, target = inv.validate_target(c, mode, outcome)
        self.f.put(self.f.path(mode + '-supervisor.log'), log)
        observed = 104 if mode.endswith('-postflight') else 102 if '-' not in mode else 100
        ev = api.strict(c.envelope_record.data)
        supervisor = api.durable(mode + '-supervisor.json', {
            'version': 1, 'mode': mode, 'state': 'recorder-terminal-tool-reconciliation-pending',
            'command': api.target_command(mode), 'source_commit': c.admission['source_commit'],
            'invoker': c.invoker_record.proof(), 'envelope': c.envelope_record.proof(), 'claim': claim,
            'outcome': outcome, 'target_proof': target, 'clock_identity': original.CLOCK,
            'budget_start_monotonic_lower_ns': 100 * api.NS, 'outer_entry_monotonic_ns': 100 * api.NS,
            'observed_monotonic_ns': observed * api.NS, 'last_clock_sample': sample(observed),
            'controller_outer_result_created': False, 'Q_released': False})
        raw = {'version': 1, 'origin': 'root-controller-actual-tool', 'mode': mode, 'stage': c.stage,
               'source_commit': c.admission['source_commit'], 'source_manifest_sha256': ev['source_manifest_sha256'],
               'admission': c.admission_record.proof(), 'invoker': c.invoker_record.proof(),
               'envelope': c.envelope_record.proof(), 'claim': claim, 'supervisor': supervisor.proof(),
               'clock_identity': original.CLOCK, 'events': self.events(inv, mode, code), 'terminal_event_index': 0,
               'root_assertion': 'awaited-terminal-before-record-before-reconcile'}
        self.f.put(self.f.path(mode + '-root-tool.json'), api.raw(raw))
        return c, inv

    @staticmethod
    def events(inv, mode, code=0, session=False):
        first = {'output': '', 'wall_time_seconds': 0.01, 'chunk_id': 'fixture', 'original_token_count': 0}
        first.update({'session_id': 17} if session else {'exit_code': code})
        values = [{'seq': 0, 'tool': 'exec_command', 'request': inv.root_request(mode), 'response': first}]
        if session:
            values.append({'seq': 1, 'tool': 'write_stdin', 'request': {
                'session_id': 17, 'chars': '', 'yield_time_ms': 45000, 'max_output_tokens': 2000},
                'response': {'output': '', 'wall_time_seconds': 0, 'exit_code': code}})
        return values

    def reconcile_mode(self, mode='capture-preprobe', at=101, mutate=None):
        c = self.c(mode.split('-')[0], at, 30)
        inv = c.load_invoker()
        own = sample(at, pid=456, birth_ticks=at * 100 + 1, birth_boot_lower_ns=at * api.NS)
        if mutate:
            mutate(own)
        with (mock.patch.object(api.OwnClock, 'sample', return_value=own),
              mock.patch.object(api.time, 'monotonic_ns', return_value=at * api.NS),
              contextlib.redirect_stdout(io.StringIO())):
            result = inv.reconcile(c, mode, (at * api.NS, at * api.NS, at * api.NS))
        return c, inv, result

    def edit(self, suffix, change):
        path = self.f.path(suffix)
        value = api.strict(path.read_bytes())
        change(value)
        self.f.put(path, api.raw(value))

    def test_real_preprobe_reconcile_then_preparation_and_launch_pin(self):
        self.generated_history()
        _, _, result = self.reconcile_mode()
        self.assertEqual(result, 0)
        c = self.c(at=102)
        self.f.bind(c, 'capture')
        c.deadline.entry_monotonic_ns = 100 * api.NS
        pre, _ = c.preparation()
        launch = c.launch(pre)
        self.assertEqual(api.strict(launch.data)['preprobe_terminal'],
                         api.read(self.f.path('capture-preprobe-terminal.json')).proof())
        c.launch_binding(launch)
        api.subprocess.Popen.assert_not_called()
        api.observations.assert_not_called()
        api.private_postflight.assert_not_called()
        self.assertEqual(c.modules, {})

    def test_real_operation_reconcile_and_outer_gate_both_child_types(self):
        for stage in ('capture', 'continue'):
            with self.subTest(stage=stage):
                self.generated_history(stage)
                self.reconcile_mode(stage, 103)
                c = self.c(stage, at=104)
                self.assertTrue(c.outer_gate()[0])
                value = api.strict(self.f.path(stage + '-outer-result.json').read_bytes())
                self.assertEqual(value['child_exit_code'], None if stage == 'capture' else 0)

    def test_known_failure_is_evidence_only_and_postflight_failure_reconciles(self):
        self.generated_history('continue-postflight', 1)
        self.reconcile_mode('continue-postflight', 105)
        c = self.c('continue', at=106)
        value = api.strict(self.f.path('continue-postflight-terminal.json').read_bytes())
        self.assertEqual(value['state'], 'known-failure')
        with self.assertRaisesRegex(ValueError, 'terminal_success_required'):
            c.terminal_gate('continue-postflight', True)
        api.observations.assert_not_called()
        api.subprocess.Popen.assert_not_called()

    def test_immediate_session_optional_and_strict_poll_chain(self):
        c = self.c()
        inv = c.load_invoker()
        for session in (False, True):
            events = self.events(inv, 'capture', session=session)
            self.assertEqual(inv.tool_chain(api, 'capture', events, len(events)-1), 0)
        changes = [lambda x: x[0]['request'].pop('sandbox_permissions'),
                   lambda x: x[0]['request'].update(prefix_rule=['python3']),
                   lambda x: x[0]['request'].update(justification='other'),
                   lambda x: x[1]['request'].update(session_id=18),
                   lambda x: x[1]['request'].update(chars='x'),
                   lambda x: x[1]['request'].update(yield_time_ms=1000),
                   lambda x: x[1]['request'].update(max_output_tokens=1000),
                   lambda x: x[1]['response'].update(session_id=17),
                   lambda x: x[0]['response'].update(exit_code=0),
                   lambda x: x[0]['response'].update(session_id=True),
                   lambda x: x[1]['response'].update(exit_code=True),
                   lambda x: x[1]['response'].update(output=1),
                   lambda x: x[1]['response'].update(wall_time_seconds=float('nan')),
                   lambda x: x[1]['response'].update(extra=0),
                   lambda x: x[0]['response'].update(original_token_count=2001),
                   lambda x: x[1].update(seq=3)]
        for change in changes:
            with self.subTest(change=change):
                events = self.events(inv, 'capture', session=True)
                change(events)
                with self.assertRaises(ValueError):
                    inv.tool_chain(api, 'capture', events, 1)

    def test_tool_chain_exact_event_and_raw_size_bounds(self):
        c = self.c()
        inv = c.load_invoker()
        events = self.events(inv, 'capture', session=True)
        poll = events.pop()
        for i in range(1, 31):
            events.append({'seq': i, 'tool': 'write_stdin', 'request': poll['request'],
                           'response': {'output': '', 'wall_time_seconds': 0, 'session_id': 17}})
        poll['seq'] = 31
        events.append(poll)
        self.assertEqual(inv.tool_chain(api, 'capture', events, 31), 0)
        with self.assertRaises(ValueError):
            inv.tool_chain(api, 'capture', events + [poll], 32)
        self.generated_history()
        self.f.put(self.f.path('capture-preprobe-root-tool.json'), b' ' * 65537)
        with self.assertRaisesRegex(ValueError, 'trusted_record'):
            self.reconcile_mode()

    def test_independent_bounds_all_modes_and_one_nanosecond_late(self):
        self.generated_history()
        c = self.c()
        inv = c.load_invoker()
        hist = inv.history(c, 'capture-preprobe')
        for seconds in (90, 600, 180):
            hist['ev']['wall_seconds'] = seconds
            at = 100 + seconds
            timing = {'start_lower_ns': 100 * api.NS, 'terminal_upper_ns': at * api.NS,
                      'entry_boot_ns': at * api.NS, 'entry_after_ns': at * api.NS,
                      'verified_sample': sample(at, pid=456, birth_ticks=at*100+1, birth_boot_lower_ns=at*api.NS),
                      'metadata_end_ns': at * api.NS}
            inv.terminal_timing(api, hist, timing)
            for field in ('terminal_upper_ns', 'entry_boot_ns'):
                with self.subTest(seconds=seconds, field=field), self.assertRaises(ValueError):
                    inv.terminal_timing(api, hist, {**timing, field: timing[field] + 1})

    def test_clock_suspend_namespace_late_bracket_and_historic_stamp(self):
        self.generated_history()
        c = self.c()
        inv = c.load_invoker()
        hist = inv.history(c, 'capture-preprobe')
        timing = {'start_lower_ns': 100*api.NS, 'terminal_upper_ns': 101*api.NS,
                  'entry_boot_ns': 101*api.NS, 'entry_after_ns': 101*api.NS,
                  'verified_sample': sample(101, pid=456, birth_ticks=10101, birth_boot_lower_ns=101*api.NS),
                  'metadata_end_ns': 101*api.NS}
        changes = [lambda v: v.update(entry_boot_ns=102*api.NS),
                   lambda v: v.update(entry_after_ns=101*api.NS+100000001),
                   lambda v: v['verified_sample'].update(namespace=[8, 9]),
                   lambda v: v.update(terminal_upper_ns=True),
                   lambda v: v.update(metadata_end_ns=132*api.NS)]
        for change in changes:
            value = json.loads(json.dumps(timing))
            change(value)
            with self.assertRaises(ValueError):
                inv.terminal_timing(api, hist, value)
        hist['stamps'].append(102*api.NS)
        with self.assertRaisesRegex(ValueError, 'terminal_clock_order'):
            inv.terminal_timing(api, hist, timing)

    def test_supervisor_and_root_unknown_or_binding_edits_fail_closed(self):
        self.generated_history()
        paths = ['capture-preprobe-supervisor.json', 'capture-preprobe-root-tool.json']
        originals = {p: self.f.path(p).read_bytes() for p in paths}
        edits = [('capture-preprobe-supervisor.json', lambda v: v['outcome'].update(timed_out=True)),
                 ('capture-preprobe-supervisor.json', lambda v: v['outcome'].update(overflow=True)),
                 ('capture-preprobe-supervisor.json', lambda v: v['outcome'].update(exit_code=-9)),
                 ('capture-preprobe-supervisor.json', lambda v: v['outcome'].update(terminal=False)),
                 ('capture-preprobe-root-tool.json', lambda v: v.update(mode='capture')),
                 ('capture-preprobe-root-tool.json', lambda v: v['claim'].update(bytes=True)),
                 ('capture-preprobe-root-tool.json', lambda v: v.update(source_commit='b'*40))]
        for path, change in edits:
            with self.subTest(path=path):
                self.edit(path, change)
                with self.assertRaises(ValueError):
                    self.reconcile_mode()
                self.assertFalse(self.f.path('capture-preprobe-terminal.json').exists())
                # Restore generated fixture only; actual records are never retried.
                self.f.put(self.f.path(path), originals[path])

    def test_empty_log_is_supported_but_generic_read_remains_strict(self):
        self.generated_history()
        with self.assertRaisesRegex(ValueError, 'trusted_record'):
            api.read(self.f.path('capture-preprobe-supervisor.log'))
        self.reconcile_mode()
        c = self.c(at=102)
        c.terminal_gate('capture-preprobe', True)

    def test_log_limit_hash_and_mode_are_checked(self):
        c = self.c()
        inv = c.load_invoker()
        p = self.f.path('capture-preprobe-supervisor.log')
        self.f.put(p, b'x' * api.LOG_LIMIT)
        self.assertEqual(len(inv.supervisor_log(c, 'capture-preprobe').data), api.LOG_LIMIT)
        self.f.put(p, b'x' * (api.LOG_LIMIT+1))
        with self.assertRaises(ValueError):
            inv.supervisor_log(c, 'capture-preprobe')
        self.f.put(p, b'')
        p.chmod(0o644)
        with self.assertRaises(ValueError):
            inv.supervisor_log(c, 'capture-preprobe')

    def test_missing_and_orphan_markers_block_real_progression(self):
        self.generated_history('capture')
        c = self.c(at=103)
        with self.assertRaises(FileNotFoundError):
            c.outer_gate()
        self.f.put(self.f.path('capture-outer-result.json'), b'{}')
        with self.assertRaises(FileNotFoundError):
            c.outer_gate()
        with self.assertRaises(FileExistsError):
            self.reconcile_mode('capture', 103)
        api.private_postflight.assert_not_called()

    def test_same_byte_marker_replacement_breaks_launch_pin(self):
        self.generated_history()
        self.reconcile_mode()
        c = self.c(at=102)
        self.f.bind(c, 'capture')
        c.deadline.entry_monotonic_ns = 100 * api.NS
        pre, _ = c.preparation()
        launch = c.launch(pre)
        path = self.f.path('capture-preprobe-terminal.json')
        body = path.read_bytes()
        path.unlink()
        self.f.put(path, body)
        fresh = self.c(at=103)
        with self.assertRaisesRegex(ValueError, 'launch_preprobe_terminal'):
            fresh.launch_binding(launch)

    def test_input_replacement_during_marker_parent_fsync_retains_no_authority(self):
        self.generated_history()
        real = api.os.fsync
        changed = False
        def fsync(fd):
            nonlocal changed
            real(fd)
            if not changed and self.f.path('capture-preprobe-terminal.json').exists():
                changed = True
                path = self.f.path('capture-preprobe-root-tool.json')
                body = path.read_bytes()
                path.unlink()
                self.f.put(path, body)
        with mock.patch.object(api.os, 'fsync', side_effect=fsync), self.assertRaises(ValueError):
            self.reconcile_mode()
        self.assertTrue(changed)
        with self.assertRaises(ValueError):
            self.c(at=102).terminal_gate('capture-preprobe')

    def test_metadata_identity_is_new_and_no_retry_or_automatic_operation(self):
        self.generated_history()
        c, _, _ = self.reconcile_mode()
        value = api.strict(self.f.path('capture-preprobe-terminal.json').read_bytes())
        self.assertEqual(value['timing']['verified_sample']['pid'], 456)
        with self.assertRaises(FileExistsError):
            self.reconcile_mode()
        self.assertFalse(self.f.path('capture-launch.json').exists())
        self.assertEqual(c.modules, {})
        api.subprocess.Popen.assert_not_called()

    def test_reconcile_bootstrap_dispatch_never_adopts_or_loads_operation(self):
        import sys
        for mode in api.MODES:
            module = mock.Mock()
            module.Controller.return_value.load_invoker.return_value.reconcile.return_value = 0
            with (mock.patch.object(sys, 'argv', ['fixed', 'reconcile', mode]),
                  mock.patch.object(bootstrap, 'load_control', return_value=module),
                  mock.patch.object(bootstrap.time, 'monotonic', return_value=bootstrap.ENTRY),
                  mock.patch.object(signal, 'signal'), mock.patch.object(signal, 'setitimer')):
                self.assertEqual(bootstrap.main(), 0)
            module.Deadline.assert_called_once_with(bootstrap.ENTRY, 30)
            module.limits.assert_called_once_with(module.METADATA_POLICY)
            controller = module.Controller.return_value
            controller.adopt_envelope.assert_not_called()
            controller.controller_module.assert_not_called()
            controller.load_modules.assert_not_called()
            controller.load_invoker.return_value.reconcile.assert_called_once_with(
                controller, mode, (bootstrap.ENTRY_NS, bootstrap.ENTRY_BOOT_NS, bootstrap.ENTRY_AFTER_NS))

    def test_bootstrap_triads_are_real_earliest_samples_before_loader(self):
        body = (ROOT / 'scripts/identity_cache_control.py').read_text().split('OBSERVER_PATH =')[0]
        calls = []
        fake = types.SimpleNamespace(monotonic_ns=lambda: (calls.append('M') or (10 if len(calls)==1 else 12)),
                                     clock_gettime_ns=lambda kind: (calls.append('B') or 11), CLOCK_BOOTTIME=7)
        values = {'__builtins__': {'__import__': lambda name: fake if name == 'time' else None}}
        exec(body, values)
        self.assertEqual(calls, ['M', 'B', 'M'])
        self.assertEqual((values['ENTRY_NS'], values['ENTRY_BOOT_NS'], values['ENTRY_AFTER_NS']), (10, 11, 12))

    def test_metadata_soft_hard_limits_and_late_budget_stop_before_outputs(self):
        self.assertEqual(api.METADATA_POLICY, {'wall_seconds': 30, 'cpu_seconds': 5,
                         'address_bytes': 134217728, 'file_bytes': 1048576})
        self.generated_history()
        c = self.c(at=101, seconds=30)
        inv = c.load_invoker()
        # Birth is too old for this metadata invocation, no budget restart.
        with mock.patch.object(api.OwnClock, 'sample', return_value=sample(131)), self.assertRaises(ValueError):
            inv.reconcile(c, 'capture-preprobe', (101*api.NS, 101*api.NS, 101*api.NS))
        self.assertFalse(self.f.path('capture-preprobe-terminal.json').exists())

    def test_partial_marker_and_stale_preprobe_never_prepare(self):
        self.generated_history()
        self.f.put(self.f.path('capture-preprobe-terminal.json'), b'{')
        c = self.c(at=102)
        self.f.bind(c, 'capture')
        with self.assertRaises(ValueError):
            c.preparation()
        with self.assertRaises(FileExistsError):
            self.reconcile_mode()
        c.deadline.current = 161
        with self.assertRaisesRegex(ValueError, 'preprobe_age'):
            c.preparation()
        self.assertFalse(self.f.path('capture-launch.json').exists())

    def test_unknown_probe_partial_receipt_and_changed_log_are_rejected(self):
        self.generated_history()
        self.f.put(self.f.path('capture-preprobe.json'), api.raw({'version': 1, 'state': 'incomplete-or-unknown-retain'}))
        with self.assertRaises(ValueError):
            self.reconcile_mode()
        self.assertFalse(self.f.path('capture-preprobe-terminal.json').exists())

    def test_outer_write_input_body_alteration_stops_before_marker(self):
        self.generated_history('capture')
        real = api.durable
        def write(suffix, value):
            result = real(suffix, value)
            if suffix == 'capture-outer-result.json':
                self.edit('capture-root-tool.json', lambda v: v.update(root_assertion='altered'))
            return result
        with mock.patch.object(api, 'durable', side_effect=write), self.assertRaises(ValueError):
            self.reconcile_mode('capture', 103)
        self.assertTrue(self.f.path('capture-outer-result.json').exists())
        self.assertFalse(self.f.path('capture-terminal.json').exists())

    def test_input_inplace_alteration_after_marker_refuses_consumer(self):
        self.generated_history()
        self.reconcile_mode()
        self.edit('capture-preprobe-deadline-accepted.json', lambda v: v.update(target_entry_monotonic_ns=101*api.NS))
        with self.assertRaises(ValueError):
            self.c(at=102).terminal_gate('capture-preprobe')

    def test_tool_terminal_disagreement_unknown_output_and_boolean_index(self):
        self.generated_history()
        self.edit('capture-preprobe-root-tool.json', lambda v: v['events'][0]['response'].update(exit_code=1))
        with self.assertRaisesRegex(ValueError, 'tool_supervisor_exit'):
            self.reconcile_mode()
        c = self.c()
        inv = c.load_invoker()
        with self.assertRaises(ValueError):
            inv.tool_chain(api, 'capture', self.events(inv, 'capture'), False)

    def test_nested_generated_clock_override_restores_fail_closed_sentinel(self):
        with mock.patch.object(api.OwnClock, 'sample', return_value=sample()):
            self.assertEqual(api.OwnClock().sample(), sample())
        with self.assertRaisesRegex(AssertionError, 'own host clock forbidden'):
            api.OwnClock().sample()
        api.own_proc_text.assert_not_called()
        self.assertEqual(api.clock_identity(), original.CLOCK)


if __name__ == '__main__':
    unittest.main()
