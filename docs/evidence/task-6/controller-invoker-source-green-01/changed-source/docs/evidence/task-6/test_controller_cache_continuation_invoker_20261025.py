"""Generated invoker fixtures only; no real proc, process, clock identity or binary."""
import json
from pathlib import Path
import resource
import unittest
from unittest import mock

import identity_cache_observe as api

ROOT = Path(__file__).absolute().parents[3]


class InvokerTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
