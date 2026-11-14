"""Generated private fixtures; clocks/children/observers are fake, never live."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import types
import unittest
from unittest import mock

import identity_cache_control as bootstrap
import identity_cache_observe as control
import identity_cache_capture as capture
import identity_cache_maintenance as maintenance
import identity_cache as old

REPO = Path(__file__).absolute().parent.parent
CLOCK = {'machine_id': '1' * 32, 'boot_id': '2' * 8 + '-2222-2222-2222-' + '2' * 12}
REAL_DIRECTORY = control.directory
REAL_OBSERVATIONS = control.observations
REAL_PRIVATE_POSTFLIGHT = control.private_postflight


class FakeDeadline(control.Deadline):
    def __init__(self, seconds=600):
        super().__init__(100, seconds)
        self.current, self.arms = 100, []

    def now(self):
        return self.current

    def arm(self, cutoff=None):
        self.check(cutoff)
        self.arms.append(self.end if cutoff is None else cutoff)


class FakeProcess:
    pid = 424242

    def __init__(self, deadline, finish=None):
        self.deadline, self.finish = deadline, finish
        self.stdout = mock.Mock()
        self.stdout.fileno.return_value = 12345

    def poll(self):
        return 0 if self.finish is not None and self.deadline.now() >= self.finish else None


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for target, name in ((control.OwnClock, 'sample'), (control, 'own_proc_text'),
                             (control.socket, 'socket'), (control.subprocess, 'Popen')):
            self.stack.enter_context(mock.patch.object(target, name,
                side_effect=AssertionError('own host clock forbidden outside explicit generated sample'
                                          if name == 'sample' else 'real host/native access forbidden')))
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='warden-controller-fixture-')))
        self.public = self.root / control.PUBLIC
        self.public.mkdir(parents=True, mode=0o700)
        self.stack.enter_context(mock.patch.object(control, 'ROOT', self.root))
        self.stack.enter_context(mock.patch.object(control, 'clock_identity', return_value=CLOCK))
        self.stack.enter_context(mock.patch.object(control.subprocess, 'Popen', side_effect=AssertionError('real child forbidden')))
        self.stack.enter_context(mock.patch.object(control.os, 'killpg', side_effect=AssertionError('real signal forbidden')))
        self.stack.enter_context(mock.patch.object(control, 'observations', side_effect=AssertionError('real observer forbidden')))
        self.stack.enter_context(mock.patch.object(control, 'private_postflight', side_effect=AssertionError('real private read forbidden')))
        self.names = set(json.loads((REPO / 'docs/evidence/task-6/controller-operations-red-01/baseline.json').read_text())['sources'])
        self.names.update('scripts/' + n for n in ('identity_cache_control.py', 'identity_cache_capture.py', 'identity_cache_maintenance.py',
                          'identity_cache_observe.py', 'test_identity_cache_control.py'))
        self.hashes = {}
        for name in sorted(self.names):
            body = ('# generated source ' + name + '\n').encode()
            self.put(self.root / name, body)
            self.hashes[name] = control.sha(body)
        self.invoker = self.public / 'controller-cache-continuation-outer-invoker-20261025.py'
        self.put(self.invoker, b'# generated fixed outer invoker\n')
        # Exact generated parents only; does not claim host ancestor acceptance.
        allowed = {self.public, self.root} | {(self.root / n).parent for n in self.names}
        self.allowed = allowed
        def fixture_directory(path):
            self.assertIn(path, allowed, 'only exact generated parent FD injection')
            return os.open(path, control.DIR_FLAGS)
        self.stack.enter_context(mock.patch.object(control, 'directory', side_effect=fixture_directory))
        self.deadline = FakeDeadline()
        self.facts = {'siblings': {'fixture': 'unchanged'}, 'charges': 5000000000,
                      'owned_images': [], 'phase_state_hashes': {'inspect': '3' * 64}}
        if not getattr(self, 'real_terminal', False):
            # Existing operation fixtures isolate their original boundary. New
            # reconciliation fixtures opt out and exercise the real whole chain.
            def terminal(instance, mode, success_only=False):
                path = self.path(mode + '-terminal.json')
                if not path.exists():
                    self.put(path, b'{"generated_unit_boundary":true}\n')
                record = instance.public(mode + '-terminal.json')
                return record
            self.stack.enter_context(mock.patch.object(control.Controller, 'terminal_gate', terminal))

    @staticmethod
    def put(path, body):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(body)
        path.chmod(0o600)

    def path(self, suffix):
        return self.public / (control.PREFIX + suffix)

    def admission(self, stage='capture', edit=None):
        value = {'version': 1, 'stage': stage, 'source_commit': 'a' * 40, 'source_hashes': self.hashes,
                 'review_sha256': 'b' * 64, 'ruling_sha256': 'c' * 64,
                 'writer_basis': 'generated fixture writers absent', 'clock_identity': CLOCK,
                 'policy': control.POLICY[stage], 'outer_invoker_sha256': control.sha(self.invoker.read_bytes())}
        if edit:
            edit(value)
        self.put(self.path(stage + '-admission.json'), control.raw(value))
        return value

    def controller(self, stage='capture'):
        self.admission(stage)
        c = control.Controller(stage, self.deadline)
        c.api = control
        self.bind(c, stage)
        return c

    def proofs(self, c, mode):
        # Generated proof chain for existing operation-unit fixtures. The dedicated
        # invoker module exercises actual adoption and one-use consumption.
        sample = {'pid': 123, 'hz': 100, 'birth_ticks': 10001, 'birth_boot_lower_ns': 100 * control.NS,
                  'namespace': [1, 2], 'monotonic_before_ns': 100 * control.NS,
                  'boottime_ns': 100 * control.NS, 'monotonic_after_ns': 100 * control.NS}
        timing = control.timing_from_birth(sample, 100 * control.NS)
        path = self.path(mode + '-deadline.json')
        if not path.exists():
            self.put(path, control.raw(control.envelope_value(c, mode, timing)))
        envelope = c.public(mode + '-deadline.json')
        claimpath = self.path(mode + '-deadline-accepted.json')
        if not claimpath.exists():
            self.put(claimpath, control.raw(c.claim_value(mode, envelope, 100 * control.NS)))
        return envelope, c.public(mode + '-deadline-accepted.json')

    def bind(self, c, mode):
        c.envelope_record, c.claim_record = self.proofs(c, mode)
        c.envelope_mode = mode
        return c

    def preprobe(self, c, at=None):
        envelope, claim = self.proofs(c, c.stage + '-preprobe')
        value = {'version': 1, 'stage': c.stage, 'state': 'preprobe-complete',
                 'admission_sha256': control.sha(c.admission_record.data), 'source_commit': c.admission['source_commit'],
                 'source_hashes': c.admission['source_hashes'], 'clock_identity': CLOCK,
                 'observed_monotonic_ns': int(self.deadline.now() * 1e9) if at is None else at,
                 'utc': '2026-10-25T00:00:00+00:00', 'facts': self.facts, 'Q_released': False,
                 'deadline_envelope': envelope.proof(), 'deadline_claim': claim.proof()}
        self.put(self.path(c.stage + '-preprobe.json'), control.raw(value))
        return value

    def public_terminal(self, c, outcome=None):
        self.preprobe(c)
        pre, _ = c.preparation()
        launch = c.launch(pre)
        outcome = outcome or {'terminal': True, 'exit_code': 0, 'timed_out': False, 'overflow': False}
        if c.stage == 'continue':
            outcome = {**outcome, 'log_bytes': 0, 'log_sha256': control.sha(b'')}
        receipt = c.receipt(launch, outcome)
        outer = {'version': 1, 'stage': c.stage, 'producer': 'controller-tool-result', 'terminal': True,
                 'exit_code': 0 if outcome['exit_code'] == 0 and not outcome['timed_out'] else 1,
                 'child_terminal': True, 'child_exit_code': None if c.stage == 'capture' else outcome['exit_code'],
                 'launch_sha256': control.sha(launch.data), 'receipt_sha256': control.sha(receipt.data),
                 'source_commit': c.admission['source_commit'], 'outer_invoker_sha256': c.admission['outer_invoker_sha256'],
                 'command': control.COMMAND[c.stage], 'clock_identity': CLOCK,
                 'started_monotonic_ns': int(self.deadline.start * 1e9),
                 'ended_monotonic_ns': int(self.deadline.now() * 1e9)}
        self.put(self.path(c.stage + '-outer-result.json'), control.raw(outer))
        return outer

    def fake_run(self, finish=100, chunks=(b'',), delay=0, clock_step=1, sink=None):
        deadline = self.deadline
        proc = FakeProcess(deadline, finish)
        signals = []
        owner = control.OwnedProcess(deadline)
        queue = list(chunks)
        def spawn(*args, **kwargs):
            deadline.current += delay
            self.spawn_args = args, kwargs
            return proc
        def chunk(timeout):
            deadline.current += clock_step
            return queue.pop(0) if queue else b''
        self.stack.enter_context(mock.patch.object(control.subprocess, 'Popen', side_effect=spawn))
        self.stack.enter_context(mock.patch.object(control.os, 'set_blocking'))
        self.stack.enter_context(mock.patch.object(control.os, 'killpg', side_effect=lambda pid, sig: signals.append((pid, sig))))
        self.stack.enter_context(mock.patch.object(owner, 'chunk', side_effect=chunk))
        self.stack.enter_context(mock.patch.object(control.time, 'sleep', side_effect=lambda n: setattr(deadline, 'current', deadline.current + max(n, 1))))
        return owner, proc, signals

    def test_maintenance_production_approval_pins_are_absent(self):
        self.assertIsNone(maintenance.EXPECTED_APPROVAL_SHA256)
        self.assertIsNone(maintenance.EXPECTED_APPROVAL_BYTES)
        c = mock.Mock()
        with self.assertRaisesRegex(ValueError, 'actual_approval_pin_absent'):
            maintenance.run(c)
        c.preparation.assert_not_called()

    def test_fixed_operation_budgets(self):
        self.assertEqual(control.POLICY['capture']['wall_seconds'], 90)
        self.assertEqual(control.POLICY['continue']['cutoffs'], [580, 585, 590, 600])

    def test_capture_has_fixed_callable(self):
        self.assertTrue(callable(capture.run))

    def test_fixed_bootstrap_pins_match_frozen_observer_source(self):
        expected = hashlib.sha256((REPO / 'scripts/identity_cache_observe.py').read_bytes()).hexdigest()
        self.assertEqual(bootstrap.EXPECTED_OBSERVER_SHA256, expected)

    def test_absent_admission_refuses_without_source_import(self):
        with self.assertRaises(FileNotFoundError):
            control.Controller('capture', self.deadline)

    def test_exact_source_set_and_hash_required(self):
        self.admission(edit=lambda v: v['source_hashes'].pop(next(iter(v['source_hashes']))))
        with self.assertRaisesRegex(ValueError, 'canonical_source_names'):
            control.Controller('capture', self.deadline)

    def test_source_changed_is_refused(self):
        self.admission()
        self.put(self.root / 'scripts/identity_cache_observe.py', b'changed\n')
        with self.assertRaisesRegex(ValueError, 'source_hash_mismatch'):
            control.Controller('capture', self.deadline)

    def test_invoker_source_is_required_and_pinned(self):
        self.admission()
        self.put(self.invoker, b'changed\n')
        with self.assertRaisesRegex(ValueError, 'outer_invoker_hash'):
            control.Controller('capture', self.deadline)

    def test_policy_and_numeric_types_are_exact(self):
        self.admission(edit=lambda v: v.update(version=True))
        with self.assertRaisesRegex(ValueError, 'admission_identity'):
            control.Controller('capture', self.deadline)

    def test_record_symlink_or_multilink_is_refused(self):
        path = self.path('fixture.json')
        target = self.path('target.json')
        self.put(target, b'{}')
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            control.read(path)
        path.unlink()
        os.link(target, path)
        with self.assertRaises(ValueError):
            control.read(path)

    def test_duplicate_json_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate_key'):
            control.strict(b'{"version":1,"version":2}')

    def test_preprobe_future_age_refused(self):
        c = self.controller()
        self.preprobe(c, int((self.deadline.now() + 1) * 1e9))
        with self.assertRaisesRegex(ValueError, 'preprobe_age'):
            c.preparation()

    def test_preprobe_stale_refused(self):
        c = self.controller()
        self.preprobe(c, int((self.deadline.now() - 61) * 1e9))
        with self.assertRaisesRegex(ValueError, 'preprobe_age'):
            c.preparation()

    def test_preprobe_other_boot_refused(self):
        c = self.controller()
        self.preprobe(c)
        with mock.patch.object(control, 'clock_identity', return_value={**CLOCK, 'boot_id': 'other'}):
            with self.assertRaisesRegex(ValueError, 'host_boot_mismatch'):
                c.preparation()

    def test_preprobe_boolean_clock_refused(self):
        c = self.controller()
        self.preprobe(c, True)
        with self.assertRaisesRegex(ValueError, 'exact_integer'):
            c.preparation()

    def test_existing_launch_prevents_retry(self):
        c = self.controller()
        self.preprobe(c)
        self.put(self.path('capture-launch.json'), b'partial')
        with self.assertRaises(FileExistsError):
            c.preparation()

    def journal_change(self, point, replace):
        path = self.path('capture-launch.json')
        sync = os.fsync
        injected = {}
        def fsync(fd):
            is_parent = os.fstat(fd).st_ino == self.public.stat().st_ino
            if path.exists() and is_parent == (point == 'parent') and not injected:
                original = path.read_bytes()
                injected['original'] = original
                if replace:
                    path.rename(self.path('retained-created.json'))
                    self.put(path, b'[' + original[1:])
                else:
                    with path.open('r+b') as stream:
                        stream.write(b'[' + original[1:])
                injected['metadata'] = control.meta(path.stat())
                injected['body'] = path.read_bytes()
            return sync(fd)
        with mock.patch.object(os, 'fsync', side_effect=fsync):
            with self.assertRaises(ValueError):
                control.durable('capture-launch.json', {'fixture': 'value'})
        self.assertTrue(injected)
        self.assertEqual(path.read_bytes(), injected['body'])
        self.assertEqual(control.meta(path.stat()), injected['metadata'])

    def test_launch_replaced_during_file_fsync_refuses(self):
        self.journal_change('file', True)

    def test_launch_altered_during_file_fsync_refuses(self):
        self.journal_change('file', False)

    def test_launch_replaced_during_parent_fsync_refuses(self):
        self.journal_change('parent', True)

    def test_launch_altered_during_parent_fsync_refuses(self):
        self.journal_change('parent', False)

    def test_public_write_fsync_failure_retains_partial(self):
        with mock.patch.object(os, 'fsync', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                control.durable('capture-launch.json', {'fixture': 'value'})
        self.assertTrue(self.path('capture-launch.json').exists())
        with self.assertRaises(FileExistsError):
            control.durable('capture-launch.json', {'fixture': 'value'})

    def test_source_replacement_after_prepare_blocks_launch(self):
        c = self.controller()
        self.preprobe(c)
        pre, _ = c.preparation()
        self.put(self.root / 'scripts/identity_cache_capture.py', b'changed')
        with self.assertRaises(ValueError):
            c.launch(pre)
        self.assertFalse(self.path('capture-launch.json').exists())

    def test_preprobe_age_rechecked_at_actual_launch(self):
        c = self.controller()
        self.preprobe(c)
        pre, _ = c.preparation()
        self.deadline.current += 61
        with self.assertRaisesRegex(ValueError, 'preprobe_age'):
            c.launch(pre)
        self.assertFalse(self.path('capture-launch.json').exists())

    def test_production_bootstrap_rejects_group_writable_ancestor(self):
        bad = types.SimpleNamespace(st_uid=1000, st_mode=0o40775)
        with (mock.patch.object(os, 'open', return_value=999), mock.patch.object(os, 'close'),
              mock.patch.object(os, 'fstat', return_value=bad)):
            with self.assertRaisesRegex(ValueError, 'untrusted_ancestor'):
                REAL_DIRECTORY(Path('/fixture'))

    def test_generated_group_writable_record_refused(self):
        path = self.path('fixture.json')
        self.put(path, b'{}')
        path.chmod(0o664)
        with self.assertRaisesRegex(ValueError, 'trusted_record'):
            control.read(path)

    def test_outer_result_required_before_private_or_guard(self):
        c = self.controller()
        self.public_terminal(c)
        self.path('capture-outer-result.json').unlink()
        with mock.patch.object(control, 'Controller', return_value=c):
            with self.assertRaises(FileNotFoundError):
                control.run_probe('capture-postflight', self.deadline, self.bind(c, 'capture-postflight'))
        control.private_postflight.assert_not_called()
        control.observations.assert_not_called()

    def test_outer_receipt_hash_mismatch_refused(self):
        c = self.controller()
        outer = self.public_terminal(c)
        outer['receipt_sha256'] = '0' * 64
        self.put(self.path('capture-outer-result.json'), control.raw(outer))
        with self.assertRaisesRegex(ValueError, 'outer_terminal_binding'):
            c.outer_gate()

    def test_outer_unknown_child_refused(self):
        c = self.controller('continue')
        outer = self.public_terminal(c)
        outer['child_terminal'] = False
        self.put(self.path('continue-outer-result.json'), control.raw(outer))
        with self.assertRaisesRegex(ValueError, 'outer_child_terminal'):
            c.outer_gate()

    def test_outer_deadline_includes_interpreter_startup(self):
        c = self.controller()
        outer = self.public_terminal(c)
        outer['started_monotonic_ns'] = 0
        self.put(self.path('capture-outer-result.json'), control.raw(outer))
        with self.assertRaisesRegex(ValueError, 'outer_(wall_bound|budget_origin)'):
            c.outer_gate()

    def test_nonzero_known_terminal_is_not_success(self):
        c = self.controller('continue')
        self.public_terminal(c, {'terminal': True, 'exit_code': -15, 'timed_out': True, 'overflow': False})
        success, _ = c.outer_gate()
        self.assertFalse(success)

    def test_owned_child_normal_stream_and_exact_spawn_options(self):
        owner, proc, signals = self.fake_run(chunks=(b'abc', b''))
        output = []
        result = owner.run(control.CHILD, [680, 685, 690], output.append)
        self.assertTrue(result['terminal'])
        self.assertEqual(b''.join(output), b'abc')
        self.assertEqual(result['log_sha256'], control.sha(b'abc'))
        self.assertEqual(signals, [])
        args, kwargs = self.spawn_args
        self.assertEqual(args[0], control.CHILD)
        self.assertEqual(kwargs['env'], control.ENV)
        self.assertTrue(kwargs['start_new_session'])
        self.assertTrue(kwargs['close_fds'])

    def test_owned_child_absolute_term_kill_and_unknown(self):
        owner, _, signals = self.fake_run(finish=None, chunks=(None,), clock_step=200)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(control.UnknownChild):
                owner.run(control.CHILD, [680, 685, 690], lambda _: None)
        self.assertIn((424242, signal.SIGTERM), signals)
        self.assertIn((424242, signal.SIGKILL), signals)
        self.assertNotIn(977390, [pid for pid, _ in signals])
        self.assertIs(self.deadline.owner, owner)

    def test_delayed_popen_does_not_restart_budget(self):
        owner, _, signals = self.fake_run(finish=None, delay=591)
        with self.assertRaises(control.UnknownChild):
            owner.run(control.CHILD, [680, 685, 690], lambda _: None)
        self.assertIn((424242, signal.SIGKILL), signals)

    def test_delayed_popen_terminal_after_run_cutoff_cannot_be_success(self):
        owner, _, signals = self.fake_run(finish=100, delay=581, chunks=(b'',), clock_step=0)
        result = owner.run(control.CHILD, [680, 685, 690], lambda _: None)
        self.assertTrue(result['timed_out'])
        self.assertEqual(signals, [])

    def test_spawn_exception_is_unknown_and_not_retried(self):
        owner = control.OwnedProcess(self.deadline)
        with mock.patch.object(control.subprocess, 'Popen', side_effect=OSError('fixture')) as spawn:
            with self.assertRaises(control.UnknownChild):
                owner.run(control.CHILD, [680, 685, 690], lambda _: None)
            self.assertTrue(owner.spawn_pending)
            with self.assertRaises(ValueError):
                owner.run(control.CHILD, [680, 685, 690], lambda _: None)
            self.assertEqual(spawn.call_count, 1)

    def test_no_signal_after_observed_terminal(self):
        owner, proc, signals = self.fake_run()
        owner.proc = proc
        owner.signal(signal.SIGKILL)
        self.assertEqual(signals, [])

    def test_log_at_limit_is_not_overflow(self):
        owner, _, _ = self.fake_run(chunks=(b'a' * control.LOG_LIMIT, b''))
        result = owner.run(control.CHILD, [680, 685, 690], lambda _: None)
        self.assertEqual(result['log_bytes'], control.LOG_LIMIT)
        self.assertFalse(result['overflow'])

    def test_log_over_limit_is_bounded_and_not_success(self):
        owner, _, _ = self.fake_run(chunks=(b'a' * (control.LOG_LIMIT + 1), b''))
        stored = []
        result = owner.run(control.CHILD, [680, 685, 690], stored.append)
        self.assertTrue(result['overflow'])
        self.assertEqual(sum(map(len, stored)), control.LOG_LIMIT)

    def test_no_launch_after_run_cutoff(self):
        self.deadline.current = 680
        owner = control.OwnedProcess(self.deadline)
        with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
            owner.run(control.CHILD, [680, 685, 690], lambda _: None)
        control.subprocess.Popen.assert_not_called()

    def test_receipt_cannot_be_written_after_whole_deadline(self):
        c = self.controller()
        self.preprobe(c)
        pre, _ = c.preparation()
        launch = c.launch(pre)
        self.deadline.current = self.deadline.end
        with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
            c.receipt(launch, {})
        self.assertFalse(self.path('capture-receipt.json').exists())

    def test_docker_only_project_scoped_readonly_commands(self):
        recovery = types.SimpleNamespace(OLD_LABELS={'project': 'warden', 'owner': 'fixture'})
        adapter = control.ReadOnlyDocker(self.deadline, recovery)
        good = ['image', 'ls', '--quiet', '--no-trunc', '--all', '--filter', 'label=project=warden']
        self.assertEqual(adapter.validate(good), ('image', True))
        for command in (['container', 'rm', 'x'], ['image', 'ls'], ['container', 'inspect', 'a' * 64],
                        [*good[:-1], 'label=project=other']):
            with self.assertRaises(ValueError):
                adapter.validate(command)
        control.subprocess.Popen.assert_not_called()

    def test_docker_inspect_requires_id_from_its_scoped_listing(self):
        recovery = types.SimpleNamespace(OLD_LABELS={'project': 'warden'})
        adapter = control.ReadOnlyDocker(self.deadline, recovery)
        identity = 'sha256:' + 'a' * 64
        adapter.ids['image'][(('project', 'warden'),)] = {identity}
        self.assertEqual(adapter.validate(['image', 'inspect', identity]), ('image', False))
        with self.assertRaises(ValueError):
            adapter.validate(['container', 'inspect', identity])

    def test_docker_adapter_restores_only_cli(self):
        lock, original = object(), object()
        recovery = types.SimpleNamespace(OLD_LABELS={'project': 'warden'}, docker=original, project_lock=lock)
        with self.assertRaises(ValueError):
            with control.docker_adapter(recovery, self.deadline):
                self.assertIs(recovery.project_lock, lock)
                self.assertIsInstance(recovery.docker, control.ReadOnlyDocker)
                raise ValueError('fixture')
        self.assertIs(recovery.docker, original)
        self.assertIs(recovery.project_lock, lock)

    def fake_capture_controller(self):
        self.deadline = FakeDeadline(90)
        c = self.controller()
        self.preprobe(c)
        events = []
        def function(basis):
            self.assertTrue(self.path('capture-launch.json').exists())
            events.append('capture')
            return {'generated': 'summary'}
        c.modules = {'identity_cache_continue': types.SimpleNamespace(capture_checkpoint=function)}
        c.load_modules = mock.Mock()
        self.stack.enter_context(mock.patch.object(control, 'summary_check'))
        return c, events

    def test_inprocess_capture_durable_launch_before_function_and_no_approval(self):
        c, events = self.fake_capture_controller()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(capture.run(c), 0)
        self.assertEqual(events, ['capture'])
        self.assertEqual(self.deadline.arms, [180, 190])
        self.assertTrue(self.path('capture-summary.json').exists())
        self.assertTrue(self.path('capture-receipt.json').exists())
        self.assertFalse((self.public / 'cache-continuation-checkpoint-approval-20261025.json').exists())
        control.subprocess.Popen.assert_not_called()

    def test_capture_phase_budget_counts_preparation_time(self):
        c, events = self.fake_capture_controller()
        self.deadline.current = 181
        self.preprobe(c)
        with self.assertRaises(ValueError):
            capture.run(c)
        self.assertEqual(events, [])
        control.subprocess.Popen.assert_not_called()

    def test_capture_parent_fsync_fault_never_calls_function(self):
        c, events = self.fake_capture_controller()
        sync = os.fsync
        def failing(fd):
            if os.fstat(fd).st_ino == self.public.stat().st_ino:
                raise OSError('fixture parent fsync')
            return sync(fd)
        with mock.patch.object(os, 'fsync', side_effect=failing):
            with self.assertRaises(OSError):
                capture.run(c)
        self.assertEqual(events, [])
        self.assertTrue(self.path('capture-launch.json').exists())

    def test_capture_known_exception_retains_launch_and_records_failure(self):
        c, events = self.fake_capture_controller()
        c.modules['identity_cache_continue'].capture_checkpoint = mock.Mock(side_effect=ValueError('fixture'))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(capture.run(c), 1)
        self.assertTrue(self.path('capture-launch.json').exists())
        receipt = control.strict(self.path('capture-receipt.json').read_bytes())
        self.assertEqual(receipt['outcome']['exit_code'], 1)
        self.assertFalse(self.path('capture-summary.json').exists())

    def test_distinct_probe_lock_holds_and_no_automatic_operation(self):
        c = self.controller()
        events = []
        @contextlib.contextmanager
        def lock():
            events.append('lock')
            try:
                yield
            finally:
                events.append('unlock')
        c.modules = {'firecracker_recovery': types.SimpleNamespace(project_lock=lock)}
        c.load_modules = mock.Mock()
        def observation(_):
            self.assertEqual(events[-1], 'lock')
            events.append('observe')
            return self.facts
        with (mock.patch.object(control, 'Controller', return_value=c),
              mock.patch.object(control, 'observations', side_effect=observation),
              contextlib.redirect_stdout(io.StringIO())):
            self.assertEqual(control.run_probe('capture-preprobe', self.deadline, self.bind(c, 'capture-preprobe')), 0)
        self.assertEqual(events, ['lock', 'observe', 'unlock'])
        self.assertFalse(self.path('capture-launch.json').exists())
        control.subprocess.Popen.assert_not_called()

    def test_postflight_sibling_change_refused_without_completion_record(self):
        c = self.controller()
        self.public_terminal(c)
        c.modules = {'firecracker_recovery': types.SimpleNamespace(project_lock=contextlib.nullcontext)}
        c.load_modules = mock.Mock()
        with (mock.patch.object(control, 'Controller', return_value=c),
              mock.patch.object(control, 'private_postflight', return_value={'state': 'verified-not-approved'}),
              mock.patch.object(control, 'observations', return_value={**self.facts, 'siblings': {'changed': True}})):
            with self.assertRaisesRegex(ValueError, 'preservation_mismatch'):
                control.run_probe('capture-postflight', self.deadline, self.bind(c, 'capture-postflight'))
        self.assertFalse(self.path('capture-postflight.json').exists())

    def test_observer_rejects_unknown_mode_before_controller(self):
        with mock.patch.object(control, 'Controller') as constructor:
            with self.assertRaises(ValueError):
                control.run_probe('restore', self.deadline)
        constructor.assert_not_called()

    def test_capture_finalization_remains_under_original90(self):
        c, _ = self.fake_capture_controller()
        durable = control.durable
        def delayed(suffix, value):
            result = durable(suffix, value)
            if suffix == 'capture-summary.json':
                self.deadline.current = 191
            return result
        with mock.patch.object(control, 'durable', side_effect=delayed):
            with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
                capture.run(c)
        self.assertTrue(self.path('capture-summary.json').exists())
        self.assertFalse(self.path('capture-receipt.json').exists())
        self.assertEqual(self.deadline.end, 190)

    def prepare_maintenance(self):
        c = self.controller('continue')
        self.preprobe(c)
        approval = b'{"generated":"approval"}\n'
        self.put(self.public / 'cache-continuation-checkpoint-approval-20261025.json', approval)
        self.stack.enter_context(mock.patch.object(maintenance, 'EXPECTED_APPROVAL_SHA256', control.sha(approval)))
        self.stack.enter_context(mock.patch.object(maintenance, 'EXPECTED_APPROVAL_BYTES', len(approval)))
        return c

    def test_maintenance_full_fake_path_records_terminal_and_retains_log(self):
        c = self.prepare_maintenance()
        owner, _, signals = self.fake_run(chunks=(b'generated child output', b''))
        with mock.patch.object(control, 'OwnedProcess', return_value=owner), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(maintenance.run(c), 0)
        self.assertEqual(self.path('continue.log').read_bytes(), b'generated child output')
        self.assertTrue(self.path('continue-launch.json').exists())
        self.assertTrue(self.path('continue-receipt.json').exists())
        self.assertFalse(self.path('continue-pending.json').exists())
        self.assertEqual(signals, [])
        with self.assertRaises(FileExistsError):
            maintenance.run(c)

    def test_maintenance_pin_mismatch_never_launches(self):
        c = self.prepare_maintenance()
        self.put(self.public / 'cache-continuation-checkpoint-approval-20261025.json', b'changed')
        with self.assertRaisesRegex(ValueError, 'approval_pin_mismatch'):
            maintenance.run(c)
        control.subprocess.Popen.assert_not_called()
        self.assertFalse(self.path('continue-launch.json').exists())

    def test_maintenance_unknown_spawn_retains_launch_and_pending(self):
        c = self.prepare_maintenance()
        with mock.patch.object(control.subprocess, 'Popen', side_effect=OSError('fixture')) as spawn:
            with self.assertRaises(control.UnknownChild):
                maintenance.run(c)
        self.assertEqual(spawn.call_count, 1)
        self.assertTrue(self.path('continue-launch.json').exists())
        pending = control.strict(self.path('continue-pending.json').read_bytes())
        self.assertTrue(pending['spawn_pending'])
        self.assertEqual(pending['state'], 'unknown-retain')
        self.assertFalse(self.path('continue-receipt.json').exists())

    def test_maintenance_receipt_fsync_deadline_never_returns_success(self):
        c = self.prepare_maintenance()
        owner, _, _ = self.fake_run(chunks=(b'',))
        durable = control.durable
        def delayed(suffix, value):
            result = durable(suffix, value)
            if suffix == 'continue-receipt.json':
                self.deadline.current = 701
            return result
        with (mock.patch.object(control, 'OwnedProcess', return_value=owner),
              mock.patch.object(control, 'durable', side_effect=delayed)):
            with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
                maintenance.run(c)
        self.assertTrue(self.path('continue-receipt.json').exists())
        self.assertFalse(self.path('continue-pending.json').exists())

    def observation_fixture(self, change=None):
        for name in ('firecracker-code', 'go-mod', 'warden-lab'):
            path = self.root / '.cache' / name
            path.mkdir(parents=True, mode=0o700)
            self.put(path / 'sentinel', b'generated fixture body not read')
        original = {'ordinary_full_guard': {'additional_bytes': '5000000000',
                    'service_memory_bytes': '1000000000', 'project_allocated_bytes': 1000},
                    'released': False, 'reserved_bytes': 5000000000, 'never_reopen': True,
                    'protected_baseline_match': True}
        if change:
            change(original)
        state = {'settled': True, 'success': True, 'step': 'complete', 'released': False, 'cid': 'a' * 64}
        scene = mock.Mock()
        recovery = types.SimpleNamespace(
            OLD_LABELS={'project': 'warden'}, docker=object(), WORK=Path('/generated-not-read'), MODULE='generated',
            Scene=mock.Mock(return_value=scene), load=mock.Mock(return_value=b'fixture-inventory'),
            file_sha=mock.Mock(return_value='72675e91ac22ab3f1607fc5f21b90db18fc8c115e9a50bd8a48761cf70c8c9b2'),
            helper=types.SimpleNamespace(validate_inventory=mock.Mock(return_value={'entries': {}})),
            state_read=mock.Mock(return_value=state), helper_absent=mock.Mock(),
            full_postflight=mock.Mock(return_value=original), current_charges=mock.Mock(return_value=5000000000),
            image_charge=mock.Mock(return_value=0), scoped_ids=mock.Mock(return_value=[]))
        c = types.SimpleNamespace(modules={'firecracker_recovery': recovery}, deadline=self.deadline)
        real_sha = control.sha
        self.stack.enter_context(mock.patch.object(control, 'sha', side_effect=lambda data:
            '55f96e5bda6ecd566602d2079e632634e43824342cb577b404a83725222c141d'
            if data == b'fixture-inventory' else real_sha(data)))
        return c, recovery, scene, state

    def test_readonly_observation_success_uses_exact_interfaces_and_sibling_metadata(self):
        c, recovery, scene, _ = self.observation_fixture()
        facts = REAL_OBSERVATIONS(c)
        self.assertEqual(set(facts['siblings']), {'firecracker-code', 'go-mod', 'warden-lab'})
        self.assertTrue(all(v['entries'] == 2 for v in facts['siblings'].values()))
        self.assertEqual(facts['charges'], 5000000000)
        recovery.state_read.assert_any_call('inspect', '0c7dedbf38499ee991f879e93e43b9f5df9bb7f4')
        recovery.state_read.assert_any_call('restore-traversal', '0c7dedbf38499ee991f879e93e43b9f5df9bb7f4')
        scene.close.assert_called_once()
        control.subprocess.Popen.assert_not_called()

    def test_readonly_observation_resource_headroom_refuses(self):
        c, _, scene, _ = self.observation_fixture(lambda v: v['ordinary_full_guard'].update(project_allocated_bytes=7000000000))
        with self.assertRaisesRegex(ValueError, 'maintenance_resource_guard'):
            REAL_OBSERVATIONS(c)
        scene.close.assert_called_once()

    def test_readonly_observation_released_Q_refuses(self):
        c, _, scene, _ = self.observation_fixture(lambda v: v.update(released=True))
        with self.assertRaisesRegex(ValueError, 'original_scene_Q'):
            REAL_OBSERVATIONS(c)
        scene.close.assert_called_once()

    def test_readonly_observation_unsettled_oldscene_refuses_before_guard(self):
        c, recovery, _, state = self.observation_fixture()
        state['settled'] = False
        with self.assertRaisesRegex(ValueError, 'old_phase_unsettled'):
            REAL_OBSERVATIONS(c)
        recovery.full_postflight.assert_not_called()

    def test_postflight_success_never_approves_or_releases(self):
        c = self.controller()
        self.public_terminal(c)
        c.modules = {'firecracker_recovery': types.SimpleNamespace(project_lock=contextlib.nullcontext)}
        c.load_modules = mock.Mock()
        with (mock.patch.object(control, 'Controller', return_value=c),
              mock.patch.object(control, 'private_postflight', return_value={'state': 'verified-not-approved'}),
              mock.patch.object(control, 'observations', return_value=self.facts),
              contextlib.redirect_stdout(io.StringIO())):
            self.assertEqual(control.run_probe('capture-postflight', self.deadline, self.bind(c, 'capture-postflight')), 0)
        value = control.strict(self.path('capture-postflight.json').read_bytes())
        self.assertFalse(value['approval_created'])
        self.assertFalse(value['Q_released'])
        self.assertFalse(value['new3GB_admitted'])

    def test_docker_failed_api_blocks_followup(self):
        recovery = types.SimpleNamespace(OLD_LABELS={'project': 'warden'})
        adapter = control.ReadOnlyDocker(self.deadline, recovery)
        adapter.failed = True
        with self.assertRaisesRegex(ValueError, 'previous_api_failed'):
            adapter(['image', 'ls', '--quiet', '--no-trunc', '--all', '--filter', 'label=project=warden'])
        control.subprocess.Popen.assert_not_called()

    def private_fixture(self, stage='continue'):
        c = self.controller(stage)
        parent = self.root / '.cache'
        lab = parent / 'warden-lab'
        lab.mkdir(parents=True, mode=0o700)
        self.allowed.update((parent, lab))
        base = parent / 'go-build'
        base.mkdir(mode=0o700)
        for bucket in old.BUCKETS:
            (base / bucket).mkdir(mode=0o700)
        self.put(base / 'README', b'preserved fixture target body')
        rows = [{'relative': str(p.relative_to(parent)), 'metadata': control.meta(p.stat()),
                 'target_mode': 0o700 if p.is_dir() else 0o600}
                for p in [base, *sorted(p for p in base.iterdir() if p.is_dir()), base / 'README']]
        names = {'CHECKPOINT': 'fixture-checkpoint.json', 'PREPARED': 'fixture-prepared.json',
                 'READY': 'fixture-ready.json', 'RESULT': 'fixture-result.json'}
        binding = {'generated': 'binding'}
        checkpoint = {'version': 1, 'state': 'captured', 'binding': binding,
                      'writer_basis': 'generated fixture', 'captured_at': '2026-10-25T00:00:00+00:00',
                      'anchors': {}, 'entries': rows}
        self.put(parent / names['CHECKPOINT'], control.raw(checkpoint))
        self.put(parent / 'fixture-original.json', b'{"generated":"old intent"}\n')
        original_sha = control.sha((parent / 'fixture-original.json').read_bytes())
        def private_read(fd, name, limit):
            self.assertEqual(os.fstat(fd).st_ino, parent.stat().st_ino)
            record = control.read(parent / name, limit)
            record.name = name
            return record
        def original(fd):
            record = private_read(fd, 'fixture-original.json', control.LIMIT)
            control.require(control.sha(record.data) == original_sha, 'fixture_old_intent_hash')
            return record
        def verify(fds, wanted, anchors, authorities):
            self.assertEqual(wanted, binding)
            for record in authorities:
                record.recheck()
        product = types.SimpleNamespace(**names, CHECKPOINT_LIMIT=16000000,
            OPERATION='task6-cache-continuation-v1', COUNTS={'entries': len(rows), 'directories': 257},
            trusted_directory=lambda path, uid: control.directory(Path(path)),
            _read_original=original, _read_private=private_read, _json=control.strict, _schema=control.schema,
            _checkpoint_rows=lambda value: self.assertEqual(len(value), len(rows)),
            _binding=lambda fds: binding, _verify_authority=verify, _meta=control.meta)
        c.modules = {'identity_cache_continue': product, 'identity_cache': old}
        summary = {'version': 1, 'state': 'checkpoint-captured-not-approved', 'binding': binding,
                   'writer_basis': checkpoint['writer_basis'], 'captured_at': checkpoint['captured_at'],
                   'checkpoint_sha256': control.sha(control.raw(checkpoint)), 'checkpoint_bytes': len(control.raw(checkpoint))}
        if stage == 'capture':
            self.put(self.path('capture-summary.json'), control.raw(summary))
            product._basis = lambda value: self.assertEqual(value, 'generated fixture')
            product._timestamp = lambda value: self.assertTrue(value.endswith('+00:00'))
            product._CheckpointPlan = old.CachePlan
            product._validate_original = lambda plan, record: rows
            receipt = {'summary': control.read(self.path('capture-summary.json')).proof()}
        else:
            product.APPROVAL_NAME = 'fixture-approval.json'
            approval = {**summary, 'state': 'approved'}
            self.put(self.public / product.APPROVAL_NAME, control.raw(approval))
            approval_sha = control.sha(control.raw(approval))
            def read_public(fd, name, limit):
                record = control.read(self.public / name, limit)
                record.name = name
                return record
            product._read = read_public
            product._approval = lambda record, wanted: control.strict(record.data)
            c.controller_module = lambda name: types.SimpleNamespace(EXPECTED_APPROVAL_SHA256=approval_sha,
                                                   EXPECTED_APPROVAL_BYTES=len(control.raw(approval)))
            common = {'version': 1, 'operation': product.OPERATION, 'binding': binding,
                      'checkpoint_sha256': summary['checkpoint_sha256'], 'approval_sha256': approval_sha,
                      'wall_limit_seconds': 600}
            prepared = {**common, 'state': 'prepared-not-completed'}
            ready = {**common, 'state': 'ready-not-completed', 'prepared_sha256': control.sha(control.raw(prepared)),
                     'synced_entries': len(rows), 'metadata_sha256': control.sha(control.raw(rows))}
            result = {**common, 'state': 'completed', 'prepared_sha256': ready['prepared_sha256'],
                      'ready_sha256': control.sha(control.raw(ready)), 'removed_files': 0, 'removed_executable_dirs': 0,
                      'removed_logical_bytes': 0, 'removed_allocated_bytes': 0,
                      'preserved_bucket_count': 256, 'preserved_metadata_count': 1}
            for key, value in (('PREPARED', prepared), ('READY', ready), ('RESULT', result)):
                self.put(parent / names[key], control.raw(value))
            receipt = {'summary': None}
        return c, parent, base, receipt

    def test_private_postflight_generated_retained_nodes_and_links_without_target_body_read(self):
        c, parent, base, receipt = self.private_fixture()
        target_inode = (base / 'README').stat().st_ino
        read = os.read
        def no_body(fd, count):
            self.assertNotEqual(os.fstat(fd).st_ino, target_inode)
            return read(fd, count)
        before = {str(p.relative_to(base)): control.meta(p.stat()) for p in base.iterdir()}
        with mock.patch.object(os, 'read', side_effect=no_body):
            result = REAL_PRIVATE_POSTFLIGHT(c, True, receipt)
        self.assertEqual(result['state'], 'completed-postflight')
        self.assertFalse(result['Q_released'])
        self.assertEqual(before, {str(p.relative_to(base)): control.meta(p.stat()) for p in base.iterdir()})

    def test_private_postflight_generated_wrong_target_mode_refused(self):
        c, _, base, receipt = self.private_fixture()
        (base / '00').chmod(0o755)  # Accepted union mode by old scanner, not post-completion target.
        with self.assertRaisesRegex(ValueError, 'retained_directory'):
            REAL_PRIVATE_POSTFLIGHT(c, True, receipt)

    def test_private_postflight_generated_receipt_link_mismatch_refused(self):
        c, parent, _, receipt = self.private_fixture()
        path = parent / 'fixture-result.json'
        value = control.strict(path.read_bytes())
        value['ready_sha256'] = '0' * 64
        self.put(path, control.raw(value))
        with self.assertRaisesRegex(ValueError, 'private_links'):
            REAL_PRIVATE_POSTFLIGHT(c, True, receipt)

    def test_private_postflight_generated_old_intent_changed_refused(self):
        c, parent, _, receipt = self.private_fixture()
        self.put(parent / 'fixture-original.json', b'{"changed":true}\n')
        with self.assertRaisesRegex(ValueError, 'fixture_old_intent_hash'):
            REAL_PRIVATE_POSTFLIGHT(c, True, receipt)

    def test_capture_postflight_generated_summary_checkpoint_hash_mismatch_refused(self):
        c, _, _, receipt = self.private_fixture('capture')
        path = self.path('capture-summary.json')
        value = control.strict(path.read_bytes())
        value['checkpoint_sha256'] = '0' * 64
        self.put(path, control.raw(value))
        receipt['summary'] = control.read(path).proof()
        with self.assertRaisesRegex(ValueError, 'capture_summary_checkpoint'):
            REAL_PRIVATE_POSTFLIGHT(c, True, receipt)

    def test_capture_postflight_generated_success_is_not_approval(self):
        c, _, _, receipt = self.private_fixture('capture')
        result = REAL_PRIVATE_POSTFLIGHT(c, True, receipt)
        self.assertEqual(result['state'], 'verified-not-approved')
        self.assertFalse((self.public / 'cache-continuation-checkpoint-approval-20261025.json').exists())

    def test_private_failure_audit_strict_refusal_has_no_relaxed_retry(self):
        c, _, base, receipt = self.private_fixture()
        self.put(base / 'unexpected', b'fixture')
        result = REAL_PRIVATE_POSTFLIGHT(c, False, receipt)
        self.assertEqual(result['state'], 'incomplete')
        self.assertEqual(result['strict_scan'], 'refused-retain-no-retry')
        self.assertTrue((base / 'unexpected').exists())


    def test_fix3_real_preexec_respects_inherited_kernel_limits(self):
        r = control.resource
        parent = {r.RLIMIT_CPU: (r.RLIM_INFINITY, r.RLIM_INFINITY),
                  r.RLIMIT_AS: (r.RLIM_INFINITY, r.RLIM_INFINITY),
                  r.RLIMIT_FSIZE: (r.RLIM_INFINITY, r.RLIM_INFINITY)}
        active = parent
        def setlimit(kind, pair):
            old = active[kind]
            if pair[0] > pair[1] or (old[1] != r.RLIM_INFINITY and pair[1] > old[1]):
                raise ValueError('generated kernel refuses hard raise')
            active[kind] = pair
        with (mock.patch.object(r, 'getrlimit', side_effect=lambda kind: active[kind]),
              mock.patch.object(r, 'setrlimit', side_effect=setlimit),
              mock.patch.object(control.os, 'umask'), mock.patch.object(control.signal, 'signal') as handler):
            control.limits(control.POLICY['continue'])
            saved = dict(parent)
            active = dict(parent)
            control.child_limits()  # Real callback, never Popen/fork/setrlimit.
            self.assertEqual(active[r.RLIMIT_CPU], (540, 540))
            self.assertEqual(active[r.RLIMIT_AS], (536870912, 536870912))
            self.assertEqual(parent, saved)
            self.assertEqual(parent[r.RLIMIT_CPU], (60, 540))
            self.assertEqual(parent[r.RLIMIT_AS], (268435456, 536870912))
            cpu_handler = [c.args[1] for c in handler.call_args_list if c.args[0] == signal.SIGXCPU][0]
            with mock.patch.object(control.os, '_exit', side_effect=SystemExit) as stop:
                with self.assertRaises(SystemExit):
                    cpu_handler(signal.SIGXCPU, None)
                stop.assert_called_once_with(124)
        control.subprocess.Popen.assert_not_called()

    def test_fix3_insufficient_hard_ceiling_refuses_before_any_limit_change(self):
        r = control.resource
        values = {r.RLIMIT_CPU: (60, 540), r.RLIMIT_AS: (268435456, 268435456),
                  r.RLIMIT_FSIZE: (1048576, 1048576)}
        with (mock.patch.object(r, 'getrlimit', side_effect=lambda kind: values[kind]),
              mock.patch.object(r, 'setrlimit') as setter, mock.patch.object(control.os, 'umask'),
              mock.patch.object(control.signal, 'signal')):
            with self.assertRaisesRegex(ValueError, 'inherited_hard_ceiling'):
                control.limits(control.POLICY['continue'])
            setter.assert_not_called()
        control.subprocess.Popen.assert_not_called()

    def test_fix3_postlaunch_admission_or_baseline_replacement_refused(self):
        for stage in ('capture', 'continue'):
            for target in ('admission', 'preprobe'):
                with self.subTest(stage=stage, target=target):
                    for file in self.public.iterdir():
                        if file.name.startswith(control.PREFIX):
                            file.unlink()
                    c = self.controller(stage)
                    self.public_terminal(c)
                    path = self.path(stage + '-' + target + '.json')
                    body = path.read_bytes()
                    changed = path.with_suffix('.replacement')
                    self.put(changed, body)
                    changed.replace(path)
                    fresh = control.Controller(stage, self.deadline)
                    with self.assertRaisesRegex(ValueError, '(launch_.*proof|envelope_binding)'):
                        fresh.outer_gate()
                    for file in self.public.iterdir():
                        if file.name.startswith(control.PREFIX):
                            file.unlink()

    def test_fix3_changed_baseline_matching_changed_facts_refuses_before_work(self):
        c = self.controller()
        self.public_terminal(c)
        prepath = self.path('capture-preprobe.json')
        pre = control.strict(prepath.read_bytes())
        pre['facts']['siblings'] = {'changed': True}
        self.put(prepath, control.raw(pre))
        with (mock.patch.object(control, 'observations', return_value=pre['facts']) as observe,
              mock.patch.object(control.Controller, 'load_modules', side_effect=AssertionError('imports reached before proof')) as load):
            with self.assertRaisesRegex(ValueError, 'launch_preprobe_proof'):
                control.run_probe('capture-postflight', self.deadline,
                                  self.bind(control.Controller('capture', self.deadline), 'capture-postflight'))
            load.assert_not_called()
            observe.assert_not_called()
        control.private_postflight.assert_not_called()

    def test_fix3_single_bootstrap_exists(self):
        self.assertTrue((REPO / 'scripts/identity_cache_control.py').is_file())

    def test_fix3_exact_running_recorder_prefix_remaining_budget(self):
        import sys
        wrapper = Path(sys.modules['__main__'].__file__).read_text()
        prefix = wrapper.split('# END DEADLINE PREFIX\n')[0]
        self.assertIn('# BEGIN DEADLINE PREFIX', prefix)
        for elapsed in (8, 45, 46):
            with self.subTest(elapsed=elapsed):
                fake_time = types.SimpleNamespace(monotonic=mock.Mock(side_effect=[100, 100 + elapsed]))
                fake_os = types.SimpleNamespace(_exit=mock.Mock(side_effect=SystemExit))
                fake_signal = types.SimpleNamespace(SIGALRM=14, ITIMER_REAL=0,
                                                   signal=mock.Mock(), setitimer=mock.Mock())
                modules = {'time': fake_time, 'os': fake_os, 'signal': fake_signal}
                namespace = {'__builtins__': {**vars(__import__('builtins')),
                             '__import__': lambda name, *args, **kwargs: modules[name]}}
                if elapsed >= 45:
                    with self.assertRaises(SystemExit):
                        exec(compile(prefix, '<exact running prefix>', 'exec'), namespace)
                    fake_signal.setitimer.assert_not_called()
                    fake_os._exit.assert_called_once_with(124)
                else:
                    exec(compile(prefix, '<exact running prefix>', 'exec'), namespace)
                    fake_signal.setitimer.assert_called_once_with(0, 37)
                    fake_time.monotonic.side_effect = [146]
                    with self.assertRaises(SystemExit):
                        namespace['finish_timer']()
                    fake_signal.setitimer.assert_called_once_with(0, 37)


    def test_fix3_changed_authority_and_preprobe_facts_refused_for_both_stages(self):
        for stage in ('capture', 'continue'):
            for field in ('writer_basis', 'review_sha256', 'ruling_sha256', 'facts'):
                with self.subTest(stage=stage, field=field):
                    for file in self.public.iterdir():
                        if file.name.startswith(control.PREFIX):
                            file.unlink()
                    c = self.controller(stage)
                    self.public_terminal(c)
                    path = self.path(stage + ('-preprobe.json' if field == 'facts' else '-admission.json'))
                    value = control.strict(path.read_bytes())
                    if field == 'facts':
                        value['facts']['siblings'] = {'changed': True}
                    else:
                        value[field] = 'changed fixture basis' if field == 'writer_basis' else 'f' * 64
                    self.put(path, control.raw(value))
                    with mock.patch.object(control.Controller, 'load_modules') as load:
                        with self.assertRaisesRegex(ValueError, '(launch_(authority|admission_proof|preprobe_proof)|envelope_binding)'):
                            control.run_probe(stage + '-postflight', self.deadline,
                                              self.bind(control.Controller(stage, self.deadline), stage + '-postflight'))
                        load.assert_not_called()
                    control.observations.assert_not_called()
                    control.private_postflight.assert_not_called()

    def test_fix3_strict_launch_schema_and_binding_refuses_before_import(self):
        changes = (lambda v: v.update(extra=True), lambda v: v.update(version=True),
                   lambda v: v.update(stage='other'), lambda v: v.update(command=['wrong']),
                   lambda v: v['policy'].update(cpu_seconds=61),
                   lambda v: v['admission']['metadata'].__setitem__(0, True),
                   lambda v: v['preprobe'].update(bytes=True))
        for change in changes:
            with self.subTest(change=change):
                for file in self.public.iterdir():
                    if file.name.startswith(control.PREFIX):
                        file.unlink()
                c = self.controller()
                self.public_terminal(c)
                path = self.path('capture-launch.json')
                launch = control.strict(path.read_bytes())
                change(launch)
                self.put(path, control.raw(launch))
                with mock.patch.object(control.Controller, 'load_modules') as load:
                    with self.assertRaises(ValueError):
                        control.run_probe('capture-postflight', self.deadline, self.bind(c, 'capture-postflight'))
                    load.assert_not_called()
                control.private_postflight.assert_not_called()
                control.observations.assert_not_called()

    def test_fix3_retained_records_rechecked_after_gate_before_imports(self):
        c = self.controller()
        self.public_terminal(c)
        gate = c.outer_gate
        def replace_after_gate():
            result = gate()
            path = self.path('capture-preprobe.json')
            temp = path.with_suffix('.new')
            self.put(temp, path.read_bytes())
            temp.replace(path)
            return result
        with (mock.patch.object(control, 'Controller', return_value=c),
              mock.patch.object(c, 'outer_gate', side_effect=replace_after_gate),
              mock.patch.object(c, 'load_modules') as load):
            with self.assertRaisesRegex(ValueError, 'record_changed'):
                control.run_probe('capture-postflight', self.deadline,
                                  self.bind(control.Controller('capture', self.deadline), 'capture-postflight'))
            load.assert_not_called()
        control.private_postflight.assert_not_called()
        control.observations.assert_not_called()

    def test_fix3_unchanged_postflight_does_not_require_new_sixty_second_age(self):
        c = self.controller()
        self.public_terminal(c)
        self.deadline.current += 61
        self.assertTrue(c.outer_gate()[0])
        self.assertEqual(c.launch_preprobe[0].data, self.path('capture-preprobe.json').read_bytes())

    def bootstrap_fixture(self, body=b'bootstrap_executed = True\n'):
        import sys
        path = self.root / 'scripts/bootstrap-observer.py'
        self.put(path, body)
        self.stack.enter_context(mock.patch.object(bootstrap, 'OBSERVER_PATH', '/scripts/bootstrap-observer.py'))
        self.stack.enter_context(mock.patch.object(bootstrap, 'EXPECTED_OBSERVER_SHA256', control.sha(body)))
        self.stack.enter_context(mock.patch.dict(sys.modules))
        opened = os.open
        def exact_root(name, flags, *args, **kwargs):
            # Only this loader's root anchor, never a path prefix or shared trust.
            if name == '/' and not args and not kwargs:
                return opened(self.root, flags)
            return opened(name, flags, *args, **kwargs)
        self.stack.enter_context(mock.patch.object(os, 'open', side_effect=exact_root))
        return path

    def test_fix3_single_loader_executes_only_verified_generated_bytes(self):
        self.bootstrap_fixture()
        module = bootstrap.load_control()
        self.assertTrue(module.bootstrap_executed)

    def test_fix3_loader_owner_mode_link_ancestor_hash_size_refuse_before_exec(self):
        import sys
        path = self.bootstrap_fixture()
        original_fstat = os.fstat
        before_module = sys.modules['identity_cache_observe']
        for defect in ('owner', 'mode', 'link', 'ancestor', 'hash', 'oversize'):
            with self.subTest(defect=defect), contextlib.ExitStack() as stack:
                self.put(path, b'bootstrap_executed = True\n')
                if defect == 'owner':
                    inode = path.stat().st_ino
                    def wrong_owner(fd):
                        value = original_fstat(fd)
                        if value.st_ino == inode:
                            fields = {n: getattr(value, n) for n in dir(value) if n.startswith('st_')}
                            fields['st_uid'] = 999
                            return types.SimpleNamespace(**fields)
                        return value
                    stack.enter_context(mock.patch.object(os, 'fstat', side_effect=wrong_owner))
                elif defect == 'mode':
                    path.chmod(0o664)
                elif defect == 'link':
                    alias = path.with_suffix('.link')
                    os.link(path, alias)
                    stack.callback(alias.unlink)
                elif defect == 'ancestor':
                    path.parent.chmod(0o770)
                    stack.callback(path.parent.chmod, 0o700)
                elif defect == 'hash':
                    self.put(path, b'bootstrap_executed = False\n')
                else:
                    self.put(path, b'x' * 131073)
                with self.assertRaises(ValueError):
                    bootstrap.load_control()
                self.assertIs(sys.modules['identity_cache_observe'], before_module)

    def test_fix3_loader_fd_path_replacement_and_alteration_refuse_before_exec(self):
        import sys
        path = self.bootstrap_fixture()
        read = os.read
        before_module = sys.modules['identity_cache_observe']
        for defect in ('samebytes-replace', 'alter'):
            with self.subTest(defect=defect):
                self.put(path, b'bootstrap_executed = True\n')
                done = False
                def changed_read(fd, amount):
                    nonlocal done
                    body = read(fd, amount)
                    if not done and body:
                        done = True
                        if defect == 'samebytes-replace':
                            temp = path.with_suffix('.new')
                            self.put(temp, path.read_bytes())
                            temp.replace(path)
                        else:
                            self.put(path, b'bootstrap_executed = False\n')
                    return body
                with mock.patch.object(os, 'read', side_effect=changed_read):
                    with self.assertRaisesRegex(ValueError, 'observer_source_changed'):
                        bootstrap.load_control()
                self.assertTrue(done)
                self.assertIs(sys.modules['identity_cache_observe'], before_module)

    def test_fix3_all_six_fixed_modes_use_one_loader(self):
        import sys
        for mode in bootstrap.MODES:
            with self.subTest(mode=mode):
                module = mock.Mock()
                module.POLICY = control.POLICY
                module.probe_entry.return_value = 0
                module.Controller.return_value.controller_module.return_value.run.return_value = 0
                with (mock.patch.object(bootstrap, 'ENTRY', 100),
                      mock.patch.object(bootstrap.time, 'monotonic', return_value=100),
                      mock.patch.object(sys, 'argv', ['fixed', mode]),
                      mock.patch.object(bootstrap, 'load_control', return_value=module) as loader,
                      mock.patch.object(signal, 'signal'), mock.patch.object(signal, 'setitimer')):
                    self.assertEqual(bootstrap.main(), 0)
                    loader.assert_called_once_with()
                    if mode in ('capture', 'continue'):
                        module.Controller.assert_called_once_with(mode, module.Deadline.return_value)
                        selected = 'identity_cache_capture' if mode == 'capture' else 'identity_cache_maintenance'
                        module.Controller.return_value.controller_module.assert_called_once_with(selected)
                        module.probe_entry.assert_not_called()
                    else:
                        module.probe_entry.assert_called_once_with(mode, module.Deadline.return_value, module.Controller.return_value)
                        module.Controller.assert_called_once_with(mode.split('-')[0], module.Deadline.return_value)
                    module.Controller.return_value.adopt_envelope.assert_called_once_with(mode)
        with mock.patch.object(sys, 'argv', ['fixed', 'arbitrary']), mock.patch.object(bootstrap, 'load_control') as loader:
            with self.assertRaisesRegex(ValueError, 'one_fixed_controller_mode'):
                bootstrap.main()
            loader.assert_not_called()

    def test_fix3_old_direct_entrypoints_fail_before_import_or_operation(self):
        import builtins
        for name in ('identity_cache_capture', 'identity_cache_maintenance', 'identity_cache_observe'):
            with self.subTest(name=name):
                namespace = {'__name__': '__main__', '__builtins__': {**vars(builtins),
                             '__import__': mock.Mock(side_effect=AssertionError('old entry imported code'))}}
                with self.assertRaisesRegex(SystemExit, 'sole identity_cache_control'):
                    exec(compile((REPO / ('scripts/' + name + '.py')).read_bytes(), name, 'exec'), namespace)


    def test_fix3_operation_modules_are_verified_before_compile_and_allowlisted(self):
        for name in ('identity_cache_capture', 'identity_cache_maintenance'):
            relative = 'scripts/' + name + '.py'
            body = b'verified_operation = True\n'
            self.put(self.root / relative, body)
            self.hashes[relative] = control.sha(body)
        c = self.controller()
        for name in ('identity_cache_capture', 'identity_cache_maintenance'):
            self.assertTrue(c.controller_module(name).verified_operation)
            self.put(self.root / ('scripts/' + name + '.py'), b'verified_operation = False\n')
            with self.assertRaisesRegex(ValueError, 'record_changed'):
                c.controller_module(name)
        with self.assertRaisesRegex(ValueError, 'fixed_controller_module'):
            c.controller_module('arbitrary')



class APITests(unittest.TestCase):
    """Entire socket/peer/host-path surface is fake; no server/socketpair or child."""
    def setUp(self):
        import socket
        import struct
        self.socket_module, self.struct = socket, struct
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for target, name in ((control.OwnClock, 'sample'), (control, 'own_proc_text'),
                             (control, 'clock_identity'), (socket, 'socket'), (control.subprocess, 'Popen')):
            self.stack.enter_context(mock.patch.object(target, name,
                side_effect=AssertionError('real host/native access forbidden')))
        self.deadline = FakeDeadline(180)
        initial = {'pid': 123, 'hz': 100, 'birth_ticks': 10001, 'birth_boot_lower_ns': 100 * control.NS,
                   'namespace': [1, 2], 'monotonic_before_ns': 100 * control.NS,
                   'boottime_ns': 100 * control.NS, 'monotonic_after_ns': 100 * control.NS}
        self.clock = mock.Mock()
        self.clock.sample.side_effect = lambda: {**initial, 'monotonic_before_ns': int(self.deadline.current * control.NS),
            'boottime_ns': int(self.deadline.current * control.NS), 'monotonic_after_ns': int(self.deadline.current * control.NS)}
        self.deadline.guard = control.ClockBudget(control.timing_from_birth(initial, 100 * control.NS), 180, self.clock)
        self.recovery = types.SimpleNamespace(OLD_LABELS={'project': 'warden', 'owner': 'generated'})
        self.sock = mock.Mock()
        self.sock.connect_ex.return_value = 0
        self.sock.getsockopt.side_effect = lambda level, option, *args: (
            struct.pack('3i', 123, 0, 0) if option == socket.SO_PEERCRED else 0)
        self.sent, self.response = bytearray(), bytearray()
        self.sock.send.side_effect = lambda data: self.send(data)
        self.sock.recv.side_effect = lambda count: self.receive(count)
        self.stack.enter_context(mock.patch.object(control, 'socket', socket, create=True))
        self.constructor = self.stack.enter_context(mock.patch.object(socket, 'socket', return_value=self.sock))
        self.stack.enter_context(mock.patch.object(control.select, 'select', side_effect=lambda r, w, x, timeout: (r, w, [])))
        self.spawn = self.stack.enter_context(mock.patch.object(control.subprocess, 'Popen', side_effect=AssertionError('CLI forbidden')))
        self.stack.enter_context(mock.patch.object(control.os, 'killpg', side_effect=AssertionError('signal forbidden')))
        def info(dev, ino, mode, uid=0, gid=0, links=1):
            return types.SimpleNamespace(st_dev=dev, st_ino=ino, st_mode=mode, st_uid=uid, st_gid=gid,
                                         st_nlink=links, st_size=0, st_mtime_ns=1, st_ctime_ns=1, st_blocks=0)
        self.root_info = info(1, 1, stat.S_IFDIR | 0o755)
        self.run_info = info(29, 2, stat.S_IFDIR | 0o755)
        self.socket_info = info(29, 4756, stat.S_IFSOCK | 0o660, gid=115)
        # Observer-local proxy: never alter unittest/traceback/recorder's os module.
        local_os = types.SimpleNamespace(**vars(os))
        local_os.open = mock.Mock(side_effect=self.open)
        local_os.fstat = mock.Mock(side_effect=lambda fd: {901: self.root_info, 902: self.run_info}[fd])
        local_os.stat = mock.Mock(side_effect=self.stat)
        local_os.close = mock.Mock()
        self.stack.enter_context(mock.patch.object(control, 'os', local_os))
        self.adapter = control.ReadOnlyDocker(self.deadline, self.recovery)

    def open(self, name, flags, **kwargs):
        self.assertEqual(flags, control.DIR_FLAGS)
        self.assertIn((name, kwargs.get('dir_fd')), (('/', None), ('run', 901)))
        return 901 if name == '/' else 902

    def stat(self, name, **kwargs):
        self.assertIs(kwargs.get('follow_symlinks'), False)
        self.assertIn((name, kwargs.get('dir_fd')), (('/', None), ('run', 901), ('docker.sock', 902)))
        return self.root_info if name == '/' else self.run_info if name == 'run' else self.socket_info

    def send(self, data):
        self.sent.extend(data)
        return len(data)

    def receive(self, count):
        data = bytes(self.response[:count])
        del self.response[:count]
        return data

    def reply(self, value, headers=b'Content-Type: application/json\r\n', body=None):
        body = control.raw(value) if body is None else body
        self.response = bytearray(b'HTTP/1.0 200 OK\r\n' + headers + b'\r\n' + body)

    def args(self, kind='image', labels=None):
        result = [kind, 'ls', '--quiet', '--no-trunc', '--all']
        for key, value in (labels or {'project': 'warden'}).items():
            result += ['--filter', 'label=' + key + '=' + value]
        return result

    def test_project_image_list_uses_exact_get_and_no_cli(self):
        identity = 'sha256:' + 'a' * 64
        self.reply([{'Id': identity, 'Labels': {'project': 'warden'}}])
        self.assertEqual(self.adapter(self.args()), identity + '\n')
        self.assertEqual(bytes(self.sent), b'GET /v1.45/images/json?all=1&filters=%7B%22label%22%3A%5B%22project%3Dwarden%22%5D%7D HTTP/1.0\r\nHost: docker\r\nConnection: close\r\nAccept: application/json\r\n\r\n')
        self.constructor.assert_called_once_with(self.socket_module.AF_UNIX, self.socket_module.SOCK_STREAM)
        self.spawn.assert_not_called()
        self.sock.close.assert_called_once()

    def test_socket_tuple_mismatch_refuses_before_connect_or_cli(self):
        self.socket_info.st_gid = 116
        with self.assertRaisesRegex(ValueError, 'socket'):
            self.adapter(self.args())
        self.sock.connect_ex.assert_not_called()
        self.spawn.assert_not_called()

    def test_unlisted_inspect_never_connects_or_spawns(self):
        with self.assertRaisesRegex(ValueError, 'inspect_requires_scoped_id'):
            self.adapter(['container', 'inspect', 'a' * 64])
        self.constructor.assert_not_called()
        self.spawn.assert_not_called()


    def fresh(self):
        self.adapter = control.ReadOnlyDocker(self.deadline, self.recovery)
        self.sent.clear()
        return self.adapter

    def listed(self, kind='image', labels=None):
        identity = ('sha256:' if kind == 'image' else '') + 'a' * 64
        self.reply([{'Id': identity, 'Labels': labels or {'project': 'warden'}}])
        self.adapter(self.args(kind, labels))
        return identity

    def test_all_four_routes_preserve_owned_inspect_shape_without_logging(self):
        for kind in ('image', 'container'):
            with self.subTest(kind=kind):
                self.fresh()
                identity = self.listed(kind)
                value = {'Id': identity, 'Config': {'Labels': {'project': 'warden'}, 'Env': ['GENERATED=private']},
                         'Size': 42, 'State': {'Running': False}}
                self.sent.clear()
                self.reply(value)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    result = self.adapter([kind, 'inspect', identity])
                self.assertEqual(json.loads(result), [value])
                self.assertEqual(output.getvalue(), '')
                route = '/v1.45/' + ('images' if kind == 'image' else 'containers') + '/' + identity + '/json'
                self.assertTrue(bytes(self.sent).startswith(('GET ' + route + ' HTTP/1.0\r\n').encode()))
        self.assertEqual(self.constructor.call_count, 4)
        self.assertEqual(self.sock.close.call_count, 4)
        self.spawn.assert_not_called()

    def test_label_conjunction_and_retained_scopes_on_inspect(self):
        identity = self.listed(labels={'project': 'warden'})
        self.listed(labels=self.recovery.OLD_LABELS)
        self.assertIn(b'%22owner%3Dgenerated%22%2C%22project%3Dwarden%22', bytes(self.sent))
        self.reply({'Id': identity, 'Config': {'Labels': {'project': 'warden', 'owner': 'other'}}})
        with self.assertRaisesRegex(ValueError, 'docker_label_scope'):
            self.adapter(['image', 'inspect', identity])
        self.assertTrue(self.adapter.failed)

    def test_refresh_removes_stale_ids_and_wrong_kind_never_connects(self):
        identity = self.listed()
        self.reply([])
        self.assertEqual(self.adapter(self.args()), '')
        calls = self.constructor.call_count
        with self.assertRaisesRegex(ValueError, 'inspect_requires_scoped_id'):
            self.adapter(['image', 'inspect', identity])
        self.assertEqual(self.constructor.call_count, calls)
        self.fresh()
        self.listed()
        with self.assertRaisesRegex(ValueError, 'inspect_requires_scoped_id'):
            self.adapter(['container', 'inspect', 'a' * 64])

    def test_foreign_or_malformed_list_invalidates_all_provenance(self):
        identity = 'sha256:' + 'a' * 64
        good = {'Id': identity, 'Labels': {'project': 'warden'}}
        bad_values = [None, {}, [good, good], [good, {'Id': 'sha256:' + 'b' * 64, 'Labels': {'project': 'other'}}],
                      [{'Id': identity, 'Labels': None}], [{'Id': identity, 'Labels': {'project': 'warden', 'bad': True}}],
                      [{'Id': 'short', 'Labels': {'project': 'warden'}}]]
        for value in bad_values:
            with self.subTest(value=value):
                self.fresh()
                self.reply(value)
                with self.assertRaises(ValueError):
                    self.adapter(self.args())
                self.assertEqual(self.adapter.ids, {'image': {}, 'container': {}})
                calls = self.constructor.call_count
                with self.assertRaisesRegex(ValueError, 'previous_api_failed'):
                    self.adapter(self.args())
                self.assertEqual(self.constructor.call_count, calls)

    def test_list_bound_1000_and_1001(self):
        values = [{'Id': 'sha256:' + format(i, '064x'), 'Labels': {'project': 'warden'}} for i in range(1001)]
        self.reply(values[:1000])
        self.assertEqual(len(self.adapter(self.args()).splitlines()), 1000)
        self.reply(values)
        with self.assertRaisesRegex(ValueError, 'docker_list_shape'):
            self.adapter(self.args())

    def test_inspect_id_or_config_mismatch_refuses(self):
        for value in ({'Id': 'wrong', 'Config': {}}, {'Id': 'sha256:' + 'a' * 64, 'Config': None}):
            with self.subTest(value=value):
                self.fresh()
                identity = self.listed()
                self.reply(value)
                with self.assertRaisesRegex(ValueError, 'docker_inspect_identity'):
                    self.adapter(['image', 'inspect', identity])

    def test_content_length_present_absent_and_eof_required(self):
        for headers in (b'Content-Type: application/json\r\n',
                        b'Content-Type: Application/JSON; charset="UTF-8"\r\nContent-Length: 3\r\n'):
            with self.subTest(headers=headers):
                self.fresh()
                self.reply([], headers=headers)
                self.assertEqual(self.adapter(self.args()), '')
        self.fresh()
        self.reply([], headers=b'Content-Type: application/json\r\nContent-Length: 3\r\n')
        receive = self.receive
        def no_eof(count):
            if not self.response:
                raise ConnectionResetError('generated reset after full CL')
            return receive(count)
        with mock.patch.object(self.sock, 'recv', side_effect=no_eof):
            with self.assertRaises(ConnectionResetError):
                self.adapter(self.args())
        self.assertTrue(self.adapter.failed)

    def test_every_single_byte_header_split_and_partial_send(self):
        self.reply([])
        receive = self.receive
        def send(data):
            count = min(3, len(data))
            self.sent.extend(data[:count])
            return count
        with (mock.patch.object(self.sock, 'send', side_effect=send),
              mock.patch.object(self.sock, 'recv', side_effect=lambda count: receive(min(count, 1)))):
            self.assertEqual(self.adapter(self.args()), '')
        self.assertEqual(bytes(self.sent).count(b'GET '), 1)
        self.assertTrue(bytes(self.sent).endswith(b'\r\n\r\n'))

    def test_header_and_body_exact_bounds_and_plus_one(self):
        item = {'Id': 'sha256:' + 'a' * 64, 'Labels': {'project': 'warden'}, 'Padding': ''}
        item['Padding'] = 'x' * (control.HTTP_BODY_LIMIT - len(control.raw([item])))
        body = control.raw([item])
        prefix = b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nX-Fill: '
        header = prefix + b'x' * (control.HTTP_HEADER_LIMIT - len(prefix) - 4) + b'\r\n\r\n'
        self.response = bytearray(header + body)
        self.assertEqual(len(header), control.HTTP_HEADER_LIMIT)
        self.assertEqual(len(body), control.HTTP_BODY_LIMIT)
        self.assertEqual(len(self.adapter(self.args()).splitlines()), 1)
        for oversized in (header[:-4] + b'x\r\n\r\n' + b'[]', header + body + b' '):
            self.fresh()
            self.response = bytearray(oversized)
            with self.assertRaises(ValueError):
                self.adapter(self.args())

    def test_framing_negative_matrix_refuses_and_never_retries(self):
        base = b'Content-Type: application/json\r\n'
        cases = [b'', base + b'Content-Type: application/json\r\n', base + b'Transfer-Encoding: chunked\r\n',
                 base + b'Trailer: X-End\r\n', base + b'Upgrade: h2c\r\n', base + b'Content-Encoding: gzip\r\n',
                 base + b'Connection: keep-alive\r\n', base + b'Connection: close\r\nconnection: close\r\n',
                 base + b'Content-Length: 3\r\nCONTENT-LENGTH: 3\r\n', base + b'Content-Length: +3\r\n',
                 base + b'Content-Length: 3,3\r\n', base + b'Content-Length: 1048577\r\n',
                 base + b'Content-Length: 2\r\n', base + b'Content-Length: 4\r\n',
                 base + b' Bad: fold\r\n', base + b'Bad : space\r\n', base + b'Bad: tab\t\r\n',
                 base + b'Bad: newline\nOther: yes\r\n', b'Content-Type: text/plain\r\n']
        for headers in cases:
            with self.subTest(headers=headers):
                self.fresh()
                self.reply([], headers=headers)
                with self.assertRaises(ValueError):
                    self.adapter(self.args())
                self.assertTrue(self.adapter.failed)
        for status in (b'HTTP/1.1 404 Not Found', b'HTTP/1.0 301 Redirect', b'HTTP/1.1 100 Continue', b'HTTP/2 200 OK'):
            self.fresh()
            self.response = bytearray(status + b'\r\n' + base + b'\r\n[]')
            with self.assertRaisesRegex(ValueError, 'http_status'):
                self.adapter(self.args())

    def test_strict_json_utf8_and_trailing_data(self):
        for body in (b'', b'[', b'[]{}', b'{"a":1,"a":2}', b'[NaN]', b'\xff', b'\xff\xfe[\x00]\x00'):
            with self.subTest(body=body):
                self.fresh()
                self.reply(None, body=body)
                with self.assertRaises((ValueError, UnicodeError)):
                    self.adapter(self.args())
        self.fresh()
        self.reply([], body=b'[] \r\n\t')
        self.assertEqual(self.adapter(self.args()), '')

    def test_pending_connect_and_blocking_retry_use_same_absolute_deadline(self):
        import errno
        self.sock.connect_ex.return_value = errno.EINPROGRESS
        self.reply([])
        send = self.send
        self.sock.send.side_effect = [BlockingIOError(), 1]
        # A generated partial send must also retain exact sent bytes.
        first = True
        def sending(data):
            nonlocal first
            if first:
                first = False
                raise BlockingIOError()
            return send(data)
        self.sock.send.side_effect = sending
        self.assertEqual(self.adapter(self.args()), '')
        self.assertEqual(self.deadline.arms, [120, 125, 130, 280])
        self.sock.connect_ex.assert_called_once_with('/run/docker.sock')

    def test_connect_error_and_nonroot_peer_refuse_before_send(self):
        import errno
        self.sock.connect_ex.return_value = errno.ECONNREFUSED
        with self.assertRaisesRegex(ValueError, 'docker_connect_failed'):
            self.adapter(self.args())
        self.sock.send.assert_not_called()
        self.fresh()
        self.sock.connect_ex.return_value = 0
        self.sock.getsockopt.side_effect = lambda *args: self.struct.pack('3i', 123, 1000, 115)
        with self.assertRaisesRegex(ValueError, 'docker_peer_uid'):
            self.adapter(self.args())
        self.sock.send.assert_not_called()

    def test_root_and_socket_identity_negative_matrix(self):
        for field, value in (('st_ino', 4757), ('st_uid', 1), ('st_gid', 116), ('st_nlink', 2),
                             ('st_mode', stat.S_IFSOCK | 0o666), ('st_mode', stat.S_IFLNK | 0o660)):
            with self.subTest(field=field, value=value):
                self.fresh()
                original = getattr(self.socket_info, field)
                setattr(self.socket_info, field, value)
                with self.assertRaisesRegex(ValueError, 'docker_socket_tuple'):
                    self.adapter(self.args())
                setattr(self.socket_info, field, original)
        self.constructor.assert_not_called()
        self.run_info.st_mode = stat.S_IFDIR | 0o775
        self.fresh()
        with self.assertRaisesRegex(ValueError, 'docker_socket_ancestor'):
            self.adapter(self.args())

    def test_socket_replacement_after_connect_refuses_before_send(self):
        def connect(path):
            self.socket_info.st_ctime_ns += 1
            return 0
        self.sock.connect_ex.side_effect = connect
        with self.assertRaisesRegex(ValueError, 'docker_socket_replaced'):
            self.adapter(self.args())
        self.sock.send.assert_not_called()
        self.sock.close.assert_called_once()

    def test_socket_or_peer_change_after_eof_refuses(self):
        self.reply([])
        receive = self.receive
        def changed(count):
            value = receive(count)
            if not value:
                self.socket_info.st_mtime_ns += 1
            return value
        with mock.patch.object(self.sock, 'recv', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'docker_socket_replaced'):
                self.adapter(self.args())
        self.fresh()
        self.reply([])
        self.sock.getsockopt.side_effect = [self.struct.pack('3i', 123, 0, 0), self.struct.pack('3i', 124, 0, 0)]
        with self.assertRaisesRegex(ValueError, 'docker_peer_changed'):
            self.adapter(self.args())

    def test_unrelated_run_directory_timestamps_do_not_refuse(self):
        self.reply([])
        receive = self.receive
        def changed(count):
            self.run_info.st_mtime_ns += 1
            self.run_info.st_ctime_ns += 1
            return receive(count)
        with mock.patch.object(self.sock, 'recv', side_effect=changed):
            self.assertEqual(self.adapter(self.args()), '')

    def test_held_parent_path_substitution_refuses_before_socket(self):
        path_stat = self.stat
        def replaced(name, **kwargs):
            value = path_stat(name, **kwargs)
            if name == 'run':
                return types.SimpleNamespace(**{**vars(value), 'st_ino': value.st_ino + 1})
            return value
        with mock.patch.object(control.os, 'stat', side_effect=replaced):
            with self.assertRaisesRegex(ValueError, 'docker_socket_ancestor'):
                self.adapter(self.args())
        self.constructor.assert_not_called()

    def test_select_timeout_and_bad_peer_shape_are_sticky(self):
        self.reply([])
        with mock.patch.object(control.select, 'select', return_value=([], [], [])):
            with self.assertRaisesRegex(ValueError, 'docker_io_timeout'):
                self.adapter(self.args())
        self.assertTrue(self.adapter.failed)
        self.sock.send.assert_not_called()
        self.fresh()
        self.sock.getsockopt.side_effect = lambda *args: b'wrong-size'
        with self.assertRaisesRegex(ValueError, 'docker_peer_shape'):
            self.adapter(self.args())
        self.assertTrue(self.adapter.failed)

    def test_close_failure_sticky_and_no_followup_socket(self):
        self.reply([])
        self.sock.close.side_effect = OSError('generated unknown close')
        with self.assertRaises(OSError):
            self.adapter(self.args())
        self.assertIs(self.adapter.sock, self.sock)
        with self.assertRaisesRegex(ValueError, 'previous_api_failed'):
            self.adapter(self.args())
        self.assertEqual(self.constructor.call_count, 1)

    def test_timeout_trickle_and_exhausted_budget_never_return_partial(self):
        self.reply([])
        receive = self.receive
        def trickle(count):
            self.deadline.current += 5
            return receive(min(1, count))
        with mock.patch.object(self.sock, 'recv', side_effect=trickle):
            with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
                self.adapter(self.args())
        self.assertTrue(self.adapter.failed)
        calls = self.constructor.call_count
        self.fresh()
        self.deadline.current = 275
        with self.assertRaisesRegex(ValueError, 'api_budget_insufficient'):
            self.adapter(self.args())
        self.assertEqual(self.constructor.call_count, calls)

    def test_suspend_during_io_parse_or_close_stays_failure(self):
        targets = [(self.sock, 'connect_ex'), (self.sock, 'send'), (self.sock, 'recv'),
                   (control, 'strict'), (self.sock, 'close')]
        clock = self.clock.sample.side_effect
        for target, name in targets:
            with self.subTest(phase=name):
                self.fresh()
                self.reply([])
                self.clock.sample.side_effect = clock
                method = getattr(target, name)
                original_call = method.side_effect if isinstance(method, mock.Mock) else method
                if original_call is None:
                    original_call = lambda *args: 0 if name == 'connect_ex' else None
                def changed(*args, call=original_call):
                    self.clock.sample.side_effect = lambda: {**clock(), 'boottime_ns': clock()['boottime_ns'] + 10 * control.NS}
                    return call(*args)
                with mock.patch.object(target, name, side_effect=changed):
                    with self.assertRaisesRegex(ValueError, 'clock_offset_changed'):
                        self.adapter(self.args())
                self.assertTrue(self.adapter.failed)
        self.clock.sample.side_effect = clock

    def test_late_inspect_serialization_cannot_publish(self):
        identity = self.listed()
        self.reply({'Id': identity, 'Config': {'Labels': {'project': 'warden'}}})
        raw = control.raw
        def late(value):
            result = raw(value)
            self.deadline.current = 131
            return result
        with mock.patch.object(control, 'raw', side_effect=late):
            with self.assertRaisesRegex(ValueError, 'deadline_exhausted'):
                self.adapter(['image', 'inspect', identity])
        self.assertTrue(self.adapter.failed)
        self.assertEqual(self.adapter.ids, {'image': {}, 'container': {}})

    def test_timeout_type_and_mutation_args_reject_without_socket(self):
        for timeout in (True, 0, 31, 1.5):
            self.fresh()
            with self.assertRaises(ValueError):
                self.adapter(self.args(), timeout=timeout)
        for args in (['image', 'rm', 'sha256:' + 'a' * 64], ['info'], ['image', 'ls']):
            self.fresh()
            with self.assertRaises(ValueError):
                self.adapter(args)
        self.constructor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
