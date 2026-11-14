"""Generated private fixtures; clocks/children/observers are fake, never live."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import types
import unittest
from unittest import mock

import identity_cache_observe as control
import identity_cache_capture as capture
import identity_cache_maintenance as maintenance

REPO = Path(__file__).absolute().parent.parent
CLOCK = {'machine_id': '1' * 32, 'boot_id': '2' * 8 + '-2222-2222-2222-' + '2' * 12}
REAL_DIRECTORY = control.directory


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
        self.names.update('scripts/' + n for n in ('identity_cache_capture.py', 'identity_cache_maintenance.py',
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
        def fixture_directory(path):
            self.assertIn(path, allowed, 'only exact generated parent FD injection')
            return os.open(path, control.DIR_FLAGS)
        self.stack.enter_context(mock.patch.object(control, 'directory', side_effect=fixture_directory))
        self.deadline = FakeDeadline()
        self.facts = {'siblings': {'fixture': 'unchanged'}, 'charges': 5000000000,
                      'owned_images': [], 'phase_state_hashes': {'inspect': '3' * 64}}

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
        return c

    def preprobe(self, c, at=None):
        value = {'version': 1, 'stage': c.stage, 'state': 'preprobe-complete',
                 'admission_sha256': control.sha(c.admission_record.data), 'source_commit': c.admission['source_commit'],
                 'source_hashes': c.admission['source_hashes'], 'clock_identity': CLOCK,
                 'observed_monotonic_ns': int(self.deadline.now() * 1e9) if at is None else at,
                 'utc': '2026-10-25T00:00:00+00:00', 'facts': self.facts, 'Q_released': False}
        self.put(self.path(c.stage + '-preprobe.json'), control.raw(value))
        return value

    def public_terminal(self, c, outcome=None):
        self.preprobe(c)
        pre, _ = c.preparation()
        launch = c.launch(pre)
        outcome = outcome or {'terminal': True, 'exit_code': 0, 'timed_out': False, 'overflow': False}
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
                control.run_probe('capture-postflight', self.deadline)
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
        with self.assertRaisesRegex(ValueError, 'outer_wall_bound'):
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
        adapter.ids['image'].add(identity)
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
            self.assertEqual(control.run_probe('capture-preprobe', self.deadline), 0)
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
                control.run_probe('capture-postflight', self.deadline)
        self.assertFalse(self.path('capture-postflight.json').exists())

    def test_observer_rejects_unknown_mode_before_controller(self):
        with mock.patch.object(control, 'Controller') as constructor:
            with self.assertRaises(ValueError):
                control.run_probe('restore', self.deadline)
        constructor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
