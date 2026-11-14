"""Phase A host fixtures. External Docker/mount/chown boundaries are not run."""
import copy
from contextlib import contextmanager, ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock
from unittest.mock import patch

import firecracker_recovery as recovery


class AdmissionTests(unittest.TestCase):
    def test_charged_scene_is_counted_once_and_all_helper_growth_is_added(self):
        try: value = recovery.admitted(4000000000, 5000000000, 100000000, 0)
        except ValueError as error: self.fail('valid recovery envelope refused: ' + str(error))
        self.assertEqual(value['disk_bytes'], 9836000000)
        self.assertEqual(value['resident_bytes'], 1256000000)
        for values in ((7000000000, 5000000000, 0, 0),
                       (4000000000, 0, 0, 0),
                       (0, 5000000000, 0, 15000000000),
                       (True, 5000000000, 0, 0), (-1, 5000000000, 0, 0)):
            with self.subTest(values=values), self.assertRaises(ValueError): recovery.admitted(*values)

    def test_rest_walk_omits_only_exact_identity_and_counts_hardlink_names(self):
        with tempfile.TemporaryDirectory(prefix='warden-rest-fixture-') as d:
            root = Path(d); live = root / 'parent/live'; live.mkdir(parents=True)
            (live / 'opaque').write_bytes(b'private fixture')
            (root / 'outside').write_bytes(b'x' * 4096)
            os.link(root / 'outside', root / 'second-name')
            (root / '.git').mkdir(); (root / '.git/state').write_bytes(b'git fixture')
            anchor = (live.stat().st_dev, live.stat().st_ino)
            want = sum(p.stat().st_blocks * 512 for p in (root / 'outside', root / 'second-name', root / '.git/state'))
            try: actual = recovery.project_rest(root, live, anchor)
            except ValueError as error: self.fail('exact rest measurement refused: ' + str(error))
            self.assertEqual(actual, want)
            live.rename(root / 'saved'); live.mkdir()
            with self.assertRaises(ValueError): recovery.project_rest(root, live, anchor)
            live.rmdir(); live.symlink_to(root / 'saved', target_is_directory=True)
            with self.assertRaises((OSError, ValueError)): recovery.project_rest(root, live, anchor)

    def test_unreadable_other_directory_is_not_silently_excluded(self):
        with tempfile.TemporaryDirectory(prefix='warden-rest-fixture-') as d:
            root = Path(d); live = root / 'live'; live.mkdir(); (root / 'other').mkdir()
            original = os.scandir
            def denied(path):
                if str(path) == str(root / 'other'): raise PermissionError('fixture unreadability')
                return original(path)
            with patch.object(recovery.os, 'scandir', side_effect=denied, create=True):
                with self.assertRaises(PermissionError):
                    recovery.project_rest(root, live, (live.stat().st_dev, live.stat().st_ino))


class OriginalIdentityTests(unittest.TestCase):
    def test_only_public_original_records_and_unreleased_charge_authorize_scene(self):
        # This is the allowed public snapshot, not the private parent files.
        path = Path(__file__).resolve().parent.parent / 'docs/evidence/task-4/live/95fa55dc0ce97d3e1b99a255a84f80e96972c71f/boot-third-postflight.json'
        observed = json.loads(path.read_text())
        records = {key: observed[key] for key in ('identity', 'binding', 'receipt', 'absence', 'charge')}
        try: recovery.verify_records(records)
        except ValueError as error: self.fail('authentic public scene refused: ' + str(error))
        for key, field, changed in (('charge', 'released', True), ('charge', 'reserved_bytes', 0),
                                    ('identity', 'mode', 'conformance'), ('receipt', 'container', 'a' * 64),
                                    ('absence', 'exact_original_entry_absent', False)):
            bad = copy.deepcopy(records); bad[key][field] = changed
            with self.subTest(key=key, field=field), self.assertRaises(ValueError): recovery.verify_records(bad)
        bad = copy.deepcopy(records); del bad['receipt']
        with self.assertRaises(ValueError): recovery.verify_records(bad)


class PackageTests(unittest.TestCase):
    def test_reads_ignore_atime_but_keep_content_identity_checks(self):
        with tempfile.TemporaryDirectory(prefix='warden-atime-fixture-') as d:
            root = Path(d); source = root / 'python'; source.write_bytes(b'fixture interpreter'); source.chmod(0o555)
            module = root / 'helper.py'; module.write_bytes(b'# fixture\n'); module.chmod(0o644)
            original = os.fstat; count = [0]
            def changing_atime(fd):
                values = list(original(fd)); count[0] += 1; values[7] += count[0]
                return os.stat_result(values)
            with patch.object(recovery.os, 'fstat', side_effect=changing_atime), \
                 patch.object(recovery, 'INPUT_UID', os.getuid()):
                try: recovery.build_archive(root / 'image.tar', {'usr/bin/python3': source}, module)
                except ValueError as error: self.fail('atime-only change refused: ' + str(error))

    def test_streamed_archive_has_only_regular_verified_inputs_and_fixed_entrypoints(self):
        with tempfile.TemporaryDirectory(prefix='warden-package-fixture-') as d:
            root = Path(d); source = root / 'python'; source.write_bytes(b'fixture interpreter'); source.chmod(0o555)
            module = root / 'helper.py'; module.write_bytes(b'# fixture reviewed helper\n'); module.chmod(0o644)
            try:
                with patch.object(recovery, 'INPUT_UID', os.getuid(), create=True):
                    result = recovery.build_archive(root / 'image.tar', {'usr/bin/python3': source}, module)
            except ValueError as error: self.fail('bounded package refused: ' + str(error))
            with tarfile.open(root / 'image.tar') as archive:
                entries = {m.name: m for m in archive}
                self.assertEqual(set(n for n, m in entries.items() if m.isfile()),
                                 {'usr/bin/python3', 'recovery.py', 'package-manifest.json'})
                self.assertTrue(all(m.isfile() or m.isdir() for m in entries.values()))
                self.assertEqual(archive.extractfile('usr/bin/python3').read(), b'fixture interpreter')
            self.assertLess(result['archive_bytes'], 160000000)
            self.assertEqual(result['files']['usr/bin/python3']['sha256'], hashlib.sha256(b'fixture interpreter').hexdigest())
            source.chmod(0o777)
            with patch.object(recovery, 'INPUT_UID', os.getuid(), create=True):
                with self.assertRaises(ValueError):
                    recovery.build_archive(root / 'bad.tar', {'usr/bin/python3': source}, module)
            self.assertFalse((root / 'bad.tar').exists())


class ProfileTests(unittest.TestCase):
    def fixture(self, mode):
        self.image = 'sha256:' + 'a' * 64
        self.labels = {'project': 'warden', 'owner': 'codex-warden', 'task': 'firecracker-recovery',
                       'session': 'a' * 32, 'original_session': '89c9296e79ce14c5dd30e0d5e4772f1d',
                       'phase': mode, 'ttl': '2026-10-25T00:00:00+00:00'}
        source = '/home/postedism/Desktop/Warden/.cache/warden-lab/docker-firecracker-89c9296e79ce14c5dd30e0d5e4772f1d/live'
        security = ['no-new-privileges'] + (['apparmor=unconfined', 'seccomp=unconfined'] if mode != 'inspect' else [])
        return {'Id': 'b' * 64, 'Image': self.image,
                'Config': {'User': '0:0', 'Labels': self.labels,
                           'Entrypoint': ['/usr/bin/python3', '-I', '-S', '-B', '/recovery.py'], 'Cmd': [mode],
                           'Env': ['WARDEN_RECOVERY_HOST_MOUNT_NS=mnt:[12]'],
                           'OpenStdin': False, 'StdinOnce': False, 'AttachStdin': False, 'Tty': False},
                'HostConfig': {'Memory': 256000000, 'MemorySwap': 256000000, 'NanoCpus': 1000000000,
                               'PidsLimit': 32, 'NetworkMode': 'none', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                               'PidMode': '', 'UsernsMode': '', 'CgroupParent': '', 'ReadonlyRootfs': True,
                               'Privileged': False, 'CapDrop': ['ALL'],
                               'CapAdd': ['CAP_CHOWN', 'CAP_SYS_ADMIN'] if mode != 'inspect' else None,
                               'Devices': [], 'DeviceCgroupRules': None, 'DeviceRequests': None,
                               'SecurityOpt': security, 'Binds': None, 'VolumesFrom': None,
                               'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=16m'},
                               'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '64k', 'max-file': '1'}},
                               'Mounts': [{'Type': 'bind', 'Source': source, 'Target': '/session', 'ReadOnly': True,
                                           'BindOptions': {'Propagation': 'rprivate'}}]},
                'Mounts': [{'Type': 'bind', 'Source': source, 'Destination': '/session', 'RW': False,
                            'Mode': '', 'Propagation': 'rprivate'}]}

    def test_exact_profile_and_unique_readonly_binding(self):
        for mode in ('inspect', 'restore-traversal'):
            data = self.fixture(mode)
            try:
                args = recovery.create_args(mode, self.image, self.labels, 'mnt:[12]')
                recovery.inspect_profile(data, mode, self.image, self.labels, 'mnt:[12]')
            except ValueError as error: self.fail('fixed profile refused: ' + str(error))
            self.assertEqual(len([x for x in args if x.startswith('--mount=')]), 1)
            self.assertIn('--memory=256000000', args)
            self.assertIn('--memory-swap=256000000', args)
            self.assertIn('--pull=never', args)
            self.assertFalse(any(x.startswith('--device') for x in args))
            for key, changed in [('Memory', 256000001), ('Privileged', True), ('PidMode', 'host'),
                                  ('Devices', [{}]), ('CapAdd', ['CAP_DAC_OVERRIDE']),
                                  ('Binds', ['/tmp:/extra']), ('ReadonlyRootfs', False)]:
                bad = copy.deepcopy(data); bad['HostConfig'][key] = changed
                with self.subTest(mode=mode, key=key), self.assertRaises(ValueError):
                    recovery.inspect_profile(bad, mode, self.image, self.labels, 'mnt:[12]')
            bad = copy.deepcopy(data); bad['Mounts'][0]['RW'] = True
            with self.assertRaises(ValueError): recovery.inspect_profile(bad, mode, self.image, self.labels, 'mnt:[12]')


class BoundaryTests(unittest.TestCase):
    def test_private_records_anchor_replacement_and_exact_absence(self):
        with tempfile.TemporaryDirectory(prefix='warden-auth-fixture-') as d:
            root = Path(d); root.chmod(0o700)
            f = root / 'record.json'; f.write_bytes(b'{"safe":1}\n'); f.chmod(0o600)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                identity = os.fstat(fd).st_dev, os.fstat(fd).st_ino
                try:
                    self.assertEqual(recovery.read_private(fd, 'record.json'), b'{"safe":1}\n')
                    recovery.check_anchor(root, fd, identity, os.getuid())
                    recovery.exact_absence(fd, (*identity, os.getuid()), 'exact-scope')
                except ValueError as error: self.fail('valid owned metadata refused: ' + str(error))
                f.chmod(0o644)
                with self.assertRaises(ValueError): recovery.read_private(fd, 'record.json')
                f.chmod(0o600); os.link(f, root / 'hardlink')
                with self.assertRaises(ValueError): recovery.read_private(fd, 'record.json')
                (root / 'hardlink').unlink()
                (root / 'exact-scope').symlink_to('/nonexistent')
                with self.assertRaises(ValueError): recovery.exact_absence(fd, (*identity, os.getuid()), 'exact-scope')
                replacement = root / 'replacement'; replacement.mkdir(mode=0o700)
                with self.assertRaises(ValueError): recovery.check_anchor(replacement, fd, identity, os.getuid())
            finally: os.close(fd)

    def test_command_output_is_bounded_and_timeout_reaps_only_own_child(self):
        try:
            result = recovery.bounded_command([sys.executable, '-I', '-S', '-B', '-c', 'print("fixture")'], 2, 64)
        except ValueError as error: self.fail('bounded harmless child refused: ' + str(error))
        self.assertEqual(result, (0, b'fixture\n', b''))
        with self.assertRaises(ValueError):
            recovery.bounded_command([sys.executable, '-I', '-S', '-B', '-c', 'print("x"*1000)'], 2, 64)
        with self.assertRaises(TimeoutError):
            recovery.bounded_command([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(2)'], .02, 64)


    def test_cleanup_requires_exact_stopped_owned_objects_and_proves_absence(self):
        labels = ProfileTests().fixture('inspect')['Config']['Labels']
        cid, image = 'b' * 64, 'sha256:' + 'a' * 64
        for running in (False, True):
            objects = {'container': [cid], 'image': [image]}; removed = []
            def docker(args, **kwargs):
                kind = args[0]
                if args[1] == 'ls': return '\n'.join(objects[kind])
                if args[1] == 'inspect':
                    return json.dumps([{'Id': args[2], 'Image': image, 'Size': 100,
                                        'Config': {'Labels': labels}, 'State': {'Running': running}}])
                if args[1] == 'rm': objects[kind].remove(args[2]); removed.append(kind); return args[2]
                raise AssertionError(args)
            with patch.object(recovery, 'docker', side_effect=docker, create=True):
                if running:
                    with self.assertRaises(ValueError): recovery.cleanup_helper(labels)
                    self.assertEqual(removed, [])
                else:
                    try: recovery.cleanup_helper(labels)
                    except ValueError as error: self.fail('exact stopped cleanup refused: ' + str(error))
                    self.assertEqual(removed, ['container', 'image'])
                    self.assertEqual(objects, {'container': [], 'image': []})


class DependencyParserTests(unittest.TestCase):
    def test_abi_dependency_output_is_closed_and_missing_library_stops(self):
        raw = b'linux-vdso.so.1 (0x1234)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x5678)\n/lib64/ld-linux-x86-64.so.2 (0x9abc)\n'
        try: result = recovery.dependencies(raw, b'', 0)
        except ValueError as error: self.fail('valid ABI fixture refused: ' + str(error))
        self.assertEqual(result, {'/lib/x86_64-linux-gnu/libc.so.6', '/lib64/ld-linux-x86-64.so.2'})
        for changed in (raw + b'libbad.so => not found\n', b'/tmp/private.so (0x123)\n', b'unknown output\n'):
            with self.assertRaises(ValueError): recovery.dependencies(changed, b'', 0)

    def test_observed_zero_exit_static_output_has_no_dependencies(self):
        self.assertEqual(recovery.dependencies(b'\tstatically linked\n', b'', 0), set())

    def test_normalized_literal_keeps_the_existing_output_bound(self):
        for output in (b'statically linked', b' \r\n statically linked\t\n',
                       b' ' * (65536 - len(b'statically linked')) + b'statically linked'):
            with self.subTest(size=len(output)):
                self.assertEqual(recovery.dependencies(output, b'', 0), set())
        with self.assertRaises(recovery.Refusal):
            recovery.dependencies(b' ' * 65536 + b'statically linked', b'', 0)

    def test_zero_exit_rejects_any_static_stderr_and_nonliteral_output(self):
        for errors in (b' ', b'\n', b'\t', b'warning'):
            with self.subTest(stderr=errors), self.assertRaises(recovery.Refusal):
                recovery.dependencies(b'\tstatically linked\n', errors, 0)
        outputs = (b'', b'\n', b'not a dynamic executable', b'Statically linked', b'statically  linked',
                   b'statically linked\x00', b'prefix statically linked', b'statically linked extra',
                   b'statically linked\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1234)\n',
                   b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1234)\nstatically linked\n')
        for output in outputs:
            with self.subTest(stdout=output), self.assertRaises(recovery.Refusal):
                recovery.dependencies(output, b'', 0)

    def test_existing_nonzero_cases_remain_unchanged(self):
        for output, errors, code in ((b'not a dynamic executable\n', b'', 1),
                                     (b'', b'\tstatically linked\n', 1),
                                     (b'statically linked', b'\n', 2)):
            with self.subTest(code=code, stdout=output):
                self.assertEqual(recovery.dependencies(output, errors, code), set())
        for output, errors in ((b'unknown output', b''), (b'statically linked', b'warning'),
                               (b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1234)', b'')):
            with self.subTest(stdout=output, stderr=errors), self.assertRaises(recovery.Refusal):
                recovery.dependencies(output, errors, 1)


class CleanupStateTests(unittest.TestCase):
    image, cid = 'sha256:' + 'a' * 64, 'b' * 64

    def state(self, step, image=None, cid=None, settled=False, success=False):
        return {'version': 1, 'source': 'c' * 40, 'mode': 'inspect',
                'labels': ProfileTests().fixture('inspect')['Config']['Labels'],
                'image': image, 'cid': cid, 'step': step, 'settled': settled, 'success': success,
                'reserved_bytes': 5000000000, 'released': False,
                'helper_envelope_bytes': 736000000, 'helper_sha256': 'd' * 64}

    @contextmanager
    def fixture(self, state, present=False):
        with tempfile.TemporaryDirectory(prefix='warden-cleanup-state-fixture-') as directory, ExitStack() as stack:
            root = Path(directory); phase = root / 'inspect'; phase.mkdir(mode=0o700)
            record = phase / 'state.json'; original = recovery.encode(state)
            record.write_bytes(original); record.chmod(0o600)
            archive = phase / 'image.tar'; archive.write_bytes(b'own tiny staging fixture'); archive.chmod(0o400)
            objects = {'container': [self.cid] if present else [], 'image': [self.image] if present else []}
            removals = []
            def docker(args, **kwargs):
                kind, action = args[:2]
                if action == 'ls': return '\n'.join(objects[kind])
                if action == 'inspect':
                    return json.dumps([{'Id': args[2], 'Image': self.image, 'Size': 100,
                                        'Config': {'Labels': state['labels']}, 'State': {'Running': False}}])
                if action == 'rm': objects[kind].remove(args[2]); removals.append(kind); return args[2]
                raise AssertionError(args)
            def private(path):
                self.assertEqual(path, phase)
                return os.open(phase, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.enter_context(patch.object(recovery, 'WORK', root))
            stack.enter_context(patch.object(recovery, 'private_directory', side_effect=private))
            cli = stack.enter_context(patch.object(recovery, 'docker', side_effect=docker))
            saved = stack.enter_context(patch.object(recovery, 'save', wraps=recovery.save))
            absent = stack.enter_context(patch.object(recovery, 'helper_absent'))
            stack.enter_context(patch.object(recovery, 'file_sha', return_value='d' * 64))
            yield record, archive, original, cli, saved, absent, removals

    def test_pending_operations_never_settle_from_empty_or_known_lists(self):
        cases = [('import-pending', None, None), ('import-pending', self.image, None),
                 ('create-pending', self.image, None), ('create-pending', self.image, self.cid),
                 ('start-pending', self.image, self.cid)]
        for step, image, cid in cases:
            for present in (False, True):
                state = self.state(step, image, cid); before = copy.deepcopy(state)
                with self.subTest(step=step, image=image is not None, cid=cid is not None, present=present), \
                     self.fixture(state, present) as (record, archive, original, cli, saved, absent, removals):
                    with self.assertRaises(recovery.Refusal): recovery.cleanup_phase(state)
                    self.assertEqual(state, before); self.assertEqual(record.read_bytes(), original)
                    self.assertEqual(archive.read_bytes(), b'own tiny staging fixture')
                    cli.assert_not_called(); saved.assert_not_called(); absent.assert_not_called()
                    self.assertEqual(removals, [])

    def test_malformed_or_inconsistent_state_refuses_read_and_cleanup(self):
        base = self.state('result-validated', self.image, self.cid)
        changes = [{'step': 'import-pending', 'settled': True}, {'step': 'start-pending', 'success': True},
                   {'step': 'material-pending'}, {'step': 'create-pending', 'image': None},
                   {'step': 'start-pending', 'cid': None}, {'cid': None}, {'image': None},
                   {'step': 'objects-settled', 'settled': False},
                   {'step': 'objects-settled', 'settled': True, 'success': True},
                   {'step': 'objects-settled', 'settled': True, 'cid': None},
                   {'step': 'complete', 'settled': True, 'success': False},
                   {'step': 'complete', 'settled': True, 'success': True, 'image': None, 'cid': None},
                   {'settled': 1}, {'released': True}, {'reserved_bytes': 0},
                   {'helper_envelope_bytes': 0}, {'cid': 'short'}, {'step': 'unknown'}]
        for change in changes:
            state = {**base, **change}; before = copy.deepcopy(state)
            with self.subTest(change=change), self.fixture(state) as (record, archive, original, cli, saved, absent, removals):
                with self.assertRaises(recovery.Refusal): recovery.state_read('inspect', 'c' * 40)
                with self.assertRaises(recovery.Refusal): recovery.cleanup_phase(state)
                self.assertEqual(state, before); self.assertEqual(record.read_bytes(), original)
                self.assertTrue(archive.exists()); self.assertEqual(removals, [])
                cli.assert_not_called(); saved.assert_not_called(); absent.assert_not_called()

    def test_pre_daemon_and_validated_terminal_cleanup_keep_original_charge(self):
        cases = [(self.state('material-pending'), False),
                 (self.state('result-validated', self.image, self.cid), False),
                 (self.state('result-validated', self.image, self.cid), True),
                 (self.state('objects-settled', self.image, self.cid, True), False),
                 (self.state('complete', self.image, self.cid, True, True), False)]
        for state, present in cases:
            settled = state['settled']
            with self.subTest(step=state['step'], present=present), \
                 self.fixture(state, present) as (record, archive, original, cli, saved, absent, removals):
                recovery.state_read('inspect', 'c' * 40)
                recovery.cleanup_phase(state)
                self.assertTrue(state['settled']); self.assertFalse(state['released'])
                self.assertEqual(state['reserved_bytes'], 5000000000)
                self.assertEqual(state['helper_envelope_bytes'], 736000000)
                self.assertEqual(archive.exists(), settled)
                self.assertEqual(removals, ['container', 'image'] if present else [])
                if settled:
                    saved.assert_not_called(); self.assertEqual(record.read_bytes(), original)
                else:
                    saved.assert_called_once()
                    self.assertEqual(json.loads(record.read_bytes()), state)
                    self.assertEqual(state['step'], 'objects-settled'); self.assertFalse(state['success'])
                    recovery.state_read('inspect', 'c' * 40)

    def test_pre_daemon_state_cannot_adopt_unexpected_objects(self):
        state = self.state('material-pending'); before = copy.deepcopy(state)
        with self.fixture(state, True) as (record, archive, original, cli, saved, absent, removals):
            with self.assertRaises(recovery.Refusal): recovery.cleanup_phase(state)
            self.assertEqual(state, before); self.assertEqual(record.read_bytes(), original)
            self.assertTrue(archive.exists()); self.assertEqual(removals, [])
            saved.assert_not_called(); absent.assert_not_called()


class MaterialPolicyTests(unittest.TestCase):
    @contextmanager
    def nofollow_enumeration_guard(self, stdlib):
        original_scan, original_open, original_stat, original_resolve = os.scandir, os.open, os.stat, Path.resolve
        omitted = [name for name in recovery.LINKS if name != recovery.SYSCONFIG_ALIAS]
        link_paths = {str(stdlib / name) for name in omitted}
        link_names = {Path(name).name for name in omitted}
        target_paths = {os.path.normpath(str((stdlib / name).parent / recovery.LINKS[name])) for name in omitted}
        targets = target_paths | {recovery.LINKS[name] for name in omitted}
        classified, scanned = [], []

        class Entry:
            def __init__(self, entry): self.entry, self.name, self.path = entry, entry.name, entry.path
            def classify(self, method, follow_symlinks):
                classified.append((self.name, method, follow_symlinks))
                if follow_symlinks:
                    raise AssertionError('following DirEntry.' + method + ' for ' + self.name)
                return getattr(self.entry, method)(follow_symlinks=False)
            def is_dir(self, *, follow_symlinks=True): return self.classify('is_dir', follow_symlinks)
            def is_file(self, *, follow_symlinks=True): return self.classify('is_file', follow_symlinks)
            def stat(self, *, follow_symlinks=True): return self.classify('stat', follow_symlinks)
            def is_symlink(self): return self.entry.is_symlink()

        @contextmanager
        def scan(path):
            scanned.append(path)
            with original_scan(path) as entries:
                # Put the actual omitted fixture link first so old os.walk's
                # implicit target-follow is caught before any target lookup.
                ordered = sorted(entries, key=lambda entry: (entry.name != 'sitecustomize.py', entry.name))
                yield iter(Entry(entry) for entry in ordered)

        def opened(path, *args, **kwargs):
            self.assertNotIn(str(path), targets | link_paths | link_names)
            return original_open(path, *args, **kwargs)

        def stated(path, *args, **kwargs):
            self.assertNotIn(str(path), targets)
            if str(path) in link_paths | link_names:
                self.assertIs(kwargs.get('follow_symlinks'), False)
            return original_stat(path, *args, **kwargs)

        def resolved(path, *args, **kwargs):
            self.assertNotIn(str(path), targets | link_paths)
            return original_resolve(path, *args, **kwargs)

        with patch.object(recovery.os, 'scandir', side_effect=scan), \
             patch.object(recovery.os, 'open', side_effect=opened), \
             patch.object(recovery.os, 'stat', side_effect=stated), \
             patch.object(Path, 'resolve', autospec=True, side_effect=resolved):
            yield classified, scanned

    def test_enumeration_never_implicitly_follows_omitted_link_targets(self):
        with self.fixture() as (_, stdlib, _, _), self.nofollow_enumeration_guard(stdlib) as (classified, scanned):
            material = recovery.select_stdlib()
            try:
                self.assertNotIn(recovery.STDLIB_NAME + 'sitecustomize.py', material)
                self.assertNotIn(recovery.STDLIB_NAME + 'config-3.14-x86_64-linux-gnu/libpython3.14.so', material)
                self.assertIn(recovery.STDLIB_NAME + recovery.SYSCONFIG_ALIAS, material)
                self.assertTrue(scanned)
                self.assertFalse(any(follow for _, _, follow in classified))
            finally: material.close()

    def test_nofollow_enumeration_refuses_unknown_links_and_types_and_keeps_directory_exclusions(self):
        for kind in ('file-link', 'directory-link', 'excluded-directory-link', 'fifo', 'excluded-directory'):
            with self.subTest(kind=kind), self.fixture() as (_, stdlib, _, _):
                if kind == 'file-link': (stdlib / 'unknown.py').symlink_to(recovery.SYSCONFIG_TARGET)
                if kind == 'directory-link': (stdlib / 'unknown-dir').symlink_to('config-3.14-x86_64-linux-gnu', target_is_directory=True)
                if kind == 'excluded-directory-link': (stdlib / 'tests').symlink_to('config-3.14-x86_64-linux-gnu', target_is_directory=True)
                if kind == 'fifo': os.mkfifo(stdlib / 'unknown.pipe', 0o600)
                if kind == 'excluded-directory':
                    excluded = stdlib / 'tests'; excluded.mkdir()
                    (excluded / 'must-not-descend').symlink_to('/nonexistent-fixture-target')
                with self.nofollow_enumeration_guard(stdlib) as (classified, scanned):
                    if kind == 'excluded-directory':
                        material = recovery.select_stdlib()
                        try: self.assertFalse(any('/tests/' in name for name in material))
                        finally: material.close()
                    else:
                        with self.assertRaises(recovery.Refusal): recovery.select_stdlib()
                    self.assertFalse(any(follow for _, _, follow in classified))
                    self.assertTrue(all(type(fd) is int for fd in scanned))

    def test_nofollow_enumeration_rejects_directory_replacement_before_descent(self):
        with self.fixture() as (_, stdlib, _, _):
            directory = stdlib / 'ordinary'; directory.mkdir()
            original = os.open
            def replaced(name, *args, **kwargs):
                if name == 'ordinary' and kwargs.get('dir_fd') is not None:
                    directory.rename(stdlib / 'retained-ordinary'); directory.mkdir()
                return original(name, *args, **kwargs)
            with self.nofollow_enumeration_guard(stdlib), patch.object(recovery.os, 'open', side_effect=replaced):
                with self.assertRaises(recovery.Refusal): recovery.select_stdlib()

    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='warden-public-material-fixture-') as d, ExitStack() as stack:
            root = Path(d); stdlib = root / 'stdlib'; stdlib.mkdir()
            config = stdlib / 'config-3.14-x86_64-linux-gnu'; config.mkdir()
            for name, text in recovery.LINKS.items(): (stdlib / name).symlink_to(text)
            target = stdlib / recovery.SYSCONFIG_TARGET
            target.write_bytes(b'build_time_vars = {"fixture": True}\n'); target.chmod(0o644)
            obj = stdlib / recovery.DEVELOPMENT_OBJECT
            obj.write_bytes(recovery.OBJECT_HEADER + bytes(11504 - 20)); obj.chmod(0o644)
            for name in ('libpython3.14.a', 'libpython3.14-pic.a'):
                path = config / name; path.write_bytes(b'!<arch>\nfixture'); path.chmod(0o644)
            python = root / 'python'; python.write_bytes(b'fixture interpreter'); python.chmod(0o555)
            module = root / 'helper.py'; module.write_bytes(b'# fixture helper\n'); module.chmod(0o644)
            stack.enter_context(patch.object(recovery, 'STDLIB', stdlib))
            stack.enter_context(patch.object(recovery, 'INPUT_UID', os.getuid()))
            stack.enter_context(patch.object(recovery, 'INPUT_GID', os.getgid()))
            stack.enter_context(patch.object(recovery, 'public_directory', side_effect=lambda p: os.open(p, recovery.NOFOLLOW_DIR)))
            yield root, stdlib, python, module

    def test_exact_materials_copy_both_regular_names_and_never_access_omitted_targets(self):
        with self.fixture() as (root, stdlib, python, module):
            denied = {'/etc/python3.14/sitecustomize.py', '../../x86_64-linux-gnu/libpython3.14.so.1'}
            original_open, original_stat, original_read = os.open, os.stat, os.read
            object_ino = (stdlib / recovery.DEVELOPMENT_OBJECT).stat().st_ino
            reads = []
            def opened(path, *args, **kwargs):
                self.assertNotIn(str(path), denied)
                return original_open(path, *args, **kwargs)
            def stated(path, *args, **kwargs):
                self.assertNotIn(str(path), denied)
                return original_stat(path, *args, **kwargs)
            def read(fd, count):
                if os.fstat(fd).st_ino == object_ino:
                    self.assertEqual(count, 20); self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0); reads.append(count)
                return original_read(fd, count)
            with patch.object(recovery.os, 'open', side_effect=opened), \
                 patch.object(recovery.os, 'stat', side_effect=stated), patch.object(recovery.os, 'read', side_effect=read):
                material = recovery.select_stdlib()
                try:
                    material['usr/bin/python3'] = python
                    result = recovery.build_archive(root / 'image.tar', material, module)
                    self.assertTrue(reads)
                    for name in recovery.OMITTED: self.assertNotIn(name, result['files'])
                    names = [recovery.STDLIB_NAME + n for n in (recovery.SYSCONFIG_ALIAS, recovery.SYSCONFIG_TARGET)]
                    self.assertEqual(result['files'][names[0]], result['files'][names[1]])
                    self.assertEqual(result['files'][names[0]]['sha256'], hashlib.sha256((stdlib / recovery.SYSCONFIG_TARGET).read_bytes()).hexdigest())
                    with tarfile.open(root / 'image.tar') as archive:
                        for name in names: self.assertTrue(archive.getmember(name).isreg())
                        self.assertFalse(any(item.issym() or item.islnk() for item in archive))
                        for name in recovery.OMITTED: self.assertNotIn(name, archive.getnames())
                    self.assertEqual(sum(n.endswith('.a') for n in result['files']), 2)
                    copied = sum(item['bytes'] for item in result['files'].values())
                    with patch.object(recovery, 'FILE_LIMIT', copied - 1):
                        with self.assertRaises(recovery.Refusal):
                            recovery.build_archive(root / 'too-large.tar', material, module)
                    self.assertFalse((root / 'too-large.tar').exists())
                finally: material.close()

    def test_alias_shape_target_identity_and_drift_refuse(self):
        cases = ('wrong-text', 'regular', 'missing', 'unknown-link', 'target-link', 'hardlink', 'writable', 'xattr')
        for case in cases:
            with self.subTest(case=case), self.fixture() as (_, stdlib, _, _), ExitStack() as stack:
                alias, target = stdlib / recovery.SYSCONFIG_ALIAS, stdlib / recovery.SYSCONFIG_TARGET
                if case in ('wrong-text', 'regular', 'missing'): alias.unlink()
                if case == 'wrong-text': alias.symlink_to('other.py')
                if case == 'regular': alias.write_text('wrong type')
                if case == 'unknown-link': (stdlib / 'unexpected.py').symlink_to(recovery.SYSCONFIG_TARGET)
                if case == 'target-link': target.unlink(); target.symlink_to('other.py')
                if case == 'hardlink': os.link(target, stdlib / 'second.py')
                if case == 'writable': target.chmod(0o666)
                if case == 'xattr': stack.enter_context(patch.object(recovery.os, 'listxattr', return_value=['user.fixture']))
                with self.assertRaises((OSError, recovery.Refusal)): recovery.select_stdlib()
        for case in ('alias-replace', 'target-replace', 'target-write', 'object-replace'):
            with self.subTest(drift=case), self.fixture() as (_, stdlib, _, _):
                material = recovery.select_stdlib()
                try:
                    target = stdlib / recovery.SYSCONFIG_TARGET
                    if case == 'alias-replace':
                        alias = stdlib / recovery.SYSCONFIG_ALIAS; alias.unlink(); alias.symlink_to(recovery.SYSCONFIG_TARGET)
                    if case == 'target-replace':
                        body = target.read_bytes(); target.unlink(); target.write_bytes(body); target.chmod(0o644)
                    if case == 'target-write': target.write_bytes(b'changed')
                    if case == 'object-replace':
                        obj = stdlib / recovery.DEVELOPMENT_OBJECT; body = obj.read_bytes(); obj.unlink(); obj.write_bytes(body)
                    with self.assertRaises(recovery.Refusal): material.recheck()
                finally: material.close()

    def test_each_expected_link_requires_exact_own_metadata_without_target_access(self):
        for name in recovery.LINKS:
            for field in ('st_uid', 'st_gid', 'st_nlink', 'st_mode'):
                with self.subTest(name=name, field=field), self.fixture() as (_, stdlib, _, _):
                    leaf = (stdlib / name).name
                    original = os.stat
                    def changed(path, *args, **kwargs):
                        info = original(path, *args, **kwargs)
                        if str(path) != leaf or kwargs.get('follow_symlinks') is not False: return info
                        from types import SimpleNamespace
                        fields = {n: getattr(info, n) for n in dir(info) if n.startswith('st_')}
                        fields[field] = {'st_uid': 12345, 'st_gid': 12345, 'st_nlink': 2,
                                         'st_mode': stat.S_IFREG | 0o777}[field]
                        return SimpleNamespace(**fields)
                    with patch.object(recovery.os, 'stat', side_effect=changed):
                        with self.assertRaises(recovery.Refusal): recovery.select_stdlib()

    def test_exact_development_object_rejects_unknown_metadata_and_header(self):
        for case in ('header', 'mode', 'size', 'hardlink', 'symlink', 'missing', 'xattr', 'uid', 'gid'):
            with self.subTest(case=case), self.fixture() as (_, stdlib, _, _), ExitStack() as stack:
                obj = stdlib / recovery.DEVELOPMENT_OBJECT; ino = obj.stat().st_ino
                if case == 'header': obj.write_bytes(b'X' + recovery.OBJECT_HEADER[1:] + bytes(11504 - 20))
                if case == 'mode': obj.chmod(0o444)
                if case == 'size': obj.write_bytes(recovery.OBJECT_HEADER)
                if case == 'hardlink': os.link(obj, obj.with_suffix('.other'))
                if case in ('symlink', 'missing'): obj.unlink()
                if case == 'symlink': obj.symlink_to('../' + recovery.SYSCONFIG_TARGET)
                if case == 'xattr':
                    original = os.listxattr
                    stack.enter_context(patch.object(recovery.os, 'listxattr', side_effect=lambda fd:
                        ['user.fixture'] if os.fstat(fd).st_ino == ino else original(fd)))
                if case in ('uid', 'gid'):
                    from types import SimpleNamespace
                    original = os.fstat
                    def changed(fd):
                        info = original(fd)
                        if info.st_ino != ino: return info
                        fields = {n: getattr(info, n) for n in dir(info) if n.startswith('st_')}
                        fields['st_' + case] = 12345
                        return SimpleNamespace(**fields)
                    stack.enter_context(patch.object(recovery.os, 'fstat', side_effect=changed))
                with self.assertRaises((OSError, recovery.Refusal)): recovery.select_stdlib()

    def test_dependency_omission_conflict_refuses_before_resolution(self):
        material = recovery.RuntimeMaterial()
        with patch.object(Path, 'resolve', side_effect=AssertionError('must not resolve omission')):
            for name in recovery.OMITTED:
                with self.subTest(name=name), self.assertRaises(recovery.Refusal): material.dependency('/' + name)

    def test_runtime_closure_never_probes_exact_object_but_rejects_an_unknown_relocatable(self):
        for unknown in (False, True):
            with self.subTest(unknown=unknown), self.fixture() as (_, stdlib, python, _), ExitStack() as stack:
                if unknown:
                    other = stdlib / 'unknown.o'; other.write_bytes(recovery.OBJECT_HEADER); other.chmod(0o644)
                # A fixture ELF extension needs ldd; the two .a files remain
                # selected bytes, and the one authenticated python.o never does.
                extension = stdlib / 'fixture.so'
                extension.write_bytes(recovery.OBJECT_HEADER[:16] + b'\x03\x00\x3e\x00'); extension.chmod(0o644)
                resolve, opened = Path.resolve, recovery.open_public
                stack.enter_context(patch.object(recovery, 'PYTHON', python))
                stack.enter_context(patch.object(Path, 'resolve', autospec=True, side_effect=lambda p, **kw:
                    python if p == Path('/usr/bin/python3') else resolve(p, **kw)))
                stack.enter_context(patch.object(recovery, 'open_public', side_effect=lambda p:
                    opened(python if p == Path('/usr/bin/ldd') else p)))
                command = stack.enter_context(patch.object(recovery, 'bounded_command', return_value=(0, b'fixture', b'')))
                stack.enter_context(patch.object(recovery, 'dependencies', return_value=set()))
                abi = stack.enter_context(patch.object(recovery, 'host_abi', return_value={'fixture': True}))
                if unknown:
                    with self.assertRaises(recovery.Refusal):
                        with recovery.runtime_inputs(): self.fail('unknown ELF accepted')
                    command.assert_not_called(); abi.assert_not_called()
                else:
                    with recovery.runtime_inputs() as inputs:
                        self.assertFalse(recovery.OMITTED.intersection(inputs))
                    command.assert_called_once_with(['/usr/bin/ldd', str(extension)], limit=65536)
                    abi.assert_called_once_with()

    def test_copied_input_drift_after_host_check_refuses_before_package(self):
        with self.fixture() as (_, stdlib, _, _):
            material = recovery.select_stdlib()
            try:
                name = recovery.STDLIB_NAME + 'config-3.14-x86_64-linux-gnu/libpython3.14.a'
                material.input_metadata[name] = recovery.helper.metadata(material[name].stat())
                material[name].write_bytes(b'changed after fixed host check')
                with self.assertRaises(recovery.Refusal): material.recheck()
            finally: material.close()

    def test_fixed_host_abi_command_and_closed_sanitized_receipt(self):
        value = {'kind': 'public-python314-host-abi-v1', 'version': [3, 14, 7], 'isolated': True,
                 'no_site': True, 'dont_write_bytecode': True, 'sitecustomize_absent': True,
                 'imports': True, 'mount_symbol': True}
        with patch.object(recovery, 'bounded_command', return_value=(0, recovery.encode(value), b'')) as command:
            self.assertEqual(recovery.host_abi(), value)
            command.assert_called_once_with(['/usr/bin/python3.14', '-I', '-S', '-B', '-c', recovery.HOST_ABI_CHECK], limit=16384)
        cases = [(1, b'{"kind":"public-python314-host-abi-refused"}\n', b''),
                 (0, recovery.encode(value), b'private fixture exception'), (0, b'x' * 16385, b'')]
        for change in ({'version': [3, 13, 9]}, {'version': [3, 14, True]}, {'isolated': 1},
                       {'sitecustomize_absent': False}, {'mount_symbol': False}, {'environment': 'private'}):
            cases.append((0, recovery.encode({**value, **change}), b''))
        for result in cases:
            with self.subTest(result=result[0]), patch.object(recovery, 'bounded_command', return_value=result):
                with self.assertRaises(recovery.Refusal): recovery.host_abi()
        import ast
        tree = ast.parse(recovery.HOST_ABI_CHECK)
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'symbol' for n in ast.walk(tree)))
        self.assertIn('ctypes.CDLL(None).mount', recovery.HOST_ABI_CHECK)

    def test_omitted_archive_names_cannot_be_reintroduced(self):
        names = ('usr/lib/python3.14/sitecustomize.py',
                 'usr/lib/python3.14/config-3.14-x86_64-linux-gnu/libpython3.14.so',
                 'usr/lib/python3.14/config-3.14-x86_64-linux-gnu/python.o')
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='warden-material-fixture-') as d:
                root = Path(d); source = root / 'public'; source.write_bytes(b'public fixture'); source.chmod(0o644)
                with patch.object(recovery, 'INPUT_UID', os.getuid()):
                    with self.assertRaises(recovery.Refusal):
                        recovery.build_archive(root / 'image.tar', {'usr/bin/python3': source, name: source}, source)
                self.assertFalse((root / 'image.tar').exists())


class HistoryBindingTests(unittest.TestCase):
    source = 'c' * 40
    second_source = 'ba8cfaf6bffd7996f54bd50db9ccf453ff121022'

    @staticmethod
    def old_records():
        paths = [recovery.PREDECESSOR_WORK / 'inspect' / name
                 for name in ('state.json', 'admission-material.json')]
        paths += [recovery.SECOND_WORK / 'operation.json']
        paths += [recovery.SECOND_WORK / 'inspect' / name
                  for name in ('state.json', 'provenance.json', 'admission-material.json')]
        return {str(p): (p.read_bytes(), recovery.helper.metadata(p.stat())) for p in paths}

    def historical_document(self, first, admission, root):
        info = root.stat()
        return {'kind': 'physical-recovery-operation-v1', 'operation': 'recovery-a-py314-v1',
                'material_policy': 'python314-public-material-v1', 'source': self.second_source,
                'helper_sha256': recovery.PREDECESSOR_HELPER,
                'scene': {'parent': list(recovery.PARENT), 'live': list(recovery.helper.ANCHOR),
                          'original_source': recovery.helper.SOURCE,
                          'records_sha256': recovery.sha(recovery.encode(recovery.EXPECTED_RECORDS))},
                'root_identity': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode & 0o7777],
                'predecessor': first, 'admission': admission,
                'reserved_bytes': 5000000000, 'released': False, 'helper_envelope_bytes': 736000000}

    @contextmanager
    def fixture(self, second=True):
        with tempfile.TemporaryDirectory(prefix='warden-dual-history-fixture-') as d, ExitStack() as stack:
            scene = Path(d); scene.chmod(0o700)
            old = scene / 'recovery-a'; old.mkdir(mode=0o700)
            phase = old / 'inspect'; phase.mkdir(mode=0o700)
            state = CleanupStateTests().state('objects-settled', settled=True)
            state.update(source=recovery.PREDECESSOR_SOURCE, helper_sha256=recovery.PREDECESSOR_HELPER)
            first = recovery.admitted(4000000000, 5000000000, 0, 0)
            first.update(free_bytes=10000000000, utc='2026-10-24T23:34:12+00:00')
            for name, value in (('state.json', state), ('admission-material.json', first)):
                path = phase / name; path.write_bytes(recovery.encode(value)); path.chmod(0o600)
            def private(path):
                self.assertTrue(Path(path).is_relative_to(scene))
                fd = os.open(path, recovery.NOFOLLOW_DIR)
                if os.fstat(fd).st_mode != stat.S_IFDIR | 0o700 or os.fstat(fd).st_uid != 1000:
                    os.close(fd); raise recovery.Refusal('fixture_private_directory')
                return fd
            stack.enter_context(patch.object(recovery, 'SCENE', scene))
            stack.enter_context(patch.object(recovery, 'PREDECESSOR_WORK', old))
            stack.enter_context(patch.object(recovery, 'SECOND_WORK', scene / 'recovery-a-py314-v1', create=True))
            stack.enter_context(patch.object(recovery, 'WORK', scene / 'recovery-a-py314-static-v1'))
            stack.enter_context(patch.object(recovery, 'private_directory', side_effect=private))
            stack.enter_context(patch.object(recovery, 'file_sha', return_value=recovery.PREDECESSOR_HELPER))
            objects = stack.enter_context(patch.object(recovery, 'scoped_ids', return_value=[]))
            if second:
                root = recovery.SECOND_WORK; root.mkdir(mode=0o700)
                prior = recovery.predecessor()
                recovery.save(root / 'operation.json', self.historical_document(prior, first, root))
                second_phase = root / 'inspect'; second_phase.mkdir(mode=0o700)
                second_state = copy.deepcopy(state)
                second_state.update(source=self.second_source)
                second_state['labels']['session'] = 'e' * 32
                material = recovery.admitted(4000004096, 5000000000, 0, 0)
                material.update(free_bytes=9999995904, utc='2026-10-25T00:10:25+00:00')
                provenance = {'operation_sha256': recovery.sha((root / 'operation.json').read_bytes()),
                              'operation_metadata': recovery.helper.metadata((root / 'operation.json').stat()),
                              'source': self.second_source, 'material_policy': 'python314-public-material-v1',
                              'predecessor_state_sha256': prior['state_sha256'],
                              'reserved_bytes': 5000000000, 'released': False, 'helper_envelope_bytes': 736000000}
                for name, value in (('state.json', second_state), ('provenance.json', provenance),
                                    ('admission-material.json', material)):
                    recovery.save(second_phase / name, value)
            yield scene, phase, state, first, objects

    def test_existing_operation_read_refuses_a_first_only_historical_document(self):
        for second in (False, True):
            with self.subTest(second=second), self.fixture(second) as (_, _, _, first, _):
                recovery.WORK.mkdir(mode=0o700)
                document = self.historical_document(recovery.predecessor(), first, recovery.WORK)
                document['source'] = self.source
                recovery.save(recovery.WORK / 'operation.json', document)
                with self.assertRaises((recovery.Refusal, OSError)): recovery.operation_read(self.source)

    def test_exact_two_histories_preserve_all_bytes_and_separate_admissions(self):
        with self.fixture() as (_, _, _, first, objects):
            before = self.old_records()
            history = recovery.histories()
            self.assertEqual(set(history), {'first', 'second'})
            second = history['second']
            self.assertEqual(second['source'], self.second_source)
            for name, key in (('operation.json', 'operation'), ('inspect/state.json', 'state'),
                              ('inspect/provenance.json', 'provenance'), ('inspect/admission-material.json', 'admission')):
                raw, info = before[str(recovery.SECOND_WORK / name)]
                self.assertEqual(second[key + '_sha256'], recovery.sha(raw))
                self.assertEqual(second[key + '_metadata'], info)
            material = json.loads((recovery.SECOND_WORK / 'inspect/admission-material.json').read_bytes())
            self.assertNotEqual(first, material)
            directory = recovery.new_phase('inspect', self.source, history, first)
            binding = recovery.operation_read(self.source)
            recovery.save(directory / 'provenance.json', binding)
            self.assertEqual(recovery.phase_binding('inspect', self.source), binding)
            operation = json.loads((recovery.WORK / 'operation.json').read_bytes())
            self.assertEqual(operation['kind'], 'physical-recovery-history-operation-v1')
            self.assertEqual(operation['history'], history)
            self.assertLessEqual(len(recovery.encode(operation)), 16384)
            self.assertEqual(self.old_records(), before)
            checked = {(call.args[0], call.args[1]['session']) for call in objects.call_args_list}
            self.assertEqual(checked, {(kind, item['labels']['session']) for kind in ('container', 'image')
                                      for item in history.values()})

    def test_second_state_and_objects_refuse_before_new_root_or_admission(self):
        changes = ({'source': self.source}, {'helper_sha256': 'a' * 64}, {'success': True},
                   {'step': 'material-pending', 'settled': False}, {'step': 'import-pending', 'settled': False},
                   {'step': 'create-pending', 'settled': False, 'image': CleanupStateTests.image},
                   {'image': CleanupStateTests.image, 'cid': CleanupStateTests.cid},
                   {'reserved_bytes': 0}, {'released': True}, {'helper_envelope_bytes': 0},
                   {'labels': {}}, 'wrong-original-session', 'wrong-phase', 'objects')
        for change in changes:
            with self.subTest(change=change), self.fixture() as (_, _, _, _, objects):
                path = recovery.SECOND_WORK / 'inspect/state.json'; state = json.loads(path.read_bytes())
                if type(change) is dict: state.update(change)
                if change == 'wrong-original-session': state['labels']['original_session'] = '0' * 32
                if change == 'wrong-phase': state['labels']['phase'] = 'restore-traversal'
                path.write_bytes(recovery.encode(state))
                if change == 'objects':
                    objects.side_effect = lambda kind, labels, run: ['unexpected'] if labels == state['labels'] else []
                before = self.old_records()
                with patch.object(recovery, 'account') as account, patch.object(recovery, 'new_phase') as new:
                    with self.assertRaises(recovery.Refusal): recovery.execute_phase(Mock(), 'inspect', 0, self.source)
                    account.assert_not_called(); new.assert_not_called()
                self.assertEqual(self.old_records(), before)
                self.assertFalse(recovery.WORK.exists())

    def test_second_literal_operation_rejects_changed_historical_fields(self):
        changes = {'kind': 'physical-recovery-history-operation-v1', 'operation': 'recovery-a-py314-static-v1',
                   'source': self.source, 'material_policy': 'unknown', 'helper_sha256': 'a' * 64,
                   'scene': {}, 'root_identity': [0, 0, 1000, 1000, 448], 'predecessor': {},
                   'admission': {}, 'reserved_bytes': 0, 'released': True, 'helper_envelope_bytes': 0, 'extra': True}
        for key, value in changes.items():
            with self.subTest(key=key), self.fixture():
                path = recovery.SECOND_WORK / 'operation.json'; old = json.loads(path.read_bytes())
                old[key] = value; path.write_bytes(recovery.encode(old))
                with self.assertRaises(recovery.Refusal): recovery.histories()
                self.assertFalse(recovery.WORK.exists())

    def test_second_provenance_and_each_admission_are_independently_closed(self):
        changes = {'operation_sha256': '0' * 64, 'operation_metadata': {}, 'source': self.source,
                   'material_policy': 'unknown', 'predecessor_state_sha256': '0' * 64,
                   'reserved_bytes': 0, 'released': True, 'helper_envelope_bytes': 0, 'history_sha256': '0' * 64}
        for key, value in changes.items():
            with self.subTest(key=key), self.fixture():
                path = recovery.SECOND_WORK / 'inspect/provenance.json'; old = json.loads(path.read_bytes())
                old[key] = value; path.write_bytes(recovery.encode(old))
                with self.assertRaises(recovery.Refusal): recovery.histories()
        for name in ('operation.json', 'inspect/admission-material.json'):
            with self.subTest(name=name), self.fixture():
                path = recovery.SECOND_WORK / name; value = json.loads(path.read_bytes())
                admission = value['admission'] if name == 'operation.json' else value
                admission['prospective_helper_growth'] = 0
                path.write_bytes(recovery.encode(value))
                with self.assertRaises(recovery.Refusal): recovery.histories()

    def test_second_exact_shapes_modes_links_size_and_canonical_bytes(self):
        cases = ('missing-operation', 'missing-state', 'extra-root', 'extra-phase', 'root-mode', 'phase-mode',
                 'hardlink', 'symlink', 'file-mode', 'oversize', 'noncanonical', 'replacement')
        for change in cases:
            with self.subTest(change=change), self.fixture() as (scene, _, _, _, _):
                root = recovery.SECOND_WORK; phase = root / 'inspect'; record = phase / 'state.json'
                if change == 'missing-operation': (root / 'operation.json').unlink()
                if change == 'missing-state': record.unlink()
                if change == 'extra-root': (root / 'restore-traversal').mkdir()
                if change == 'extra-phase': (phase / 'result.json').write_bytes(b'{}')
                if change == 'root-mode': root.chmod(0o750)
                if change == 'phase-mode': phase.chmod(0o750)
                if change == 'hardlink': os.link(record, scene / 'linked-state')
                if change == 'symlink': record.rename(scene / 'saved-state'); record.symlink_to(scene / 'saved-state')
                if change == 'file-mode': record.chmod(0o640)
                if change == 'oversize': record.write_bytes(b' ' * 16385)
                if change == 'noncanonical': record.write_bytes(json.dumps(json.loads(record.read_bytes()), indent=2).encode())
                if change == 'replacement':
                    op = root / 'operation.json'; raw = op.read_bytes()
                    op.rename(scene / 'saved-operation'); op.write_bytes(raw); op.chmod(0o600)
                with self.assertRaises((recovery.Refusal, OSError)): recovery.histories()
                self.assertFalse(recovery.WORK.exists())

    def test_first_is_revalidated_after_second_and_second_records_rechecked(self):
        with self.fixture() as (_, phase, state, _, _):
            read = recovery.second_predecessor
            def drift(prior):
                result = read(prior)
                state['labels']['session'] = 'd' * 32
                (phase / 'state.json').write_bytes(recovery.encode(state))
                return result
            with patch.object(recovery, 'second_predecessor', side_effect=drift):
                with self.assertRaisesRegex(recovery.Refusal, 'first_history_changed'): recovery.histories()
        for name in ('operation.json', 'inspect/state.json', 'inspect/provenance.json', 'inspect/admission-material.json'):
            with self.subTest(name=name), self.fixture() as (_, _, _, _, objects):
                def drift_record(kind, labels, run):
                    if labels['session'] == 'e' * 32:
                        path = recovery.SECOND_WORK / name
                        path.write_bytes(path.read_bytes() + b' ')
                    return []
                objects.side_effect = drift_record
                with self.assertRaisesRegex(recovery.Refusal, 'second_history_changed'): recovery.histories()

    def test_second_drift_blocks_existing_new_binding_and_metadata_size_stays_bounded(self):
        with self.fixture() as (_, _, _, first, _):
            history = recovery.histories()
            directory = recovery.new_phase('inspect', self.source, history, first)
            recovery.save(directory / 'provenance.json', recovery.operation_read(self.source))
            path = recovery.SECOND_WORK / 'inspect/state.json'; state = json.loads(path.read_bytes())
            state['labels']['session'] = 'f' * 32; path.write_bytes(recovery.encode(state))
            with patch.object(recovery, 'account') as account:
                with self.assertRaisesRegex(recovery.Refusal, 'operation_binding'):
                    recovery.bound_account(Mock(), 0, self.source, 'inspect')
                account.assert_not_called()
            fd = os.open(recovery.WORK, recovery.NOFOLLOW_DIR)
            try:
                history['second']['unexpected'] = 'x' * 16384
                with self.assertRaisesRegex(recovery.Refusal, 'operation_metadata_size'):
                    recovery.operation_document(self.source, history, first, fd)
            finally: os.close(fd)


class OperationBindingTests(unittest.TestCase):
    source = 'c' * 40

    @contextmanager
    def fixture(self):
        with HistoryBindingTests().fixture() as fixture: yield fixture

    def test_exact_settled_predecessor_and_immutable_new_operation(self):
        with self.fixture() as (scene, phase, state, first, objects):
            old = {p.name: p.read_bytes() for p in phase.iterdir()}
            prior = recovery.histories()
            self.assertEqual(prior['first']['state_sha256'], recovery.sha(old['state.json']))
            self.assertEqual(prior['first']['labels'], state['labels'])
            directory = recovery.new_phase('inspect', self.source, prior, first)
            self.assertEqual(directory, scene / 'recovery-a-py314-static-v1/inspect')
            operation = recovery.WORK / 'operation.json'; original = operation.read_bytes()
            binding = recovery.operation_read(self.source)
            recovery.save(directory / 'provenance.json', binding)
            self.assertEqual(recovery.phase_binding('inspect', self.source), binding)
            with self.assertRaises(FileExistsError): recovery.new_phase('inspect', self.source, prior, first)
            restored = recovery.new_phase('restore-traversal', self.source)
            self.assertTrue(restored.is_dir())
            with self.assertRaises(FileExistsError): recovery.new_phase('restore-traversal', self.source)
            self.assertEqual(operation.read_bytes(), original)
            self.assertEqual({p.name: p.read_bytes() for p in phase.iterdir()}, old)
            self.assertEqual(json.loads(original)['admission']['prospective_helper_growth'], 736000000)
            self.assertFalse(json.loads(original)['released'])
            self.assertTrue(all(call.args[1] in [item['labels'] for item in prior.values()]
                                for call in objects.call_args_list))
            self.assertEqual(binding['history_sha256'], recovery.sha(recovery.encode(prior)))
            self.assertNotIn('predecessor_state_sha256', binding)

    def test_predecessor_mismatch_pending_shape_and_objects_refuse_without_writes(self):
        cases = ({'source': 'a' * 40}, {'helper_sha256': 'a' * 64}, {'success': True},
                 {'step': 'import-pending', 'settled': False}, {'step': 'create-pending', 'settled': False,
                                                               'image': CleanupStateTests.image},
                 {'image': CleanupStateTests.image, 'cid': CleanupStateTests.cid},
                 {'reserved_bytes': 0}, {'released': True}, {'helper_envelope_bytes': 0},
                 {'labels': {}}, 'extra-file', 'extra-phase', 'record-link', 'record-mode', 'objects', 'admission')
        for change in cases:
            with self.subTest(change=change), self.fixture() as (_, phase, state, first, objects):
                if type(change) is dict: (phase / 'state.json').write_bytes(recovery.encode({**state, **change}))
                if change == 'extra-file': (phase / 'result.json').write_bytes(b'not an inventory')
                if change == 'extra-phase': (phase.parent / 'restore-traversal').mkdir()
                if change == 'record-link': os.link(phase / 'state.json', phase / 'second')
                if change == 'record-mode': (phase / 'state.json').chmod(0o644)
                if change == 'objects': objects.return_value = ['unexpected']
                if change == 'admission':
                    (phase / 'admission-material.json').write_bytes(recovery.encode({**first, 'prospective_helper_growth': 0}))
                before = (phase / 'state.json').read_bytes()
                with self.assertRaises(recovery.Refusal): recovery.predecessor()
                self.assertEqual((phase / 'state.json').read_bytes(), before)
                self.assertFalse(recovery.WORK.exists())

    def test_predecessor_and_operation_drift_block_later_phase_admission(self):
        for change in ('predecessor', 'operation', 'replace-operation', 'provenance', 'source'):
            with self.subTest(change=change), self.fixture() as (_, phase, state, first, _):
                directory = recovery.new_phase('inspect', self.source, recovery.histories(), first)
                recovery.save(directory / 'provenance.json', recovery.operation_read(self.source))
                if change == 'predecessor':
                    state['labels']['session'] = 'e' * 32
                    (phase / 'state.json').write_bytes(recovery.encode(state))
                if change == 'operation':
                    path = recovery.WORK / 'operation.json'; value = json.loads(path.read_bytes())
                    value['material_policy'] = 'unknown'; path.write_bytes(recovery.encode(value))
                if change == 'replace-operation':
                    path = recovery.WORK / 'operation.json'; body = path.read_bytes()
                    path.rename(recovery.WORK / 'retained'); path.write_bytes(body); path.chmod(0o600)
                if change == 'provenance': (directory / 'provenance.json').write_bytes(b'{}\n')
                with patch.object(recovery, 'account') as account:
                    with self.assertRaises(recovery.Refusal):
                        recovery.bound_account(Mock(), 0, 'd' * 40 if change == 'source' else self.source, 'inspect')
                    account.assert_not_called()

    def test_metadata_read_pins_the_same_inode_observed_before_open(self):
        with self.fixture() as (_, phase, _, _, _):
            parent = os.open(phase, recovery.NOFOLLOW_DIR)
            original = os.open
            def replaced(name, *args, **kwargs):
                if name == 'state.json' and kwargs.get('dir_fd') == parent:
                    (phase / 'state.json').rename(phase / 'retained-state')
                    (phase / 'state.json').write_bytes(b'{}\n'); (phase / 'state.json').chmod(0o600)
                return original(name, *args, **kwargs)
            try:
                with patch.object(recovery.os, 'open', side_effect=replaced):
                    with self.assertRaises(recovery.Refusal): recovery.private_snapshot(parent, 'state.json')
            finally: os.close(parent)

    def test_each_bound_transition_recounts_rest_images_other_charges_and_full_envelope(self):
        with self.fixture() as (scene, _, _, first, _):
            directory = recovery.new_phase('inspect', self.source, recovery.histories(), first)
            recovery.save(directory / 'provenance.json', recovery.operation_read(self.source))
            live = scene / 'live'; live.mkdir(); (live / 'opaque').write_bytes(b'opaque fixture')
            anchor = (live.stat().st_dev, live.stat().st_ino)
            # Use the real rest walker on only this fixture tree; keep the
            # original fixed scene tuple in both historical documents unchanged.
            walk = recovery.project_rest
            package = scene / 'public-recovery-package-v1'; package.mkdir()
            (package / 'image.tar').write_bytes(bytes(8192))
            def rest(root, omitted, fixed_anchor):
                self.assertEqual(fixed_anchor, recovery.helper.ANCHOR)
                return walk(root, omitted, anchor)
            with patch.object(recovery, 'ROOT', scene), patch.object(recovery, 'LIVE', live), \
                 patch.object(recovery, 'project_rest', side_effect=rest), \
                 patch.object(recovery, 'current_charges', return_value=6000000000), \
                 patch.object(recovery, 'image_charge', side_effect=[0, 100000000, 200000000, 300000000]):
                previous = 0
                for number in range(4):
                    (directory / ('growth-' + str(number))).write_bytes(bytes(4096))
                    value = recovery.bound_account(Mock(), 100000000, self.source, 'inspect')
                    expected = walk(scene, live, anchor)
                    self.assertEqual(value['rest_allocated_bytes'], expected)
                    self.assertGreater(expected, previous); previous = expected
                    self.assertEqual(value['disk_bytes'], expected + 6000000000 + number * 100000000 + 736000000)
                    self.assertEqual(value['resident_bytes'], 1356000000)
                    self.assertFalse(value['ordinary_guard_pass'])

    def test_initial_phase_cannot_reuse_an_existing_operation_root(self):
        with tempfile.TemporaryDirectory(prefix='warden-operation-fixture-') as d:
            scene = Path(d); work = scene / 'recovery-a'; work.mkdir(mode=0o700)
            def private(path): return os.open(path, recovery.NOFOLLOW_DIR)
            with patch.object(recovery, 'SCENE', scene), patch.object(recovery, 'WORK', work), \
                 patch.object(recovery, 'private_directory', side_effect=private):
                with self.assertRaises(FileExistsError): recovery.new_phase('inspect')
            self.assertEqual(list(work.iterdir()), [])


class WorkflowTests(unittest.TestCase):
    def test_failed_helper_preserves_only_bounded_typed_refusal_evidence(self):
        reason = b'{"kind":"recovery-refused","error_type":"Refusal","reason":"scene_schema","charge_released":false}\n'
        with patch.object(recovery, 'bounded_command', return_value=(1, b'', reason)), \
             patch.object(recovery, 'save') as save:
            with self.assertRaises(recovery.Refusal): recovery.run_helper('a' * 64, recovery.WORK / 'inspect')
            self.assertEqual(save.call_args.args[1]['helper_refusal']['reason'], 'scene_schema')
            self.assertFalse(save.call_args.args[1]['released'])
        with patch.object(recovery, 'bounded_command', return_value=(1, b'private fixture', b'arbitrary loader text')), \
             patch.object(recovery, 'save') as save:
            with self.assertRaises(recovery.Refusal): recovery.run_helper('a' * 64, recovery.WORK / 'inspect')
            value = save.call_args.args[1]
            self.assertIsNone(value['helper_refusal'])
            self.assertNotIn('private fixture', str(value)); self.assertNotIn('loader text', str(value))

    def test_ordinary_postflight_includes_original_charge_and_never_repairs_it(self):
        import azure_guard
        scene = Mock()
        def guard(additional, memory, download):
            self.assertEqual((additional, memory, download), (5100000000, 1000000000, 0))
            print('{"event":"local-preflight","fixture":true}')
        baseline = {'vm/overcommit_memory': '1', 'vm/panic_on_oom': '0', 'kernel/panic': '10',
                    'kernel/panic_on_oops': '1', 'kernel/keys/root_maxkeys': '1000000',
                    'kernel/keys/root_maxbytes': '25000000'}
        with patch.object(recovery, 'restored_metadata') as metadata, \
             patch.object(recovery, 'scoped_ids', return_value=[]), \
             patch.object(recovery, 'current_charges', return_value=5000000000), \
             patch.object(recovery, 'image_charge', return_value=100000000), \
             patch.object(azure_guard, 'preflight', side_effect=guard), \
             patch.object(recovery.helper, 'fixed_read', side_effect=lambda p, n: baseline[p.removeprefix('/proc/sys/')].encode()):
            result = recovery.full_postflight(scene, 0, {'entries': {}})
            self.assertFalse(result['released']); self.assertTrue(result['never_reopen'])
            self.assertEqual(scene.check.call_args_list, [unittest.mock.call(1000), unittest.mock.call(1000)])
            metadata.assert_called_once_with({})

    def test_restore_receipt_cannot_release_charge_or_claim_retirement(self):
        inventory = {'digest': 'd' * 64}
        value = {'kind': 'physical-traversal-restored-v1', 'source': recovery.helper.SOURCE,
                 'anchor': list(recovery.helper.ANCHOR), 'inventory_digest': inventory['digest'],
                 'helper_sha256': 'a' * 64, 'original_owner_retirement': 'cleanup_pending',
                 'creation_outcome': 'unknown', 'never_reopen': True,
                 'reserved_bytes': 5000000000, 'released': False}
        try:
            self.assertEqual(recovery.validate_result('restore-traversal', recovery.encode(value), 'a' * 64, inventory), value)
        except ValueError as error: self.fail('physical-only receipt refused: ' + str(error))
        for key, change in [('released', True), ('reserved_bytes', 0), ('creation_outcome', 'known'),
                            ('original_owner_retirement', 'retired'), ('never_reopen', False),
                            ('inventory_digest', 'b' * 64)]:
            bad = dict(value); bad[key] = change
            with self.subTest(key=key), self.assertRaises(ValueError):
                recovery.validate_result('restore-traversal', recovery.encode(bad), 'a' * 64, inventory)

    def test_restore_requires_this_new_operations_successful_inventory(self):
        with HistoryBindingTests().fixture() as (_, _, _, first, _):
            source = HistoryBindingTests.source
            directory = recovery.new_phase('inspect', source, recovery.histories(), first)
            recovery.save(directory / 'provenance.json', recovery.operation_read(source))
            state = CleanupStateTests().state('objects-settled', settled=True)
            state.update(source=source, helper_sha256=recovery.PREDECESSOR_HELPER)
            recovery.save(directory / 'state.json', state)
            with patch.object(recovery, 'account') as account, \
                 patch.object(recovery.helper, 'validate_inventory') as inventory:
                with self.assertRaisesRegex(recovery.Refusal, 'inspect_not_complete'):
                    recovery.execute_phase(Mock(), 'restore-traversal', 0, source)
                account.assert_not_called(); inventory.assert_not_called()
            self.assertFalse((recovery.WORK / 'restore-traversal').exists())

    def test_lost_create_response_keeps_durable_labels_envelope_charge_and_histories(self):
        events = []; image = 'sha256:' + 'a' * 64
        def docker(args, **kwargs):
            events.append(args[:2])
            if args[:2] == ['image', 'import']: return image + '\n'
            if args[:2] == ['container', 'create']:
                state = json.loads((recovery.WORK / 'inspect/state.json').read_bytes())
                self.assertEqual(state['step'], 'create-pending')
                self.assertEqual(state['image'], image)
                self.assertEqual(state['reserved_bytes'], 5000000000)
                self.assertEqual(state['helper_envelope_bytes'], 736000000)
                self.assertFalse(state['settled']); self.assertFalse(state['released'])
                raise TimeoutError('fixture lost create response')
            raise AssertionError(args)
        package = {'helper_sha256': recovery.PREDECESSOR_HELPER, 'archive_sha256': 'd' * 64, 'archive_bytes': 100}
        with HistoryBindingTests().fixture() as (_, _, _, first, _), ExitStack() as stack:
            old = HistoryBindingTests.old_records()
            for name, replacement in {
                'account': Mock(return_value=first),
                'runtime_inputs': Mock(side_effect=lambda: contextmanager(lambda: iter([{}]))()),
                'build_archive': Mock(return_value=package),
                'docker': Mock(side_effect=docker), 'check_image': Mock(),
                'cleanup_phase': Mock(), 'check_archive': Mock(),
            }.items(): stack.enter_context(patch.object(recovery, name, replacement))
            with self.assertRaises(TimeoutError): recovery.execute_phase(Mock(), 'inspect', 0, HistoryBindingTests.source)
            state = json.loads((recovery.WORK / 'inspect/state.json').read_bytes())
            self.assertEqual(state['step'], 'create-pending')
            self.assertIsNone(state['cid']); self.assertFalse(state['settled'])
            recovery.cleanup_phase.assert_not_called()
            self.assertEqual(events, [['image', 'import'], ['container', 'create']])
            self.assertEqual(recovery.account.call_count, 4)  # operation, material, import, create
            self.assertEqual(HistoryBindingTests.old_records(), old)


if __name__ == '__main__': unittest.main()
