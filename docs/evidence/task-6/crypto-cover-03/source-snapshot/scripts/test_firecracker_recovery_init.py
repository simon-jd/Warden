"""Native fixtures only: no container, mount, chown, private scene or VM access."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import firecracker_recovery_init as recovery

RUN = '7J2G4KCYZWPQ3B53EV4TR2RXAI'
DIRECTORIES = ('.', 'node', 'node/gate', 'node/uids', 'node/runs',
               'node/assets', 'node/snapshots', 'jails', 'jails/firecracker')
FILES = {'node/owner': 48, 'node/gate/node': 118,
         'node/gate/admission': 0, 'node/gate/retirement': 0,
         'node/gate/admission-sealed': 63, 'node/gate/' + RUN: 18,
         'node/uids/lock': 0, 'node/uids/state': 85,
         'node/uids/' + RUN: 54, 'node/runs/' + RUN: 300,
         'node/assets/kernel': 27893008, 'node/assets/agent.ext4': 33554432,
         'node/assets/payload.ext4': 33554432}


class InventoryFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='warden-recovery-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in DIRECTORIES[1:]:
            (self.root / name).mkdir(mode=0o700)
        for name, size in FILES.items():
            with (self.root / name).open('wb') as f:
                f.truncate(size)  # sparse fixture, not an actual material copy
            (self.root / name).chmod(0o444 if '/assets/' in name else 0o600)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.owner = patch.object(recovery, 'OWNER', os.getuid(), create=True)
        self.group = patch.object(recovery, 'GROUP', os.getgid(), create=True)
        self.owner.start(); self.group.start()
        self.addCleanup(self.owner.stop); self.addCleanup(self.group.stop)
        anchor = os.fstat(self.fd)
        self.anchor = patch.object(recovery, 'ANCHOR', (anchor.st_dev, anchor.st_ino))
        self.anchor.start(); self.addCleanup(self.anchor.stop)

    def collect(self):
        return recovery.collect(self.fd)

    def test_inventory_is_metadata_only_and_keeps_held_nofollow_descriptors(self):
        # A file read, missing schema member, or unclosed FD must break this.
        try:
            held = self.collect()
        except ValueError as error:
            self.fail('valid closed fixture refused: ' + str(error))
        with held:
            self.assertEqual(set(held.entries), set(DIRECTORIES) | set(FILES))
            self.assertEqual(len(held.entries), 22)
            for name in FILES:
                self.assertEqual(held.entries[name]['size'], FILES[name])
                self.assertEqual(os.readlink('/proc/self/fd/' + str(held.fds[name])),
                                 str(self.root / name))
                with self.assertRaises(OSError): os.read(held.fds[name], 1)
            saved = list(held.fds.values())
        for fd in saved:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_host_post_restore_check_preserves_files_and_rejects_owner_mode_drift(self):
        import firecracker_recovery as host
        with self.collect() as held: expected = held.entries
        with patch.object(host, 'LIVE', self.root):
            host.restored_metadata(expected)
            (self.root / 'node/owner').chmod(0o644)
            with self.assertRaises(ValueError): host.restored_metadata(expected)
            (self.root / 'node/owner').chmod(0o600)
            (self.root / 'node/snapshots/extra').write_text('fixture')
            with self.assertRaises(ValueError): host.restored_metadata(expected)

    def test_inventory_refuses_unknown_alias_link_and_nonempty_jail(self):
        mutations = ('extra', 'symlink', 'hardlink', 'jail', 'mode', 'size', 'missing')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                p = self.root / 'node/owner'
                if mutation == 'extra': (self.root / 'unknown').touch()
                elif mutation == 'symlink': p.rename(self.root / 'saved'); p.symlink_to('../saved')
                elif mutation == 'hardlink': os.link(p, self.root / 'alias')
                elif mutation == 'jail': (self.root / 'jails/firecracker' / ('warden-' + RUN)).mkdir()
                elif mutation == 'mode': p.chmod(0o644)
                elif mutation == 'size': p.write_bytes(b'x' * 65537)
                elif mutation == 'missing': p.rename(self.root / 'saved')
                with self.assertRaises((ValueError, OSError)): self.collect()
                if mutation == 'extra': (self.root / 'unknown').unlink()
                elif mutation == 'symlink': p.unlink(); (self.root / 'saved').rename(p)
                elif mutation == 'hardlink': (self.root / 'alias').unlink()
                elif mutation == 'jail': (self.root / 'jails/firecracker' / ('warden-' + RUN)).rmdir()
                elif mutation == 'mode': p.chmod(0o600)
                elif mutation == 'size': p.write_bytes(b'\0' * 48)
                elif mutation == 'missing': (self.root / 'saved').rename(p)

    def test_replacement_after_inventory_refuses_before_any_mutation(self):
        with self.collect() as held:
            expected = copy.deepcopy(held.entries)
            old = self.root / 'node/owner'
            old.rename(self.root / 'saved')
            old.write_bytes(b'x' * 48); old.chmod(0o600)
            calls = []
            with patch.object(recovery.os, 'fchown', side_effect=lambda *args: calls.append(args)):
                with self.assertRaises(ValueError):
                    recovery.restore(held, expected, lambda writable: calls.append(writable))
            self.assertEqual(calls, [])

    def test_restore_changes_only_directory_fds_deepest_first_and_preserves_files(self):
        # Chown is an explicitly mocked privileged syscall; FD/type/order are real.
        with self.collect() as held:
            expected = copy.deepcopy(held.entries)
            calls = []
            names = {fd: name for name, fd in held.fds.items()}
            def chown(fd, uid, gid):
                self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
                self.assertEqual((uid, gid), (1000, 1000))
                calls.append(names[fd])
            with patch.object(recovery.os, 'fchown', side_effect=chown), \
                 patch.object(recovery, 'TARGET', os.getuid(), create=True), \
                 patch.object(recovery, 'TARGET_GROUP', os.getgid(), create=True):
                try:
                    recovery.restore(held, expected, lambda rw: calls.append('rw' if rw else 'ro'))
                except ValueError as error: self.fail('valid restoration refused: ' + str(error))
            self.assertEqual(calls[0], 'rw')
            self.assertEqual(calls[-2:], ['.', 'ro'])
            self.assertEqual(set(calls[1:-1]), set(DIRECTORIES))
            for name in FILES:
                self.assertEqual(recovery.metadata(os.fstat(held.fds[name])), expected[name])

    def test_restore_failure_is_incomplete_and_attempts_readonly_remount(self):
        with self.collect() as held:
            calls = []
            def chown(fd, uid, gid):
                calls.append('chown')
                raise OSError('fixture denial')
            with patch.object(recovery.os, 'fchown', side_effect=chown):
                with self.assertRaises(OSError):
                    recovery.restore(held, held.entries, lambda rw: calls.append(rw))
            self.assertEqual(calls, [True, 'chown', False])

    def test_immutable_inventory_ingress_binds_source_helper_and_digest(self):
        with self.collect() as held:
            body = {'version': 1, 'source': '95fa55dc0ce97d3e1b99a255a84f80e96972c71f',
                    'helper_sha256': 'a' * 64, 'anchor': list(recovery.ANCHOR),
                    'entries': held.entries,
                    'allocated_bytes': sum(x['blocks'] * 512 for x in held.entries.values())}
            body['digest'] = hashlib.sha256(recovery.encode(body)).hexdigest()
            raw = recovery.encode(body)
            try: value = recovery.validate_inventory(raw, 'a' * 64)
            except ValueError as error: self.fail('valid inventory ingress refused: ' + str(error))
            self.assertEqual(value['entries'], held.entries)
            for key, changed in [('source', '0' * 40), ('helper_sha256', 'b' * 64),
                                 ('anchor', [1, 2]), ('digest', '0' * 64), ('version', True),
                                 ('allocated_bytes', body['allocated_bytes'] + 1)]:
                bad = copy.deepcopy(body); bad[key] = changed
                with self.subTest(key=key), self.assertRaises(ValueError):
                    recovery.validate_inventory(recovery.encode(bad), 'a' * 64)
            with self.assertRaises(ValueError): recovery.validate_inventory(raw + b'{}', 'a' * 64)

    def test_restore_package_embeds_exact_inventory_as_fixed_immutable_file(self):
        import firecracker_recovery as host
        import tarfile
        with self.collect() as held, tempfile.TemporaryDirectory(prefix='warden-ingress-fixture-') as d:
            root = Path(d)
            interpreter = root / 'python'; interpreter.write_bytes(b'fixture'); interpreter.chmod(0o555)
            module = root / 'helper.py'; module.write_bytes(b'# fixture\n'); module.chmod(0o644)
            body = {'version': 1, 'source': recovery.SOURCE, 'helper_sha256': host.file_sha(module),
                    'anchor': list(recovery.ANCHOR), 'entries': held.entries,
                    'allocated_bytes': sum(x['blocks'] * 512 for x in held.entries.values())}
            body['digest'] = hashlib.sha256(recovery.encode(body)).hexdigest()
            raw = recovery.encode(body)
            with patch.object(host, 'INPUT_UID', os.getuid()):
                package = host.build_archive(root / 'image.tar', {'usr/bin/python3': interpreter}, module, raw)
            with tarfile.open(root / 'image.tar') as archive:
                item = archive.getmember('expected-inventory.json')
                self.assertTrue(item.isfile()); self.assertEqual((item.uid, item.gid, item.mode), (0, 0, 0o444))
                self.assertEqual(archive.extractfile(item).read(), raw)
                self.assertEqual(package['expected_inventory_sha256'], hashlib.sha256(raw).hexdigest())


class MountTests(unittest.TestCase):
    def test_fixed_runtime_refuses_extra_caps_or_host_writable_proc(self):
        for mode, caps, seccomp in [('inspect', 0, 2), ('restore-traversal', 2097153, 0)]:
            status = ('CapInh:\t0000000000000000\nCapPrm:\t%016x\nCapEff:\t%016x\n'
                      'CapBnd:\t%016x\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t%d\n') % (caps, caps, caps, seccomp)
            mounts = '1 0 0:1 / / ro - overlay overlay ro\n2 1 0:2 /sys /proc/sys ro - proc proc rw\n'
            try: recovery.validate_runtime(mode, 1, 0, status, mounts)
            except ValueError as error: self.fail('fixed runtime refused: ' + str(error))
            for changed in (status.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'),
                            status.replace('CapAmb:\t0000000000000000', 'CapAmb:\t0000000000000001')):
                with self.assertRaises(ValueError): recovery.validate_runtime(mode, 1, 0, changed, mounts)
            with self.assertRaises(ValueError): recovery.validate_runtime(mode, 2, 0, status, mounts)
            with self.assertRaises(ValueError): recovery.validate_runtime(mode, 1, 0, status, mounts.replace('/proc/sys ro', '/proc/sys rw'))

    def test_only_initial_ro_private_matching_mount_is_accepted(self):
        meta = {'dev': os.makedev(259, 3), 'ino': 56377608, 'uid': 0, 'gid': 0,
                'mode': stat.S_IFDIR | 0o700}
        line = '42 29 259:3 /fixed/live /session ro,nosuid,nodev,relatime - ext4 /dev/fixed rw\n'
        try:
            mount_id, flags = recovery.verify_mount(line, meta, 'mnt:[12]', 'mnt:[13]', True)
        except ValueError as error: self.fail('valid private RO fixture refused: ' + str(error))
        self.assertEqual(mount_id, 42)
        self.assertEqual(flags, 2 | 4 | (1 << 21))
        for raw, host, current in ((line.replace('ro,', 'rw,'), 'mnt:[12]', 'mnt:[13]'),
                                  (line.replace(' - ', ' shared:4 - '), 'mnt:[12]', 'mnt:[13]'),
                                  (line + line, 'mnt:[12]', 'mnt:[13]'),
                                  (line + '43 42 0:3 / /session/hidden ro - tmpfs tmpfs rw\n', 'mnt:[12]', 'mnt:[13]'),
                                  (line, 'mnt:[12]', 'mnt:[12]')):
            with self.subTest(raw=raw, current=current), self.assertRaises(ValueError):
                recovery.verify_mount(raw, meta, host, current, True)


if __name__ == '__main__': unittest.main()
