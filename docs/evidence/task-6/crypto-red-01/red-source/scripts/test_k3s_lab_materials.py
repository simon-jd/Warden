"""Material ingestion rejects substituted, ambiguous and executable archive metadata."""
import hashlib
import importlib.util
import io
import tarfile
import unittest

SPEC = importlib.util.find_spec('k3s_lab_materials')
if SPEC:
    import k3s_lab_materials as materials


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as tar:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(data)
            elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = data
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return out.getvalue()


class MaterialsTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(SPEC, 'verified material ingestion is not implemented')

    def test_wrong_length_or_digest_cannot_be_used(self):
        pin = {'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}
        self.assertEqual(materials.verify(b'abc', pin), b'abc')
        for data in (b'ab', b'abcd', b'xyz'):
            with self.assertRaises(ValueError):
                materials.verify(data, pin)

    def test_tar_returns_regular_bytes_without_extracting_links(self):
        data = archive([('./bin/tool', b'ok', tarfile.REGTYPE),
                        ('./bin/alias', 'tool', tarfile.SYMTYPE)])
        self.assertEqual(materials.regular_files(data), {'bin/tool': b'ok'})

    def test_internal_parent_alias_is_checked_but_never_installed(self):
        data = archive([('bin/tool', b'ok', tarfile.REGTYPE),
                        ('bin/aux/alias', '../tool', tarfile.SYMTYPE)])
        self.assertEqual(materials.regular_files(data), {'bin/tool': b'ok'})

    def test_unsafe_paths_aliases_devices_duplicates_and_oversize_fail(self):
        cases = [
            [('a/../escape', b'x', tarfile.REGTYPE)],
            [('/absolute', b'x', tarfile.REGTYPE)],
            [('a', '/etc/shadow', tarfile.SYMTYPE)],
            [('a', '../escape', tarfile.SYMTYPE)],
            [('a', 'missing', tarfile.SYMTYPE)],
            [('a', b'', tarfile.CHRTYPE)],
            [('a', b'x', tarfile.REGTYPE), ('./a', b'y', tarfile.REGTYPE)],
            [('a', b'0123456789', tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                materials.regular_files(archive(entries), limit=8)

    def test_embedded_zstd_requires_digest_named_frame_and_safe_tar(self):
        from compression import zstd
        raw = archive([('bin/k3s', b'ELF', tarfile.REGTYPE)])
        frame = zstd.compress(raw)
        digest = hashlib.sha256(frame).hexdigest().encode()
        binary = b'\x7fELFgarbage' + digest + b'.tar.zstmore' + frame + b'trailer'
        self.assertEqual(materials.embedded_k3s(binary), {'bin/k3s': b'ELF'})
        with self.assertRaises(ValueError):
            materials.embedded_k3s(binary.replace(digest, b'0' * 64))


if __name__ == '__main__':
    unittest.main()
