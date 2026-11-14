"""Exercise packaged corpus validation without a container daemon."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import runtime_lab_docker as docker_lab

class CorpusPackagingTests(unittest.TestCase):
    def test_corpus_members_are_bounded_regular_files(self):
        self.assertTrue(hasattr(docker_lab, 'corpus_files'), 'corpus packaging is missing')
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temporary:
            root = Path(temporary)
            corpus = root / 'attacks/corpus'
            entry = corpus / 'ptrace'
            entry.mkdir(parents=True)
            for directory in (root, root / 'attacks', corpus, entry):
                directory.chmod(0o700)
            (entry / 'run.sh').write_text('exec /warden-attack ptrace')
            (entry / 'expect.yaml').write_text('id: ptrace\n')
            (corpus / 'README.md').write_text('corpus documentation')
            (entry / 'run.sh').chmod(0o644)
            (entry / 'expect.yaml').chmod(0o644)
            files = docker_lab.corpus_files(root)
            self.assertEqual(files['corpus/ptrace/run.sh'], b'exec /warden-attack ptrace')
            (entry / 'run.sh').unlink()
            (entry / 'run.sh').symlink_to('/etc/passwd')
            with self.assertRaises((ValueError, OSError)):
                docker_lab.corpus_files(root)

    def test_matrix_mode_retains_run_bounds(self):
        import test_runtime_lab_docker as existing
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temporary:
            cli = existing.FakeDocker()
            with patch.object(docker_lab.os, 'readlink', return_value='cgroup:[123]'):
                docker_lab.execute(existing.IMAGE, Path(temporary), existing.LABELS, 'matrix', cli)
            create = next(c for c in cli.calls if c[:2] == ['container', 'create'])
            self.assertIn('--memory=4000000000', create)
            self.assertIn('--pids-limit=512', create)
            self.assertIn('--network=none', create)
            self.assertIn('--cap-add=SYS_ADMIN', create)
            self.assertEqual(create[-1], 'matrix')

class MatrixCleanupTests(unittest.TestCase):
    def test_confirmed_matrix_image_cleanup_releases_charge(self):
        import json
        import test_runtime_lab_docker as existing
        container = existing.FakeDocker()
        exists = False
        def cli(args, **kwargs):
            nonlocal exists
            if args[:2] == ['image', 'import']:
                exists = True
                return existing.IMAGE
            if args[:2] == ['image', 'inspect']:
                return json.dumps([{'Id': existing.IMAGE, 'Config': {'Labels': existing.LABELS}}])
            if args[:2] == ['image', 'rm']:
                exists = False
                return existing.IMAGE
            if args[:2] == ['image', 'ls']:
                return existing.IMAGE if exists else ''
            return container(args, **kwargs)
        with tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve())) as temporary:
            output = Path(temporary)
            with patch.object(docker_lab.os, 'readlink', return_value='cgroup:[123]'):
                docker_lab.image_session(output / 'archive.tar', output, existing.LABELS, 'matrix', cli)
            self.assertTrue(json.loads((output / 'charge.json').read_text())['released'])

class FirecrackerPayloadTests(unittest.TestCase):
    def test_payload_layer_contains_real_shell_helper_and_probe(self):
        import firecracker_lab
        import io
        import tarfile
        self.assertTrue(hasattr(firecracker_lab, 'payload_layer'), 'enriched payload layer is missing')
        raw = firecracker_lab.payload_layer(b'probe', {'bin/sh': b'shell', 'warden-attack': b'attack', 'lib64/loader': b'loader'})
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            self.assertEqual(tar.extractfile('bin/sh').read(), b'shell')
            self.assertEqual(tar.extractfile('warden-attack').read(), b'attack')
            self.assertEqual(tar.extractfile('warden-probe').read(), b'probe')
            self.assertEqual(tar.getmember('bin/sh').mode, 0o555)
            self.assertTrue(tar.getmember('bin').isdir())
