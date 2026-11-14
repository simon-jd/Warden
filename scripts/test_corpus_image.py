import unittest
from pathlib import Path
import tempfile
from corpus_image import checked
class CorpusImageTest(unittest.TestCase):
 def test_rejects_changed_fixed_material(self):
  with self.assertRaisesRegex(ValueError,'changed'):
   checked(Path('/bin/sh'),4,'0'*64)
 def test_rejects_writable_material(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'shell';p.write_bytes(b'good');p.chmod(0o666)
   with self.assertRaisesRegex(ValueError,'unsafe'):
    checked(p)
