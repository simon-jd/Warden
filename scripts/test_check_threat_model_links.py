#!/usr/bin/env python3
"""Finite behavior checks using only tiny disposable /tmp fixtures."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("task17_links", Path(__file__).with_name("check_threat_model_links.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class LinkBehavior(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="warden-task17-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        (self.root / "docs").mkdir(parents=True)
        (self.root / "docs/target.md").write_text("# Valid heading\n# Valid heading\n# 中文\n", encoding="utf-8")

    def check(self, body):
        (self.root / "docs/source.md").write_text(body, encoding="utf-8")
        return checker.check_files(self.root, ["docs/source.md"])

    def test_valid_files_fragments_references_and_fenced_example(self):
        errors, count = self.check('[ok](target.md#valid-heading)\n[dup](target.md#valid-heading-1)\n[encoded](target.md#%E4%B8%AD%E6%96%87)\n[ref]: target.md\n[web](https://example.invalid/missing)\n```\n[example](missing.md)\n```\n')
        self.assertEqual(errors, [])
        self.assertEqual(count, 4)

    def test_missing_target_and_fragment_have_source_line(self):
        errors, _ = self.check('[gone](missing.md)\n[bad](target.md#absent)\n')
        self.assertEqual(len(errors), 2)
        self.assertTrue(errors[0].startswith('docs/source.md:1: missing.md:'))
        self.assertIn('docs/source.md:2: target.md#absent: missing heading', errors[1])

    def test_escape_absolute_private_and_uri_rejected(self):
        for target in ('../../secret.md', '%2e%2e/%2e%2e/secret.md', '/etc/passwd', '../.cache/secret', 'file:///etc/passwd', '//example.invalid/file'):
            with self.subTest(target=target):
                errors, _ = self.check(f'[bad]({target})\n')
                self.assertEqual(len(errors), 1)

    def test_symlink_file_and_directory_escape_rejected(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "secret.md").write_text("secret", encoding="utf-8")
        (self.root / "docs/alias.md").symlink_to(outside / "secret.md")
        (self.root / "docs/alias-dir").symlink_to(outside, target_is_directory=True)
        errors, _ = self.check('[file](alias.md)\n[dir](alias-dir/secret.md)\n')
        self.assertEqual(len(errors), 2)
        self.assertTrue(all('symlink' in error for error in errors))

    def test_unreadable_source_nonfile_and_nonmarkdown_fragment_fail(self):
        errors, _ = checker.check_files(self.root, ['docs/absent.md'])
        self.assertEqual(len(errors), 1)
        (self.root / 'docs/test.py').write_text('# Not a heading', encoding='utf-8')
        errors, _ = self.check('[dir](.)\n[fragment](test.py#not-a-heading)\n')
        self.assertEqual(len(errors), 2)


if __name__ == '__main__':
    checker.limit_resources()
    unittest.main(verbosity=2)
