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


if __name__ == '__main__':
    unittest.main()
