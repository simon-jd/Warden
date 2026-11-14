#!/usr/bin/env python3
import importlib.util
import unittest
from unittest.mock import patch
import subprocess

SPEC = importlib.util.find_spec('runtime_lab_docker_init')
if SPEC:
    import runtime_lab_docker_init as init

class PrivateCgroupTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(SPEC, 'private cgroup bootstrap is missing')
        self.context = dict(pid=1, uid=0, host_ns='cgroup:[10]', current_ns='cgroup:[20]', membership='0::/\n', mount_root='/', memory='4000000000', pids='512', cpu='200000 100000')
    def test_wrong_runtime_version_refuses_smoke(self):
        with patch('runtime_lab_docker_init.system_binary', return_value='/usr/bin/runc'):
            with patch('runtime_lab_docker_init.subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'runc version 9.9.9')):
                with self.assertRaisesRegex(ValueError, 'version'):
                    init.smoke()

    def test_private_bounded_root_accepted(self):
        init.validate_context(**self.context)
    def test_host_namespace_nonroot_membership_and_excess_limits_reject(self):
        for key, value in [('pid', 3), ('uid', 1000), ('host_ns', 'cgroup:[20]'), ('host_ns', ''), ('membership', '0::/system.slice/docker.scope\n'), ('mount_root', '/system.slice'), ('memory', 'max'), ('memory', '4000000001'), ('pids', 'max'), ('pids', '513'), ('cpu', 'max 100000'), ('cpu', '200001 100000')]:
            with self.subTest(key=key, value=value):
                args = {**self.context, key: value}
                with self.assertRaises(ValueError):
                    init.validate_context(**args)

if __name__ == '__main__':
    unittest.main(verbosity=2)
