import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('stratus_emulate', Path(__file__).with_name('emulate.py'))
stratus = None
if spec and Path(spec.origin).exists():
    stratus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stratus)


class StratusTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(stratus, 'Stratus wrapper missing')

    def config(self):
        return {'current-context': 'kind-warden-lab',
                'contexts': [{'name': 'kind-warden-lab', 'context': {'cluster': 'kind-warden-lab', 'user': 'kind-warden-lab'}}],
                'clusters': [{'name': 'kind-warden-lab', 'cluster': {'server': 'https://127.0.0.1:6443', 'certificate-authority-data': 'abc'}}],
                'users': [{'name': 'kind-warden-lab', 'user': {'client-certificate-data': 'cert', 'client-key-data': 'key'}}]}

    def test_guard_refuses_remote_context_plugins_and_insecure_tls(self):
        stratus.guard_kubeconfig(self.config())
        for location, key, value in [('cluster', 'server', 'https://prod.example.com'),
                                     ('cluster', 'insecure-skip-tls-verify', True),
                                     ('cluster', 'proxy-url', 'http://127.0.0.1'),
                                     ('user', 'exec', {'command': 'anything'}),
                                     ('user', 'auth-provider', {'name': 'azure'})]:
            config = self.config()
            config['clusters' if location == 'cluster' else 'users'][0][location][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                stratus.guard_kubeconfig(config)
        config = self.config()
        config['current-context'] = 'production'
        with self.assertRaises(ValueError):
            stratus.guard_kubeconfig(config)

    def test_cloud_techniques_blocked_without_calling_tools(self):
        with self.assertRaisesRegex(ValueError, 'local-only'):
            stratus.validate_technique('azure.credential-access.app-service-publishing-credentials')
        with self.assertRaises(ValueError):
            stratus.validate_technique('aws.persistence.iam-create-admin-user')
        self.assertEqual(stratus.validate_technique('k8s.privilege-escalation.privileged-pod'), 'T1611')

    def test_cluster_inventory_must_be_dedicated_kind(self):
        nodes = {'items': [{'metadata': {'name': 'warden-lab-control-plane', 'labels': {'kubernetes.io/hostname': 'warden-lab-control-plane'}}}]}
        stratus.guard_nodes(nodes)
        nodes['items'][0]['metadata']['name'] = 'production-node'
        with self.assertRaises(ValueError):
            stratus.guard_nodes(nodes)

class StratusCLITests(unittest.TestCase):
    def test_cloud_plan_does_not_run_a_tool_and_execute_stays_blocked(self):
        import contextlib
        import io
        import json
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            result = stratus.main(['--plan', '--technique', stratus.AZURE, '--stratus', '/does/not/exist'])
        self.assertEqual(result, 0)
        self.assertFalse(json.loads(capture.getvalue())['execution_authorized'])
        with contextlib.redirect_stderr(io.StringIO()):
            result = stratus.main(['--technique', stratus.AZURE])
        self.assertEqual(result, 2)

    def test_pod_configuration_requires_pinned_image_and_labels_run(self):
        image = 'busybox@sha256:' + 'a' * 64
        config = stratus.pod_configuration(image, 'stratus-123')
        self.assertEqual(config['kubernetes']['default']['pod']['image'], image)
        self.assertEqual(config['kubernetes']['default']['pod']['labels']['warden_run_id'], 'stratus-123')
        with self.assertRaises(ValueError):
            stratus.pod_configuration('busybox:stable', 'stratus-123')


if __name__ == '__main__':
    unittest.main()
