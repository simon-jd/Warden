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

    def test_namespace_must_be_owned_active_lab_namespace(self):
        namespace = {'metadata': {'name': 'warden-lab',
                                  'labels': {'project': 'warden', 'owner': 'warden-lab'}},
                     'status': {'phase': 'Active'}}
        stratus.guard_namespace(namespace)
        for field, value in (('name', 'default'), ('labels', {'project': 'other'})):
            changed = {'metadata': dict(namespace['metadata']), 'status': {'phase': 'Active'}}
            changed['metadata'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                stratus.guard_namespace(changed)
        namespace['status']['phase'] = 'Terminating'
        with self.assertRaises(ValueError):
            stratus.guard_namespace(namespace)

    def test_cloud_techniques_blocked_without_calling_tools(self):
        with self.assertRaisesRegex(ValueError, 'local-only'):
            stratus.validate_technique('azure.credential-access.app-service-publishing-credentials')
        with self.assertRaises(ValueError):
            stratus.validate_technique('aws.persistence.iam-create-admin-user')
        self.assertEqual(stratus.validate_technique('k8s.privilege-escalation.privileged-pod'), 'T1611')
        self.assertEqual(stratus.validate_technique('k8s.credential-access.steal-serviceaccount-token'), 'T1528')
        self.assertEqual(stratus.TECHNIQUES, {
            'k8s.credential-access.dump-secrets': 'T1552.007',
            'k8s.credential-access.steal-serviceaccount-token': 'T1528',
            'k8s.persistence.create-admin-clusterrole': 'T1098.006',
            'k8s.persistence.create-client-certificate': 'T1649',
            'k8s.persistence.create-token': 'T1098',
            'k8s.privilege-escalation.hostpath-volume': 'T1611',
            'k8s.privilege-escalation.nodes-proxy': 'T1609',
            'k8s.privilege-escalation.privileged-pod': 'T1611',
        })

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

    def test_all_kubernetes_plans_are_explicit_and_no_tools_run(self):
        import contextlib
        import io
        import json
        for technique in stratus.TECHNIQUES:
            output = io.StringIO()
            with self.subTest(technique=technique), contextlib.redirect_stdout(output):
                self.assertEqual(stratus.main(['--plan', '--technique', technique]), 0)
            plan = json.loads(output.getvalue())
            self.assertTrue(plan['execution_authorized'])
            self.assertEqual(plan['command'], ['stratus', 'detonate', technique, '--cleanup'])
            self.assertEqual(plan['target'], 'kind-warden-lab')

    def test_pod_configuration_requires_pinned_image_and_labels_run(self):
        image = 'busybox@sha256:' + 'a' * 64
        run = 'stratus-12345678-1234-4234-8234-123456789abc'
        config = stratus.pod_configuration(image, run)
        self.assertEqual(config['kubernetes']['default']['namespace'], 'warden-lab')
        self.assertEqual(config['kubernetes']['default']['pod']['image'], image)
        self.assertEqual(config['kubernetes']['default']['pod']['labels'],
                         {'project': 'warden', 'owner': 'warden-lab',
                          'warden.dev/run': run, 'warden_lab': 'warden-lab', 'warden_run_id': run})
        with self.assertRaises(ValueError):
            stratus.pod_configuration('busybox:stable', run)
        with self.assertRaises(ValueError):
            stratus.pod_configuration(image, 'stratus-123')

    def test_main_binds_run_to_namespace_and_redacts_token(self):
        import hashlib
        import json
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            binary = base / 'stratus'
            kubectl = base / 'kubectl'
            for path in (binary, kubectl):
                path.write_text('test')
                path.chmod(0o700)
            kubeconfig = base / 'kubeconfig.json'
            kubeconfig.write_text(json.dumps(StratusTests().config()))
            out = base / 'run'
            run = 'stratus-12345678-1234-4234-8234-123456789abc'
            seen = []
            token = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature'

            def invoke(argv, *, env=None, timeout=60, file_limit_bytes=None):
                seen.append((argv, dict(env), file_limit_bytes))
                if argv[0] == str(kubectl) and 'nodes' in argv:
                    return 0, json.dumps({'items': [{'metadata': {'name': 'warden-lab-control-plane'}}]})
                if argv[0] == str(kubectl) and 'namespace' in argv:
                    return 0, json.dumps({'metadata': {'name': 'warden-lab',
                                                        'labels': {'project': 'warden', 'owner': 'warden-lab'}},
                                          'status': {'phase': 'Active'}})
                if argv[0] == str(binary) and argv[1] == 'detonate':
                    config = json.loads(Path(env['STRATUS_CONFIG_PATH']).read_text())
                    self.assertEqual(config['kubernetes']['default']['pod']['labels']['warden.dev/run'], run)
                    self.assertEqual(env.get('KUBE_CONFIG_PATH'), env['KUBECONFIG'])
                    self.assertEqual(json.loads(Path(env['KUBE_CONFIG_PATH']).read_text()), StratusTests().config())
                    return 0, 'token=' + token
                if argv[0] == str(binary) and argv[1] == 'cleanup':
                    return 1, 'already COLD and should already be clean, use --force'
                self.fail('unexpected command: ' + repr(argv))

            with mock.patch.object(stratus, 'command', side_effect=invoke), \
                 mock.patch.object(stratus.uuid, 'uuid4', return_value=stratus.uuid.UUID('12345678-1234-4234-8234-123456789abc')):
                self.assertEqual(stratus.main([
                    '--technique', stratus.STEAL_SA_TOKEN, '--ack-dedicated-lab',
                    '--stratus', str(binary), '--stratus-sha256', hashlib.sha256(b'test').hexdigest(),
                    '--kubectl', str(kubectl), '--kubeconfig', str(kubeconfig),
                    '--pod-image', 'busybox@sha256:' + 'a' * 64, '--out', str(out)]), 0)
            self.assertEqual(len(seen), 3)
            self.assertTrue(all(env['STRATUS_RED_TEAM_CORRELATION_ID'] == run.removeprefix('stratus-') for _, env, _ in seen))
            self.assertTrue(all(kwargs == stratus.STRATUS_FILE_LIMIT for argv, _, kwargs in seen if argv[0] == str(binary)))
            receipt = (out / 'receipt.json').read_text()
            self.assertNotIn(token, receipt)
            self.assertEqual(json.loads(receipt)['run_id'], run)
            self.assertEqual(json.loads(receipt)['correlation_id'], run.removeprefix('stratus-'))
            self.assertEqual(json.loads(receipt)['cleanup_returncode'], 0)
            self.assertFalse(json.loads(receipt)['cleanup_invoked'])
            self.assertIsNone(json.loads(receipt)['cleanup_command_returncode'])
            self.assertEqual(json.loads(receipt)['cleanup_mode'], 'detonate --cleanup')
            self.assertEqual(json.loads((out / 'executions.jsonl').read_text())['technique_id'], 'T1528')

    def failed_detonation_with_status(self, state):
        import hashlib
        import json
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            binary = base / 'stratus'
            kubectl = base / 'kubectl'
            for path in (binary, kubectl):
                path.write_text('test')
                path.chmod(0o700)
            kubeconfig = base / 'kubeconfig.json'
            kubeconfig.write_text(json.dumps(StratusTests().config()))
            seen = []
            status_output = ('+--------------------------------------------------+---------------------------------+--------+\n'
                             '| ID                                               | NAME                            | STATUS |\n'
                             '+--------------------------------------------------+---------------------------------+--------+\n'
                             '| k8s.credential-access.steal-serviceaccount-token | Steal Pod Service Account Token | '
                             + state.ljust(6) + ' |\n'
                             '+--------------------------------------------------+---------------------------------+--------+\n')

            def invoke(argv, *, env=None, timeout=60, file_limit_bytes=None):
                seen.append((argv, dict(env)))
                if argv[0] == str(kubectl) and 'nodes' in argv:
                    return 0, json.dumps({'items': [{'metadata': {'name': 'warden-lab-control-plane'}}]})
                if argv[0] == str(kubectl) and 'namespace' in argv:
                    return 0, json.dumps({'metadata': {'name': 'warden-lab',
                                                        'labels': {'project': 'warden', 'owner': 'warden-lab'}},
                                          'status': {'phase': 'Active'}})
                if argv[0] == str(binary) and argv[1] == 'detonate':
                    return 1, 'token=private-value; detonation failed'
                if argv[0] == str(binary) and argv[1] == 'status':
                    return 0, status_output
                if argv[0] == str(binary) and argv[1] == 'cleanup':
                    return 0, 'fallback cleanup complete'
                self.fail('unexpected command: ' + repr(argv))

            out = base / 'run'
            with mock.patch.object(stratus, 'command', side_effect=invoke):
                result = stratus.main([
                    '--technique', stratus.STEAL_SA_TOKEN, '--ack-dedicated-lab',
                    '--stratus', str(binary), '--stratus-sha256', hashlib.sha256(b'test').hexdigest(),
                    '--kubectl', str(kubectl), '--kubeconfig', str(kubeconfig),
                    '--pod-image', 'busybox@sha256:' + 'a' * 64, '--out', str(out)])
            receipt_text = (out / 'receipt.json').read_text()
            self.assertNotIn('private-value', receipt_text)
            return result, seen, json.loads(receipt_text), status_output, str(binary)

    def test_failed_detonation_when_cold_skips_redundant_cleanup(self):
        result, seen, receipt, status_output, binary = self.failed_detonation_with_status('COLD')
        self.assertEqual(result, 1)
        self.assertEqual(len(seen), 4)
        self.assertEqual(seen[-1][0], [binary, 'status', stratus.STEAL_SA_TOKEN])
        self.assertEqual(seen[-1][1]['HOME'], seen[-2][1]['HOME'])
        self.assertEqual(seen[-1][1]['STRATUS_RED_TEAM_CORRELATION_ID'], receipt['correlation_id'])
        self.assertEqual(receipt['returncode'], 1)
        self.assertEqual(receipt['cleanup_returncode'], 0)
        self.assertFalse(receipt['cleanup_invoked'])
        self.assertIsNone(receipt['cleanup_command_returncode'])
        self.assertEqual(receipt['cleanup_mode'], 'skipped already COLD')
        self.assertEqual(receipt['cleanup_output'], '[not invoked]')
        self.assertEqual(receipt['cleanup_status_check']['returncode'], 0)
        self.assertEqual(receipt['cleanup_status_check']['state'], 'COLD')
        self.assertEqual(receipt['cleanup_status_check']['output_bytes'], len(status_output.encode()))

    def test_failed_detonation_when_warm_attempts_cleanup(self):
        result, seen, receipt, _, binary = self.failed_detonation_with_status('WARM')
        self.assertEqual(result, 1)
        self.assertEqual(len(seen), 5)
        self.assertEqual(seen[-2][0], [binary, 'status', stratus.STEAL_SA_TOKEN])
        self.assertEqual(seen[-1][0], [binary, 'cleanup', stratus.STEAL_SA_TOKEN])
        self.assertEqual(seen[-1][1]['HOME'], seen[-2][1]['HOME'])
        self.assertEqual(receipt['cleanup_returncode'], 0)
        self.assertTrue(receipt['cleanup_invoked'])
        self.assertEqual(receipt['cleanup_command_returncode'], 0)
        self.assertEqual(receipt['cleanup_mode'], 'fallback cleanup')
        self.assertEqual(receipt['cleanup_status_check']['state'], 'WARM')

    def test_unrecognized_status_still_attempts_cleanup_and_records_uncertainty(self):
        result, seen, receipt, _, binary = self.failed_detonation_with_status('UNKNOWN')
        self.assertEqual(result, 1)
        self.assertEqual(len(seen), 5)
        self.assertEqual(seen[-2][0], [binary, 'status', stratus.STEAL_SA_TOKEN])
        self.assertEqual(seen[-1][0], [binary, 'cleanup', stratus.STEAL_SA_TOKEN])
        self.assertIsNone(receipt['cleanup_status_check']['state'])
        self.assertIn('unrecognized', receipt['cleanup_status_check']['error'])
        self.assertEqual(receipt['cleanup_returncode'], 0)

    def test_large_stratus_binary_digest_is_explicitly_admitted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / 'stratus'
            with binary.open('wb') as output:
                output.truncate(362_000_000)
            with self.assertRaises(ValueError):
                stratus.digest(binary)
            self.assertRegex(stratus.digest(binary, max_bytes=512 * 1024 * 1024), r'^[a-f0-9]{64}$')
            with self.assertRaises(ValueError):
                stratus.digest(binary, max_bytes=300_000_000)

    def test_command_file_bound_can_exceed_output_bound(self):
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'terraform-package'
            script = ('import sys; f=open(sys.argv[1], "wb"); '
                      '[f.write(b"x" * 1048576) for _ in range(9)]; f.close()')
            argv = [sys.executable, '-c', script, str(target)]
            code, _ = stratus.command(argv, timeout=10)
            self.assertNotEqual(code, 0)
            target.unlink(missing_ok=True)
            code, _ = stratus.command(argv, timeout=10, file_limit_bytes=512 * 1024 * 1024)
            self.assertEqual(code, 0)
            self.assertEqual(target.stat().st_size, 9 * 1024 * 1024)
            noisy = [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"x" * 9437184)']
            code, output = stratus.command(noisy, timeout=10, file_limit_bytes=512 * 1024 * 1024)
            self.assertNotEqual(code, 0)
            self.assertLessEqual(len(output.encode()), 8 * 1024 * 1024)

    def test_token_theft_output_is_not_written_to_receipt(self):
        token = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature'
        receipt = stratus.receipt_output(stratus.STEAL_SA_TOKEN, 'token=' + token)
        self.assertNotIn(token, str(receipt))
        self.assertEqual(receipt['output'], '[redacted credential output]')
        self.assertEqual(len(receipt['output_sha256']), 64)
        for technique in stratus.TECHNIQUES:
            result = stratus.receipt_output(technique, 'token=' + token)
            if technique != stratus.K8S:
                self.assertNotIn(token, str(result))
            else:
                self.assertEqual(result['output'], 'token=' + token)


if __name__ == '__main__':
    unittest.main()
