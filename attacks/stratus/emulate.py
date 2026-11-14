"""Official Stratus invocation restricted to the dedicated local kind lab.

Azure is described by --plan, but execution is blocked in the current local-only
phase. This wrapper never provisions a cloud account, AKS cluster or Entra app.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import tempfile
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'atomic'))
from lab_common import (checked_tool, clean_environment, command, digest, execution_record,
                        prepare_output, utc_now, write_new_json)

K8S = 'k8s.privilege-escalation.privileged-pod'
AZURE = 'azure.credential-access.app-service-publishing-credentials'


def validate_technique(technique):
    if technique != K8S:
        raise ValueError('local-only phase: only the reviewed Kubernetes technique may execute; cloud techniques are blocked')
    return 'T1611'


def guard_kubeconfig(config):
    if (config.get('current-context') != 'kind-warden-lab' or
        len(config.get('contexts', [])) != 1 or len(config.get('clusters', [])) != 1 or
        len(config.get('users', [])) != 1):
        raise ValueError('single explicit kind-warden-lab kubeconfig required')
    context, cluster, user = config['contexts'][0], config['clusters'][0], config['users'][0]
    if (context.get('name') != 'kind-warden-lab' or cluster.get('name') != 'kind-warden-lab' or
        context.get('context', {}).get('cluster') != 'kind-warden-lab' or
        context.get('context', {}).get('user') != user.get('name')):
        raise ValueError('dedicated lab context and cluster required')
    values = cluster.get('cluster', {})
    endpoint = urlsplit(values.get('server', ''))
    credentials = user.get('user', {})
    if (endpoint.scheme != 'https' or endpoint.hostname not in ('127.0.0.1', '::1') or
        endpoint.username or endpoint.password or endpoint.path not in ('', '/') or
        endpoint.query or endpoint.fragment or values.get('insecure-skip-tls-verify') or
        values.get('proxy-url') or not values.get('certificate-authority-data') or
        set(credentials) - {'client-certificate-data', 'client-key-data'} or
        not credentials.get('client-certificate-data') or not credentials.get('client-key-data')):
        raise ValueError('loopback TLS cluster with embedded client credentials required; plugins/proxies refused')


def guard_nodes(nodes):
    items = nodes.get('items')
    if not isinstance(items, list) or not items:
        raise ValueError('dedicated lab node inventory required')
    for node in items:
        name = node.get('metadata', {}).get('name', '')
        if not re.fullmatch('warden-lab-(control-plane[0-9]*|worker[0-9]*)', name):
            raise ValueError('all nodes must belong to dedicated kind warden-lab')


def pod_configuration(image, run_id):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}', image):
        raise ValueError('explicit digest-pinned Kubernetes pod image required')
    return {'kubernetes': {'default': {'pod': {'image': image,
            'labels': {'warden_lab': 'warden-lab', 'warden_run_id': run_id}}}}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--technique', choices=(K8S, AZURE), default=K8S)
    parser.add_argument('--plan', action='store_true', help='print plan only; never invokes a tool')
    parser.add_argument('--stratus')
    parser.add_argument('--stratus-sha256')
    parser.add_argument('--kubectl')
    parser.add_argument('--kubeconfig')
    parser.add_argument('--pod-image', help='digest-pinned image for the official privileged pod')
    parser.add_argument('--out')
    parser.add_argument('--ack-dedicated-lab', action='store_true')
    args = parser.parse_args(argv)
    if args.plan:
        print(json.dumps({'technique': args.technique, 'execution_authorized': args.technique == K8S,
                          'phase': 'local-only', 'target': 'kind-warden-lab' if args.technique == K8S else None,
                          'command': ['stratus', 'detonate', args.technique, '--cleanup'],
                          'blocked_reason': 'Cloud/Entra provisioning and execution require a separately authorized phase.' if args.technique == AZURE else None}, sort_keys=True))
        return 0
    snapshot = None
    try:
        technique_id = validate_technique(args.technique)
        if not args.ack_dedicated_lab:
            raise ValueError('--ack-dedicated-lab required')
        stratus, kubectl = checked_tool(args.stratus or ''), checked_tool(args.kubectl or '')
        if not re.fullmatch('[a-f0-9]{64}', args.stratus_sha256 or '') or digest(stratus) != args.stratus_sha256:
            raise ValueError('explicit Stratus binary SHA256 pin must match')
        kubeconfig = Path(args.kubeconfig or '')
        if not kubeconfig.is_absolute() or not kubeconfig.is_file() or kubeconfig.is_symlink():
            raise ValueError('explicit absolute kubeconfig regular file required')
        # Strict JSON kubeconfig avoids executing credential plugins even during
        # validation. kubectl accepts JSON, a YAML subset, as its config format.
        if kubeconfig.stat().st_size > 1024 * 1024:
            raise ValueError('kubeconfig exceeds byte limit')
        config = json.loads(kubeconfig.read_text())
        guard_kubeconfig(config)
        # Run both clients from the validated private snapshot. A later edit
        # of the original kubeconfig cannot redirect detonation or cleanup.
        snapshot = tempfile.TemporaryDirectory(prefix='warden-stratus-kube-')
        pinned_kubeconfig = Path(snapshot.name) / 'config.json'
        write_new_json(pinned_kubeconfig, config)
        env = clean_environment()
        env['KUBECONFIG'] = str(pinned_kubeconfig)
        code, raw_nodes = command([kubectl, '--kubeconfig', str(pinned_kubeconfig), '--context',
                                  'kind-warden-lab', 'get', 'nodes', '-o', 'json'], env=env)
        if code:
            raise ValueError('cannot verify dedicated kind node inventory')
        guard_nodes(json.loads(raw_nodes))
        run_id = 'stratus-' + secrets.token_hex(12)
        pod_config = pod_configuration(args.pod_image or '', run_id)
        output = prepare_output(args.out or '')
        # Stratus state and all Terraform caches remain in this run directory.
        home = output / 'home'
        home.mkdir(mode=0o700)
        env['HOME'] = str(home)
        env['XDG_CONFIG_HOME'] = str(home / '.config')
        env['XDG_CACHE_HOME'] = str(home / '.cache')
        config_path = output / 'stratus-config.json'
        write_new_json(config_path, pod_config)
        env['STRATUS_CONFIG_PATH'] = str(config_path)
        started = utc_now()
        code, log = command([stratus, 'detonate', args.technique, '--cleanup'], env=env, timeout=240)
        # A separate cleanup attempt also runs after failed or timed out detonation.
        cleanup_code, cleanup_log = command([stratus, 'cleanup', args.technique], env=env, timeout=120)
        finished = utc_now()
        write_new_json(output / 'executions.jsonl', execution_record(run_id, run_id, technique_id, started, code))
        write_new_json(output / 'receipt.json', {'source': 'official-stratus-red-team',
                       'technique': args.technique, 'stratus_sha256': args.stratus_sha256,
                       'run_id': run_id, 'execution_id': run_id, 'started_at': started,
                       'finished_at': finished, 'returncode': code, 'cleanup_returncode': cleanup_code,
                       'output': log, 'cleanup_output': cleanup_log, 'context': 'kind-warden-lab',
                       'pod_image': args.pod_image,
                       'limitations': ['No detection is inferred from tool output.',
                                       'Nonzero cleanup requires manual recovery of this dedicated lab.']})
        print(str(output))
        return 0 if code == 0 and cleanup_code == 0 else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2
    finally:
        if snapshot is not None:
            snapshot.cleanup()


if __name__ == '__main__':
    sys.exit(main())
