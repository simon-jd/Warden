"""Official Stratus invocation restricted to the dedicated local kind lab.

Azure is described by --plan, but execution is blocked in the current local-only
phase. This wrapper never provisions a cloud account, AKS cluster or Entra app.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import uuid
import sys
import tempfile
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'atomic'))
from lab_common import (checked_tool, clean_environment, command, digest, execution_record,
                        prepare_output, utc_now, write_new_json)

K8S = 'k8s.privilege-escalation.privileged-pod'
STEAL_SA_TOKEN = 'k8s.credential-access.steal-serviceaccount-token'
# Local ATT&CK analysis mappings; Stratus itself lists tactics, not these IDs.
TECHNIQUES = {
    'k8s.credential-access.dump-secrets': 'T1552.007',
    STEAL_SA_TOKEN: 'T1528',
    'k8s.persistence.create-admin-clusterrole': 'T1098.006',
    'k8s.persistence.create-client-certificate': 'T1649',
    'k8s.persistence.create-token': 'T1098',
    'k8s.privilege-escalation.hostpath-volume': 'T1611',
    'k8s.privilege-escalation.nodes-proxy': 'T1609',
    K8S: 'T1611',
}
RUN_LABEL = 'warden.dev/run'
RUN_ID = re.compile(r'stratus-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}')
STRATUS_FILE_LIMIT = 512 * 1024 * 1024
LAB_NAMESPACE = 'warden-lab'
AZURE = 'azure.credential-access.app-service-publishing-credentials'


def validate_technique(technique):
    if technique not in TECHNIQUES:
        raise ValueError('local-only phase: only reviewed Kubernetes techniques may execute; cloud techniques are blocked')
    return TECHNIQUES[technique]


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


def guard_namespace(namespace):
    metadata = namespace.get('metadata') or {}
    labels = metadata.get('labels') or {}
    if (metadata.get('name') != LAB_NAMESPACE or metadata.get('deletionTimestamp') or
            labels.get('project') != 'warden' or labels.get('owner') != 'warden-lab' or
            (namespace.get('status') or {}).get('phase') != 'Active'):
        raise ValueError('active owned warden-lab namespace required')


def pod_configuration(image, run_id):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}', image):
        raise ValueError('explicit digest-pinned Kubernetes pod image required')
    if not RUN_ID.fullmatch(run_id):
        raise ValueError('unique Stratus run ID required')
    return {'kubernetes': {'default': {'namespace': LAB_NAMESPACE, 'pod': {'image': image,
            'labels': {'project': 'warden', 'owner': 'warden-lab', RUN_LABEL: run_id,
                       'warden_lab': 'warden-lab', 'warden_run_id': run_id}}}}}


def parse_stratus_status(output, technique):
    header_seen = False
    states = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith('|') or not line.endswith('|'):
            continue
        columns = [cell.strip() for cell in line[1:-1].split('|')]
        if columns == ['ID', 'NAME', 'STATUS']:
            header_seen = True
        elif len(columns) == 3 and columns[0] == technique:
            states.append(columns[2])
    if not header_seen or len(states) != 1 or states[0] not in {'COLD', 'WARM', 'DETONATED'}:
        raise ValueError('unrecognized Stratus status output for technique')
    return states[0]


def receipt_output(technique, log):
    if technique != K8S:
        raw = log.encode('utf-8')
        return {'output': '[redacted credential output]', 'output_sha256': hashlib.sha256(raw).hexdigest(),
                'output_bytes': len(raw)}
    return {'output': log}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--technique', choices=(*TECHNIQUES, AZURE), default=K8S)
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
        print(json.dumps({'technique': args.technique, 'execution_authorized': args.technique in TECHNIQUES,
                          'phase': 'local-only', 'target': 'kind-warden-lab' if args.technique in TECHNIQUES else None,
                          'command': ['stratus', 'detonate', args.technique, '--cleanup'],
                          'blocked_reason': 'Cloud/Entra provisioning and execution require a separately authorized phase.' if args.technique == AZURE else None}, sort_keys=True))
        return 0
    snapshot = None
    try:
        technique_id = validate_technique(args.technique)
        if not args.ack_dedicated_lab:
            raise ValueError('--ack-dedicated-lab required')
        stratus, kubectl = checked_tool(args.stratus or ''), checked_tool(args.kubectl or '')
        if not re.fullmatch('[a-f0-9]{64}', args.stratus_sha256 or '') or digest(stratus, max_bytes=STRATUS_FILE_LIMIT) != args.stratus_sha256:
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
        correlation_id = str(uuid.uuid4())
        run_id = 'stratus-' + correlation_id
        env = clean_environment()
        env['KUBECONFIG'] = str(pinned_kubeconfig)
        env['KUBE_CONFIG_PATH'] = str(pinned_kubeconfig)
        env['STRATUS_RED_TEAM_CORRELATION_ID'] = correlation_id
        code, raw_nodes = command([kubectl, '--kubeconfig', str(pinned_kubeconfig), '--context',
                                  'kind-warden-lab', 'get', 'nodes', '-o', 'json'], env=env)
        if code:
            raise ValueError('cannot verify dedicated kind node inventory')
        guard_nodes(json.loads(raw_nodes))
        code, raw_namespace = command([kubectl, '--kubeconfig', str(pinned_kubeconfig), '--context',
                                       'kind-warden-lab', 'get', 'namespace', LAB_NAMESPACE, '-o', 'json'], env=env)
        if code:
            raise ValueError('cannot verify dedicated Warden namespace')
        guard_namespace(json.loads(raw_namespace))
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
        code, log = command([stratus, 'detonate', args.technique, '--cleanup'], env=env, timeout=240,
                            file_limit_bytes=STRATUS_FILE_LIMIT)
        # A successful detonate --cleanup has already cleaned its Stratus state.
        # Failed detonation may leave state or resources: check the same run's
        # state before trying cleanup again, without treating COLD as lab-clean.
        cleanup_code, cleanup_log, cleanup_mode = 0, '', 'detonate --cleanup'
        status_check = None
        if code != 0:
            status_code, status_log = command([stratus, 'status', args.technique], env=env, timeout=30,
                                              file_limit_bytes=STRATUS_FILE_LIMIT)
            raw_status = status_log.encode('utf-8')
            status_check = {'returncode': status_code, 'state': None,
                            'output_sha256': hashlib.sha256(raw_status).hexdigest(),
                            'output_bytes': len(raw_status)}
            if status_code == 0:
                try:
                    status_check['state'] = parse_stratus_status(status_log, args.technique)
                except ValueError as exc:
                    status_check['error'] = str(exc)
            else:
                status_check['error'] = 'stratus status returned nonzero'
            if status_check['state'] == 'COLD':
                cleanup_code, cleanup_log, cleanup_mode = 0, '', 'skipped already COLD'
            else:
                cleanup_code, cleanup_log = command([stratus, 'cleanup', args.technique], env=env, timeout=120,
                                                    file_limit_bytes=STRATUS_FILE_LIMIT)
                cleanup_mode = 'fallback cleanup'
        finished = utc_now()
        write_new_json(output / 'executions.jsonl', execution_record(run_id, run_id, technique_id, started, code))
        write_new_json(output / 'receipt.json', {'source': 'official-stratus-red-team',
                       'technique': args.technique, 'stratus_sha256': args.stratus_sha256,
                       'run_id': run_id, 'correlation_id': correlation_id, 'execution_id': run_id, 'started_at': started,
                       'finished_at': finished, 'returncode': code, 'cleanup_returncode': cleanup_code,
                       'cleanup_mode': cleanup_mode, 'cleanup_status_check': status_check,
                       'cleanup_invoked': cleanup_mode == 'fallback cleanup',
                       'cleanup_command_returncode': cleanup_code if cleanup_mode == 'fallback cleanup' else None,
                       **receipt_output(args.technique, log),
                       'cleanup_output': ('[not invoked]' if cleanup_mode == 'skipped already COLD' else
                                          cleanup_log if args.technique == K8S else '[redacted credential output]'),
                       'context': 'kind-warden-lab', 'namespace': LAB_NAMESPACE,
                       'pod_image': args.pod_image,
                       'limitations': ['No detection is inferred from tool output.',
                                       'COLD after failed detonation does not prove resources were removed.',
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
