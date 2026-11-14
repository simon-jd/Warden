"""Writes the experiment's Job (see run.sh) as JSON: which name digest node."""
import json
import sys

which, name, digest, node = sys.argv[1:5]
res = {'cpu': '1000m', 'memory': '640Mi'}
container = {
    'name': 'run', 'image': 'docker.io/warden-lab/probe@' + digest, 'imagePullPolicy': 'Never',
    'resources': {'limits': res, 'requests': res},
    'terminationMessagePath': '/dev/termination-log', 'terminationMessagePolicy': 'File',
}
spec = {
    'runtimeClassName': 'gvisor', 'restartPolicy': 'Never', 'automountServiceAccountToken': False,
    'enableServiceLinks': False, 'terminationGracePeriodSeconds': 1, 'dnsPolicy': 'Default',
    'nodeSelector': {'kubernetes.io/hostname': node}, 'containers': [container],
}
if which == 'supervisor':
    # As gvisor.go job() writes it, with -timeout-s 300 so that the deadline comes first.
    container.update({
        'command': ['/.warden/init'], 'args': ['-pids', '32', '-timeout-s', '300', '--', '/warden-probe', 'hold'],
        'env': [{'name': 'WARDEN_GVISOR_INIT', 'value': '1'}],
        'volumeMounts': [{'name': 'warden-init', 'mountPath': '/.warden/init', 'readOnly': True}],
        'securityContext': {
            'runAsUser': 0, 'runAsGroup': 0, 'runAsNonRoot': False, 'privileged': False,
            'readOnlyRootFilesystem': True,
            'capabilities': {'drop': ['ALL'], 'add': ['SETGID', 'SETPCAP', 'SETUID', 'SYS_ADMIN']},
            'seccompProfile': {'type': 'RuntimeDefault'},
        },
    })
    spec['volumes'] = [{'name': 'warden-init', 'hostPath': {'path': '/opt/warden/gvisor-init', 'type': 'File'}}]
elif which == 'bare':
    container.update({
        'command': ['/warden-probe', 'hold'],
        'securityContext': {'runAsUser': 65534, 'runAsGroup': 65534, 'runAsNonRoot': True,
                            'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']},
                            'seccompProfile': {'type': 'RuntimeDefault'}},
    })
else:
    sys.exit('which: supervisor or bare')
labels = {'app.kubernetes.io/managed-by': 'warden', 'warden.dev/run': name}
job = {
    'apiVersion': 'batch/v1', 'kind': 'Job',
    'metadata': {'name': name, 'namespace': 'warden-lab', 'labels': labels},
    'spec': {'backoffLimit': 0, 'completions': 1, 'parallelism': 1, 'activeDeadlineSeconds': 6,
             'ttlSecondsAfterFinished': 600,
             'template': {'metadata': {'labels': dict(labels, **{'warden.dev/sandbox': 'true'})}, 'spec': spec}},
}
json.dump(job, sys.stdout, indent=1)
print()
