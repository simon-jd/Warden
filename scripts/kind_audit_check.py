#!/usr/bin/env python3
"""Is the kind audit lab's namespace warden-lab empty? Call it before each run.

    scripts/kind_lab.sh check-empty --audit      (make kind-audit-check-empty)
    python3 -I -B scripts/kind_audit_check.py --kubectl K --kubeconfig .cache/kind-warden-lab/kubeconfig.json

detect/report/audit_alert_import.py attributes an alert by namespace without
looking at who made the request, so a run must start in an empty namespace:
otherwise a kubelet or controller request about an earlier run's leftovers
would count for it. This lists every object of every namespaced resource type
the API server serves (kubectl api-resources --namespaced --verbs=list) in
warden-lab, except what Kubernetes puts in every namespace (the ServiceAccount
default and the ConfigMap kube-root-ca.crt) and events, which outlive the
objects they describe and are no request of a run. It prints one JSON object
and exits 0 if nothing is left, 1 if something is (each named as
kind/name), 2 if the namespace is missing, not Active or cannot be read.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# kubectl's discovery cache: without HOME it would write .kube/ into the
# working directory.
CACHE = Path(__file__).resolve().parents[1] / '.cache/kind-warden-lab/kubectl-cache'
NAMESPACE = 'warden-lab'
CONTEXT = 'kind-warden-lab'
# Present in every namespace; Kubernetes creates them.
DEFAULTS = {('ServiceAccount', 'default'), ('ConfigMap', 'kube-root-ca.crt')}
EVENT_TYPES = {'events', 'events.events.k8s.io'}


def resource_types(names):
    """The namespaced types to list: what api-resources printed, without events."""
    return sorted({name.strip() for name in names if name.strip()} - EVENT_TYPES)


def leftovers(listing):
    """kind/name of each object of a `kubectl get ... -o json` List that a run left."""
    found = []
    for item in listing.get('items') or []:
        kind, name = item.get('kind'), (item.get('metadata') or {}).get('name')
        if (kind, name) in DEFAULTS or kind == 'Event':
            continue
        found.append('%s/%s' % (kind, name))
    return sorted(found)


def kubectl(base, *args):
    result = subprocess.run(base + list(args), capture_output=True, text=True, timeout=120,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    if result.returncode != 0:
        raise RuntimeError('kubectl %s failed (%d): %s' % (' '.join(args[:3]), result.returncode, result.stderr.strip()[-500:]))
    return result.stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--kubectl', required=True)
    parser.add_argument('--kubeconfig', required=True)
    args = parser.parse_args(argv)
    base = [args.kubectl, '--kubeconfig', args.kubeconfig, '--context', CONTEXT, '--cache-dir', str(CACHE)]
    try:
        namespace = json.loads(kubectl(base, 'get', 'namespace', NAMESPACE, '-o', 'json'))
        if (namespace.get('status') or {}).get('phase') != 'Active' or (namespace.get('metadata') or {}).get('deletionTimestamp'):
            raise RuntimeError('namespace %s is not Active' % NAMESPACE)
        types = resource_types(kubectl(base, 'api-resources', '--namespaced=true', '--verbs=list', '-o', 'name').splitlines())
        listing = json.loads(kubectl(base, 'get', ','.join(types), '-n', NAMESPACE, '-o', 'json'))
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'namespace': NAMESPACE, 'error': str(error)}, sort_keys=True))
        return 2
    left = leftovers(listing)
    print(json.dumps({'namespace': NAMESPACE, 'empty': not left, 'left': left, 'types_checked': len(types)}, sort_keys=True))
    return 1 if left else 0


if __name__ == '__main__':
    sys.exit(main())
