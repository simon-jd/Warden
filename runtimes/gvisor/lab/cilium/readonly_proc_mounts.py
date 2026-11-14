#!/usr/bin/env python3
"""Make the Cilium chart's mounts of the node's /proc read-only.

The k3s lab node (scripts/k3s_gvisor_lab.sh up --cilium) is a privileged
container on the host's kernel, so the node's /proc/sys/kernel and
/proc/sys/vm are the host's global sysctls. Cilium's agent mounts the node's
/proc/sys/kernel (hostPath) to set kernel.timer_migration and
kernel.unprivileged_bpf_disabled; on 2026-11-12 it set both on the host,
although warden-node-init had made the node's /proc/sys read-only
(docs/evidence/task-10/cilium-lab-20261112/README.md has why that did not
hold). A mount the pod asks to be read-only is.

Reads the rendered chart as JSON on stdin (what `kubectl create
--dry-run=client -o json` prints: one object after another, or a List) and
writes it to stdout as one List, with readOnly: true on every container's
and init container's mount of a hostPath volume at /proc or below it, except
/proc/sys/net and below (the node's own network namespace, which the agent
configures). Prints one line per mount it changed on stderr. Fails, writing
nothing, if the input is not JSON objects or the cilium DaemonSet has no
hostPath mount of /proc/sys/kernel: the chart changed, and how the agent
reaches the kernel sysctls needs a new look.
"""
import json
import sys


def normal(path):
    return '/' + path.strip('/')


def under(path, top):
    return path == top or path.startswith(top + '/')


def proc_volumes(spec):
    """Names and paths of the pod's hostPath volumes in /proc, without /proc/sys/net."""
    out = {}
    for v in spec.get('volumes') or []:
        if 'hostPath' not in v:
            continue
        p = normal(v['hostPath'].get('path', ''))
        if under(p, '/proc') and not under(p, '/proc/sys/net'):
            out[v['name']] = p
    return out


def objects(text):
    """The objects of a v1 List, or of JSON objects one after another (how
    kubectl prints the objects of a multi-document file)."""
    dec, i, out, docs = json.JSONDecoder(), 0, [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i == len(text):
            break
        obj, i = dec.raw_decode(text, i)
        docs += 1
        if not isinstance(obj, dict):
            raise ValueError('not a JSON object')
        if obj.get('kind') == 'List':
            if not isinstance(obj.get('items'), list):
                raise ValueError('a List without items')
            out.extend(obj['items'])
        else:
            out.append(obj)
    if not docs:
        raise ValueError('no input')
    return out


def main():
    try:
        items = objects(sys.stdin.read())
    except ValueError as e:
        sys.exit('readonly_proc_mounts: want the chart\'s objects as JSON: %s' % e)
    doc = {'apiVersion': 'v1', 'kind': 'List', 'items': items}
    agent_kernel = False
    for it in items:
        spec = ((it.get('spec') or {}).get('template') or {}).get('spec')
        if not spec:
            continue
        volumes = proc_volumes(spec)
        kind, name = it.get('kind'), it.get('metadata', {}).get('name')
        for c in (spec.get('initContainers') or []) + (spec.get('containers') or []):
            for m in c.get('volumeMounts') or []:
                path = volumes.get(m.get('name'))
                if path is None:
                    continue
                if kind == 'DaemonSet' and name == 'cilium' and path == '/proc/sys/kernel':
                    agent_kernel = True
                if m.get('readOnly') is not True:
                    m['readOnly'] = True
                    print('read-only: %s/%s %s %s (%s)' % (kind, name, c.get('name'), m['name'], path),
                          file=sys.stderr)
    if not agent_kernel:
        sys.exit('readonly_proc_mounts: the cilium DaemonSet has no hostPath mount of /proc/sys/kernel; '
                 'the chart changed, check how its agent sets kernel sysctls')
    json.dump(doc, sys.stdout)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
