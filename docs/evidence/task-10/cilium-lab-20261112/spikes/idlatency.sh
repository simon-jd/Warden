#!/usr/bin/env bash
# idlatency.sh <out> <reps>: label a fresh gVisor pod warden.dev/quarantine=true and time until its Cilium endpoint's identity carries the label.
set -u
out=$1; reps=$2; mkdir -p "$out"
k() { docker exec warden-k3s-gvisor kubectl "$@"; }
ki() { docker exec -i warden-k3s-gvisor kubectl "$@"; }
cdbg() { k -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg "$@"; }
D=sha256:bf35755959d8856840f6d6a0219d087c938e25b82c52a1d5c2b4d8a5c7488aeb
k -n kube-system get cm cilium-config -o jsonpath='{.data.identity-max-jitter} {.data.identity-change-grace-period}' > "$out/config.txt"; echo >> "$out/config.txt"
for r in $(seq 1 "$reps"); do
  n=spike-id-$r
cat <<Y | ki apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: $n, namespace: warden-lab, labels: {app: $n, warden.dev/sandbox: "true", warden.dev/test: spike}}
spec:
  runtimeClassName: gvisor-netstack
  automountServiceAccountToken: false
  enableServiceLinks: false
  terminationGracePeriodSeconds: 1
  restartPolicy: Never
  containers:
  - name: probe
    image: docker.io/warden-lab/probe@$D
    imagePullPolicy: Never
    args: [hold]
    securityContext: {runAsNonRoot: true, runAsUser: 65534, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
Y
  k -n warden-lab wait --for=condition=Ready pod/$n --timeout=120s >/dev/null
  sleep 2
  ip=$(k -n warden-lab get pod $n -o jsonpath='{.status.podIP}')
  t0=$(date +%s.%N)
  k -n warden-lab label pod $n warden.dev/quarantine=true >/dev/null
  while :; do
    t=$(date +%s.%N)
    q=$(cdbg endpoint list -o json | python3 -c "
import json,sys
for e in json.load(sys.stdin):
  if '$ip' in [x.get('ipv4') for x in e['status']['networking']['addressing']]:
    print('Q' if 'k8s:warden.dev/quarantine=true' in e['status']['identity']['labels'] else '-', e['status']['identity']['id'])
")
    case $q in Q*) break;; esac
    last=$t
    python3 -c "import sys; sys.exit(0 if float('$t')-float('$t0') < 60 else 1)" || { q="timeout"; break; }
  done
  python3 -c "print('rep $r: last poll without %.3f s, first with %.3f s, identity $q' % (float('${last:-$t0}')-float('$t0'), float('$t')-float('$t0')))" | tee -a "$out/result.txt"
  k -n warden-lab delete pod $n --grace-period=0 --force --wait=true >/dev/null 2>&1
done
