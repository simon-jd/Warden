#!/usr/bin/env bash
# Spike 4: direct streams T and C; quarantine.yaml; label T; poll T's endpoint identity until it changes; watch 12 s more.
set -u
out=$1; mkdir -p "$out"
cd /home/postedism/Desktop/Warden-next
k() { docker exec warden-k3s-gvisor kubectl "$@"; }
ki() { docker exec -i warden-k3s-gvisor kubectl "$@"; }
cdbg() { k -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg "$@"; }
D=sha256:bf35755959d8856840f6d6a0219d087c938e25b82c52a1d5c2b4d8a5c7488aeb
ki apply -f - < policies/cilium/quarantine.yaml
pod() { # name streamname
cat <<Y | ki apply -f -
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: warden-lab, labels: {app: $1, warden.dev/sandbox: "true", warden.dev/test: spike}}
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
    args: [stream, "-", "198.18.18.22:443", "$2", "20"]
    securityContext: {runAsNonRoot: true, runAsUser: 65534, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
Y
}
pod spike-t st4-t
pod spike-c st4-c
k -n warden-lab wait --for=condition=Ready pod/spike-t pod/spike-c --timeout=120s
sleep 3
ip=$(k -n warden-lab get pod spike-t -o jsonpath='{.status.podIP}')
echo "ip $ip" > "$out/info"
date +%s.%N > "$out/t0"
k -n warden-lab label pod spike-t warden.dev/quarantine=true
date +%s.%N > "$out/t1"
: > "$out/poll"
for i in $(seq 1 120); do
  l=$(cdbg endpoint list -o json | python3 -c "
import json,sys
for e in json.load(sys.stdin):
  if '$ip' in [x.get('ipv4') for x in e['status']['networking']['addressing']]:
    print(e['status']['identity']['id'], 'Q' if any('quarantine' in l for l in e['status']['identity']['labels']) else '-', e['status']['state'], e['status']['policy']['realized'].get('policy-revision'))
")
  echo "$(date +%s.%N) $l" >> "$out/poll"
  case $l in *" Q "*) break;; esac
  sleep 0.5
done
k -n warden-lab exec spike-t -- /warden-probe net "after-switch,tcp,198.18.18.22:443" > "$out/new-after.json" 2>&1
sleep 12
date +%s.%N > "$out/t2"
cp "$out/t2" "$out/t3"
k -n warden-lab logs spike-t > "$out/t.log"
k -n warden-lab logs spike-c > "$out/c.log"
docker logs --since 150s warden-k3s-stream > "$out/server.log" 2>&1
k -n warden-lab delete pod spike-t spike-c --grace-period=0 --force --wait=true
ki delete -f - < policies/cilium/quarantine.yaml
