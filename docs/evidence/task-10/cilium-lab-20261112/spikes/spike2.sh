#!/usr/bin/env bash
# Spike 2: as spike1, plus: a new connection from the labelled pod (positive control), the endpoint's identity and policy.
set -u
out=$1; mkdir -p "$out"
cd /home/postedism/Desktop/Warden-next
k() { docker exec -i warden-k3s-gvisor kubectl "$@"; }
cdbg() { k -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg "$@"; }
D=sha256:bf35755959d8856840f6d6a0219d087c938e25b82c52a1d5c2b4d8a5c7488aeb
k apply -f - < policies/cilium/quarantine.yaml
pod() { # name streamname
cat <<Y | k apply -f -
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
pod spike-t st-t
pod spike-c st-c
k -n warden-lab wait --for=condition=Ready pod/spike-t pod/spike-c --timeout=120s
sleep 3
ip=$(k -n warden-lab get pod spike-t -o jsonpath='{.status.podIP}')
echo "ip $ip" > "$out/info"
k -n warden-lab exec spike-t -- /warden-probe net "before,tcp,198.18.18.22:443" > "$out/new-before.json" 2>&1
cdbg endpoint list -o json > "$out/ep-before.json"
date +%s.%N > "$out/t0"
k -n warden-lab label pod spike-t warden.dev/quarantine=true
date +%s.%N > "$out/t1"
sleep 3
cdbg endpoint list -o json > "$out/ep-during.json"
k -n warden-lab exec spike-t -- /warden-probe net "during,tcp,198.18.18.22:443" "during-get,get,http://198.18.18.20/x" > "$out/new-during.json" 2>&1
sleep 5
date +%s.%N > "$out/t2"
cdbg bpf ct list global -o json > "$out/ct-during.json" 2>&1 || cdbg bpf ct list global > "$out/ct-during.txt" 2>&1
k -n warden-lab label pod spike-t warden.dev/quarantine-
date +%s.%N > "$out/t3"
sleep 6
k -n warden-lab logs spike-t > "$out/t.log"
k -n warden-lab logs spike-c > "$out/c.log"
docker logs --since 90s warden-k3s-stream > "$out/server.log" 2>&1
k -n warden-lab delete pod spike-t spike-c --grace-period=0 --force --wait=true
k delete -f - < policies/cilium/quarantine.yaml
