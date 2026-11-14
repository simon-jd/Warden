#!/usr/bin/env bash
# Spike: does labelling a pod warden.dev/quarantine=true under policies/cilium/quarantine.yaml stop an established direct stream?
set -u
cd /home/postedism/Desktop/Warden-next
k() { docker exec -i warden-k3s-gvisor kubectl "$@"; }
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
date +%s.%N > t0
k -n warden-lab label pod spike-t warden.dev/quarantine=true
date +%s.%N > t1
sleep 10
date +%s.%N > t2
k -n warden-lab label pod spike-t warden.dev/quarantine-
date +%s.%N > t3
sleep 6
k -n warden-lab logs spike-t > t.log
k -n warden-lab logs spike-c > c.log
docker logs --since 60s warden-k3s-stream > server.log 2>&1
k -n warden-lab delete pod spike-t spike-c --grace-period=0 --force --wait=true
k delete -f - < policies/cilium/quarantine.yaml
