#!/usr/bin/env bash
# run-variant.sh <name> <image id> <pod-init file>: the detector's gVisor instance at debug level, one probe pod, its log.
set -u
cd ~/Desktop/Warden-detect
g=.cache/detect/gv; name=$1; img=$2; init=$3
docker volume inspect warden-detect-gvisor >/dev/null 2>&1 || docker volume create --label owner=warden-lab --label warden.detect/role=falco warden-detect-gvisor >/dev/null
docker rm -f warden-detect-falco-gvisor >/dev/null 2>&1
docker run -d --name warden-detect-falco-gvisor --label owner=warden-lab --label warden.detect/role=falco --pull never --network none --cap-drop ALL \
  --security-opt no-new-privileges --read-only --tmpfs /run/warden-runsc-root:size=1m --tmpfs /tmp:size=16m --cpuset-cpus 0-7,16-31 --memory 512m --memory-swap 512m \
  --log-driver json-file --log-opt max-size=10m --log-opt max-file=2 \
  --mount type=bind,src=$PWD/.tools/gvisor/runsc,dst=/usr/local/bin/runsc,readonly --mount type=volume,src=warden-detect-gvisor,dst=/warden-detect \
  --mount type=bind,src=$PWD/$g/90-debug.yaml,dst=/etc/falco/config.d/90-warden.yaml,readonly \
  --mount type=bind,src=$PWD/detect/falco/falco-gvisor.yaml,dst=/etc/falco/config.d/91-warden-engine.yaml,readonly \
  --mount type=bind,src=$PWD/$init,dst=/etc/warden-detect/gvisor-pod-init.json,readonly $img /usr/bin/falco >/dev/null
sleep 4
if [[ $(docker inspect -f '{{.State.Running}}' warden-k3s-gvisor 2>/dev/null) != true ]]; then
  WARDEN_LAB_CPUSET=0-7,16-31 taskset -c 0-7,16-31 scripts/k3s_gvisor_lab.sh up --without-corpus --falco >/dev/null
fi
d=$(cat .cache/warden-lab/image-digest)
docker exec warden-k3s-gvisor kubectl -n warden-lab delete pod gv-probe --ignore-not-found --wait=true </dev/null >/dev/null
for i in $(seq 30); do docker exec warden-k3s-gvisor kubectl -n warden-lab get sa default >/dev/null 2>&1 && break; sleep 1; done
docker exec -i warden-k3s-gvisor kubectl apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: gv-probe, namespace: warden-lab, labels: {owner: warden-lab, warden.dev/run: gv-$name}}
spec:
  runtimeClassName: gvisor
  restartPolicy: Never
  automountServiceAccountToken: false
  containers:
  - {name: p, image: "docker.io/warden-lab/probe@$d", imagePullPolicy: Never, command: ["/warden-probe", "uid"], resources: {limits: {cpu: 500m, memory: 256Mi}}}
Y
for i in $(seq 30); do docker exec warden-k3s-gvisor kubectl -n warden-lab get pod gv-probe -o jsonpath='{.status.phase}' 2>/dev/null | grep -q -E 'Succeeded|Failed' && break; sleep 1; done
sleep 2
cid=$(docker exec warden-k3s-gvisor kubectl -n warden-lab get pod gv-probe -o jsonpath='{.status.containerStatuses[0].containerID}' </dev/null)
sandbox=$(docker exec warden-k3s-gvisor crictl pods --name gv-probe -q </dev/null)
{ echo "# variant $name: image $img, trace config $(basename $init) (sha256 $(sha256sum $init | cut -c1-64))"
  echo "# probe pod gv-probe in warden-lab, app container $cid, pod sandbox $sandbox"
  echo "# Falco container after the pod: $(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' warden-detect-falco-gvisor)"
  docker logs warden-detect-falco-gvisor 2>&1 | grep -v '\[container\]: \* enabled container runtime socket'; } > $g/$name.log
docker rm -f warden-detect-falco-gvisor >/dev/null
docker exec warden-k3s-gvisor kubectl -n warden-lab delete pod gv-probe --ignore-not-found --wait=true </dev/null >/dev/null
