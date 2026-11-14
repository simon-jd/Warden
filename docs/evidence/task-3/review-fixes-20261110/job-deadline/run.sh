#!/usr/bin/env bash
# How the Job's activeDeadlineSeconds ends a gVisor run on the lab of
# scripts/k3s_gvisor_lab.sh. Two Jobs in warden-lab, each with a 6 s
# deadline (job.py writes them):
#   supervisor  the driver's Job (gvisor.go job()): warden-gvisor-init as
#               PID 1 with -timeout-s 300, payload /warden-probe hold
#   bare        /warden-probe hold as PID 1 and no supervisor, standing in
#               for a supervisor that writes no report
# Every watch event of the Job and of its pods is kept as it came from
# kubectl (<which>.job-events.json, <which>.pod-events.json); timeline.py
# prints them in order. Run from the repository root, with the lab up:
#   scripts/k3s_gvisor_lab.sh env docs/evidence/task-3/review-fixes-20261110/job-deadline/run.sh
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
node=$WARDEN_GVISOR_NODE_CONTAINER
k() { docker exec -i "$node" kubectl -n warden-lab "$@"; }
for which in supervisor bare; do
  name=warden-deadline-$which
  k delete job "$name" --ignore-not-found --cascade=foreground --wait=true >/dev/null
  python3 -I "$here/job.py" "$which" "$name" "$WARDEN_LAB_IMAGE_DIGEST" "$WARDEN_GVISOR_NODE" >"$here/$which.job.json"
  timeout 90 docker exec "$node" kubectl -n warden-lab get jobs --field-selector "metadata.name=$name" \
    -w --output-watch-events -o json >"$here/$which.job-events.json" 2>&1 &
  wj=$!
  timeout 90 docker exec "$node" kubectl -n warden-lab get pods -l "job-name=$name" \
    -w --output-watch-events -o json >"$here/$which.pod-events.json" 2>&1 &
  wp=$!
  sleep 2
  echo "$(date -Is) create $name"
  k create -f - <"$here/$which.job.json"
  for _ in $(seq 1 120); do
    failed=$(k get job "$name" -o 'jsonpath={.status.conditions[?(@.type=="Failed")].status}')
    pods=$(k get pods -l "job-name=$name" -o name)
    [[ $failed == True && -z $pods ]] && break
    sleep 0.5
  done
  echo "$(date -Is) $name: Failed=$failed, pods left: ${pods:-none}"
  sleep 2
  kill "$wj" "$wp" 2>/dev/null || true
  wait "$wj" "$wp" 2>/dev/null || true
  k delete job "$name" --ignore-not-found --cascade=foreground --wait=true
done
python3 -I "$here/timeline.py" "$here" >"$here/timeline.txt"
cat "$here/timeline.txt"
