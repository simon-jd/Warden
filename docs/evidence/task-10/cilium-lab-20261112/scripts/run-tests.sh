#!/usr/bin/env bash
# run-tests.sh <dir under runs/> <go test -run regexp> [make vars...]: make test-cilium on the lab that is up.
cd /home/postedism/Desktop/Warden-next || exit 1
d=docs/evidence/task-10/cilium-lab-20261112/runs/$1; shift
run=$1; shift
mkdir -p "$d"
{
  echo "# $(date -Iseconds) head $(git rev-parse --short HEAD); git status --short:"
  git status --short
  cat /proc/loadavg
  echo "\$ taskset -c 0-7,16-31 make test-cilium CILIUM_REUSE=1 CILIUM_RUN='$run' CILIUM_OUT=$PWD/$d $*"
  taskset -c 0-7,16-31 make test-cilium CILIUM_REUSE=1 CILIUM_RUN="$run" CILIUM_OUT="$PWD/$d" "$@" 2>&1
  echo "exit $?"
  echo "# $(date -Iseconds)"; cat /proc/loadavg
} >"$d/run.log" 2>&1
