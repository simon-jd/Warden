#!/usr/bin/env bash
# Throwaway kind cluster for the live Kubernetes tests (Task 14 IsolatePod /
# CordonNode, Task 9 JIT RoleBindings). One node, named warden-respond, on its
# own Docker network (warden-kind) and with the project-local kubeconfig
# .cache/kind/kubeconfig; ~/.kube/config is never read or written.
#
#   scripts/kind_lab.sh run <command...>   up, run the command, always down
#   scripts/kind_lab.sh up | down
#
# The node image is pinned by digest (the one kind v0.33.0 publishes for
# v1.34.11). Pod images are loaded from the local Docker image store; nothing
# is pulled inside the cluster (pods use imagePullPolicy: Never).
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
kind=$root/.tools/kind/kind
name=warden-respond
kubeconfig=$root/.cache/kind/kubeconfig
node_image=kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d
pod_images=(python:3.14.4-alpine)
export KIND_EXPERIMENTAL_DOCKER_NETWORK=warden-kind

up() {
  [[ -x $kind ]] || "$root/scripts/restore-tools.sh" kind
  mkdir -p "$(dirname "$kubeconfig")"
  "$kind" create cluster --name "$name" --kubeconfig "$kubeconfig" --image "$node_image" --wait 180s
  # `kind load docker-image` fails on multi-platform images whose other
  # platforms are not in the local store, so load a linux/amd64-only archive.
  local archive=$root/.cache/kind/images.tar
  for img in "${pod_images[@]}"; do
    docker save --platform linux/amd64 -o "$archive" "$img"
    "$kind" load image-archive "$archive" --name "$name"
    rm -f "$archive"
  done
}

down() {
  "$kind" delete cluster --name "$name" --kubeconfig "$kubeconfig" || true
  # kind creates the network on first use; remove it only if no container is left on it.
  if docker network inspect warden-kind >/dev/null 2>&1; then
    docker network rm warden-kind >/dev/null || echo "warden-kind network still in use; left in place" >&2
  fi
  rm -f "$kubeconfig"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  run)
    shift
    [[ $# -gt 0 ]] || { echo "usage: $0 run <command...>" >&2; exit 2; }
    trap down EXIT
    up
    "$@"
    ;;
  *) echo "usage: $0 up|down|run <command...>" >&2; exit 2 ;;
esac
