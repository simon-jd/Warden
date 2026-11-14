#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/.cache/go-build" "$root/.cache/go-mod" "$root/.cache/home"
exec docker run --rm --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --network host --tmpfs /tmp:rw,exec,nosuid,nodev \
  --mount "type=bind,src=$root,dst=/workspace" --workdir /workspace \
  -e HOME=/workspace/.cache/home -e GOCACHE=/workspace/.cache/go-build \
  -e GOPATH=/workspace/.cache/go -e GOMODCACHE=/workspace/.cache/go-mod -e GOTOOLCHAIN=auto \
  -e WARDEN_TEST_DATABASE_URL -e DATABASE_URL -e WARDEN_LISTEN_ADDR \
  golang:1.26.8-bookworm go "$@"
