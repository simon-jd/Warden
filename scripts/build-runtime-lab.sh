#!/usr/bin/env bash
# Build only. Does not run a guest or contact any container daemon.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
mkdir -p .cache/warden-lab
scripts/go.sh build -tags netgo,osusergo -trimpath -ldflags=-s -o .cache/warden-lab/warden-probe ./runtimes/conformance/guest
scripts/go.sh test -tags netgo,osusergo -c -o .cache/warden-lab/runc.test ./runtimes/runc
scripts/go.sh test -tags netgo,osusergo -c -o .cache/warden-lab/api.test ./controlplane/internal/apilab
scripts/go.sh test -tags netgo,osusergo -c -o .cache/warden-lab/runs.test ./controlplane/internal/runs
scripts/go.sh test -tags netgo,osusergo -c -o .cache/warden-lab/scheduler.test ./controlplane/internal/scheduler
python3 scripts/build-probe-oci.py

# Privileged runner rejects build artifacts writable by group/other.
chmod go-w .cache/warden-lab/{warden-probe,runc.test,api.test,runs.test,scheduler.test,probe.oci.tar,image-digest,image-name}
