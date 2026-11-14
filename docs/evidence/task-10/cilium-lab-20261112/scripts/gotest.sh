#!/usr/bin/env bash
# gotest.sh <pkg> <run regexp>: go test with the Makefile's environment, on CPUs 0-7,16-31.
cd /home/postedism/Desktop/Warden-next || exit 1
R=$PWD
echo "# $(date -Iseconds) head $(git rev-parse --short HEAD); git status --short:"
git status --short
echo "\$ go test -count=1 -run '$2' $1"
taskset -c 0-7,16-31 env -u GOFLAGS -u GOPATH -u GOROOT GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly \
  GOCACHE=$R/.cache/go-build GOMODCACHE=$R/.cache/go-mod GOPATH=$R/.cache/go HOME=$R/.cache/home TMPDIR=$R/.cache/test-tmp \
  $R/.tools/go/bin/go test -buildvcs=false -count=1 -run "$2" "$1" 2>&1
echo "exit $?"
