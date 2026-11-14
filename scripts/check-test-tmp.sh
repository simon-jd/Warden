#!/usr/bin/env bash
# Preflight for `make test-go`: the Go tests' temp dir (TEST_TMP) and every
# directory above it must not be writable by group or others; a root-owned
# sticky directory such as /tmp is fine. runtimes/firecracker's privateRoot
# rejects a private directory below any other such ancestor ("writable
# private ancestor"), and the check is not relaxed for tests. git clone and
# mkdir -p create directories with the caller's umask, so a checkout made
# with umask 0002 has group-writable directories, and without this preflight
# the Firecracker tests fail one by one and make stops before the Python,
# pySigma and Vector suites.
#
#   scripts/check-test-tmp.sh DIR
set -euo pipefail
[[ $# -eq 1 && $1 == /* ]] || { echo "usage: $0 ABSOLUTE_DIR" >&2; exit 2; }
dir=$(realpath -ms -- "$1")
bad=()
p=$dir
while :; do
  info=$(stat -c '%f %u' -- "$p")
  mode=$((16#${info% *})) uid=${info#* }
  if ((mode & 8#022)) && ! ((uid == 0 && mode & 8#1000)); then
    bad+=("$p")
  fi
  [[ $p == / ]] && break
  p=$(dirname -- "$p")
done
((${#bad[@]} == 0)) && exit 0
{
  echo "make: group or others can write the Go tests' temp dir $dir or a directory above it:"
  stat -c '  %A %U %n' -- "${bad[@]}"
  echo "runtimes/firecracker refuses a private directory there (writable private ancestor), so its tests would fail."
  echo "Fix, then run make again:"
  echo "  chmod go-w ${bad[*]}"
  echo "git clone and make create directories with your umask; a clone made, and make run, with umask 022 has none of these."
} >&2
exit 1
