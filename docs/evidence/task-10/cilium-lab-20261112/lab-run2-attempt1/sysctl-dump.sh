#!/usr/bin/env bash
# Every sysctl this user can read in the host's namespaces, one per line as
# key=value (tabs and newlines become spaces), sorted under LC_ALL=C.
# Per-interface entries (net.ipv4/ipv6 conf and neigh other than all/default)
# are left out: Docker adds and removes veths all the time.
export LC_ALL=C
cd /proc/sys || exit 1
find . -type f -perm -u=r 2>/dev/null | sed 's#^\./##' |
  grep -Ev '^net/ipv[46]/(conf|neigh)/' | sort | while read -r f; do
  v=$(tr '\t\n' '  ' < "$f" 2>/dev/null) || continue
  printf '%s=%s\n' "${f//\//.}" "${v% }"
done
find . -type f -perm -u=r 2>/dev/null | sed 's#^\./##' |
  grep -E '^net/ipv[46]/(conf|neigh)/(all|default)/' | sort | while read -r f; do
  v=$(tr '\t\n' '  ' < "$f" 2>/dev/null) || continue
  printf '%s=%s\n' "${f//\//.}" "${v% }"
done
