#!/usr/bin/env bash
# Which kernel modules appeared on the host, and in which window, from the lab's own lists.
# Every list is re-sorted bytewise here: lab-run1-1945/modules-before.txt was sorted in the
# user's locale (the script at 19:45 did not set LC_ALL=C), so its modules-added.txt and
# modules-removed.txt, made with comm from two sort orders, are wrong.
# Run from this directory: ./modules-attribution.sh > modules-attribution.txt
export LC_ALL=C
cd "$(dirname "$0")" || exit 1
s() { sort -u "$1"; }
step() { # label older newer
  local add rem
  add=$(comm -13 <(s "$2") <(s "$3") | paste -sd' ')
  rem=$(comm -23 <(s "$2") <(s "$3") | paste -sd' ')
  printf '%-62s +[%s] -[%s]\n' "$1" "$add" "$rem"
}
old=../cilium-k3s-20261110/modules-now.txt
echo "# Each line: what appeared (+) and disappeared (-) between two lists of loaded modules."
echo "# 2026-11-10 attempt (../cilium-k3s-20261110): after = before + geneve xt_socket nf_socket_ipv4 nf_socket_ipv6 (its README)."
step "11-10 17:57 (after that attempt) -> 11-12 19:32 baseline" $old lab-run1-1945/modules-baseline.txt
step "11-12 19:32 baseline -> run 1 up started (~19:45)" lab-run1-1945/modules-baseline.txt lab-run1-1945/modules-before.txt
step "run 1: up started -> node registered" lab-run1-1945/modules-before.txt lab-run1-1945/modules-at-node-registered.txt
step "run 1: node registered -> Cilium ready" lab-run1-1945/modules-at-node-registered.txt lab-run1-1945/modules-at-cilium-ready.txt
step "run 1: Cilium ready -> up done" lab-run1-1945/modules-at-cilium-ready.txt lab-run1-1945/modules-at-up.txt
step "run 1: up done -> down (11-12 23:26)" lab-run1-1945/modules-at-up.txt lab-run1-1945/modules-after.txt
step "run 1 down -> run 2 attempt 1 (23:34)" lab-run1-1945/modules-after.txt lab-run2-attempt1/modules-host-before.txt
step "run 2 attempt 1: before -> after (failed up, 23:34)" lab-run2-attempt1/modules-before.txt lab-run2-attempt1/modules-after.txt
step "run 2 attempt 1 after -> run 2 (23:36)" lab-run2-attempt1/modules-after.txt lab-run2/modules-host-before.txt
step "run 2: up started -> node registered" lab-run2/modules-before.txt lab-run2/modules-at-node-registered.txt
step "run 2: node registered -> Cilium ready" lab-run2/modules-at-node-registered.txt lab-run2/modules-at-cilium-ready.txt
step "run 2: Cilium ready -> up done" lab-run2/modules-at-cilium-ready.txt lab-run2/modules-at-up.txt
step "run 2: up done -> down (11-13 08:27)" lab-run2/modules-at-up.txt lab-run2/modules-after.txt
if [[ -f lab-run3/modules-after.txt ]]; then
  step "run 2 down -> run 3 (08:28)" lab-run2/modules-host-after.txt lab-run3/modules-host-before.txt
  step "run 3: up started -> node registered" lab-run3/modules-before.txt lab-run3/modules-at-node-registered.txt
  step "run 3: node registered -> Cilium ready" lab-run3/modules-at-node-registered.txt lab-run3/modules-at-cilium-ready.txt
  step "run 3: Cilium ready -> up done" lab-run3/modules-at-cilium-ready.txt lab-run3/modules-at-up.txt
  step "run 3: up done -> down" lab-run3/modules-at-up.txt lab-run3/modules-after.txt
  step "run 3 down -> after the run" lab-run3/modules-after.txt lab-run3/modules-host-after.txt
fi
for f in final/modules-host-final.txt; do [[ -f $f ]] && step "last record -> final ($f)" lab-run3/modules-host-after.txt $f; done
echo
echo "# All of 11-12 and 11-13 together: 19:32 baseline -> last list"
last=lab-run2/modules-host-after.txt
[[ -f lab-run3/modules-host-after.txt ]] && last=lab-run3/modules-host-after.txt
[[ -f final/modules-host-final.txt ]] && last=final/modules-host-final.txt
step "baseline -> $last" lab-run1-1945/modules-baseline.txt $last
