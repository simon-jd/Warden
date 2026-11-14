#!/bin/bash
# Firecracker capacity-pressure, corpus-free package, 2026-11-13. Scratch only; evidence copied out afterwards.
set -u
W=$HOME/Desktop/Warden-next; R=$W/.cache/fc-run; cd "$W" || exit 1
sysctls=(vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxkeys kernel.keys.root_maxbytes fs.inotify.max_user_instances fs.inotify.max_user_watches net.ipv4.ip_forward kernel.timer_migration kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid net.core.bpf_jit_enable net.ipv4.conf.all.rp_filter net.ipv4.fib_multipath_use_neigh)
snap() { # prefix
  { echo "at_utc $(date -u +%FT%T.%NZ)"; echo "kernel $(uname -r)"; echo "loadavg $(cat /proc/loadavg)"; for k in "${sysctls[@]}"; do printf '%s=%s\n' "$k" "$(cat /proc/sys/${k//.//})"; done; echo "modules_sha256 $(cut -d' ' -f1 /proc/modules | sort | sha256sum | cut -d' ' -f1)"; free -b | sed 's/^/free /'; } > "$1.protected.txt"
  cut -d' ' -f1 /proc/modules | sort > "$1.modules.txt"
  sysctl -a 2>/dev/null | sort > "$1.sysctl.txt"
  for f in /sys/module/kvm/parameters/* /sys/module/kvm_intel/parameters/*; do echo "$f=$(cat "$f" 2>/dev/null)"; done > "$1.kvm.txt"
  { echo "containers:"; docker ps -a --filter label=project=warden --format '{{.ID}} {{.Names}} {{.Status}} {{.Labels}}'; echo "images:"; docker images --filter label=project=warden --format '{{.ID}} {{.Repository}}:{{.Tag}} {{.Size}}'; } > "$1.docker.txt"
}
pin() { # pins every Warden lab container to the CPUs this host lends to it
  while [ ! -e "$R/stop" ]; do
    for id in $(docker ps -aq --no-trunc --filter label=project=warden --filter label=owner=warden-lab 2>/dev/null); do
      grep -q "$id" "$R/pinned.txt" 2>/dev/null && continue
      st=$(docker inspect -f '{{.State.Status}} task={{index .Config.Labels "task"}}' "$id" 2>/dev/null)
      if docker update --cpuset-cpus 0-7,16-31 "$id" >/dev/null 2>&1; then echo "$(date -u +%FT%T.%NZ) pinned $id state_before=$st" >> "$R/pinned.txt"; else echo "$(date -u +%FT%T.%NZ) pin-failed $id state=$st" >> "$R/pin-errors.txt"; fi
    done
    sleep 0.2
  done
}
sample() { # prefix: host-side view of the running outer's cgroup, once a second
  while [ ! -e "$1.done" ]; do
    for id in $(docker ps -q --no-trunc --filter label=project=warden --filter label=task=firecracker 2>/dev/null); do
      c=/sys/fs/cgroup/system.slice/docker-$id.scope
      [ -d "$c" ] && echo "$(date -u +%FT%T.%NZ) ${id:0:12} pids.current=$(cat $c/pids.current 2>/dev/null) pids.peak=$(cat $c/pids.peak 2>/dev/null) pids.max=$(cat $c/pids.max 2>/dev/null) pids.events=[$(tr '\n' ' ' < $c/pids.events 2>/dev/null)] pids.events.local=[$(tr '\n' ' ' < $c/pids.events.local 2>/dev/null)] memory.current=$(cat $c/memory.current 2>/dev/null) memory.events=[$(tr '\n' ' ' < $c/memory.events 2>/dev/null)] cpuset.effective=$(cat $c/cpuset.cpus.effective 2>/dev/null) load=[$(cat /proc/loadavg)]"
    done
    sleep 1
  done >> "$1.cgroup.txt"
}
step() { # name args...
  local n=$1; shift
  snap "$R/$n.before"; rm -f "$R/$n.done"; sample "$R/$n" & local s=$!
  echo "start_utc $(date -u +%FT%T.%NZ) head $(git rev-parse HEAD) status=[$(git status --short | tr '\n' ' ')] cmd=$*" > "$R/$n.host.txt"
  taskset -c 0-7,16-31 "$@" > "$R/$n.log" 2>&1; local rc=$?
  echo "exit $rc end_utc $(date -u +%FT%T.%NZ)" >> "$R/$n.host.txt"
  touch "$R/$n.done"; wait $s; snap "$R/$n.after"
  for k in protected modules sysctl kvm; do diff "$R/$n.before.$k.txt" "$R/$n.after.$k.txt" > "$R/$n.diff.$k.txt"; done
  return $rc
}
rm -f "$R/stop"; pin & P=$!
step prepare python3 -B scripts/firecracker_lab.py prepare --without-corpus --other-service-memory-bytes 0 \
 && { step pressure-1 python3 -B scripts/firecracker_lab.py capacity-pressure --without-corpus --other-service-memory-bytes 0
      step pressure-2 python3 -B scripts/firecracker_lab.py capacity-pressure --without-corpus --other-service-memory-bytes 0; }
touch "$R/stop"; wait $P
echo "all done $(date -u +%FT%T.%NZ)" > "$R/finished"
