#!/usr/bin/env bash
# lab-run3: make test-cilium on a fresh lab (scripts/k3s_gvisor_lab.sh run --cilium: up, every live test, down),
# with the host's sysctls and modules before and after, and the refcounts of the Cilium modules every 10 s.
cd /home/postedism/Desktop/Warden-next || exit 1
export LC_ALL=C
E=docs/evidence/task-10/cilium-lab-20261112
d=$E/lab-run3; r=$E/runs/09-all
mkdir -p $d $r
st=.cache/k3s-gvisor/lab
{ echo "head $(git rev-parse HEAD)"; git status --short; } > $d/source.txt
date -Is > $d/started.txt; cat /proc/loadavg >> $d/started.txt
.cache/cilium-lab-baseline/sysctl-dump.sh 2>/dev/null > $d/sysctl-full-before.txt
sort -u <(cut -d' ' -f1 /proc/modules) > $d/modules-host-before.txt
cat /proc/modules > $d/proc-modules-before.txt
mods='^(cls_bpf|sch_ingress|xt_TPROXY|nf_tproxy_ipv4|nf_tproxy_ipv6|xt_CT|xt_socket|nf_socket_ipv4|nf_socket_ipv6|geneve|vxlan|nft_masq|xt_mark|ip_set) '
( while :; do echo "# $(date -Is) lab: $(docker ps --filter name=^warden-k3s-gvisor$ --format '{{.Status}}')"; grep -E "$mods" /proc/modules | cut -d' ' -f1,3,4; sleep 10; done ) > $d/module-refcounts.txt 2>&1 &
poller=$!
{
  echo "# $(date -Iseconds) head $(git rev-parse --short HEAD); git status --short:"
  git status --short
  cat /proc/loadavg
  echo "\$ WARDEN_LAB_CPUSET=0-7,16-31 taskset -c 0-7,16-31 make test-cilium CILIUM_OUT=$PWD/$r"
  WARDEN_LAB_CPUSET=0-7,16-31 taskset -c 0-7,16-31 make test-cilium CILIUM_OUT="$PWD/$r" 2>&1
  echo "exit $?"
  echo "# $(date -Iseconds)"; cat /proc/loadavg
} > $r/run.log 2>&1
kill $poller
for f in modules-before.txt modules-at-node-registered.txt modules-at-cilium-ready.txt modules-at-up.txt modules-after.txt modules-added.txt modules-removed.txt host-before.txt host-after.txt cilium-status.txt cilium-version.txt node-manifest.txt cilium-readonly-mounts.txt agent-mountinfo.txt cni; do cp $st/$f $d/ 2>/dev/null; done
sleep 15
cat /proc/modules > $d/proc-modules-after.txt
sort -u <(cut -d' ' -f1 /proc/modules) > $d/modules-host-after.txt
.cache/cilium-lab-baseline/sysctl-dump.sh 2>/dev/null > $d/sysctl-full-after.txt
diff $d/sysctl-full-before.txt $d/sysctl-full-after.txt > $d/sysctl-full-diff.txt; echo "diff rc=$?" >> $d/sysctl-full-diff.txt
{ docker ps -a --filter label=project=warden --format '{{.Names}} {{.Status}}'; docker network ls --filter label=project=warden --format '{{.Name}}'; } > $d/warden-docker-after.txt
date -Is > $d/finished.txt; cat /proc/loadavg >> $d/finished.txt
