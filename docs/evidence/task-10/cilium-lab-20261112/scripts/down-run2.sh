#!/usr/bin/env bash
# Take the lab that has been up since 23:36 (lab-run2) down, with the host records.
cd /home/postedism/Desktop/Warden-next || exit 1
export LC_ALL=C
d=docs/evidence/task-10/cilium-lab-20261112/lab-run2
st=.cache/k3s-gvisor/lab
k() { docker exec warden-k3s-gvisor kubectl "$@"; }
date -Is > $d/down-started.txt; cat /proc/loadavg >> $d/down-started.txt
{ k get pods -A -o wide; k get ccnp,cnp -A; k -n kube-system get cm cilium-config -o jsonpath='{.data.identity-max-jitter} {.data.identity-change-grace-period}'; echo; k -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg endpoint list; } > $d/pods-and-endpoints-before-down.txt 2>&1
cat /proc/modules > $d/proc-modules-before-down.txt
for f in modules-before.txt modules-at-node-registered.txt modules-at-cilium-ready.txt modules-at-up.txt host-before.txt cilium-status.txt cilium-version.txt node-manifest.txt cilium-readonly-mounts.txt agent-mountinfo.txt cni; do cp $st/$f $d/; done
scripts/k3s_gvisor_lab.sh down > $d/down.log 2>&1; echo "down rc=$? $(date -Is)" >> $d/down.log
for f in modules-after.txt modules-added.txt modules-removed.txt host-after.txt; do cp $st/$f $d/ 2>/dev/null; done
cat /proc/modules > $d/proc-modules-after-down.txt
LC_ALL=C sort -u <(cut -d' ' -f1 /proc/modules) > $d/modules-host-after.txt
.cache/cilium-lab-baseline/sysctl-dump.sh 2>/dev/null > $d/sysctl-full-after.txt
diff $d/sysctl-full-before.txt $d/sysctl-full-after.txt > $d/sysctl-full-diff.txt; echo "diff rc=$?" >> $d/sysctl-full-diff.txt
{ docker ps -a --filter label=project=warden --format '{{.Names}} {{.Status}}'; docker network ls --filter label=project=warden --format '{{.Name}}'; } > $d/warden-docker-after-down.txt
date -Is >> $d/down.log
