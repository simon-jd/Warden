#!/usr/bin/env bash
cd /home/postedism/Desktop/Warden-next
d=/home/postedism/Desktop/Warden-next/docs/evidence/task-10/cilium-lab-20261112/lab-run2
{ echo "head $(git rev-parse HEAD)"; git status --short; } > $d/source.txt
date -Is > $d/up-started.txt; cat /proc/loadavg >> $d/up-started.txt
.cache/cilium-lab-baseline/sysctl-dump.sh 2>/dev/null > $d/sysctl-full-before.txt
LC_ALL=C sort -u <(cut -d' ' -f1 /proc/modules) > $d/modules-host-before.txt
WARDEN_LAB_CPUSET=0-7,16-31 taskset -c 0-7,16-31 scripts/k3s_gvisor_lab.sh up --cilium > $d/up.log 2>&1
echo "up rc=$?" >> $d/up.log
date -Is >> $d/up.log; cat /proc/loadavg >> $d/up.log
