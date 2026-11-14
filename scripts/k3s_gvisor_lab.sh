#!/usr/bin/env bash
# One-node k3s + gVisor lab for Task 3 (runtimes/gvisor) and, with --cilium,
# the Cilium checks of Tasks 7, 10 and 14 (controlplane/internal/ciliumlab).
# The node is one Docker container, warden-k3s-gvisor, built from scratch out
# of the pinned k3s and runsc in .tools/ plus warden-gvisor-init and the pause
# binary built from this tree; nothing is pulled. It sits on the --internal
# network warden-k3s (no route out); the host reaches the API server on the
# node's address there. State is in .cache/k3s-gvisor/lab: kubeconfig (0600),
# lab.env (what the live tests read), node-manifest.txt and host snapshots.
#
#   scripts/k3s_gvisor_lab.sh run [--cilium] [--without-corpus] [--falco] <command...>
#                                     up, run the command, then remove what
#                                     this up created (only that)
#   scripts/k3s_gvisor_lab.sh env <command...>   run the command with lab.env exported
#   scripts/k3s_gvisor_lab.sh up [--cilium] [--without-corpus] [--falco] | down | status
#   scripts/k3s_gvisor_lab.sh purge              down, and remove the lab images
#
# By default up also builds the attack helper and the Task 5 corpus image
# (scripts/build-corpus-image.py), imports it and exports the matrix paths in
# lab.env. --without-corpus (opt-in) skips all three: nothing from attacks/ is
# built, read or imported, the node gets only the pause and probe images, and
# lab.env says WARDEN_K3S_CORPUS=without instead of the WARDEN_MATRIX_* lines.
#
# --falco (opt-in, off by default, Task 13) points the node's runsc at the
# online detector's opt-in gVisor-engine instance (detect/falco/detector.py up
# --gvisor-engine). That Falco engine exits at the first event
# (falcosecurity/libs#3074), so this mode is kept only for when it is fixed;
# the default detector covers gVisor at host level. The node image gets
# detect/falco/gvisor-pod-init.json as runsc's pod-init-config, and the node
# mounts the detector's volume warden-detect-gvisor (only its socket)
# read-only at /warden-detect. Every new sandbox then sends its trace events
# there. up refuses unless the detector's gVisor container runs. The lab never
# stops or removes the detector or its volume. lab.env says WARDEN_K3S_FALCO=1.
#
# The node container is privileged (as kind's nodes are): runsc and kubelet
# need it. What keeps it off the host: kubelet runs with
# protect-kernel-defaults (it checks the global sysctls, never writes them),
# no /lib/modules is mounted, the network, PID and cgroup namespaces are
# private, there are no host bind mounts, and it is capped at 4 GiB, 4 CPUs
# and 4096 tasks. `up` records the protected sysctls and the loaded kernel
# modules (modules-before.txt; host-before.txt has their hash), `down` records
# them again (modules-after.txt, modules-added.txt, modules-removed.txt) and
# fails if a sysctl changed. In the bridge mode it also fails if the module
# list changed.
#
# --cilium replaces the bridge CNI with Cilium 1.20.4: chart and images by
# digest from scripts/restore-tools.sh helm|cilium, imported into the node
# with ctr; values, CoreDNS and the extra gVisor handler in
# runtimes/gvisor/lab/cilium/. The node's PID 1 is then warden-node-init
# (/proc/sys read-only except net, then k3s), because Cilium's agent writes
# global kernel sysctls. That alone did not stop the agent (2026-11-12), so
# the chart's mounts of the node's /proc are made read-only too
# (readonly_proc_mounts.py), and up stops if a host sysctl changed by the time
# Cilium is ready or the agent's /host/proc/sys/kernel is writable.
# RuntimeClass gvisor-netstack runs gVisor with its own
# network stack on the pod's veth, so Cilium's policies apply to the sandbox.
# The node also joins warden-k3s-world, an --internal network in
# 198.18.0.0/15 (not RFC 1918, so Cilium sees it as "world"), where stand-ins
# (runtimes/gvisor/lab/cilium/world.py, in the local image $world_image,
# never pulled) play two origins, a stream server, a resolver that logs every
# query, and the cloud metadata server at 169.254.169.254 (routed inside the
# node only). Cilium makes the host kernel load modules; the user allowed that
# on 2026-11-11, so in this mode `down` reports the modules that appeared
# instead of failing (it still fails on a sysctl change), and `up` also lists
# the modules at each stage (modules-at-*.txt).
#
# WARDEN_LAB_CPUSET=<cpus> pins every container the lab creates
# (docker --cpuset-cpus), for a host whose other CPUs are reserved.
set -euo pipefail
# The module lists are compared with comm, which needs one byte order.
export LC_ALL=C
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
name=warden-k3s-gvisor
net=warden-k3s
world_net=warden-k3s-world
node_image=warden-k3s-gvisor:lab
cilium_image=warden-k3s-gvisor:cilium
pause_image=warden-lab/pause:1
world_image=python:3.14.4-alpine@sha256:dd4d2bd5b53d9b25a51da13addf2be586beebd5387e289e798e4083d94ca837a
state=$root/.cache/k3s-gvisor/lab
# Which worktree made the node (warden.lab/root on its container): the online
# detector's cleanup (detect/falco/detector.py clean_labs) takes down only its own.
root_id=$(printf %s "$(cd -- "$root" && pwd -P)" | sha256sum | cut -c1-16)
kubeconfig=$state/kubeconfig
envfile=$state/lab.env
go=$root/.tools/go/bin/go
helm=$root/.tools/helm/helm
cilium_tools=$root/.tools/cilium
cilium_chart=$cilium_tools/cilium-1.20.4.tgz
lab_cilium=$root/runtimes/gvisor/lab/cilium
proc=${WARDEN_LAB_PROC:-/proc} # the tests point this at a fake /proc
cpuset=()
[[ -n ${WARDEN_LAB_CPUSET:-} ]] && cpuset=(--cpuset-cpus "$WARDEN_LAB_CPUSET")
# The world's stand-ins: name, last octet on the world /24, world.py arguments.
standins=(
  "warden-k3s-origin-allowed 20 http origin-allowed"
  "warden-k3s-origin-blocked 21 http origin-blocked"
  "warden-k3s-stream 22 stream 20"
  "warden-k3s-imds 30 http warden-lab-imds"
  "warden-k3s-dns 40 dns"
)
# What this invocation created. `run` removes these and nothing else, so it
# never takes down a lab (or a network) that was there before it, or one
# that someone else created while it was building.
made_container=0
made_network=0
made_world=0
made_standins=()
snapshot_taken=0
# up --without-corpus sets corpus to 0, --falco sets falco to 1.
corpus=1
falco=0
detect_container=warden-detect-falco-gvisor
detect_volume=warden-detect-gvisor
falco_pod_init=$root/detect/falco/gvisor-pod-init.json
falco_runsc_config=/etc/containerd/warden-falco-pod-init.json
sysctls=(vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxkeys
  kernel.keys.root_maxbytes fs.inotify.max_user_instances fs.inotify.max_user_watches net.ipv4.ip_forward
  kernel.timer_migration kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid net.core.bpf_jit_enable
  net.ipv4.conf.all.rp_filter net.ipv4.fib_multipath_use_neigh)

gobuild() { # out pkg
  env -u GOFLAGS -u GOPATH -u GOROOT GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0 \
    GOFLAGS='-mod=readonly -buildvcs=false' GOCACHE="$root/.cache/go-build" GOMODCACHE="$root/.cache/go-mod" \
    GOPATH="$root/.cache/go" HOME="$root/.cache/home" "$go" build -tags netgo,osusergo -trimpath -ldflags=-s -o "$1" "$2"
}

modules() { cut -d' ' -f1 "$proc/modules" | sort; }

host_snapshot() {
  for k in "${sysctls[@]}"; do printf '%s=%s\n' "$k" "$(cat "$proc/sys/${k//.//}")"; done
  printf 'modules_sha256=%s\n' "$(modules | sha256sum | cut -d' ' -f1)"
}

build() { # bridge|cilium
  [[ -x $root/.tools/k3s/k3s ]] || "$root/scripts/restore-tools.sh" k3s
  [[ -x $root/.tools/gvisor/runsc ]] || "$root/scripts/restore-tools.sh" gvisor
  [[ -x $go ]] || "$root/scripts/restore-tools.sh" go
  local ctx=$state/node-ctx pctx=$state/pause-ctx
  rm -rf "$ctx" "$pctx"
  mkdir -p "$ctx/cni-bin" "$ctx/cni-conf" "$ctx/extra" "$pctx" "$root/.cache/warden-lab"
  cp "$root"/runtimes/gvisor/lab/node/* "$ctx/"
  if [[ $1 == cilium ]]; then
    # No bridge CNI: Cilium writes its own config once its agent runs.
    rm "$ctx/10-warden.conflist"
    cp "$lab_cilium/config-v3.toml.tmpl" "$ctx/config-v3.toml.tmpl"
    mkdir -p "$ctx/extra/etc/containerd"
    cp "$lab_cilium/runsc-netstack.toml" "$ctx/extra/etc/containerd/"
    gobuild "$ctx/extra/warden-node-init" ./runtimes/gvisor/lab/nodeinit
    chmod 0555 "$ctx/extra/warden-node-init"
  else
    mv "$ctx/10-warden.conflist" "$ctx/cni-conf/"
  fi
  if ((falco)); then
    mkdir -p "$ctx/extra/etc/containerd"
    cp "$falco_pod_init" "$ctx/extra$falco_runsc_config"
    local toml
    for toml in "$ctx/runsc.toml" "$ctx/extra/etc/containerd/runsc-netstack.toml"; do
      [[ -f $toml ]] && printf '  pod-init-config = "%s"\n' "$falco_runsc_config" >>"$toml"
    done
  fi
  ln "$root/.tools/k3s/k3s" "$ctx/k3s" 2>/dev/null || cp "$root/.tools/k3s/k3s" "$ctx/k3s"
  cp -a "$root/.tools/gvisor/runsc" "$root/.tools/gvisor/containerd-shim-runsc-v1" "$root/.tools/gvisor/gvisor-bin" "$ctx/"
  for p in bridge host-local loopback; do ln -s /var/lib/rancher/k3s/data/current/bin/cni "$ctx/cni-bin/$p"; done
  gobuild "$ctx/gvisor-init" ./runtimes/gvisor/cmd/warden-gvisor-init
  gobuild "$pctx/pause" ./runtimes/gvisor/lab/pause
  # The conformance probe, the same image the runc lab imports.
  gobuild "$root/.cache/warden-lab/warden-probe" ./runtimes/conformance/guest
  python3 -I "$root/scripts/build-probe-oci.py" >/dev/null
  if ((corpus)); then
    gobuild "$root/.cache/warden-lab/warden-attack" ./attacks/cmd/warden-attack
    python3 -B "$root/scripts/build-corpus-image.py" >/dev/null
  fi
  printf 'FROM scratch\nCOPY --chmod=0555 pause /pause\nUSER 65534:65534\nENTRYPOINT ["/pause"]\n' >"$pctx/Dockerfile"
  docker build -q --label project=warden -t "$pause_image" "$pctx" >/dev/null
  docker save "$pause_image" -o "$state/pause.tar"
  # Every input of the node, hashed; its hash is the node config identity.
  (cd "$ctx" && find . -type f -print0 | sort -z | xargs -0 sha256sum
   find . -type l -printf '%p -> %l\n' | sort) >"$state/node-manifest.txt"
  local image=$node_image
  if [[ $1 == cilium ]]; then
    image=$cilium_image
    # The chart, the images the node imports and the lab's Cilium files are inputs too.
    (cd "$cilium_tools" && sha256sum "$(basename "$cilium_chart")" images/*.oci.tar) >>"$state/node-manifest.txt"
    (cd "$root" && sha256sum runtimes/gvisor/lab/cilium/*) >>"$state/node-manifest.txt"
  fi
  docker build -q --label project=warden -t "$image" "$ctx" >/dev/null
}

# --falco needs the detector's gVisor instance running and its volume.
check_detector() {
  if [[ $(docker container inspect -f '{{.State.Running}} {{index .Config.Labels "owner"}} {{index .Config.Labels "warden.detect/role"}}' \
    "$detect_container" 2>/dev/null) != "true warden-lab falco" ]]; then
    echo "--falco needs the detector's gVisor instance $detect_container running (make detect-up)" >&2
    return 1
  fi
  if [[ $(docker volume inspect -f '{{index .Labels "owner"}} {{index .Labels "warden.detect/role"}}' "$detect_volume" \
    2>/dev/null) != "warden-lab falco" ]]; then
    echo "--falco needs the detector's volume $detect_volume (make detect-up)" >&2
    return 1
  fi
  [[ -f $falco_pod_init ]] || { echo "--falco: detector config $falco_pod_init missing" >&2; return 1; }
}

# Fails if a network with this name exists and is not Warden's internal
# network: that one is someone else's, and the lab neither joins nor removes it.
check_net() { # [name]
  local n=${1:-$net}
  if docker network inspect "$n" >/dev/null 2>&1 &&
    [[ $(docker network inspect -f '{{.Internal}} {{index .Labels "project"}}' "$n") != "true warden" ]]; then
    echo "$n exists and is not Warden's internal network; left in place" >&2
    return 1
  fi
}

kubectl() { docker exec -i "$name" kubectl "$@"; }
uid() { kubectl get "$@" -o 'jsonpath={.metadata.uid}'; }
import_oci() { docker exec -i "$name" ctr -n k8s.io images import - <"$1" >/dev/null; }

# A /24 in 198.18.0.0/15 (RFC 2544 benchmarking, never routed publicly) that
# no other Docker network uses; sets world to its first three octets.
make_world_net() {
  local x
  for x in $(seq 18 120); do
    if docker network create --internal --label project=warden --subnet "198.18.$x.0/24" "$world_net" >/dev/null 2>&1; then
      made_world=1
      world=198.18.$x
      return 0
    fi
    # Someone else may have taken the name meanwhile: never try another subnet then.
    docker network inspect "$world_net" >/dev/null 2>&1 && break
  done
  echo "no free /24 in 198.18.18.0-198.18.120.0 for $world_net" >&2
  return 1
}

# The stand-ins run world.py from this tree, read-only, in the local Python
# image (--pull never). Only the metadata stand-in keeps a capability:
# NET_ADMIN, to put 169.254.169.254 on its own loopback.
start_standins() { # world-prefix
  local s c last mode args
  for s in "${standins[@]}"; do
    read -r c last mode args <<<"$s"
    local run=(--name "$c" --label project=warden --pull never --network "$world_net" --ip "$1.$last"
      --read-only --memory 64m --memory-swap 64m --pids-limit 64 --security-opt no-new-privileges
      -v "$lab_cilium/world.py:/world.py:ro" "${cpuset[@]}")
    if [[ $c == warden-k3s-imds ]]; then
      run+=(--cap-drop ALL --cap-add NET_ADMIN "$world_image" sh -c
        "ip addr add 169.254.169.254/32 dev lo && exec python -I -u /world.py $mode $args")
    else
      # shellcheck disable=SC2206 # args is one word or none
      run+=(--user 65534:65534 --cap-drop ALL "$world_image" python -I -u /world.py "$mode" $args)
    fi
    # create, then start: if create fails, the name is someone else's.
    docker create "${run[@]}" >/dev/null
    made_standins+=("$c")
    docker start "$c" >/dev/null
  done
}

cilium_up() { # node-ip world-prefix
  local img
  for img in "$cilium_tools"/images/*.oci.tar; do import_oci "$img"; done
  "$helm" template cilium "$cilium_chart" --namespace kube-system \
    -f "$lab_cilium/values.yaml" --set k8sServiceHost="$1" >"$state/cilium-rendered.yaml"
  # The node's /proc/sys/kernel is the host's: every mount of the node's
  # /proc in the chart becomes read-only (except /proc/sys/net), or nothing
  # is applied.
  kubectl create --dry-run=client -o json -f - <"$state/cilium-rendered.yaml" >"$state/cilium-rendered.json"
  python3 -I "$lab_cilium/readonly_proc_mounts.py" <"$state/cilium-rendered.json" >"$state/cilium-applied.json" \
    2>"$state/cilium-readonly-mounts.txt" || { cat "$state/cilium-readonly-mounts.txt" >&2; return 1; }
  kubectl apply -f - <"$state/cilium-applied.json" >/dev/null
  kubectl -n kube-system rollout status ds/cilium --timeout=600s >/dev/null
  kubectl -n kube-system rollout status ds/cilium-envoy --timeout=300s >/dev/null
  kubectl -n kube-system rollout status deploy/cilium-operator --timeout=300s >/dev/null
  modules >"$state/modules-at-cilium-ready.txt"
  # Stop here if the host changed or the agent could change it.
  if ! cmp -s <(grep -v '^modules_sha256=' "$state/host-before.txt") <(host_snapshot | grep -v '^modules_sha256='); then
    echo "host sysctls changed while Cilium started:" >&2
    diff <(grep -v '^modules_sha256=' "$state/host-before.txt") <(host_snapshot | grep -v '^modules_sha256=') >&2 || true
    return 1
  fi
  kubectl -n kube-system exec ds/cilium -c cilium-agent -- cat /proc/self/mountinfo >"$state/agent-mountinfo.txt"
  local opts
  opts=$(awk '$5 == "/host/proc/sys/kernel" { print $6 }' "$state/agent-mountinfo.txt")
  if [[ $opts != ro && $opts != ro,* ]]; then
    echo "Cilium's agent can write the host's kernel sysctls (/host/proc/sys/kernel: ${opts:-not mounted})" >&2
    return 1
  fi
  sed "s/@WORLD@/$2/g" "$lab_cilium/coredns.yaml" | kubectl apply -f - >/dev/null
  kubectl -n kube-system rollout status deploy/coredns --timeout=180s >/dev/null
  # The metadata stand-in answers on 169.254.169.254; only the node routes there.
  docker exec "$name" ip route replace 169.254.169.254/32 via "$2.30"
  kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --verbose >"$state/cilium-status.txt"
  kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg version >"$state/cilium-version.txt"
}

up() { # [--cilium] [--without-corpus] [--falco]
  local cni=bridge opt
  for opt in "$@"; do
    case "$opt" in
      --cilium) cni=cilium ;;
      --without-corpus) corpus=0 ;;
      --falco) falco=1 ;;
      *) echo "unknown option $opt" >&2; return 2 ;;
    esac
  done
  if ((falco)); then check_detector || return 1; fi
  if docker container inspect "$name" >/dev/null 2>&1; then
    echo "$name already exists; run '$0 down' first" >&2
    return 1
  fi
  check_net || return 1
  if [[ $cni == cilium ]]; then
    check_net "$world_net" || return 1
    local s c
    for s in "${standins[@]}"; do
      c=${s%% *}
      if docker container inspect "$c" >/dev/null 2>&1; then
        echo "$c already exists; run '$0 down' first" >&2
        return 1
      fi
    done
    docker image inspect "$world_image" >/dev/null 2>&1 ||
      { echo "$world_image is not in the local image store; the lab does not pull it" >&2; return 1; }
    [[ -x $helm ]] || "$root/scripts/restore-tools.sh" helm
    [[ -f $cilium_tools/.complete ]] || "$root/scripts/restore-tools.sh" cilium
  fi
  mkdir -p "$state" && chmod 700 "$state"
  rm -f "$state"/modules-*.txt "$state/host-after.txt"
  echo "$cni" >"$state/cni"
  host_snapshot >"$state/host-before.txt"
  modules >"$state/modules-before.txt"
  snapshot_taken=1
  build "$cni"
  check_net || return 1 # again: build takes a while
  # k3s finds its node IP through the default route, and an internal
  # network has none, so the node gets a fixed address and --node-ip. A
  # fixed address needs a user-configured subnet: take the one Docker picks.
  if ! docker network inspect "$net" >/dev/null 2>&1; then
    docker network create --internal --label project=warden "$net" >/dev/null
    made_network=1
    local subnet
    subnet=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$net")
    docker network rm "$net" >/dev/null
    made_network=0
    docker network create --internal --label project=warden --subnet "$subnet" "$net" >/dev/null
    made_network=1
  fi
  local ip
  ip=$(python3 -I -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1])[10])' \
    "$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$net")")
  local run=(--name "$name" --label project=warden --label "warden.lab/root=$root_id" --hostname warden-gvisor
    --privileged --cgroupns=private --memory 4g --memory-swap 4g --cpus 4 --pids-limit 4096 "${cpuset[@]}"
    --tmpfs /run --tmpfs /var/run --tmpfs /tmp --network "$net" --ip "$ip")
  ((falco)) && run+=(--mount "type=volume,src=$detect_volume,dst=/warden-detect,readonly")
  local world=""
  if [[ $cni == cilium ]]; then
    check_net "$world_net" || return 1
    if docker network inspect "$world_net" >/dev/null 2>&1; then
      world=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$world_net")
      world=${world%.0/24}
    else
      make_world_net
    fi
    start_standins "$world"
    # A new network namespace copies net.ipv4.conf.all.* from the host's. A
    # host with src_valid_mark=1 (VPN clients set it) makes the node's
    # reverse-path check route a pod's packets by Cilium's proxy mark, which
    # leads to a local route: the kernel drops them as martians and Cilium's
    # DNS proxy never sees a query. This is the node's own setting only.
    # create, then start: if create fails, the name is someone else's.
    docker create "${run[@]}" --sysctl net.ipv4.conf.all.src_valid_mark=0 \
      --entrypoint /warden-node-init "$cilium_image" server --node-ip "$ip" >/dev/null
    made_container=1
    docker network connect --ip "$world.10" "$world_net" "$name"
  else
    docker create "${run[@]}" "$node_image" server --node-ip "$ip" >/dev/null
    made_container=1
  fi
  docker start "$name" >/dev/null
  local i
  # In Cilium mode the node registers but is not Ready before Cilium runs.
  for i in $(seq 1 90); do
    kubectl get node warden-gvisor >/dev/null 2>&1 && break
    [[ $i == 90 ]] && { echo "node not registered after 180 s" >&2; return 1; }
    sleep 2
  done
  [[ $cni == cilium ]] && modules >"$state/modules-at-node-registered.txt"
  local digest
  digest=$(cat "$root/.cache/warden-lab/image-digest")
  import_oci "$state/pause.tar"
  import_oci "$root/.cache/warden-lab/probe.oci.tar"
  # The archive names the image warden-lab/probe:conformance. CRI resolves
  # only normalized names, and a run refers to the image by digest.
  docker exec "$name" ctr -n k8s.io images tag warden-lab/probe:conformance docker.io/warden-lab/probe:conformance >/dev/null
  docker exec "$name" ctr -n k8s.io images tag warden-lab/probe:conformance "docker.io/warden-lab/probe@$digest" >/dev/null
  docker exec "$name" ctr -n k8s.io images rm warden-lab/probe:conformance >/dev/null
  [[ $cni == cilium ]] && cilium_up "$ip" "$world"
  for i in $(seq 1 90); do
    kubectl get node warden-gvisor 2>/dev/null | grep -q ' Ready ' && break
    [[ $i == 90 ]] && { echo "node not Ready after 180 s" >&2; return 1; }
    sleep 2
  done
  local corpus_digest='' corpus_name=''
  if ((corpus)); then
    [[ -s $root/.cache/warden-lab/corpus.oci.tar && -s $root/.cache/warden-lab/corpus-image-digest && -s $root/.cache/warden-lab/corpus-image-name ]] || { echo "corpus image missing" >&2; return 1; }
    if [[ -f $root/.cache/warden-lab/corpus.oci.tar ]]; then
      corpus_digest=$(cat "$root/.cache/warden-lab/corpus-image-digest")
      corpus_name=$(cat "$root/.cache/warden-lab/corpus-image-name")
      [[ $corpus_digest =~ ^sha256:[0-9a-f]{64}$ && $corpus_name =~ ^warden-lab/corpus:[a-zA-Z0-9._-]+$ ]] || { echo 'invalid corpus image identity' >&2; return 1; }
      docker exec -i "$name" ctr -n k8s.io images import - <"$root/.cache/warden-lab/corpus.oci.tar" >/dev/null
      docker exec "$name" ctr -n k8s.io images tag "$corpus_name" docker.io/warden-lab/corpus:matrix >/dev/null
      # The runtime uses one fixed repository and addresses both payloads by
      # manifest digest. This alias does not replace the conformance image.
      docker exec "$name" ctr -n k8s.io images tag "$corpus_name" "docker.io/warden-lab/probe@$corpus_digest" >/dev/null
    fi
  fi
  kubectl apply -f - >/dev/null <<'Y'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: gvisor}
handler: runsc
---
apiVersion: v1
kind: Namespace
metadata: {name: warden-lab}
Y
  if [[ $cni == cilium ]]; then
    kubectl apply -f - >/dev/null <<'Y'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: gvisor-netstack}
handler: runsc-netstack
Y
  fi
  (umask 077 && docker exec "$name" cat /etc/rancher/k3s/k3s.yaml | sed "s#https://127.0.0.1:6443#https://$ip:6443#" >"$kubeconfig")
  chmod 600 "$kubeconfig" # the directory's default ACL can override the umask
  cat >"$envfile" <<E
WARDEN_GVISOR_KUBECONFIG=$kubeconfig
WARDEN_GVISOR_API_HOST=$ip
WARDEN_GVISOR_NODE=warden-gvisor
WARDEN_GVISOR_NODE_CONTAINER=$name
WARDEN_GVISOR_NODE_UID=$(uid node warden-gvisor)
WARDEN_GVISOR_NAMESPACE_UID=$(uid namespace warden-lab)
WARDEN_GVISOR_CLUSTER_UID=$(uid namespace kube-system)
WARDEN_GVISOR_NODE_CONFIG_SHA256=$(sha256sum "$state/node-manifest.txt" | cut -d' ' -f1)
WARDEN_LAB_IMAGE_DIGEST=$digest
WARDEN_K3S_CNI=$cni
E
  if [[ $cni == cilium ]]; then
    cat >>"$envfile" <<E
WARDEN_CILIUM_WORLD_NETWORK=$world_net
WARDEN_CILIUM_WORLD_PREFIX=$world
WARDEN_CILIUM_STATE=$state
E
    modules >"$state/modules-at-up.txt"
  fi
  ((corpus)) || echo 'WARDEN_K3S_CORPUS=without' >>"$envfile"
  ((falco)) && echo 'WARDEN_K3S_FALCO=1' >>"$envfile"
  if [[ -n $corpus_digest ]]; then
    mkdir -p "$state/matrix" && chmod 700 "$state/matrix"
    cat >>"$envfile" <<E
WARDEN_MATRIX_CORPUS=$root/attacks/corpus
WARDEN_MATRIX_OUT=$state/matrix
WARDEN_MATRIX_IMAGE_DIGEST=$corpus_digest
WARDEN_MATRIX_TIMEOUT_S=60
E
  fi
  echo "lab up ($cni): $name on $net ($ip)${world:+ and $world_net ($world.10)}, probe $digest"
}

rm_container() { # [name]
  local c=${1:-$name}
  docker container inspect "$c" >/dev/null 2>&1 || return 0
  [[ $(docker inspect -f '{{index .Config.Labels "project"}}' "$c") == warden ]] || { echo "$c is not a Warden container" >&2; return 1; }
  docker rm -f "$c" >/dev/null
}

rm_network() { # [name]
  local n=${1:-$net}
  docker network inspect "$n" >/dev/null 2>&1 || return 0
  if [[ $(docker network inspect -f '{{index .Labels "project"}}' "$n") != warden ]]; then
    echo "$n is not a Warden network; left in place" >&2
    return 1
  fi
  docker network rm "$n" >/dev/null || { echo "$n still in use; left in place" >&2; return 1; }
}

# Compares the host with what up recorded. Sysctl changes always fail. A
# change of the module list fails in the bridge mode; in the Cilium mode it is
# allowed (user decision 2026-11-11) and reported, with the lists kept.
check_host() {
  [[ -f $state/host-before.txt ]] || return 0
  host_snapshot >"$state/host-after.txt"
  local cni=bridge rc=0
  [[ -f $state/cni ]] && cni=$(cat "$state/cni")
  if [[ -f $state/modules-before.txt ]]; then
    modules >"$state/modules-after.txt"
    comm -13 "$state/modules-before.txt" "$state/modules-after.txt" >"$state/modules-added.txt"
    comm -23 "$state/modules-before.txt" "$state/modules-after.txt" >"$state/modules-removed.txt"
  fi
  if ! cmp -s <(grep -v '^modules_sha256=' "$state/host-before.txt") <(grep -v '^modules_sha256=' "$state/host-after.txt"); then
    echo "host sysctls changed while the lab ran:" >&2
    diff "$state/host-before.txt" "$state/host-after.txt" >&2 || true
    rc=1
  fi
  if ! cmp -s "$state/host-before.txt" "$state/host-after.txt" && ((rc == 0)); then
    if [[ $cni == cilium && -f $state/modules-added.txt ]]; then
      echo "host kernel modules changed while the Cilium lab ran (allowed; lists in $state):" \
        "added: $(paste -sd' ' "$state/modules-added.txt")," \
        "removed: $(paste -sd' ' "$state/modules-removed.txt")" >&2
    else
      echo "host kernel modules changed while the lab ran:" >&2
      diff "$state/host-before.txt" "$state/host-after.txt" >&2 || true
      rc=1
    fi
  fi
  return $rc
}

down() {
  local rc=0 s
  for s in "${standins[@]}"; do rm_container "${s%% *}" || rc=1; done
  rm_container || return 1
  rm_network "$world_net" || rc=1
  rm_network || rc=1
  rm -f "$kubeconfig" "$envfile"
  check_host || rc=1
  return $rc
}

# run's EXIT trap: remove what this invocation created and nothing else.
# The exit status is the command's (or up's), or 1 if it passed and the
# teardown failed.
cleanup() {
  local rc=$? ok=0 c
  for c in "${made_standins[@]}"; do rm_container "$c" || ok=1; done
  if ((made_container)); then
    rm_container || ok=1
    rm -f "$kubeconfig" "$envfile"
  fi
  if ((made_world)); then rm_network "$world_net" || ok=1; fi
  if ((made_network)); then rm_network || ok=1; fi
  if ((snapshot_taken)); then check_host || ok=1; fi
  if ((rc == 0 && ok != 0)); then rc=1; fi
  exit "$rc"
}

case "${1:-}" in
  up) shift; up "$@" ;;
  down) down ;;
  status) docker ps -a --filter "name=^$name\$" --format '{{.Names}} {{.Status}}'; [[ -f $envfile ]] && cat "$envfile" ;;
  purge) down; docker image rm "$node_image" "$cilium_image" "$pause_image" >/dev/null 2>&1 || true ;;
  env)
    shift
    [[ -f $envfile ]] || { echo "no lab is up ($envfile missing)" >&2; exit 1; }
    set -a
    # shellcheck source=/dev/null
    . "$envfile"
    set +a
    exec "$@"
    ;;
  run)
    shift
    flag=()
    while [[ ${1:-} == --cilium || ${1:-} == --without-corpus || ${1:-} == --falco ]]; do flag+=("$1"); shift; done
    [[ $# -gt 0 ]] || { echo "usage: $0 run [--cilium] [--without-corpus] [--falco] <command...>" >&2; exit 2; }
    trap cleanup EXIT
    up "${flag[@]}"
    "$@"
    ;;
  *) echo "usage: $0 up [--cilium] [--without-corpus] [--falco]|down|status|purge|env <command...>|run [--cilium] [--without-corpus] [--falco] <command...>" >&2; exit 2 ;;
esac
