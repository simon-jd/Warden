#!/usr/bin/env bash
# Restore project-local toolchains into .tools/ (gitignored, inside the 24 GB
# disk share). Each tool is taken from the project .cache when it is already
# there, otherwise downloaded from its official release URL and checked
# against a pinned SHA-256. Nothing is installed outside the project.
#
#   scripts/restore-tools.sh go|vector|python|kyverno|kind|k3s|gvisor|terraform|helm|cilium|kubectl|falco
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tools=$root/.tools
cache=$root/.cache
mkdir -p "$tools"

GO_VERSION=1.26.10
VECTOR_VERSION=0.45.0
VECTOR_SHA256=0588f529200befa3237481255b9b7715316de73d626e1d01042e054f92205c71
KYVERNO_VERSION=1.19.2
# From the release's checksums.txt (sha256 f06301ce...) and the GitHub API asset digest.
KYVERNO_SHA256=357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a
KIND_VERSION=0.33.0
# From the release's kind-linux-amd64.sha256sum and the GitHub API asset digest.
# kind 0.33.0 pins kindest/node:v1.34.11@sha256:44e222ee..., the image the kind labs use.
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
K3S_VERSION=v1.36.5+k3s1
# From the release's sha256sum-amd64.txt (the "k3s" line).
K3S_SHA256=d73847bcd3c5fccef0115b372e2f9a91f3032dc84bbf71518a4617565294d313
GVISOR_RELEASE=release-20261019.0
# From the release's SHA256SUMS (the "gvisor-x86_64.tar.bz2" line).
GVISOR_SHA256=1298e8ed9c3fee900f00d2ea96ec2d79d80ed93f2175812f29b7e7da718041a3
TERRAFORM_VERSION=1.17.1
# From terraform_1.17.1_SHA256SUMS, whose .sig verified against HashiCorp's key
# C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F on 2026-11-10.
TERRAFORM_SHA256=4638628058e71a55212b1c563712eac03b902128f40740f3dc8174df12135061
KUBECTL_VERSION=v1.36.5
# From dl.k8s.io/release/v1.36.5/bin/linux/amd64/kubectl.sha256 (2026-11-13;
# the binary is dated 2026-09-23). The AKS drill (scripts/aks_drill.py) runs
# Kubernetes 1.36.5, so client and server are the same version.
KUBECTL_SHA256=33bc88a24c3b09cf55bfd59e6ca977881b61fc3f25ab65bc80c65b430248648e
HELM_VERSION=v3.22.1
# From get.helm.sh/helm-v3.22.1-linux-amd64.tar.gz.sha256sum. Only used for
# `helm template` (scripts/k3s_gvisor_lab.sh up --cilium).
HELM_SHA256=896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea
# Cilium for the k3s lab's --cilium mode, all from quay.io / Docker Hub by
# digest (no GitHub): the chart is the OCI artifact quay.io/cilium/charts/cilium
# (manifest digest below; its one layer is the chart .tgz), and the images are
# the digests the chart's values.yaml pins (cilium, operator-generic,
# cilium-envoy), CoreDNS for kube-dns, and the Envoy the egress proxy runs
# (the same digest as the Docker egress lab's envoyproxy/envoy:v1.40.2).
CILIUM_VERSION=1.20.4
CILIUM_CHART_MANIFEST=sha256:712e1f65bf30533d117d1996ac3ace3efdb2521302d31ee887b1e45806bd6b64
CILIUM_CHART_SHA256=505abff8385811df1a949776fc42e9f10697989a332acc86d6e8933efcb855ed
CILIUM_IMAGES=(
  cilium=quay.io/cilium/cilium:v1.20.4@sha256:20fe92e4c86641233a450098c158d2d29085f3419931ab6bf681d2485dedf16e
  operator-generic=quay.io/cilium/operator-generic:v1.20.4@sha256:7a7a3489dc66ad67e420d285c8a8d2e169b0957ad15e120f593d27081bf38d82
  cilium-envoy=quay.io/cilium/cilium-envoy:v1.39.5-1792733054-8c73b2816bc8239e27f1fd53b271884688137459@sha256:547ab45f6092f681d9f54f3be9fa8fb1e705c9c5dc2df388efe3a52aa6965629
  coredns=docker.io/coredns/coredns:1.14.7@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286
  envoy=docker.io/envoyproxy/envoy:v1.40.2@sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb
)

# Task 13's online detector (detect/falco/detector.py): two Falco images by
# index digest, read from registry-1.docker.io on 2026-11-14. 0.45.2 runs the
# host's modern eBPF probe; 0.43.1's probe is rejected by this kernel's (7.0)
# verifier (docs/evidence/task-13/online-detector-20261113). 0.43.1 runs the
# gVisor engine, which 0.44.0 dropped. scripts/oci_fetch.py checks the index,
# the linux/amd64 manifest and every blob; the detector runs each by its
# manifest digest (Docker's image ID): 0.45.2 sha256:27a94a28...e102,
# 0.43.1 sha256:9f3e058c...8a31.
FALCO_IMAGES=(
  falco-0.45.2=docker.io/falcosecurity/falco:0.45.2@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e
  falco-0.43.1=docker.io/falcosecurity/falco:0.43.1@sha256:b4166a61f41e2fa638c041cac881d8bb32c284e3aaf282fdfed80f15f6eb55e3
)

check_sha() { # file expected
  local got
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [[ "$got" != "$2" ]]; then
    echo "checksum mismatch for $1: got $got want $2" >&2
    return 1
  fi
}

restore_go() {
  local dest=$tools/go cached=$cache/go-mod/golang.org/toolchain@v0.0.1-go$GO_VERSION.linux-amd64
  [[ -x $dest/bin/go ]] && return 0
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  if [[ -x $cached/bin/go ]]; then
    # The Go module cache already verified this toolchain against sum.golang.org.
    cp -a "$cached/." "$dest.tmp/"
    chmod -R u+w "$dest.tmp"
  else
    local tgz=$tools/go$GO_VERSION.linux-amd64.tar.gz want
    curl -fsSL -o "$tgz" "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz"
    want=$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' | python3 -I -c '
import json, sys
name = sys.argv[1]
for release in json.load(sys.stdin):
    for f in release["files"]:
        if f["filename"] == name:
            print(f["sha256"]); sys.exit(0)
sys.exit("no checksum published for " + name)' "go$GO_VERSION.linux-amd64.tar.gz")
    check_sha "$tgz" "$want"
    tar -xzf "$tgz" -C "$dest.tmp" --strip-components=1
    rm -f "$tgz"
  fi
  mv "$dest.tmp" "$dest"
}

restore_vector() {
  local dest=$tools/vector name=vector-$VECTOR_VERSION-x86_64-unknown-linux-musl.tar.gz
  [[ -x $dest/bin/vector ]] && return 0
  local tgz=$cache/task11-material-once-$VECTOR_VERSION/$name
  if [[ ! -f $tgz ]]; then
    tgz=$tools/$name
    curl -fsSL -o "$tgz" "https://github.com/vectordotdev/vector/releases/download/v$VECTOR_VERSION/$name"
  fi
  check_sha "$tgz" "$VECTOR_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  tar -xzf "$tgz" -C "$dest.tmp"
  [[ $tgz == "$tools/$name" ]] && rm -f "$tgz"
  local bin
  bin=$(find "$dest.tmp" -path '*/bin/vector' -type f | head -n 1)
  [[ -n $bin ]] || { echo "no bin/vector in $name" >&2; return 1; }
  mv "$(dirname "$(dirname "$bin")")" "$dest"
  rm -rf "$dest.tmp"
}

restore_kyverno() {
  local dest=$tools/kyverno name=kyverno-cli_v${KYVERNO_VERSION}_linux_x86_64.tar.gz
  [[ -x $dest/kyverno ]] && return 0
  local tgz=$cache/kyverno-download/$name
  if [[ ! -f $tgz ]]; then
    mkdir -p "$cache/kyverno-download"
    curl -fsSL "https://github.com/kyverno/kyverno/releases/download/v$KYVERNO_VERSION/$name" -o "$tgz"
  fi
  check_sha "$tgz" "$KYVERNO_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  tar -xzf "$tgz" -C "$dest.tmp" kyverno
  mv "$dest.tmp" "$dest"
}

restore_kubectl() {
  local dest=$tools/kubectl bin=$cache/kubectl-download/kubectl-$KUBECTL_VERSION
  [[ -x $dest/kubectl ]] && return 0
  if [[ ! -f $bin ]]; then
    mkdir -p "$cache/kubectl-download"
    curl -fsSL "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" -o "$bin.part"
    mv "$bin.part" "$bin"
  fi
  check_sha "$bin" "$KUBECTL_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  install -m 0755 "$bin" "$dest.tmp/kubectl"
  mv "$dest.tmp" "$dest"
}

restore_kind() {
  local dest=$tools/kind bin=$cache/kind-download/kind-linux-amd64
  [[ -x $dest/kind ]] && return 0
  if [[ ! -f $bin ]]; then
    mkdir -p "$cache/kind-download"
    curl -fsSL "https://github.com/kubernetes-sigs/kind/releases/download/v$KIND_VERSION/kind-linux-amd64" -o "$bin"
  fi
  check_sha "$bin" "$KIND_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  install -m 0755 "$bin" "$dest.tmp/kind"
  mv "$dest.tmp" "$dest"
}

# k3s and gVisor for the Task 3 lab (scripts/k3s_gvisor_lab.sh). Both are
# kept in .cache/warden-k3s-materials, where the earlier Task 3 rounds put them.
restore_k3s() {
  local dest=$tools/k3s bin=$cache/warden-k3s-materials/k3s
  [[ -x $dest/k3s ]] && return 0
  if [[ ! -f $bin ]]; then
    mkdir -p "$cache/warden-k3s-materials"
    curl -fsSL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION//+/%2B}/k3s" -o "$bin"
  fi
  check_sha "$bin" "$K3S_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  install -m 0755 "$bin" "$dest.tmp/k3s"
  mv "$dest.tmp" "$dest"
}

restore_gvisor() {
  local dest=$tools/gvisor tbz=$cache/warden-k3s-materials/gvisor.tar.bz2
  [[ -x $dest/runsc ]] && return 0
  if [[ ! -f $tbz ]]; then
    mkdir -p "$cache/warden-k3s-materials"
    curl -fsSL "https://github.com/google/gvisor/releases/download/$GVISOR_RELEASE/gvisor-x86_64.tar.bz2" -o "$tbz"
  fi
  check_sha "$tbz" "$GVISOR_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  # Only the runtime, its shim and the sidecars runsc expects next to itself.
  tar -xjf "$tbz" -C "$dest.tmp" --no-same-owner --no-same-permissions runsc containerd-shim-runsc-v1 gvisor-bin
  chmod -R go-w "$dest.tmp"
  mv "$dest.tmp" "$dest"
}

restore_helm() {
  local dest=$tools/helm name=helm-$HELM_VERSION-linux-amd64.tar.gz
  [[ -x $dest/helm ]] && return 0
  local tgz=$cache/cilium-download/$name
  if [[ ! -f $tgz ]]; then
    mkdir -p "$cache/cilium-download"
    curl -fsSL "https://get.helm.sh/$name" -o "$tgz"
  fi
  check_sha "$tgz" "$HELM_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  tar -xzf "$tgz" -C "$dest.tmp" --strip-components=1 --no-same-owner linux-amd64/helm
  rm -rf "$dest" && mv "$dest.tmp" "$dest"
}

# The chart and the images, each checked against its pin before .complete is
# written; scripts/oci_fetch.py writes an image archive only if every byte
# matches the digest.
restore_cilium() {
  local dest=$tools/cilium dl=$cache/cilium-download
  [[ -f $dest/.complete ]] && return 0
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp/images" "$dl"
  local chart=$dl/cilium-$CILIUM_VERSION.tgz
  if [[ ! -f $chart ]]; then
    local token manifest=$dl/chart-manifest.json
    token=$(curl -fsS "https://quay.io/v2/auth?service=quay.io&scope=repository:cilium/charts/cilium:pull" |
      python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])')
    curl -fsS -H "Authorization: Bearer $token" -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
      "https://quay.io/v2/cilium/charts/cilium/manifests/$CILIUM_CHART_MANIFEST" -o "$manifest"
    check_sha "$manifest" "${CILIUM_CHART_MANIFEST#sha256:}"
    grep -q "sha256:$CILIUM_CHART_SHA256" "$manifest" || { echo "chart manifest does not name the pinned chart" >&2; return 1; }
    curl -fsSL -H "Authorization: Bearer $token" \
      "https://quay.io/v2/cilium/charts/cilium/blobs/sha256:$CILIUM_CHART_SHA256" -o "$chart.tmp"
    mv "$chart.tmp" "$chart"
  fi
  check_sha "$chart" "$CILIUM_CHART_SHA256"
  cp "$chart" "$dest.tmp/"
  local entry
  for entry in "${CILIUM_IMAGES[@]}"; do
    python3 -I -B "$root/scripts/oci_fetch.py" "${entry#*=}" "$dest.tmp/images/${entry%%=*}.oci.tar" \
      >"$dest.tmp/images/${entry%%=*}.receipt.json"
  done
  touch "$dest.tmp/.complete"
  rm -rf "$dest" && mv "$dest.tmp" "$dest"
}

# Each image archive is written only if every byte matches its digest.
restore_falco() {
  local dest=$tools/falco entry
  [[ -f $dest/.complete ]] && return 0
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  for entry in "${FALCO_IMAGES[@]}"; do
    python3 -I -B "$root/scripts/oci_fetch.py" "${entry#*=}" "$dest.tmp/${entry%%=*}.oci.tar" \
      >"$dest.tmp/${entry%%=*}.receipt.json"
  done
  touch "$dest.tmp/.complete"
  rm -rf "$dest" && mv "$dest.tmp" "$dest"
}

restore_terraform() {
  local dest=$tools/terraform name=terraform_${TERRAFORM_VERSION}_linux_amd64.zip
  [[ -x $dest/terraform ]] && return 0
  local zip=$cache/terraform-download/$name
  if [[ ! -f $zip ]]; then
    mkdir -p "$cache/terraform-download"
    curl -fsSL "https://releases.hashicorp.com/terraform/$TERRAFORM_VERSION/$name" -o "$zip"
  fi
  check_sha "$zip" "$TERRAFORM_SHA256"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("terraform", sys.argv[2])' "$zip" "$dest.tmp"
  chmod 0755 "$dest.tmp/terraform"
  mv "$dest.tmp" "$dest"
}

restore_python() {
  # Virtualenv for the pySigma suite; hashes are pinned in requirements.lock.
  local dest=$tools/py lock=$root/detect/sigma/requirements.lock
  local wheels=$cache/task12-material-20261025-a/wheels
  # .lock-sha256 is written last and marks a complete venv for this lock file.
  if [[ -f $dest/.lock-sha256 ]] && check_sha "$lock" "$(cat "$dest/.lock-sha256")" 2>/dev/null; then
    return 0
  fi
  rm -rf "$dest"
  # venvs are not relocatable, so build in place; ensurepip uses the bundled pip.
  python3 -I -m venv "$dest"
  local source=(--index-url https://pypi.org/simple)
  [[ -d $wheels ]] && source=(--no-index --find-links "$wheels")
  "$dest/bin/python" -I -m pip install --quiet --disable-pip-version-check \
    --no-deps --require-hashes --only-binary=:all: "${source[@]}" -r "$lock"
  sha256sum "$lock" | cut -d' ' -f1 >"$dest/.lock-sha256"
}

case "${1:-}" in
  go) restore_go ;;
  vector) restore_vector ;;
  python) restore_python ;;
  kyverno) restore_kyverno ;;
  kind) restore_kind ;;
  k3s) restore_k3s ;;
  gvisor) restore_gvisor ;;
  terraform) restore_terraform ;;
  helm) restore_helm ;;
  cilium) restore_cilium ;;
  kubectl) restore_kubectl ;;
  falco) restore_falco ;;
  *) echo "usage: $0 go|vector|python|kyverno|kind|k3s|gvisor|terraform|helm|cilium|kubectl|falco" >&2; exit 2 ;;
esac
