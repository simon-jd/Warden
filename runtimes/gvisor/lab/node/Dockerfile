# One-node k3s lab with gVisor (scripts/k3s_gvisor_lab.sh). Built from scratch
# out of the pinned binaries in .tools/ and binaries built from this tree;
# nothing is pulled.
FROM scratch
COPY k3s /bin/k3s
COPY runsc containerd-shim-runsc-v1 /usr/local/bin/
COPY gvisor-bin/ /usr/local/bin/gvisor-bin/
COPY passwd group /etc/
COPY runsc.toml /etc/containerd/runsc.toml
COPY config.yaml /etc/rancher/k3s/config.yaml
COPY config-v3.toml.tmpl /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
# With flannel off, containerd uses the default CNI paths. The plugins are
# symlinks to k3s's own multicall "cni" binary, resolved at run time.
# cni-conf/ holds 10-warden.conflist, or nothing in Cilium mode (Cilium
# writes its own config once its agent runs).
COPY cni-conf/ /etc/cni/net.d/
COPY cni-bin/ /opt/cni/bin/
# The supervisor every gVisor run starts with (runtimes/gvisor/supervisor);
# pods mount it read-only from here.
COPY --chmod=0555 gvisor-init /opt/warden/gvisor-init
# Empty in the bridge mode. In Cilium mode (scripts/k3s_gvisor_lab.sh up
# --cilium): /warden-node-init, the node's PID 1 there
# (runtimes/gvisor/lab/nodeinit), and /etc/containerd/runsc-netstack.toml
# (runtimes/gvisor/lab/cilium).
COPY extra/ /
ENV PATH=/var/lib/rancher/k3s/data/current/bin:/var/lib/rancher/k3s/data/current/bin/aux:/usr/local/bin:/bin
ENTRYPOINT ["/bin/k3s"]
CMD ["server"]
