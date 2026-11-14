package runc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// netnsDir is where `ip netns add` binds named network namespaces.
const netnsDir = "/run/netns"

var ifacePattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

// EgressNetwork is trusted operator configuration for Network "allowlist".
// Each run gets its own network namespace holding one ipvlan (L2, private)
// slave of Parent with the scheduler-assigned source address. The namespace
// has no route beyond Prefix, so the only useful peer is the egress proxy;
// "private" stops slaves of the same parent from reaching each other.
type EgressNetwork struct {
	// IPPath is the absolute path of a trusted iproute2 `ip` binary.
	IPPath string
	// Parent is the node interface on the proxy network.
	Parent string
	Prefix netip.Prefix
	// Proxy is the Envoy HTTP proxy listener (scheduler.HTTPProxyPort).
	Proxy netip.AddrPort
}

func (e *EgressNetwork) validate() error {
	switch {
	case !filepath.IsAbs(e.IPPath) || filepath.Clean(e.IPPath) != e.IPPath:
		return errors.New("egress: absolute ip binary path required")
	case !ifacePattern.MatchString(e.Parent):
		return errors.New("egress: invalid parent interface")
	case !e.Prefix.IsValid() || !e.Prefix.Addr().Is4() || e.Prefix.Bits() < 16 || e.Prefix.Masked() != e.Prefix:
		return errors.New("egress: prefix must be an IPv4 network of /16 or narrower")
	case !e.Prefix.Contains(e.Proxy.Addr()) || e.Proxy.Port() == 0:
		return errors.New("egress: proxy must be a port on an address inside the prefix")
	}
	return nil
}

func (e *EgressNetwork) proxyURL() string { return "http://" + e.Proxy.String() }

func netnsName(runID string) string { return "warden-" + runID }

// ifaceName fits IFNAMSIZ: "wd" plus the first 12 run ID characters. Run IDs
// are random base32, so a collision on one node needs 60 equal bits.
func ifaceName(runID string) string { return "wd" + runID[:12] }

func (e *EgressNetwork) ip(ctx context.Context, args ...string) error {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, e.IPPath, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// attach creates the run's namespace and returns its path. On failure the
// namespace (and with it any slave already moved into it) is removed.
func (e *EgressNetwork) attach(ctx context.Context, runID string, src netip.Addr) (string, error) {
	if !runPattern.MatchString(runID) {
		return "", errors.New("egress: invalid run ID")
	}
	network := e.Prefix.Addr().As4()
	var broadcast [4]byte
	binary.BigEndian.PutUint32(broadcast[:], binary.BigEndian.Uint32(network[:])|(uint32(1)<<(32-e.Prefix.Bits())-1))
	if !src.Is4() || !e.Prefix.Contains(src) || src == e.Prefix.Addr() || src == netip.AddrFrom4(broadcast) || src == e.Proxy.Addr() {
		return "", fmt.Errorf("egress: source %s is not a usable host address in %s", src, e.Prefix)
	}
	ns, link := netnsName(runID), ifaceName(runID)
	if err := e.ip(ctx, "netns", "add", ns); err != nil {
		return "", err
	}
	steps := [][]string{
		{"link", "add", "link", e.Parent, "name", link, "type", "ipvlan", "mode", "l2", "private"},
		{"link", "set", link, "netns", ns},
		{"-n", ns, "link", "set", "lo", "up"},
		{"-n", ns, "addr", "add", netip.PrefixFrom(src, e.Prefix.Bits()).String(), "dev", link},
		{"-n", ns, "link", "set", link, "up"},
	}
	for i, args := range steps {
		if err := e.ip(ctx, args...); err != nil {
			var cleanup error
			if i == 1 {
				// The slave was created but is still in the node namespace.
				cleanup = e.ip(context.WithoutCancel(ctx), "link", "del", link)
			}
			return "", errors.Join(err, cleanup, e.detach(context.WithoutCancel(ctx), runID))
		}
	}
	return filepath.Join(netnsDir, ns), nil
}

// detach removes the namespace binding; the kernel frees the slave once no
// process holds the namespace.
func (e *EgressNetwork) detach(ctx context.Context, runID string) error {
	if !runPattern.MatchString(runID) {
		return errors.New("egress: invalid run ID")
	}
	return e.ip(ctx, "netns", "del", netnsName(runID))
}
