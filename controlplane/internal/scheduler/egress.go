package scheduler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Egress allowlisting: every sandbox reaches the network only through one
// Envoy proxy. Each run is identified by its sandbox source address and gets
// its own filter chain on two listeners:
//
//   - HTTPProxyListener (:3128): explicit proxy. CONNECT host:443 and plain
//     HTTP by Host are routed only for the run's domains; everything else is 403.
//   - SNIProxyListener (:10443): transparent TLS (the target of a Cilium/iptables
//     redirect). Only ClientHello SNI values on the run's list are forwarded.
//
// Unknown sources hit a default chain that closes the connection. The
// controller writes the whole listener set to LDSFile with an atomic rename;
// Envoy watches the directory and swaps listeners without a restart.

const (
	HTTPProxyListener = "warden_http_proxy"
	SNIProxyListener  = "warden_sni_proxy"
	LDSFile           = "lds.json"
	BootstrapFile     = "envoy.json"
	HTTPProxyPort     = 3128
	SNIProxyPort      = 10443
	MaxAllowDomains   = 64
	// Path of the controller directory inside the proxy container.
	proxyConfigDir = "/etc/warden-egress"
)

type EgressGrant struct {
	RunID        string
	Source       netip.Addr
	AllowDomains []string
}

var egressRunPattern = regexp.MustCompile(`^[A-Z2-7]{26}$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// normalizeDomain accepts a lowercase DNS name with at least two labels, or
// "*.<name>" with at least two labels after the wildcard. IPs, ports, paths
// and bare TLD wildcards are rejected.
func normalizeDomain(d string) (string, error) {
	d = strings.ToLower(d)
	name := strings.TrimPrefix(d, "*.")
	if len(d) == 0 || len(d) > 253 || strings.Contains(name, "*") {
		return "", fmt.Errorf("invalid allow domain %q", d)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fmt.Errorf("allow domain %q is an IP address", d)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("allow domain %q needs at least two labels", d)
	}
	for _, l := range labels {
		if !labelPattern.MatchString(l) {
			return "", fmt.Errorf("invalid label in allow domain %q", d)
		}
	}
	return d, nil
}

func validateGrants(grants []EgressGrant) ([]EgressGrant, error) {
	out := make([]EgressGrant, 0, len(grants))
	runs, sources := map[string]bool{}, map[netip.Addr]bool{}
	for _, g := range grants {
		if !egressRunPattern.MatchString(g.RunID) || runs[g.RunID] {
			return nil, errors.New("invalid or duplicate egress run ID")
		}
		if !g.Source.IsValid() || !g.Source.Is4() || sources[g.Source] {
			return nil, errors.New("egress source must be a unique IPv4 address")
		}
		if len(g.AllowDomains) > MaxAllowDomains {
			return nil, errors.New("too many allow domains")
		}
		runs[g.RunID], sources[g.Source] = true, true
		domains := []string{}
		for _, d := range g.AllowDomains {
			n, err := normalizeDomain(d)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(domains, n) {
				domains = append(domains, n)
			}
		}
		out = append(out, EgressGrant{RunID: g.RunID, Source: g.Source, AllowDomains: domains})
	}
	return out, nil
}

type obj = map[string]any

func typed(t string, fields obj) obj {
	fields["@type"] = t
	return fields
}

func dnsCache() obj {
	return obj{"name": "warden_egress_dns", "dns_lookup_family": "V4_ONLY"}
}

func sourceMatch(a netip.Addr) []obj {
	return []obj{{"address_prefix": a.String(), "prefix_len": 32}}
}

func accessLog(format string) []obj {
	return []obj{{"name": "envoy.access_loggers.stdout", "typed_config": typed(
		"type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
		obj{"log_format": obj{"text_format_source": obj{"inline_string": format + "\n"}}})}}
}

// closeChain is the default for sources without a grant: no bytes are proxied.
func closeChain() obj {
	return obj{"name": "deny_unknown_source", "filters": []obj{{
		"name":         "envoy.filters.network.direct_response",
		"typed_config": typed("type.googleapis.com/envoy.extensions.filters.network.direct_response.v3.Config", obj{}),
	}}}
}

func httpChain(g EgressGrant) obj {
	deny := obj{"direct_response": obj{"status": 403, "body": obj{"inline_string": "warden egress: domain not allowlisted\n"}}}
	vhosts := []obj{}
	if len(g.AllowDomains) > 0 {
		var tls, plain []string
		for _, d := range g.AllowDomains {
			tls = append(tls, d+":443")
			plain = append(plain, d, d+":80")
		}
		vhosts = append(vhosts,
			obj{"name": "tls", "domains": tls, "routes": []obj{{
				"match": obj{"connect_matcher": obj{}},
				"route": obj{"cluster": "warden_dfp_http", "upgrade_configs": []obj{{"upgrade_type": "CONNECT", "connect_config": obj{}}}},
			}}},
			obj{"name": "http", "domains": plain, "routes": []obj{{
				"match": obj{"prefix": "/"}, "route": obj{"cluster": "warden_dfp_http"},
			}}})
	}
	vhosts = append(vhosts, obj{"name": "deny", "domains": []string{"*"}, "routes": []obj{
		{"match": obj{"connect_matcher": obj{}}, "direct_response": deny["direct_response"]},
		{"match": obj{"prefix": "/"}, "direct_response": deny["direct_response"]},
	}})
	hcm := typed("type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
		"stat_prefix":     "warden_egress_" + g.RunID,
		"upgrade_configs": []obj{{"upgrade_type": "CONNECT"}},
		"route_config":    obj{"name": "run_" + g.RunID, "virtual_hosts": vhosts},
		"http_filters": []obj{
			{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig",
				obj{"dns_cache_config": dnsCache()})},
			{"name": "envoy.filters.http.router", "typed_config": typed("type.googleapis.com/envoy.extensions.filters.http.router.v3.Router", obj{})},
		},
		"access_log": accessLog(`http run=` + g.RunID + ` src=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% method=%REQ(:METHOD)% authority=%REQ(:AUTHORITY)% status=%RESPONSE_CODE% upstream=%UPSTREAM_HOST%`),
	})
	return obj{"name": "run_" + g.RunID, "filter_chain_match": obj{"source_prefix_ranges": sourceMatch(g.Source)},
		"filters": []obj{{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}}}
}

func sniChain(g EgressGrant) obj {
	return obj{"name": "run_" + g.RunID,
		"filter_chain_match": obj{"source_prefix_ranges": sourceMatch(g.Source), "server_names": g.AllowDomains},
		"filters": []obj{
			{"name": "envoy.filters.network.sni_dynamic_forward_proxy", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig",
				obj{"port_value": 443, "dns_cache_config": dnsCache()})},
			{"name": "envoy.filters.network.tcp_proxy", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
				obj{"stat_prefix": "warden_sni_" + g.RunID, "cluster": "warden_dfp_sni",
					"access_log": accessLog(`sni run=` + g.RunID + ` src=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% sni=%REQUESTED_SERVER_NAME% upstream=%UPSTREAM_HOST%`)})},
		}}
}

func listener(name string, port int, chains []obj, inspectTLS bool) obj {
	l := obj{
		"@type":                "type.googleapis.com/envoy.config.listener.v3.Listener",
		"name":                 name,
		"address":              obj{"socket_address": obj{"address": "0.0.0.0", "port_value": port}},
		"filter_chains":        chains,
		"default_filter_chain": closeChain(),
	}
	if inspectTLS {
		l["listener_filters"] = []obj{{"name": "envoy.filters.listener.tls_inspector", "typed_config": typed(
			"type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector", obj{})}}
	}
	return l
}

// RenderEgressLDS returns the Envoy LDS discovery response for the grants.
func RenderEgressLDS(version uint64, grants []EgressGrant) ([]byte, error) {
	grants, err := validateGrants(grants)
	if err != nil {
		return nil, err
	}
	httpChains, sniChains := []obj{}, []obj{}
	for _, g := range grants {
		httpChains = append(httpChains, httpChain(g))
		if len(g.AllowDomains) > 0 {
			sniChains = append(sniChains, sniChain(g))
		}
	}
	return json.MarshalIndent(obj{
		"version_info": fmt.Sprint(version),
		"resources": []obj{
			listener(HTTPProxyListener, HTTPProxyPort, httpChains, false),
			listener(SNIProxyListener, SNIProxyPort, sniChains, true),
		},
	}, "", " ")
}

// RenderEgressBootstrap is the static Envoy bootstrap: admin on loopback, the
// two dynamic-forward-proxy clusters, and LDS read from the watched directory.
func RenderEgressBootstrap() ([]byte, error) {
	cluster := func(name string) obj {
		return obj{"name": name, "lb_policy": "CLUSTER_PROVIDED", "connect_timeout": "5s",
			"cluster_type": obj{"name": "envoy.clusters.dynamic_forward_proxy", "typed_config": typed(
				"type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
				obj{"dns_cache_config": dnsCache()})}}
	}
	return json.MarshalIndent(obj{
		"node":  obj{"id": "warden-egress", "cluster": "warden-egress"},
		"admin": obj{"address": obj{"socket_address": obj{"address": "127.0.0.1", "port_value": 9901}}},
		"dynamic_resources": obj{"lds_config": obj{"resource_api_version": "V3", "path_config_source": obj{
			"path":              proxyConfigDir + "/" + LDSFile,
			"watched_directory": obj{"path": proxyConfigDir},
		}}},
		"static_resources": obj{"clusters": []obj{cluster("warden_dfp_http"), cluster("warden_dfp_sni")}},
	}, "", " ")
}

// EgressController owns the proxy configuration directory (mounted read-only
// at /etc/warden-egress in the proxy). Apply/Remove rewrite LDS atomically.
type EgressController struct {
	dir     string
	mu      sync.Mutex
	version uint64
	grants  map[string]EgressGrant
}

func NewEgressController(dir string) (*EgressController, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("egress config directory must be absolute")
	}
	c := &EgressController{dir: dir, grants: map[string]EgressGrant{}}
	boot, err := RenderEgressBootstrap()
	if err != nil {
		return nil, err
	}
	if err := c.write(BootstrapFile, boot); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c, c.publish(nil)
}

// Apply grants (or replaces) one run's allowlist.
func (c *EgressController) Apply(g EgressGrant) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := []EgressGrant{}
	for id, old := range c.grants {
		if id != g.RunID {
			next = append(next, old)
		}
	}
	next = append(next, g)
	return c.publish(next)
}

// Remove revokes a run's egress; its source falls through to the deny chain.
func (c *EgressController) Remove(runID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := []EgressGrant{}
	for id, g := range c.grants {
		if id != runID {
			next = append(next, g)
		}
	}
	return c.publish(next)
}

func (c *EgressController) publish(grants []EgressGrant) error {
	// Stable order keeps diffs and Envoy filter-chain updates minimal.
	slices.SortFunc(grants, func(a, b EgressGrant) int { return strings.Compare(a.RunID, b.RunID) })
	b, err := RenderEgressLDS(c.version+1, grants)
	if err != nil {
		return err
	}
	if err := c.write(LDSFile, b); err != nil {
		return err
	}
	c.version++
	c.grants = map[string]EgressGrant{}
	for _, g := range grants {
		c.grants[g.RunID] = g
	}
	return nil
}

// EgressPool assigns node-local sandbox source addresses to allowlist runs and
// keeps each run's proxy grant exactly as long as the run. An address whose
// sandbox may still be alive (cleanup pending) is quarantined: its grant is
// revoked but the address is never handed to another run.
type EgressPool struct {
	Controller *EgressController
	Sources    []netip.Addr

	mu          sync.Mutex
	inUse       map[netip.Addr]string
	byRun       map[string]netip.Addr
	quarantined map[netip.Addr]bool
}

var ErrEgressUnavailable = errors.New("no egress source address available")

// Acquire picks a free address and makes the run's grant live before returning.
func (p *EgressPool) Acquire(runID string, domains []string) (netip.Addr, error) {
	if p == nil || p.Controller == nil {
		return netip.Addr{}, ErrEgressUnavailable
	}
	if len(domains) == 0 {
		return netip.Addr{}, errors.New("allowlist run needs at least one domain")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inUse == nil {
		p.inUse, p.byRun, p.quarantined = map[netip.Addr]string{}, map[string]netip.Addr{}, map[netip.Addr]bool{}
	}
	if _, dup := p.byRun[runID]; dup {
		return netip.Addr{}, errors.New("run already holds an egress source")
	}
	for _, a := range p.Sources {
		if p.inUse[a] != "" || p.quarantined[a] {
			continue
		}
		if err := p.Controller.Apply(EgressGrant{RunID: runID, Source: a, AllowDomains: domains}); err != nil {
			return netip.Addr{}, err
		}
		p.inUse[a], p.byRun[runID] = runID, a
		return a, nil
	}
	return netip.Addr{}, ErrEgressUnavailable
}

// Release revokes the run's grant. sandboxGone frees the address; otherwise,
// or if the revocation fails, the address stays quarantined.
func (p *EgressPool) Release(runID string, sandboxGone bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a, ok := p.byRun[runID]
	if !ok {
		return nil
	}
	err := p.Controller.Remove(runID)
	delete(p.byRun, runID)
	delete(p.inUse, a)
	if err != nil || !sandboxGone {
		p.quarantined[a] = true
	}
	return err
}

func (c *EgressController) write(name string, b []byte) error {
	tmp, err := os.CreateTemp(c.dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(c.dir, name))
}
