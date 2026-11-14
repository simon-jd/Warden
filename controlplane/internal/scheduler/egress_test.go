package scheduler

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	runA = "AAAAAAAAAAAAAAAAAAAAAAAAAA"
	runB = "BBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type lds struct {
	VersionInfo string `json:"version_info"`
	Resources   []struct {
		Name         string            `json:"name"`
		FilterChains []json.RawMessage `json:"filter_chains"`
		Default      json.RawMessage   `json:"default_filter_chain"`
	} `json:"resources"`
}

type chain struct {
	Name  string `json:"name"`
	Match struct {
		Sources []struct {
			Prefix string `json:"address_prefix"`
			Len    int    `json:"prefix_len"`
		} `json:"source_prefix_ranges"`
		ServerNames []string `json:"server_names"`
	} `json:"filter_chain_match"`
	Filters []struct {
		Name   string         `json:"name"`
		Config map[string]any `json:"typed_config"`
	} `json:"filters"`
}

func decodeLDS(t *testing.T, b []byte) (lds, map[string][]chain) {
	t.Helper()
	var l lds
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	out := map[string][]chain{}
	for _, r := range l.Resources {
		if len(r.Default) == 0 {
			t.Fatalf("listener %s has no default deny chain", r.Name)
		}
		for _, raw := range r.FilterChains {
			var c chain
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			out[r.Name] = append(out[r.Name], c)
		}
	}
	return l, out
}

func vhosts(t *testing.T, c chain) map[string][]string {
	t.Helper()
	b, _ := json.Marshal(c.Filters[0].Config["route_config"])
	var rc struct {
		VirtualHosts []struct {
			Name    string   `json:"name"`
			Domains []string `json:"domains"`
		} `json:"virtual_hosts"`
	}
	if err := json.Unmarshal(b, &rc); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, v := range rc.VirtualHosts {
		out[v.Name] = v.Domains
	}
	return out
}

func TestRenderEgressPerRunAllowlist(t *testing.T) {
	b, err := RenderEgressLDS(7, []EgressGrant{
		{RunID: runA, Source: netip.MustParseAddr("10.0.0.10"), AllowDomains: []string{"Allowed.Warden.Test", "*.cdn.example.org"}},
		{RunID: runB, Source: netip.MustParseAddr("10.0.0.11")},
	})
	if err != nil {
		t.Fatal(err)
	}
	l, chains := decodeLDS(t, b)
	if l.VersionInfo != "7" {
		t.Fatalf("version %q", l.VersionInfo)
	}
	httpChains := chains[HTTPProxyListener]
	if len(httpChains) != 2 {
		t.Fatalf("want one HTTP proxy chain per run, got %d", len(httpChains))
	}
	for _, c := range httpChains {
		if len(c.Match.Sources) != 1 || c.Match.Sources[0].Len != 32 {
			t.Fatalf("chain %s must match exactly one /32 source: %+v", c.Name, c.Match.Sources)
		}
		v := vhosts(t, c)
		if got := v["deny"]; !slices.Equal(got, []string{"*"}) {
			t.Fatalf("deny vhost domains %v", got)
		}
		switch c.Match.Sources[0].Prefix {
		case "10.0.0.10":
			if !slices.Equal(v["tls"], []string{"allowed.warden.test:443", "*.cdn.example.org:443"}) {
				t.Fatalf("CONNECT allowlist %v", v["tls"])
			}
			if !slices.Contains(v["http"], "allowed.warden.test") || !slices.Contains(v["http"], "allowed.warden.test:80") {
				t.Fatalf("plain HTTP allowlist %v", v["http"])
			}
		case "10.0.0.11":
			if _, ok := v["tls"]; ok {
				t.Fatal("a run without allow_domains must get no allow vhost")
			}
		default:
			t.Fatalf("unexpected source %s", c.Match.Sources[0].Prefix)
		}
	}
	sni := chains[SNIProxyListener]
	// Empty server_names would match every SNI, so a run with no domains gets no chain.
	if len(sni) != 1 || sni[0].Match.Sources[0].Prefix != "10.0.0.10" {
		t.Fatalf("want one SNI chain for run A only, got %+v", sni)
	}
	if !slices.Equal(sni[0].Match.ServerNames, []string{"allowed.warden.test", "*.cdn.example.org"}) {
		t.Fatalf("SNI allowlist %v", sni[0].Match.ServerNames)
	}
}

func TestRenderEgressRejectsUnsafeInput(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.10")
	for _, d := range []string{"", "*", "*.org", "com", "10.0.0.1", "a..b.test", "-a.test", "a-.test", "a.test:443",
		"a.test/x", "a b.test", "*.*.test", "a.*.test", "xn--\x00.test", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 127) + "test"} {
		if _, err := RenderEgressLDS(1, []EgressGrant{{RunID: runA, Source: src, AllowDomains: []string{d}}}); err == nil {
			t.Errorf("domain %q accepted", d)
		}
	}
	bad := [][]EgressGrant{
		{{RunID: "short", Source: src}},
		{{RunID: runA}},
		{{RunID: runA, Source: netip.MustParseAddr("::1")}},
		{{RunID: runA, Source: src}, {RunID: runB, Source: src}},
		{{RunID: runA, Source: src}, {RunID: runA, Source: netip.MustParseAddr("10.0.0.11")}},
	}
	for i, g := range bad {
		if _, err := RenderEgressLDS(1, g); err == nil {
			t.Errorf("grant set %d accepted", i)
		}
	}
	many := make([]string, MaxAllowDomains+1)
	for i := range many {
		many[i] = "d" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + ".test"
	}
	if _, err := RenderEgressLDS(1, []EgressGrant{{RunID: runA, Source: src, AllowDomains: many}}); err == nil {
		t.Error("too many domains accepted")
	}
}

func TestEgressControllerAppliesAndRevokesAtomically(t *testing.T) {
	dir := t.TempDir()
	c, err := NewEgressController(dir)
	if err != nil {
		t.Fatal(err)
	}
	read := func() (lds, map[string][]chain) {
		b, err := os.ReadFile(filepath.Join(dir, LDSFile))
		if err != nil {
			t.Fatal(err)
		}
		return decodeLDS(t, b)
	}
	if l, chains := read(); l.VersionInfo != "1" || len(chains[HTTPProxyListener]) != 0 {
		t.Fatalf("initial config must deny everything: %+v", chains)
	}
	if err := c.Apply(EgressGrant{RunID: runA, Source: netip.MustParseAddr("10.0.0.10"), AllowDomains: []string{"allowed.warden.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(EgressGrant{RunID: runB, Source: netip.MustParseAddr("10.0.0.10")}); err == nil {
		t.Fatal("second run on the same source address accepted")
	}
	if err := c.Apply(EgressGrant{RunID: runB, Source: netip.MustParseAddr("10.0.0.11"), AllowDomains: []string{"other.warden.test"}}); err != nil {
		t.Fatal(err)
	}
	if l, chains := read(); l.VersionInfo != "3" || len(chains[HTTPProxyListener]) != 2 || len(chains[SNIProxyListener]) != 2 {
		t.Fatalf("after two grants: version %s chains %d/%d", l.VersionInfo, len(chains[HTTPProxyListener]), len(chains[SNIProxyListener]))
	}
	if err := c.Remove(runA); err != nil {
		t.Fatal(err)
	}
	l, chains := read()
	if l.VersionInfo != "4" || len(chains[SNIProxyListener]) != 1 || chains[SNIProxyListener][0].Match.ServerNames[0] != "other.warden.test" {
		t.Fatalf("revocation not applied: %+v", chains)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != LDSFile && e.Name() != BootstrapFile {
			t.Fatalf("leftover file %s", e.Name())
		}
		info, _ := e.Info()
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode %v", e.Name(), info.Mode())
		}
	}
	var boot map[string]any
	b, err := os.ReadFile(filepath.Join(dir, BootstrapFile))
	if err != nil || json.Unmarshal(b, &boot) != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if !strings.Contains(string(b), `"watched_directory"`) || !strings.Contains(string(b), "/etc/warden-egress/"+LDSFile) {
		t.Fatal("bootstrap must watch the LDS file for hot reload")
	}
}
