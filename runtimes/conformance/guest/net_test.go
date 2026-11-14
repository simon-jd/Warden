package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func runNet(t *testing.T, cases ...string) []netResult {
	t.Helper()
	var buf bytes.Buffer
	netMain(&buf, cases)
	var out []netResult
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var r netResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad output line %q: %v", line, err)
		}
		out = append(out, r)
	}
	if len(out) != len(cases) {
		t.Fatalf("%d results for %d cases: %s", len(out), len(cases), buf.String())
	}
	return out
}

func plainOrigin(t *testing.T, body string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body+" host="+r.Host+"\n")
	}))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

// plainProxy answers CONNECT to allowed with a tunnel to origin and
// absolute-form GET for allowed by forwarding it; everything else is 403.
func plainProxy(t *testing.T, allowed, origin string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				host := req.Host
				if req.Method != http.MethodConnect {
					host = req.URL.Host
				}
				if strings.Split(host, ":")[0] != allowed {
					io.WriteString(c, "HTTP/1.1 403 Forbidden\r\ncontent-length: 4\r\n\r\ndeny")
					return
				}
				up, err := net.Dial("tcp", origin)
				if err != nil {
					return
				}
				defer up.Close()
				if req.Method == http.MethodConnect {
					io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
					go io.Copy(up, br)
					io.Copy(c, up)
					return
				}
				req.RequestURI = ""
				req.Write(up)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestNetGetReadsStatusAndBody(t *testing.T) {
	origin := plainOrigin(t, "origin-allowed")
	r := runNet(t, "a,get,http://"+origin+"/")[0]
	if r.Key != "a" || !r.OK || r.Status != 200 || r.Body != "origin-allowed host="+origin {
		t.Fatalf("%+v", r)
	}
}

func TestNetGetSeparatesResolveAndConnectErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	rs := runNet(t, "refused,get,http://"+closed+"/", "noname,get,http://no-such-name.invalid/")
	if rs[0].OK || rs[0].ConnectError == "" || rs[0].ResolveError != "" {
		t.Errorf("refused: %+v", rs[0])
	}
	if rs[1].OK || rs[1].ResolveError == "" || rs[1].ConnectError != "" {
		t.Errorf("noname: %+v", rs[1])
	}
}

func TestNetProxyAndTunnelGoThroughTheProxy(t *testing.T) {
	origin := plainOrigin(t, "origin-allowed")
	proxy := plainProxy(t, "allowed.test", origin)
	rs := runNet(t,
		"p,proxy,"+proxy+",http://allowed.test/",
		"t,tunnel,"+proxy+",allowed.test:443",
		"pd,proxy,"+proxy+",http://blocked.test/",
		"td,tunnel,"+proxy+",blocked.test:443")
	if !rs[0].OK || rs[0].Status != 200 || rs[0].Body != "origin-allowed host=allowed.test" {
		t.Errorf("proxy: %+v", rs[0])
	}
	if !rs[1].OK || rs[1].ProxyStatus != 200 || rs[1].Status != 200 || rs[1].Body != "origin-allowed host=allowed.test" {
		t.Errorf("tunnel: %+v", rs[1])
	}
	if rs[2].OK || rs[2].Status != 403 {
		t.Errorf("proxy denied: %+v", rs[2])
	}
	if rs[3].OK || rs[3].ProxyStatus != 403 || rs[3].Status != 0 {
		t.Errorf("tunnel denied: %+v", rs[3])
	}
}

func TestNetTCPConnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := runNet(t, "c,tcp,"+ln.Addr().String())[0]
	if !r.OK || r.Error != "" {
		t.Fatalf("%+v", r)
	}
}

// fakeDNS answers TXT queries with "hello" and everything else NXDOMAIN, and
// records the names it was asked.
func fakeDNS(t *testing.T) (addr string, names func() []string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			i, labels := 12, []string{}
			for q[i] != 0 {
				labels = append(labels, string(q[i+1:i+1+int(q[i])]))
				i += 1 + int(q[i])
			}
			qtype := binary.BigEndian.Uint16(q[i+1:])
			question := q[12 : i+5]
			mu.Lock()
			seen = append(seen, strings.Join(labels, "."))
			mu.Unlock()
			hdr := []byte{q[0], q[1], 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0}
			var ans []byte
			if qtype == 16 {
				hdr[3], hdr[7] = 0x80, 1
				ans = []byte{0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, 6, 5, 'h', 'e', 'l', 'l', 'o'}
			}
			pc.WriteTo(append(append(hdr, question...), ans...), from)
		}
	}()
	return pc.LocalAddr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

func TestNetDNSQueriesTheServerAndReadsTheAnswer(t *testing.T) {
	addr, names := fakeDNS(t)
	rs := runNet(t, "txt,dns,TXT,abc.x.exfil.test,"+addr, "a,dns,A,nothing.test,"+addr)
	if !rs[0].OK || rs[0].Rcode == nil || *rs[0].Rcode != 0 || strings.Join(rs[0].Answers, ",") != "hello" {
		t.Errorf("txt: %+v", rs[0])
	}
	if rs[1].OK || rs[1].Rcode == nil || *rs[1].Rcode != 3 || len(rs[1].Answers) != 0 {
		t.Errorf("a: %+v", rs[1])
	}
	if got := strings.Join(names(), " "); got != "abc.x.exfil.test nothing.test" {
		t.Errorf("server saw %q", got)
	}
}

func TestNetDNSTimesOutWithoutAnAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	start := time.Now()
	r := runNet(t, "x,dns,TXT,a.test,"+pc.LocalAddr().String())[0]
	if r.OK || r.Rcode != nil || !strings.Contains(r.Error, "timeout") || time.Since(start) > 2*netTimeout {
		t.Fatalf("%+v after %v", r, time.Since(start))
	}
}

func TestDNSServerDefaultsToPort53(t *testing.T) {
	for in, want := range map[string]string{"198.18.18.40": "198.18.18.40:53", "198.18.18.40:5353": "198.18.18.40:5353", "": ""} {
		if got := dnsServer(in); got != want {
			t.Errorf("dnsServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolvConfNameserver(t *testing.T) {
	got := nameserver("search warden-lab.svc.cluster.local svc.cluster.local\nnameserver 10.43.0.10\nnameserver 10.43.0.11\noptions ndots:5\n")
	if got != "10.43.0.10:53" {
		t.Fatalf("nameserver = %q", got)
	}
	if got := nameserver("options ndots:5\n"); got != "" {
		t.Fatalf("nameserver without one = %q", got)
	}
}

// heartbeatServer sends "hb N" every 10 ms on every connection and records
// the lines it receives.
func heartbeatServer(t *testing.T) (addr string, lines func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				for i := 1; ; i++ {
					time.Sleep(10 * time.Millisecond)
					if _, err := io.WriteString(c, "hb "+string(rune('0'+i%10))+"\n"); err != nil {
						return
					}
				}
			}()
			go func() {
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					mu.Lock()
					got = append(got, sc.Text())
					mu.Unlock()
				}
				c.Close()
			}()
		}
	}()
	return ln.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestStreamSendsNumberedLinesAndLogsWhatItReceives(t *testing.T) {
	origin, received := heartbeatServer(t)
	proxy := plainProxy(t, "stream.test", origin)
	for _, via := range []string{proxy, "-"} {
		target := "stream.test:443"
		if via == "-" {
			target = origin
		}
		var out syncBuffer
		stop := make(chan struct{})
		done := make(chan error, 1)
		go func() { done <- stream(&out, via, target, "pod-a", 10*time.Millisecond, stop) }()
		time.Sleep(300 * time.Millisecond)
		close(stop)
		if err := <-done; err != nil {
			t.Fatalf("via %s: %v", via, err)
		}
		log := out.String()
		if !strings.Contains(log, " connected") || strings.Count(log, " rx hb ") < 5 {
			t.Errorf("via %s: client log %q", via, log)
		}
	}
	var seqs []string
	for _, l := range received() {
		f := strings.Fields(l)
		if len(f) != 3 || f[0] != "pod-a" {
			t.Fatalf("server got %q", l)
		}
		seqs = append(seqs, f[1])
	}
	if len(seqs) < 10 || seqs[0] != "1" || seqs[1] != "2" {
		t.Fatalf("server got sequence %v", seqs)
	}
}

func TestStreamGivesUpWhenTheProxyRefuses(t *testing.T) {
	proxy := plainProxy(t, "only-this.test", "127.0.0.1:1")
	var out syncBuffer
	stop := make(chan struct{})
	time.AfterFunc(1500*time.Millisecond, func() { close(stop) })
	err := stream(&out, proxy, "other.test:443", "pod-a", 10*time.Millisecond, stop)
	if err == nil || !strings.Contains(out.String(), "connect-failed") || strings.Contains(out.String(), " connected") {
		t.Fatalf("err %v, log %q", err, out.String())
	}
}

// The imds case reads one harmless instance metadata value, the VM's region,
// with the header IMDS requires. It never asks for anything else: a token
// endpoint, another path or another host is refused before any connection.
func TestNetIMDSReadsOnlyTheLocation(t *testing.T) {
	var mu sync.Mutex
	var got []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.RequestURI()+" host="+r.Host+" metadata="+r.Header.Get("Metadata"))
		mu.Unlock()
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		io.WriteString(w, "westus2")
	}))
	defer s.Close()
	old := imdsAddr
	imdsAddr = strings.TrimPrefix(s.URL, "http://")
	defer func() { imdsAddr = old }()

	r := runNet(t,
		"loc,imds,"+imdsLocationURL,
		"token,imds,http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
		"instance,imds,http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"host,imds,http://"+imdsAddr+"/metadata/instance/compute/location?api-version=2021-02-01&format=text")
	if !r[0].OK || r[0].Status != 200 || r[0].Body != "westus2" {
		t.Errorf("location: %+v", r[0])
	}
	for _, x := range r[1:] {
		if x.OK || x.Error == "" || x.ConnectError != "" {
			t.Errorf("%s: %+v, want refused before connecting", x.Key, x)
		}
	}
	want := "GET /metadata/instance/compute/location?api-version=2021-02-01&format=text host=169.254.169.254 metadata=true"
	if len(got) != 1 || got[0] != want {
		t.Errorf("requests %q, want only %q", got, want)
	}
}

func TestNetIMDSReportsAConnectError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	old := imdsAddr
	imdsAddr = addr
	defer func() { imdsAddr = old }()
	r := runNet(t, "loc,imds,"+imdsLocationURL)[0]
	if r.OK || r.ConnectError == "" {
		t.Fatalf("got %+v, want a connect error", r)
	}
}
