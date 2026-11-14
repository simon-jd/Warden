package main

// Network probes for the k3s Cilium lab (controlplane/internal/ciliumlab).
// The lab's sandbox pods run "warden-probe hold" with gVisor's own network
// stack, and the tests exec:
//
//	warden-probe net CASE...    one JSON object per case; CASE is key,mode,args:
//	  get,URL                   direct plain-HTTP GET (no proxy); a host name
//	                            is resolved first (resolve_error) and then
//	                            connected to (connect_error)
//	  proxy,PROXY,URL           plain-HTTP GET through the proxy (absolute form)
//	  tunnel,PROXY,HOST:PORT    CONNECT through the proxy, then GET / over the tunnel
//	  tcp,HOST:PORT             direct TCP connect
//	  imds,URL                  plain-HTTP GET to the cloud instance metadata
//	                            endpoint with "Metadata: true"; URL must be
//	                            imdsLocationURL (the VM's region), so the
//	                            probe never asks for a token or anything else
//	  dns,TYPE,NAME[,SERVER]    one DNS query over UDP to SERVER[:PORT] (port 53
//	                            by default; server: the first nameserver in
//	                            /etc/resolv.conf); TYPE is A or TXT
//
//	warden-probe stream PROXY HOST:PORT NAME EVERY_MS
//	  one long-lived connection, through PROXY with CONNECT, or direct when
//	  PROXY is "-". Every EVERY_MS it sends "NAME SEQ T"; every line it
//	  receives it logs as "T rx LINE". It retries the connect for up to
//	  two minutes ("T connect-failed ERR"), then never reconnects: the first
//	  error after "T connected" ends it ("T closed ERR").
//
// T is the epoch time in seconds; a gVisor sandbox reads the host's clock.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const netTimeout = 3 * time.Second

type netResult struct {
	Key          string   `json:"key"`
	OK           bool     `json:"ok"`
	Status       int      `json:"status,omitempty"`
	ProxyStatus  int      `json:"proxy_status,omitempty"`
	Body         string   `json:"body,omitempty"`
	Error        string   `json:"error,omitempty"`
	Resolved     string   `json:"resolved,omitempty"`
	ResolveError string   `json:"resolve_error,omitempty"`
	ConnectError string   `json:"connect_error,omitempty"`
	Rcode        *int     `json:"rcode,omitempty"`
	Answers      []string `json:"answers,omitempty"`
	Millis       float64  `json:"ms"`
}

func netMain(w io.Writer, cases []string) {
	for _, c := range cases {
		parts := strings.Split(c, ",")
		start := time.Now()
		var r netResult
		switch {
		case len(parts) == 3 && parts[1] == "get":
			r = netGet(parts[2])
		case len(parts) == 4 && parts[1] == "proxy":
			r = netProxyGet(parts[2], parts[3])
		case len(parts) == 4 && parts[1] == "tunnel":
			r = netTunnel(parts[2], parts[3])
		case len(parts) == 3 && parts[1] == "tcp":
			r = netTCP(parts[2])
		case len(parts) == 3 && parts[1] == "imds":
			r = netIMDS(parts[2])
		case (len(parts) == 4 || len(parts) == 5) && parts[1] == "dns":
			server := ""
			if len(parts) == 5 {
				server = parts[4]
			}
			r = netDNS(parts[2], parts[3], server)
		default:
			r = netResult{Error: "bad case " + strconv.Quote(c)}
		}
		r.Key = parts[0]
		r.Millis = float64(time.Since(start).Microseconds()) / 1000
		b, _ := json.Marshal(r)
		fmt.Fprintln(w, string(b))
	}
}

// httpOver sends GET target with the Host header host (and the extra header
// lines, if any) on conn and reads the response (the server closes after it).
func httpOver(conn net.Conn, target, host string, header ...string) netResult {
	_ = conn.SetDeadline(time.Now().Add(netTimeout))
	extra := ""
	for _, h := range header {
		extra += h + "\r\n"
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", target, host, extra); err != nil {
		return netResult{Error: err.Error()}
	}
	code, body, err := readResponse(conn)
	if err != nil {
		return netResult{Error: err.Error()}
	}
	return netResult{OK: code == 200, Status: code, Body: body}
}

func netGet(raw string) netResult {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return netResult{Error: "want an http:// URL"}
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	var r netResult
	ip := u.Hostname()
	if net.ParseIP(ip) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), netTimeout)
		addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", ip)
		cancel()
		if err != nil || len(addrs) == 0 {
			r.ResolveError = fmt.Sprint(err)
			return r
		}
		var names []string
		for _, a := range addrs {
			names = append(names, a.String())
		}
		r.Resolved, ip = strings.Join(names, ","), names[0]
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), netTimeout)
	if err != nil {
		r.ConnectError = err.Error()
		return r
	}
	defer conn.Close()
	path := u.RequestURI()
	got := httpOver(conn, path, u.Host)
	got.Resolved = r.Resolved
	return got
}

func netProxyGet(proxy, raw string) netResult {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return netResult{Error: "want an http:// URL"}
	}
	conn, err := net.DialTimeout("tcp", proxy, netTimeout)
	if err != nil {
		return netResult{ConnectError: err.Error()}
	}
	defer conn.Close()
	return httpOver(conn, raw, u.Host)
}

// connectVia opens a CONNECT tunnel to target through proxy. On a non-200
// answer it returns the status and the error "proxy answered N".
func connectVia(proxy, target string) (net.Conn, *bufio.Reader, int, error) {
	conn, err := net.DialTimeout("tcp", proxy, netTimeout)
	if err != nil {
		return nil, nil, 0, err
	}
	_ = conn.SetDeadline(time.Now().Add(netTimeout))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, 0, fmt.Errorf("proxy closed during CONNECT: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		conn.Close()
		return nil, nil, 0, errors.New("bad CONNECT response")
	}
	status, _ := strconv.Atoi(fields[1])
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	if status != 200 {
		conn.Close()
		return nil, nil, status, fmt.Errorf("proxy answered %d", status)
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{conn, br}, br, status, nil
}

func netTunnel(proxy, target string) netResult {
	conn, _, status, err := connectVia(proxy, target)
	if err != nil {
		r := netResult{ProxyStatus: status}
		if status == 0 {
			r.ConnectError = err.Error()
		} else {
			r.Error = err.Error()
		}
		return r
	}
	defer conn.Close()
	host, _, _ := net.SplitHostPort(target)
	r := httpOver(conn, "/", host)
	r.ProxyStatus = status
	return r
}

// imdsLocationURL is the only instance metadata request the probe makes: the
// VM's region as text, which says nothing secret and needs no identity. The
// address is the same on Azure, GCP and AWS; tests point imdsAddr elsewhere.
const imdsLocationURL = "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text"

var imdsAddr = "169.254.169.254:80"

func netIMDS(raw string) netResult {
	if raw != imdsLocationURL {
		return netResult{Error: "imds: only " + imdsLocationURL + " is allowed"}
	}
	u, _ := url.Parse(raw)
	conn, err := net.DialTimeout("tcp", imdsAddr, netTimeout)
	if err != nil {
		return netResult{ConnectError: err.Error()}
	}
	defer conn.Close()
	return httpOver(conn, u.RequestURI(), u.Host, "Metadata: true")
}

func netTCP(target string) netResult {
	conn, err := net.DialTimeout("tcp", target, netTimeout)
	if err != nil {
		return netResult{Error: err.Error()}
	}
	conn.Close()
	return netResult{OK: true}
}

// dnsServer returns server as host:port, port 53 when it has none.
func dnsServer(server string) string {
	if server != "" && !strings.Contains(server, ":") {
		return net.JoinHostPort(server, "53")
	}
	return server
}

// nameserver returns the first nameserver of a resolv.conf, as host:53.
func nameserver(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			return net.JoinHostPort(f[1], "53")
		}
	}
	return ""
}

var dnsTypes = map[string]uint16{"A": 1, "TXT": 16}

func netDNS(qtype, name, server string) netResult {
	t, ok := dnsTypes[qtype]
	if !ok {
		return netResult{Error: "unknown type " + qtype}
	}
	server = dnsServer(server)
	if server == "" {
		conf, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return netResult{Error: err.Error()}
		}
		if server = nameserver(string(conf)); server == "" {
			return netResult{Error: "no nameserver in /etc/resolv.conf"}
		}
	}
	id := uint16(rand.IntN(1 << 16))
	q := binary.BigEndian.AppendUint16(nil, id)
	q = append(q, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) // RD, one question
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(l) == 0 || len(l) > 63 {
			return netResult{Error: "bad name " + name}
		}
		q = append(append(q, byte(len(l))), l...)
	}
	q = binary.BigEndian.AppendUint16(append(q, 0), t)
	q = binary.BigEndian.AppendUint16(q, 1)
	conn, err := net.Dial("udp", server)
	if err != nil {
		return netResult{Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(netTimeout))
	if _, err := conn.Write(q); err != nil {
		return netResult{Error: err.Error()}
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return netResult{Error: err.Error()}
		}
		if n < 12 || binary.BigEndian.Uint16(buf) != id || buf[2]&0x80 == 0 {
			continue
		}
		return parseDNSReply(buf[:n])
	}
}

// skipName returns the offset after the (possibly compressed) name at i.
func skipName(m []byte, i int) (int, error) {
	for i < len(m) {
		switch l := int(m[i]); {
		case l == 0:
			return i + 1, nil
		case l&0xc0 == 0xc0:
			return i + 2, nil
		default:
			i += 1 + l
		}
	}
	return 0, errors.New("truncated name")
}

func parseDNSReply(m []byte) netResult {
	rcode := int(m[3] & 0x0f)
	r := netResult{Rcode: &rcode}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	i := 12
	var err error
	for range qd {
		if i, err = skipName(m, i); err != nil {
			r.Error = err.Error()
			return r
		}
		i += 4
	}
	for range an {
		if i, err = skipName(m, i); err != nil || i+10 > len(m) {
			r.Error = "truncated answer"
			return r
		}
		typ, rdlen := binary.BigEndian.Uint16(m[i:]), int(binary.BigEndian.Uint16(m[i+8:]))
		i += 10
		if i+rdlen > len(m) {
			r.Error = "truncated answer"
			return r
		}
		rd := m[i : i+rdlen]
		switch typ {
		case 1:
			if rdlen == 4 {
				r.Answers = append(r.Answers, net.IP(rd).String())
			}
		case 16:
			var parts []string
			for j := 0; j < len(rd); j += 1 + int(rd[j]) {
				end := min(len(rd), j+1+int(rd[j]))
				parts = append(parts, string(rd[j+1:end]))
			}
			r.Answers = append(r.Answers, strings.Join(parts, ""))
		}
		i += rdlen
	}
	r.OK = rcode == 0 && len(r.Answers) > 0
	return r
}

func ts() string { return strconv.FormatFloat(float64(time.Now().UnixNano())/1e9, 'f', 3, 64) }

// lockedWriter keeps the reader's and the writer's log lines whole.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) line(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, ts()+" "+format+"\n", args...)
}

// stream runs until the connection fails or stop is closed. It returns an
// error only when it never connected.
func stream(w io.Writer, proxy, target, name string, every time.Duration, stop <-chan struct{}) error {
	out := &lockedWriter{w: w}
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if proxy == "-" {
			conn, err = net.DialTimeout("tcp", target, netTimeout)
		} else {
			conn, _, _, err = connectVia(proxy, target)
		}
		if err == nil {
			break
		}
		out.line("connect-failed %v", err)
		select {
		case <-stop:
			return fmt.Errorf("never connected: %w", err)
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("never connected: %w", err)
		}
	}
	defer conn.Close()
	out.line("connected %s via %s", target, proxy)
	done := make(chan struct{})
	var once sync.Once
	end := func(format string, args ...any) {
		once.Do(func() {
			out.line(format, args...)
			close(done)
		})
	}
	go func() {
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			out.line("rx %s", sc.Text())
		}
		end("closed read %v", sc.Err())
	}()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for seq := 1; ; seq++ {
		select {
		case <-stop:
			return nil
		case <-done:
			return nil
		case <-tick.C:
		}
		if _, err := fmt.Fprintf(conn, "%s %d %s\n", name, seq, ts()); err != nil {
			end("closed write %v", err)
			return nil
		}
	}
}

func streamMain(args []string) {
	if len(args) != 4 {
		fail(errors.New("stream: PROXY HOST:PORT NAME EVERY_MS"))
	}
	ms, err := strconv.Atoi(args[3])
	if err != nil || ms <= 0 {
		fail(fmt.Errorf("stream: bad interval %q", args[3]))
	}
	if err := stream(os.Stdout, args[0], args[1], args[2], time.Duration(ms)*time.Millisecond, nil); err != nil {
		fail(err)
	}
}
