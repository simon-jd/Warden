package main

// Egress probes for the runc allowlist lab, ported from
// controlplane/internal/scheduler/testdata/egress_client.py (the scratch
// image has no Python). The proxy comes from HTTPS_PROXY, as the driver sets
// it. Usage: warden-probe egress CA_PEM_BASE64 CASE...
// CASE is key,mode,host[,extra]:
//
//	connect  CONNECT host:443 through the proxy, then TLS (SNI=host) + GET /
//	http     plain GET http://host/ through the proxy
//	sni      TLS straight to the proxy's :10443 with SNI=host + GET /
//	front    as sni, but with Host header extra
//	direct   bypass the proxy: resolve host, then TCP to extra (ip) port 443
//	poll     repeat connect every 50 ms until it succeeds (extra=until-denied:
//	         until it fails) or 30 s pass
//
// Each case prints one JSON object; poll also prints {"polling_since": t} first.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const egressTimeout = 5 * time.Second

type egressResult struct {
	Key          string  `json:"key"`
	OK           bool    `json:"ok"`
	Status       int     `json:"status,omitempty"`
	ProxyStatus  int     `json:"proxy_status,omitempty"`
	Body         string  `json:"body,omitempty"`
	Error        string  `json:"error,omitempty"`
	Resolved     string  `json:"resolved,omitempty"`
	ResolveError string  `json:"resolve_error,omitempty"`
	ConnectError string  `json:"connect_error,omitempty"`
	Attempts     int     `json:"attempts,omitempty"`
	SucceededAt  float64 `json:"succeeded_at,omitempty"`
	PollingSince float64 `json:"polling_since,omitempty"`
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func emit(r egressResult) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func readResponse(r io.Reader) (int, string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<16))
	if err != nil && len(data) == 0 {
		return 0, "", err
	}
	head, body, _ := strings.Cut(string(data), "\r\n\r\n")
	fields := strings.Fields(head)
	if len(fields) < 2 {
		return 0, "", errors.New("short HTTP response")
	}
	status, err := strconv.Atoi(fields[1])
	return status, strings.TrimSpace(body), err
}

func tlsGet(conn net.Conn, roots *x509.CertPool, host, headerHost string) (int, string, error) {
	if headerHost == "" {
		headerHost = host
	}
	c := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(egressTimeout))
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", headerHost); err != nil {
		return 0, "", err
	}
	return readResponse(c)
}

func connectProbe(proxy string, roots *x509.CertPool, host string) egressResult {
	conn, err := net.DialTimeout("tcp", proxy, egressTimeout)
	if err != nil {
		return egressResult{Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(egressTimeout))
	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return egressResult{Error: "proxy closed during CONNECT: " + err.Error()}
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return egressResult{Error: "bad CONNECT response"}
	}
	status, _ := strconv.Atoi(fields[1])
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	if status != 200 {
		// One read, like the Python client: the proxy may keep the connection open.
		rest := make([]byte, 4096)
		n, _ := br.Read(rest)
		return egressResult{ProxyStatus: status, Body: strings.TrimSpace(string(rest[:n]))}
	}
	code, body, err := tlsGet(&bufferedConn{conn, br}, roots, host, "")
	if err != nil {
		return egressResult{ProxyStatus: 200, Error: err.Error()}
	}
	return egressResult{OK: code == 200, ProxyStatus: 200, Status: code, Body: body}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func httpProbe(proxy, host string) egressResult {
	conn, err := net.DialTimeout("tcp", proxy, egressTimeout)
	if err != nil {
		return egressResult{Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(egressTimeout))
	fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host)
	code, body, err := readResponse(conn)
	if err != nil {
		return egressResult{Error: err.Error()}
	}
	return egressResult{OK: code == 200, Status: code, Body: body}
}

func sniProbe(proxyHost string, roots *x509.CertPool, host, headerHost string) egressResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(proxyHost, "10443"), egressTimeout)
	if err != nil {
		return egressResult{Error: err.Error()}
	}
	code, body, err := tlsGet(conn, roots, host, headerHost)
	if err != nil {
		return egressResult{Error: err.Error()}
	}
	return egressResult{OK: code == 200, Status: code, Body: body}
}

func directProbe(host, ip string) egressResult {
	var r egressResult
	if addrs, err := net.LookupHost(host); err == nil {
		r.Resolved = strings.Join(addrs, ",")
	} else {
		r.ResolveError = err.Error()
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 3*time.Second)
	if err == nil {
		conn.Close()
		r.OK = true
	} else {
		r.ConnectError = err.Error()
	}
	return r
}

func egressMain(args []string) {
	if len(args) < 2 {
		fail(errors.New("egress: CA and at least one case required"))
	}
	pem, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		fail(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fail(errors.New("egress: bad CA PEM"))
	}
	u, err := url.Parse(os.Getenv("HTTPS_PROXY"))
	if err != nil || u.Scheme != "http" || u.Port() == "" {
		fail(fmt.Errorf("egress: HTTPS_PROXY must be http://host:port, got %q", os.Getenv("HTTPS_PROXY")))
	}
	proxy := u.Host
	for _, c := range args[1:] {
		parts := strings.Split(c, ",")
		if len(parts) < 3 {
			fail(fmt.Errorf("egress: bad case %q", c))
		}
		key, mode, host, extra := parts[0], parts[1], parts[2], ""
		if len(parts) > 3 {
			extra = parts[3]
		}
		var r egressResult
		switch mode {
		case "connect":
			r = connectProbe(proxy, roots, host)
		case "http":
			r = httpProbe(proxy, host)
		case "sni":
			r = sniProbe(u.Hostname(), roots, host, "")
		case "front":
			r = sniProbe(u.Hostname(), roots, host, extra)
		case "direct":
			r = directProbe(host, extra)
		case "poll":
			want := extra != "until-denied"
			start := now()
			emit(egressResult{Key: key, PollingSince: start})
			attempts := 0
			for now()-start < 30 {
				attempts++
				r = connectProbe(proxy, roots, host)
				if r.OK == want {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			r.Attempts, r.SucceededAt = attempts, now()
		default:
			fail(fmt.Errorf("egress: unknown mode %q", mode))
		}
		r.Key = key
		emit(r)
	}
}
