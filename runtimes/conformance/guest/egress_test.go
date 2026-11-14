package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeProxy answers CONNECT for allowed with a tunnel to origin, 403 otherwise.
func fakeProxy(t *testing.T, allowed, origin string) string {
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
				if req.Method != http.MethodConnect || req.Host != allowed+":443" {
					io.WriteString(c, "HTTP/1.1 403 Forbidden\r\ncontent-length: 4\r\n\r\ndeny")
					br.ReadByte() // keep the connection open like Envoy
					return
				}
				up, err := net.Dial("tcp", origin)
				if err != nil {
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestConnectProbeThroughProxy(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "origin-allowed\n")
	}))
	defer origin.Close()
	roots := origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	proxy := fakeProxy(t, "example.com", strings.TrimPrefix(origin.URL, "https://"))
	// httptest's certificate is valid for example.com.
	if r := connectProbe(proxy, roots, "example.com"); !r.OK || r.Body != "origin-allowed" || r.ProxyStatus != 200 {
		t.Fatalf("allowed: %+v", r)
	}
	if r := connectProbe(proxy, roots, "blocked.example.com"); r.OK || r.ProxyStatus != 403 || r.Body != "deny" {
		t.Fatalf("blocked: %+v", r)
	}
}

func TestDirectProbeReportsUnreachable(t *testing.T) {
	r := directProbe("blocked.invalid", "127.0.0.1")
	if r.OK || r.Resolved != "" || r.ResolveError == "" || r.ConnectError == "" {
		t.Fatalf("%+v", r)
	}
}
