// Package kindlab drives the throwaway kind cluster of scripts/kind_lab.sh
// for live Kubernetes tests: it reads the project-local kubeconfig and talks
// to the API server with plain JSON over HTTPS (no client-go).
package kindlab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// QuarantinePolicyPath is the NetworkPolicy the lab applies, relative to this package.
const QuarantinePolicyPath = "../../policies/kubernetes/quarantine-networkpolicy.json"

// Cluster is the single cluster and user of a kind kubeconfig.
type Cluster struct {
	Server        string
	CA, Cert, Key []byte
}

// ParseKubeconfig reads the fields kind writes. It refuses anything but one
// cluster on a loopback https address with inline credentials.
func ParseKubeconfig(raw []byte) (Cluster, error) {
	c, err := parseKubeconfig(raw)
	if err != nil {
		return Cluster{}, err
	}
	u, err := url.Parse(c.Server)
	if err != nil || u.Scheme != "https" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		return Cluster{}, fmt.Errorf("kubeconfig server %q is not https on loopback", c.Server)
	}
	return c, nil
}

// ParseKubeconfigFor is ParseKubeconfig for a lab whose API server is on a
// node address rather than loopback (scripts/k3s_gvisor_lab.sh): the server
// must be https on exactly host.
func ParseKubeconfigFor(raw []byte, host string) (Cluster, error) {
	if host == "" {
		return Cluster{}, errors.New("no lab node host given")
	}
	c, err := parseKubeconfig(raw)
	if err != nil {
		return Cluster{}, err
	}
	u, err := url.Parse(c.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() != host {
		return Cluster{}, fmt.Errorf("kubeconfig server %q is not https on %s", c.Server, host)
	}
	return c, nil
}

func parseKubeconfig(raw []byte) (Cluster, error) {
	var c Cluster
	clusters := 0
	fields := map[string]*[]byte{"certificate-authority-data": &c.CA, "client-certificate-data": &c.Cert, "client-key-data": &c.Key}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "- cluster:" {
			clusters++
			continue
		}
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if key == "server" {
			c.Server = val
		} else if dst, ok := fields[key]; ok {
			b, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				return Cluster{}, fmt.Errorf("kubeconfig %s: %v", key, err)
			}
			*dst = b
		}
	}
	if err := sc.Err(); err != nil {
		return Cluster{}, err
	}
	if clusters != 1 {
		return Cluster{}, fmt.Errorf("kubeconfig has %d clusters, want exactly 1", clusters)
	}
	if len(c.CA) == 0 || len(c.Cert) == 0 || len(c.Key) == 0 {
		return Cluster{}, errors.New("kubeconfig needs inline CA, client certificate and key")
	}
	return c, nil
}

func (c Cluster) tlsConfig(withClientCert bool) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CA) {
		return nil, errors.New("kubeconfig CA is not PEM")
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if withClientCert {
		pair, err := tls.X509KeyPair(c.Cert, c.Key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// HTTPClient trusts only the cluster CA. With admin=true it also presents the
// kubeconfig's client certificate (cluster-admin in kind); otherwise callers
// authenticate with a bearer token.
func (c Cluster) HTTPClient(admin bool) (*http.Client, error) {
	cfg, err := c.tlsConfig(admin)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}

// API is a minimal JSON client for the API server.
type API struct {
	Server string
	HTTP   *http.Client
	Token  string // optional bearer token
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body) }

// IsStatus reports whether err is a StatusError with the given code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// Do sends body (JSON-encoded unless it is []byte) and decodes a JSON answer into out.
func (a API) Do(ctx context.Context, method, path, contentType string, body, out any) error {
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.Server, "/")+path, r)
	if err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	if r != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := string(raw)
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return &StatusError{Code: resp.StatusCode, Body: msg}
	}
	if out == nil {
		return nil
	}
	if p, ok := out.(*[]byte); ok {
		*p = raw
		return nil
	}
	return json.Unmarshal(raw, out)
}
