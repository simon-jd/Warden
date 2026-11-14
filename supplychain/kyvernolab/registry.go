// Package kyvernolab builds signed and unsigned OCI fixtures in memory so the
// real Kyverno CLI can verify Warden's rendered admission policies offline.
//
// Nothing here is a production signer: the CA and keys live only for one test
// process, and the registry is read-only over HTTP and bound to loopback.
package kyvernolab

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ociManifest = "application/vnd.oci.image.manifest.v1+json"
	ociIndex    = "application/vnd.oci.image.index.v1+json"
	ociConfig   = "application/vnd.oci.image.config.v1+json"
	ociLayerGz  = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// Descriptor is an OCI content descriptor.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

type stored struct {
	mediaType string
	body      []byte
}

// Registry is a minimal in-memory OCI distribution server (pull side only).
// Fixtures are written through the Go API, never over HTTP.
type Registry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string]map[string]stored // repo -> tag or digest
	layers    map[string][]Descriptor      // repo:tag -> appended signature layers
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{blobs: map[string][]byte{}, manifests: map[string]map[string]stored{},
		layers: map[string][]Descriptor{}}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *Registry) putBlob(mediaType string, b []byte) Descriptor {
	d := digestOf(b)
	r.blobs[d] = append([]byte(nil), b...)
	return Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(b))}
}

// repoPath drops a registry host ("127.0.0.1:5000/warden/api" -> "warden/api"):
// fixtures are addressed by full image name, HTTP requests by repository path.
func repoPath(image string) string {
	if i := strings.Index(image, "/"); i > 0 && strings.ContainsAny(image[:i], ".:") {
		return image[i+1:]
	}
	return image
}

func (r *Registry) putManifest(image, tag string, m manifest) (string, error) {
	repo := repoPath(image)
	body, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	d := digestOf(body)
	if r.manifests[repo] == nil {
		r.manifests[repo] = map[string]stored{}
	}
	s := stored{mediaType: m.MediaType, body: body}
	r.manifests[repo][d] = s
	if tag != "" {
		r.manifests[repo][tag] = s
	}
	return d, nil
}

func configFor(diffIDs []string) []byte {
	cfg, _ := json.Marshal(map[string]any{
		"architecture": "amd64", "os": "linux", "config": map[string]any{},
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	})
	return cfg
}

// PushImage stores a one-layer image holding the given file and returns its
// manifest digest. The layer is deterministic, so equal input gives an equal
// digest.
func (r *Registry) PushImage(repo, path, content string) (string, error) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o444, Size: int64(len(content)),
		ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
		return "", err
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	layer := r.putBlob(ociLayerGz, gz.Bytes())
	cfg := r.putBlob(ociConfig, configFor([]string{digestOf(raw.Bytes())}))
	return r.putManifest(repo, "", manifest{SchemaVersion: 2, MediaType: ociManifest,
		Config: cfg, Layers: []Descriptor{layer}})
}

// appendLayer adds an uncompressed layer (a cosign signature or DSSE
// envelope) to the image at repo:tag, rewriting that manifest the way cosign
// does when a second signature is attached.
func (r *Registry) appendLayer(repo, tag, mediaType string, content []byte, annotations map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.putBlob(mediaType, content)
	d.Annotations = annotations
	key := repo + ":" + tag
	r.layers[key] = append(r.layers[key], d)
	diffIDs := make([]string, len(r.layers[key]))
	for i, l := range r.layers[key] {
		diffIDs[i] = l.Digest
	}
	cfg := r.putBlob(ociConfig, configFor(diffIDs))
	_, err := r.putManifest(repo, tag, manifest{SchemaVersion: 2, MediaType: ociManifest,
		Config: cfg, Layers: append([]Descriptor(nil), r.layers[key]...)})
	return err
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"code": code, "message": msg}}})
}

func send(w http.ResponseWriter, req *http.Request, mediaType string, body []byte) {
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", digestOf(body))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if req.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// ServeHTTP implements GET/HEAD for /v2/, blobs, manifests, tags and the
// referrers API (always an empty index: legacy cosign uses tags).
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "read-only registry")
		return
	}
	p := req.URL.Path
	if p == "/v2/" || p == "/v2" {
		send(w, req, "application/json", []byte("{}"))
		return
	}
	if !strings.HasPrefix(p, "/v2/") {
		writeError(w, http.StatusNotFound, "NOT_FOUND", p)
		return
	}
	rest := strings.TrimPrefix(p, "/v2/")
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, kind := range []string{"/manifests/", "/blobs/", "/referrers/", "/tags/"} {
		i := strings.LastIndex(rest, kind)
		if i <= 0 {
			continue
		}
		repo, ref := rest[:i], rest[i+len(kind):]
		switch kind {
		case "/manifests/":
			m, ok := r.manifests[repo][ref]
			if !ok {
				writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", repo+":"+ref)
				return
			}
			send(w, req, m.mediaType, m.body)
		case "/blobs/":
			b, ok := r.blobs[ref]
			if !ok {
				writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", ref)
				return
			}
			send(w, req, "application/octet-stream", b)
		case "/referrers/":
			body, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociIndex,
				"manifests": []any{}})
			send(w, req, ociIndex, body)
		case "/tags/":
			if ref != "list" {
				writeError(w, http.StatusNotFound, "NOT_FOUND", p)
				return
			}
			tags := []string{}
			for t := range r.manifests[repo] {
				if !strings.HasPrefix(t, "sha256:") {
					tags = append(tags, t)
				}
			}
			sort.Strings(tags)
			body, _ := json.Marshal(map[string]any{"name": repo, "tags": tags})
			send(w, req, "application/json", body)
		}
		return
	}
	writeError(w, http.StatusNotFound, "NAME_UNKNOWN", fmt.Sprintf("unsupported path %q", p))
}
