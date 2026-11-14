package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/tenant"
)

type handler struct {
	store    *runs.Store
	verifier tenant.Verifier
}

func New(s *runs.Store, v tenant.Verifier) http.Handler { return &handler{store: s, verifier: v} }
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	write(w, status, map[string]string{"error": message})
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	auth := strings.Fields(r.Header.Get("Authorization"))
	if h.verifier == nil || len(auth) != 2 || !strings.EqualFold(auth[0], "Bearer") {
		fail(w, 401, "unauthorized")
		return
	}
	claims, err := h.verifier.Verify(ctx, auth[1])
	if err != nil || strings.TrimSpace(claims.TenantID) == "" {
		fail(w, 401, "unauthorized")
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/runs" {
		h.create(w, r, claims.TenantID)
		return
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/runs/") {
		path := strings.TrimPrefix(r.URL.Path, "/v1/runs/")
		logs := strings.HasSuffix(path, "/logs")
		id := path
		if logs {
			id = strings.TrimSuffix(path, "/logs")
		}
		if id == "" || strings.Contains(id, "/") {
			fail(w, 404, "not found")
			return
		}
		run, err := h.store.Get(ctx, claims.TenantID, id)
		if errors.Is(err, runs.ErrNotFound) {
			fail(w, 404, "not found")
			return
		}
		if err != nil {
			fail(w, 500, "internal error")
			return
		}
		if logs {
			write(w, 200, run.Logs)
		} else {
			write(w, 200, run)
		}
		return
	}
	fail(w, 404, "not found")
}
func (h *handler) create(w http.ResponseWriter, r *http.Request, tenantID string) {
	key := r.Header.Get("Idempotency-Key")
	if strings.TrimSpace(key) == "" || len(key) > 256 {
		fail(w, 400, "Idempotency-Key required (1..256 bytes)")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			fail(w, 413, "request too large")
		} else {
			fail(w, 400, "invalid request body")
		}
		return
	}
	spec, err := runs.Normalize(raw)
	if err != nil {
		fail(w, 400, "invalid run specification")
		return
	}
	id, err := h.store.Create(r.Context(), tenantID, key, spec)
	if errors.Is(err, runs.ErrForbidden) {
		fail(w, 403, "run denied by tenant policy")
		return
	}
	if errors.Is(err, runs.ErrPolicyUnavailable) {
		fail(w, 503, "tenant policy unavailable")
		return
	}
	if errors.Is(err, runs.ErrConflict) {
		fail(w, 409, "idempotency key payload conflict")
		return
	}
	if err != nil {
		fail(w, 500, "internal error")
		return
	}
	write(w, 201, map[string]string{"run_id": id})
}
