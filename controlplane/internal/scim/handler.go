package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"warden/controlplane/internal/canonical"
)

const (
	usersPath   = "/scim/v2/Users"
	maxBody     = 64 << 10
	maxPageSize = 100
)

var idPattern = regexp.MustCompile(`^[A-Z2-7]{26}$`)

// StaticTokens maps provisioning bearer tokens to tenants. Only SHA-256
// digests are held; the tokens themselves live in the IdP's provisioning config.
type StaticTokens struct{ entries []tokenEntry }

type tokenEntry struct {
	digest [32]byte
	tenant string
}

// NewStaticTokens takes lowercase hex SHA-256 digests mapped to tenant IDs.
func NewStaticTokens(digests map[string]string) (*StaticTokens, error) {
	if len(digests) == 0 {
		return nil, errors.New("scim: no provisioning token digests")
	}
	s := &StaticTokens{}
	for d, tenantID := range digests {
		raw, err := hex.DecodeString(d)
		if err != nil || len(raw) != sha256.Size || d != strings.ToLower(d) {
			return nil, errors.New("scim: token digest must be 64 lowercase hex characters")
		}
		if tenantID == "" || len(tenantID) > maxText {
			return nil, errors.New("scim: token digest needs a tenant ID")
		}
		var e tokenEntry
		copy(e.digest[:], raw)
		e.tenant = tenantID
		s.entries = append(s.entries, e)
	}
	return s, nil
}

// LoadStaticTokens reads a JSON object {"<sha256 hex>": "<tenant id>", ...}.
func LoadStaticTokens(path string) (*StaticTokens, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err := canonical.JSON(raw); err != nil {
		return nil, fmt.Errorf("scim token digests: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("scim token digests: %w", err)
	}
	return NewStaticTokens(m)
}

// tenant compares against every digest so timing does not reveal which matched.
func (s *StaticTokens) tenant(raw string) (string, bool) {
	if s == nil || raw == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(raw))
	found := ""
	for _, e := range s.entries {
		if subtle.ConstantTimeCompare(sum[:], e.digest[:]) == 1 {
			found = e.tenant
		}
	}
	return found, found != ""
}

type handler struct {
	store  *Store
	tokens *StaticTokens
}

func NewHandler(s *Store, t *StaticTokens) http.Handler { return &handler{store: s, tokens: t} }

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func fail(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{"schemas": []string{errorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	writeSCIM(w, status, body)
}

func resource(u User) map[string]any {
	r := map[string]any{
		"schemas":    []string{userSchema},
		"id":         u.ID,
		"externalId": u.ExternalID,
		"userName":   u.UserName,
		"active":     u.Active,
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.Created.UTC().Format(time.RFC3339Nano),
			"lastModified": u.Updated.UTC().Format(time.RFC3339Nano),
			"location":     usersPath + "/" + u.ID,
			"version":      fmt.Sprintf(`W/"%d"`, u.Version),
		},
	}
	if u.DisplayName != "" {
		r["displayName"] = u.DisplayName
	}
	return r
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	auth := strings.Fields(r.Header.Get("Authorization"))
	if len(auth) != 2 || !strings.EqualFold(auth[0], "Bearer") {
		fail(w, http.StatusUnauthorized, "", "unauthorized")
		return
	}
	tenantID, ok := h.tokens.tenant(auth[1])
	if !ok || h.store == nil {
		fail(w, http.StatusUnauthorized, "", "unauthorized")
		return
	}
	if r.URL.Path == usersPath {
		switch r.Method {
		case http.MethodPost:
			h.create(ctx, w, r, tenantID)
		case http.MethodGet:
			h.list(ctx, w, r, tenantID)
		default:
			fail(w, http.StatusMethodNotAllowed, "", "method not allowed")
		}
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, usersPath+"/")
	if !ok || !idPattern.MatchString(id) {
		fail(w, http.StatusNotFound, "", "not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, err := h.store.Get(ctx, tenantID, id)
		h.respond(w, http.StatusOK, u, err)
	case http.MethodPatch:
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		c, err := parsePatch(body)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalidValue", err.Error())
			return
		}
		u, err := h.store.Update(ctx, tenantID, id, c)
		h.respond(w, http.StatusOK, u, err)
	case http.MethodPut:
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		u, err := parseUser(body)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalidValue", err.Error())
			return
		}
		u, err = h.store.Update(ctx, tenantID, id, change{active: &u.Active, userName: &u.UserName, externalID: &u.ExternalID, displayName: &u.DisplayName})
		h.respond(w, http.StatusOK, u, err)
	case http.MethodDelete:
		if err := h.store.Delete(ctx, tenantID, id); err != nil {
			h.respond(w, 0, User{}, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(w, http.StatusMethodNotAllowed, "", "method not allowed")
	}
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			fail(w, http.StatusRequestEntityTooLarge, "", "request too large")
		} else {
			fail(w, http.StatusBadRequest, "invalidSyntax", "unreadable body")
		}
		return nil, false
	}
	return raw, true
}

func (h *handler) respond(w http.ResponseWriter, status int, u User, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "", "not found")
	case errors.Is(err, ErrConflict):
		fail(w, http.StatusConflict, "uniqueness", "userName or externalId already provisioned in this tenant")
	case err != nil:
		fail(w, http.StatusInternalServerError, "", "internal error")
	default:
		writeSCIM(w, status, resource(u))
	}
}

func (h *handler) create(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID string) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	u, err := parseUser(body)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	u, err = h.store.Create(ctx, tenantID, u)
	if err == nil {
		w.Header().Set("Location", usersPath+"/"+u.ID)
	}
	h.respond(w, http.StatusCreated, u, err)
}

func (h *handler) list(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID string) {
	q := r.URL.Query()
	var f *filter
	if raw := q.Get("filter"); raw != "" {
		parsed, err := parseFilter(raw)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalidFilter", `supported filters: userName eq "..." and externalId eq "..."`)
			return
		}
		f = &parsed
	}
	start, count := 1, maxPageSize
	if v := q.Get("startIndex"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalidValue", "startIndex must be an integer")
			return
		}
		start = max(n, 1) // RFC 7644 3.4.2.4: values below 1 are treated as 1
	}
	if v := q.Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalidValue", "count must be an integer")
			return
		}
		count = min(max(n, 0), maxPageSize)
	}
	users, total, err := h.store.List(ctx, tenantID, f, start-1, count)
	if err != nil {
		fail(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	resources := make([]map[string]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, resource(u))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas": []string{listSchema}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(resources), "Resources": resources,
	})
}
