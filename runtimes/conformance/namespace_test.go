package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/respond/kindlab"
)

// fakeNamespaces is the API server's namespace and service account
// endpoints, enough for createNamespace. A deleted namespace stays,
// Terminating, for a few GETs (the namespace controller empties it first);
// meanwhile POSTing it again answers 409, as the API server does.
type fakeNamespaces struct {
	mu      sync.Mutex
	ns      map[string]*fakeNS
	uids    int
	failSA  bool
	deletes int
}

type fakeNS struct {
	uid         int
	terminating int // GETs left until it is gone; -1 while active
	accounts    map[string]bool
}

func (f *fakeNamespaces) add(name string, accounts ...string) *fakeNS {
	f.uids++
	n := &fakeNS{uid: f.uids, terminating: -1, accounts: map[string]bool{}}
	for _, a := range accounts {
		n.accounts[a] = true
	}
	f.ns[name] = n
	return n
}

func (f *fakeNamespaces) get(name string) *fakeNS {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ns[name]
}

func (f *fakeNamespaces) deleted() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deletes
}

func (f *fakeNamespaces) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := func(code int, reason string) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"kind":"Status","code":%d,"reason":%q}`, code, reason)
	}
	var body struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Metadata.Name == "" {
			status(400, "BadRequest")
			return
		}
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces"), "/")
	switch {
	case r.Method == "POST" && len(parts) == 1:
		if f.ns[body.Metadata.Name] != nil {
			status(409, "AlreadyExists")
			return
		}
		f.add(body.Metadata.Name)
		status(201, "")
	case len(parts) == 2:
		n := f.ns[parts[1]]
		if n == nil {
			status(404, "NotFound")
			return
		}
		switch r.Method {
		case "GET":
			if n.terminating == 0 {
				delete(f.ns, parts[1])
				status(404, "NotFound")
				return
			}
			if n.terminating > 0 {
				n.terminating--
			}
			status(200, "")
		case "DELETE":
			f.deletes++
			if n.terminating < 0 {
				n.terminating = 2
			}
			status(200, "")
		default:
			status(405, "MethodNotAllowed")
		}
	case r.Method == "POST" && len(parts) == 3 && parts[2] == "serviceaccounts":
		n := f.ns[parts[1]]
		switch {
		case n == nil:
			status(404, "NotFound")
		case n.terminating >= 0:
			status(403, "Forbidden") // "is being terminated"
		case f.failSA:
			status(500, "InternalError")
		case n.accounts[body.Metadata.Name]:
			status(409, "AlreadyExists")
		default:
			n.accounts[body.Metadata.Name] = true
			status(201, "")
		}
	default:
		status(404, "NotFound")
	}
}

func startNamespaces(t *testing.T) (*fakeNamespaces, kindlab.API) {
	f := &fakeNamespaces{ns: map[string]*fakeNS{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, kindlab.API{Server: srv.URL, HTTP: srv.Client()}
}

// cleanupRecorder stands in for the test that calls createNamespace.
type cleanupRecorder struct {
	fns  []func()
	errs []string
}

func (c *cleanupRecorder) Cleanup(f func()) { c.fns = append(c.fns, f) }
func (c *cleanupRecorder) Errorf(format string, args ...any) {
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}
func (c *cleanupRecorder) run() {
	for i := len(c.fns) - 1; i >= 0; i-- {
		c.fns[i]()
	}
}

const testNS, testSA = "warden-system", "warden-controlplane"

func createTestNamespace(t *testing.T, api kindlab.API, tb *cleanupRecorder) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := json.RawMessage(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"` + testNS + `"}}`)
	sa := json.RawMessage(`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"` + testSA + `","namespace":"` + testNS + `"}}`)
	return createNamespace(ctx, tb, api, testNS, ns, []json.RawMessage{sa})
}

// A failure after the namespace exists must still leave its deletion
// registered: t.Fatal runs the cleanups, and nothing else removes it.
func TestCreateNamespaceIsCleanedUpWhenItsAccountFails(t *testing.T) {
	f, api := startNamespaces(t)
	f.failSA = true
	var tb cleanupRecorder
	if err := createTestNamespace(t, api, &tb); err == nil {
		t.Fatal("the service account was not created, and createNamespace succeeded")
	}
	tb.run()
	if f.get(testNS) != nil {
		t.Fatalf("namespace %s left behind after the failed setup (%d cleanups registered)", testNS, len(tb.fns))
	}
	if len(tb.errs) > 0 {
		t.Fatal(tb.errs)
	}
}

// With IDENTITY_REUSE=1 the lab outlives a run, and a run that was killed,
// or whose cleanup timed out, leaves the namespace behind.
func TestCreateNamespaceReplacesOneAnEarlierRunLeft(t *testing.T) {
	for _, terminating := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminating=%v", terminating), func(t *testing.T) {
			f, api := startNamespaces(t)
			old := f.add(testNS, testSA, "left-by-the-earlier-run")
			if terminating {
				old.terminating = 2
			}
			var tb cleanupRecorder
			if err := createTestNamespace(t, api, &tb); err != nil {
				t.Fatal(err)
			}
			n := f.get(testNS)
			if n == nil || n.uid == old.uid {
				t.Fatalf("namespace %s is the earlier run's", testNS)
			}
			if len(n.accounts) != 1 || !n.accounts[testSA] {
				t.Fatalf("accounts %v, want only %s", n.accounts, testSA)
			}
			tb.run()
			if f.get(testNS) != nil || len(tb.errs) > 0 {
				t.Fatalf("namespace not removed at the end: %v", tb.errs)
			}
		})
	}
}

func TestCreateNamespaceCreatesTheNamespaceAndItsAccounts(t *testing.T) {
	f, api := startNamespaces(t)
	var tb cleanupRecorder
	if err := createTestNamespace(t, api, &tb); err != nil {
		t.Fatal(err)
	}
	if n := f.get(testNS); n == nil || !n.accounts[testSA] || f.deleted() != 0 {
		t.Fatalf("namespace %+v, %d deletes", n, f.deleted())
	}
	tb.run()
	if f.get(testNS) != nil || len(tb.errs) > 0 {
		t.Fatalf("namespace not removed at the end: %v", tb.errs)
	}
}
