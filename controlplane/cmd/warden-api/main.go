package main

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"warden/controlplane/internal/api"
	"warden/controlplane/internal/authn"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scheduler"
	"warden/controlplane/internal/scim"
	"warden/controlplane/internal/store"
	"warden/controlplane/internal/tenant"
)

// identity builds the API verifier from WARDEN_OIDC_{ISSUER,AUDIENCE,JWKS_URL}
// (all or none) and, if WARDEN_SCIM_TOKEN_DIGESTS names a digest file, the SCIM
// endpoint. Unconfigured OIDC yields a nil verifier, which denies every request;
// a partial or invalid configuration is an error, never a silent fallback.
func identity(getenv func(string) string, pool *pgxpool.Pool) (tenant.Verifier, http.Handler, error) {
	cfg := authn.Config{Issuer: getenv("WARDEN_OIDC_ISSUER"), Audience: getenv("WARDEN_OIDC_AUDIENCE"), JWKSURL: getenv("WARDEN_OIDC_JWKS_URL")}
	digests := getenv("WARDEN_SCIM_TOKEN_DIGESTS")
	if cfg == (authn.Config{}) {
		if digests != "" {
			return nil, nil, errors.New("SCIM needs OIDC: provisioned users could never sign in")
		}
		return nil, nil, nil
	}
	tokens, err := authn.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	directory := &scim.Store{Pool: pool}
	verifier := scim.TenantVerifier(tokens, directory)
	if digests == "" {
		return verifier, nil, nil
	}
	provisioners, err := scim.LoadStaticTokens(digests)
	if err != nil {
		return nil, nil, err
	}
	return verifier, scim.NewHandler(directory, provisioners), nil
}

// routes sends /scim/v2/ to SCIM when it is configured; everything else, and
// SCIM paths when it is not, goes to the run API.
func routes(apiHandler, scimHandler http.Handler) http.Handler {
	if scimHandler == nil {
		return apiHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/scim/v2/") {
			scimHandler.ServeHTTP(w, r)
			return
		}
		apiHandler.ServeHTTP(w, r)
	})
}

func main() {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		log.Fatal("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		log.Fatal("database configuration failed")
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		log.Fatal("database unavailable")
	}
	if err = store.Migrate(ctx, pool); err != nil {
		log.Fatal("database migration failed")
	}
	runStore := &runs.Store{Pool: pool}
	lifetime, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	workerDone := make(chan error, 1)
	if path := os.Getenv("WARDEN_SCHEDULER_CONFIG"); path != "" {
		configFile, openErr := os.Open(path)
		if openErr != nil {
			log.Fatal("scheduler configuration unavailable")
		}
		cfg, parseErr := scheduler.ParseConfig(configFile)
		_ = configFile.Close()
		if parseErr != nil {
			log.Fatal("scheduler configuration invalid")
		}
		worker, buildErr := cfg.Scheduler(runStore)
		if buildErr != nil {
			log.Fatal("scheduler runtime validation failed")
		}
		go func() { workerDone <- worker.Run(lifetime) }()
	} else {
		workerDone <- nil
	}
	address := os.Getenv("WARDEN_LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	verifier, scimHandler, err := identity(os.Getenv, pool)
	if err != nil {
		log.Fatalf("identity configuration invalid: %v", err)
	}
	server := &http.Server{Addr: address, Handler: routes(api.New(runStore, verifier), scimHandler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	switch {
	case verifier == nil:
		log.Printf("control plane listening on %s; OIDC not configured: all requests denied", address)
	case scimHandler == nil:
		log.Printf("control plane listening on %s; OIDC on, SCIM off: only already-provisioned users", address)
	default:
		log.Printf("control plane listening on %s; OIDC and SCIM on", address)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ListenAndServe() }()
	select {
	case <-lifetime.Done():
	case err = <-serverDone:
		if err != nil && err != http.ErrServerClosed {
			log.Print("HTTP server failed")
		}
		stop()
	}
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()
	_ = server.Shutdown(shutdown)
	// Scheduler owns its handles and performs bounded cleanup before the database
	// pool closes. Signal cancellation is separate from every HTTP request.
	if err = <-workerDone; err != nil {
		log.Print("scheduler stopped with an error")
	}
}
