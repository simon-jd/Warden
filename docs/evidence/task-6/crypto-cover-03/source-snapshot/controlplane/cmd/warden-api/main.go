package main

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"warden/controlplane/internal/api"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scheduler"
	"warden/controlplane/internal/store"
)

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
	// Task 6 supplies a cryptographically verifying tenant.Verifier. Until then,
	// nil rejects every request; no header or bearer text is treated as identity.
	server := &http.Server{Addr: address, Handler: api.New(runStore, nil), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("control plane listening on %s; authentication unavailable: all requests denied", address)
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
