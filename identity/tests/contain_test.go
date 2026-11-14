package tests

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"warden/respond"
)

// nearestRank returns the p-th percentile (0 < p <= 100) of sorted values.
func nearestRank(sorted []float64, p float64) float64 {
	i := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	return sorted[max(0, min(i, len(sorted)-1))]
}

// TestTimeToContainVaultLease is the Task 14 drill: a sandbox holds a live
// dynamic DB credential and an open session; an alert for that lease reaches
// the response executor, which revokes the lease through Vault. The clock
// runs from the alert's arrival at the executor to the first verified failed
// login. A dry run first must leave the credential working.
func TestTimeToContainVaultLease(t *testing.T) {
	l := live(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exec, err := respond.New(respond.Config{
		Playbook: respond.Playbook{ID: "revoke-db-lease", Trigger: "warden-db-credential-misuse",
			Steps: []respond.Action{{Name: respond.RevokeVaultLease, Resource: respond.Resource{Type: "vault_lease"}}}},
		AllowedTenantIDs: []string{"tenant-a"},
		JournalPath:      filepath.Join(dir, "attempts.journal"),
		Actions:          respond.Router{respond.RevokeVaultLease: respond.VaultLeases{Client: l.v}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Close()

	const runs = 20
	var handleMS, containMS []float64
	var sessionKilled, noOps int
	for i := range runs {
		c, err := l.v.DBCreds(ctx, "database", "warden-app")
		if err != nil {
			t.Fatal(err)
		}
		session, err := l.login(ctx, c.Username, c.Password)
		if err != nil {
			t.Fatal(err)
		}
		alert := respond.Alert{ID: fmt.Sprintf("alert-%02d", i), RuleID: "warden-db-credential-misuse", TenantID: "tenant-a",
			Resource: respond.Resource{Type: "vault_lease", ID: c.LeaseID}}
		if i == 0 {
			if r, err := exec.Handle(alert, true); err != nil || r.Status != respond.Preview {
				t.Fatalf("dry run = %+v, %v", r, err)
			}
			conn, err := l.login(ctx, c.Username, c.Password)
			if err != nil {
				t.Fatalf("dry run changed the credential: %v", err)
			}
			conn.Close(ctx)
		}
		t0 := time.Now()
		r, err := exec.Handle(alert, false)
		handled := time.Since(t0)
		if err != nil || r.Status != respond.Completed {
			t.Fatalf("run %d: %+v, %v", i, r, err)
		}
		var contained time.Duration
		for time.Since(t0) < 5*time.Second {
			conn, err := l.login(ctx, c.Username, c.Password)
			if err != nil {
				contained = time.Since(t0)
				break
			}
			conn.Close(ctx)
			time.Sleep(5 * time.Millisecond)
		}
		if contained == 0 {
			t.Fatalf("run %d: credential still works 5 s after the alert", i)
		}
		if _, err := session.Exec(ctx, "SELECT 1"); err != nil {
			sessionKilled++
		}
		session.Close(context.Background())
		if r2, err := exec.Handle(alert, false); err == nil && r2.NoOp {
			noOps++
		}
		handleMS = append(handleMS, float64(handled.Microseconds())/1000)
		containMS = append(containMS, float64(contained.Microseconds())/1000)
	}
	raw := map[string]any{"handle_ms": append([]float64(nil), handleMS...), "alert_to_contained_ms": append([]float64(nil), containMS...)}
	sort.Float64s(handleMS)
	sort.Float64s(containMS)
	summary := func(v []float64) map[string]float64 {
		return map[string]float64{"p50": nearestRank(v, 50), "p95": nearestRank(v, 95), "max": v[len(v)-1], "min": v[0]}
	}
	l.record("time_to_contain", map[string]any{"runs": runs, "handle_ms": summary(handleMS),
		"alert_to_contained_ms": summary(containMS), "open_sessions_killed": sessionKilled,
		"duplicate_alerts_noop": noOps, "raw": raw})
	t.Logf("handle p50 %.1f ms p95 %.1f ms; alert->contained p50 %.1f ms p95 %.1f ms",
		nearestRank(handleMS, 50), nearestRank(handleMS, 95), nearestRank(containMS, 50), nearestRank(containMS, 95))
	if sessionKilled != runs {
		t.Errorf("open sessions killed %d/%d", sessionKilled, runs)
	}
	if noOps != runs {
		t.Errorf("duplicate alerts no-op %d/%d", noOps, runs)
	}
}
