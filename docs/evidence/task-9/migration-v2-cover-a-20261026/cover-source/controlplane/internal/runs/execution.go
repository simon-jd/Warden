package runs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"warden/controlplane/internal/audit"
	"warden/runtimes"
	"warden/runtimes/gate"
)

var ErrBusy = errors.New("execution busy")
var ErrStale = errors.New("execution ownership lost")

const LogLimit = 1 << 20

type Logs struct {
	Encoding     string   `json:"encoding,omitempty"`
	Lines        []string `json:"logs"`
	Status       string   `json:"status"`
	Truncated    bool     `json:"truncated"`
	DroppedBytes uint64   `json:"dropped_bytes"`
}
type Completion struct {
	Reconciliation *gate.Reconciliation
	State          string
	ErrorCode      string
	Result         *runtimes.Exit
	Logs           Logs
	CleanupPending bool
}

// Claim owns a dedicated, non-reconnecting PostgreSQL session. Closing it
// releases the advisory lock. All mutations use this session plus its generation.
// No transaction (or audit row lock) is held while the runtime executes.
type Claim struct {
	RunID, TenantID string
	authority       string
	ambiguous       bool
	Spec            Spec
	Recovery        bool
	conn            *pgx.Conn
	generation      int64
	finished        bool
	state           string
	mu              sync.Mutex
}

func (s *Store) Candidates(ctx context.Context, node string, limit int) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.run_id FROM runs r LEFT JOIN run_executions e ON e.run_id=r.run_id WHERE (state IN ('queued','starting','running') OR cleanup_pending) AND (e.runtime_node IS NULL OR e.runtime_node=$1) ORDER BY updated_at,r.run_id LIMIT $2`, node, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) Claim(ctx context.Context, id string, node string) (*Claim, error) {
	pooled, err := s.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	c := &Claim{RunID: id, authority: node, conn: pooled.Hijack()}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	var locked bool
	// Hash collisions only serialize unrelated runs; they never permit overlap.
	if err = c.conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 177603))`, id).Scan(&locked); err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrBusy
	}
	tx, err := c.conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var raw []byte
	var pending bool
	var errorCode string
	if err = tx.QueryRow(ctx, `SELECT tenant_id,canonical_spec,state,cleanup_pending,error_code FROM runs WHERE run_id=$1 FOR UPDATE`, id).Scan(&c.TenantID, &raw, &c.state, &pending, &errorCode); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if c.state != "queued" && c.state != "starting" && c.state != "running" && !pending {
		return nil, ErrBusy
	}
	if err = json.Unmarshal(raw, &c.Spec); err != nil {
		return nil, err
	}
	c.Recovery = c.state != "queued"
	c.ambiguous = pending && (errorCode == "runtime_start_ambiguous" || errorCode == "creation_outcome_unknown")
	if err = tx.QueryRow(ctx, `INSERT INTO run_executions(run_id,generation,owner_pid,runtime_node) VALUES($1,1,pg_backend_pid(),$2) ON CONFLICT(run_id) DO UPDATE SET generation=run_executions.generation+1,owner_pid=pg_backend_pid(),claimed_at=clock_timestamp() WHERE run_executions.runtime_node=$2 RETURNING generation`, id, node).Scan(&c.generation); err != nil {
		return nil, err
	}
	event := "run.claimed"
	if !c.Recovery {
		c.state = "starting"
	} else {
		event = "run.recovery_claimed"
	}
	if _, err = tx.Exec(ctx, `UPDATE runs SET state=$2,updated_at=clock_timestamp() WHERE run_id=$1`, id, c.state); err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]any{"generation": c.generation, "state": c.state})
	if _, _, err = audit.AppendTx(ctx, tx, audit.Event{TenantID: c.TenantID, RunID: id, Type: event, Payload: payload}); err != nil {
		return nil, err
	}
	// A commit error is ambiguous: never return a launch-capable claim.
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	ok = true
	return c, nil
}

func (c *Claim) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.conn.Close(ctx)
		c.conn = nil
	}
}

func (c *Claim) Check(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return ErrStale
	}
	var owned bool
	err := c.conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM run_executions WHERE run_id=$1 AND generation=$2 AND owner_pid=pg_backend_pid())`, c.RunID, c.generation).Scan(&owned)
	if err != nil {
		return err
	}
	if !owned {
		return ErrStale
	}
	return nil
}

func (c *Claim) Running(ctx context.Context) error {
	if c.Recovery {
		return ErrStale
	}
	return c.transition(ctx, Completion{State: "running", Logs: Logs{Lines: []string{}, Status: "pending"}}, "starting")
}
func (c *Claim) Finish(ctx context.Context, out Completion) error {
	switch out.State {
	case "succeeded", "failed", "denied", "interrupted":
	default:
		return errors.New("invalid terminal state")
	}
	return c.transition(ctx, out, c.state)
}
func (c *Claim) transition(ctx context.Context, out Completion, previous string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil || c.finished {
		return ErrStale
	}
	if c.ambiguous && out.CleanupPending && out.ErrorCode != "creation_outcome_unknown" && out.ErrorCode != "runtime_start_ambiguous" {
		return errors.New("ambiguous creation must remain explicitly identified")
	}
	if out.Reconciliation != nil {
		if !c.Recovery || !out.Reconciliation.ValidFor(c.RunID, c.authority) || out.State != "interrupted" || out.ErrorCode != "node_retired" || out.CleanupPending || out.Result != nil || out.Logs.Status != "lost" {
			return errors.New("invalid original-node reconciliation")
		}
	} else if out.ErrorCode == "node_retired" || (c.ambiguous && !out.CleanupPending) {
		return errors.New("ambiguous creation requires bound original-node quiescence")
	}
	if c.state != previous || (c.state != "starting" && c.state != "running" && !c.Recovery) {
		return ErrStale
	}
	if out.State == "succeeded" && (previous != "running" || c.Recovery || out.Result == nil || !out.Result.CgroupEmpty || out.Result.Code != 0 || out.Result.OOMKilled || out.Result.TimedOut || out.CleanupPending || out.ErrorCode != "" || out.Logs.Status != "complete") {
		return errors.New("success requires a clean running execution")
	}
	if out.State == "denied" && (previous != "starting" || c.Recovery || out.Result != nil || out.CleanupPending) {
		return errors.New("invalid denied transition")
	}
	size := 0
	for _, line := range out.Logs.Lines {
		size += len(line)
	}
	if size > LogLimit {
		return errors.New("logs exceed persistence limit")
	}
	if out.Logs.Lines == nil {
		out.Logs.Lines = []string{}
	}
	tx, err := c.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE runs SET state=$3,result=$4,error_code=$5,logs=$6,cleanup_pending=$7,updated_at=clock_timestamp() WHERE run_id=$1 AND state=$8 AND EXISTS(SELECT 1 FROM run_executions e WHERE e.run_id=runs.run_id AND e.generation=$2 AND e.owner_pid=pg_backend_pid())`, c.RunID, c.generation, out.State, out.Result, out.ErrorCode, out.Logs, out.CleanupPending, previous)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStale
	}
	// Logs and outcome share the transaction with an event carrying safe metadata.
	payload, err := json.Marshal(map[string]any{"generation": c.generation, "state": out.State, "result": out.Result, "error_code": out.ErrorCode, "logs_status": out.Logs.Status, "logs_truncated": out.Logs.Truncated, "dropped_bytes": out.Logs.DroppedBytes, "cleanup_pending": out.CleanupPending, "reconciliation": out.Reconciliation.Evidence()})
	if err != nil {
		return err
	}
	if _, _, err = audit.AppendTx(ctx, tx, audit.Event{TenantID: c.TenantID, RunID: c.RunID, Type: "run." + out.State, Payload: payload}); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	c.state = out.State
	c.finished = out.State != "running"
	return nil
}
