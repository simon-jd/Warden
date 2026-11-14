// Package audit persists a globally ordered SHA-256 chain in PostgreSQL.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"math"
	"time"
	"warden/controlplane/internal/canonical"
)

type Event struct {
	TenantID string          `json:"tenant_id"`
	Type     string          `json:"type"`
	RunID    string          `json:"run_id"`
	Payload  json.RawMessage `json:"payload"`
}
type Log struct{ Pool *pgxpool.Pool }
type IntegrityError struct{ Seq uint64 }

func (e *IntegrityError) Error() string { return fmt.Sprintf("audit integrity error at seq %d", e.Seq) }
func (l *Log) Append(e Event) (uint64, [32]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := l.Pool.Begin(ctx)
	if err != nil {
		return 0, [32]byte{}, err
	}
	defer tx.Rollback(ctx)
	seq, hash, err := AppendTx(ctx, tx, e)
	if err != nil {
		return 0, [32]byte{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, [32]byte{}, err
	}
	return seq, hash, nil
}

// AppendTx participates in the caller's transaction, including rollback. Holding
// the singleton row lock until commit prevents forks and rollback sequence gaps.
func AppendTx(ctx context.Context, tx pgx.Tx, e Event) (uint64, [32]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return 0, [32]byte{}, err
	}
	snapshot, err := canonical.JSON(raw)
	if err != nil {
		return 0, [32]byte{}, err
	}
	var last int64
	var prev []byte
	if err = tx.QueryRow(ctx, `SELECT last_seq,last_hash FROM audit_head WHERE singleton FOR UPDATE`).Scan(&last, &prev); err != nil {
		return 0, [32]byte{}, err
	}
	if last == math.MaxInt64 {
		return 0, [32]byte{}, errors.New("audit sequence exhausted")
	}
	digest := sha256.New()
	digest.Write(prev)
	digest.Write(snapshot)
	var hash [32]byte
	copy(hash[:], digest.Sum(nil))
	seq := last + 1
	if _, err = tx.Exec(ctx, `INSERT INTO audit_entries(seq,canonical_event,prev_hash,hash) VALUES($1,$2,$3,$4)`, seq, snapshot, prev, hash[:]); err != nil {
		return 0, [32]byte{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE audit_head SET last_seq=$1,last_hash=$2 WHERE singleton`, seq, hash[:]); err != nil {
		return 0, [32]byte{}, err
	}
	return uint64(seq), hash, nil
}
func (l *Log) Verify(from, to uint64) error {
	if from == 0 || to < from || to > math.MaxInt64 {
		return errors.New("invalid audit range")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := l.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	prev := make([]byte, 32)
	if from > 1 {
		if err = tx.QueryRow(ctx, `SELECT hash FROM audit_entries WHERE seq=$1`, int64(from-1)).Scan(&prev); errors.Is(err, pgx.ErrNoRows) {
			return &IntegrityError{Seq: from - 1}
		} else if err != nil {
			return err
		}
	}
	rows, err := tx.Query(ctx, `SELECT seq,canonical_event,prev_hash,hash FROM audit_entries WHERE seq BETWEEN $1 AND $2 ORDER BY seq`, int64(from), int64(to))
	if err != nil {
		return err
	}
	defer rows.Close()
	next := from
	for rows.Next() {
		var seq uint64
		var raw, storedPrev, hash []byte
		if err = rows.Scan(&seq, &raw, &storedPrev, &hash); err != nil {
			return err
		}
		if seq != next {
			return &IntegrityError{Seq: next}
		}
		normalized, nerr := canonical.JSON(raw)
		if nerr != nil || !bytes.Equal(normalized, raw) || !bytes.Equal(prev, storedPrev) {
			return &IntegrityError{Seq: seq}
		}
		digest := sha256.New()
		digest.Write(prev)
		digest.Write(raw)
		if !bytes.Equal(digest.Sum(nil), hash) {
			return &IntegrityError{Seq: seq}
		}
		prev = hash
		next++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if next <= to {
		return &IntegrityError{Seq: next}
	}
	// For a verification reaching the head, also verify its independent metadata.
	var head int64
	var headHash []byte
	if err = tx.QueryRow(ctx, `SELECT last_seq,last_hash FROM audit_head WHERE singleton`).Scan(&head, &headHash); err != nil {
		return err
	}
	if uint64(head) < to {
		return &IntegrityError{Seq: uint64(head) + 1}
	}
	if uint64(head) == to && !bytes.Equal(prev, headHash) {
		return &IntegrityError{Seq: to}
	}
	return tx.Commit(ctx)
}
