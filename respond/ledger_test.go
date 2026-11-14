package respond

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func attachLedger(t *testing.T, e *Executor) *ledger {
	t.Helper()
	l, err := openLedger(e.config.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	e.ledger = l
	return l
}

func journalKey(t *testing.T, e *Executor, alert Alert) (string, string) {
	t.Helper()
	b, err := e.binding(alert)
	if err != nil {
		t.Fatal(err)
	}
	return digest(struct{ TenantID, AlertID string }{b.TenantID, b.AlertID}), digest(b)
}

func writeJournal(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableIncompleteIntentSuppressesRestart(t *testing.T) {
	e, alert, client, _, _ := executorFixture(t)
	l := attachLedger(t, e)
	key, fingerprint := journalKey(t, e, alert)
	if err := l.intent(key, fingerprint); err != nil {
		t.Fatal(err)
	}
	// Close/reopen models restart after durable intent, not a real power cut.
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result, err := reopened.Handle(alert, false)
	if !errors.Is(err, ErrOutcomeUnknown) || result.Status != Unknown || !result.NoOp || client.count() != 0 {
		t.Fatalf("unresolved intent retried: %+v %v", result, err)
	}
	if _, err = reopened.Handle(alert, false); !errors.Is(err, ErrOutcomeUnknown) || client.count() != 0 {
		t.Fatal("unknown replay retried")
	}
}

func TestDurableBindingConflictAndTenantKeys(t *testing.T) {
	e, alert, client, _, _ := executorFixture(t)
	if _, err := e.Handle(alert, false); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := e.config
	cfg.Playbook.ID = "different-playbook"
	conflict, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conflict.Handle(alert, false); !errors.Is(err, ErrConflict) || client.count() != 1 {
		t.Fatalf("binding conflict: %v", err)
	}
	if err = conflict.Close(); err != nil {
		t.Fatal(err)
	}
	cfg = e.config
	cfg.Playbook.Steps = append([]Action(nil), cfg.Playbook.Steps...)
	cfg.Playbook.Steps[0].Resource.ID = "tenant-b"
	cfg.AllowedTenantIDs = []string{"tenant-b"}
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	alert.TenantID = "tenant-b"
	alert.Resource.ID = "tenant-b"
	result, err := second.Handle(alert, false)
	if err != nil || result.NoOp || result.Status != Completed || client.count() != 2 {
		t.Fatalf("tenant key collision: %+v %v", result, err)
	}
	if len(second.ledger.entries) != 2 {
		t.Fatal("tenant entries were merged")
	}
	if client.tenants[0] != "tenant-a" || client.tenants[1] != "tenant-b" {
		t.Fatalf("wrong targets: %v", client.tenants)
	}
}

func rawFrame(raw []byte) []byte {
	result := make([]byte, 4+len(raw)+sha256.Size)
	binary.BigEndian.PutUint32(result, uint32(len(raw)))
	copy(result[4:], raw)
	sum := sha256.Sum256(raw)
	copy(result[4+len(raw):], sum[:])
	return result
}

func TestCorruptJournalFailsClosedWithoutRepair(t *testing.T) {
	key, fp := strings.Repeat("a", 64), strings.Repeat("b", 64)
	intent := frame(ledgerRecord{1, "intent", key, fp, InProgress})
	complete := frame(ledgerRecord{1, "complete", key, fp, Completed})
	badChecksum := append([]byte(nil), intent...)
	badChecksum[len(badChecksum)-1] ^= 1
	payload, _ := json.Marshal(ledgerRecord{1, "intent", key, fp, InProgress})
	cases := map[string][]byte{
		"short-prefix":            {0, 0},
		"oversized-record":        {0, 0, 2, 1},
		"short-payload":           intent[:len(intent)-1],
		"checksum":                badChecksum,
		"complete-without-intent": complete,
		"duplicate-intent":        append(append([]byte(nil), intent...), intent...),
		"duplicate-complete":      append(append(append([]byte(nil), intent...), complete...), complete...),
		"wrong-fingerprint":       append(append([]byte(nil), intent...), frame(ledgerRecord{1, "complete", key, strings.Repeat("c", 64), Completed})...),
		"version":                 frame(ledgerRecord{2, "intent", key, fp, InProgress}),
		"bad-digest":              frame(ledgerRecord{1, "intent", "invalid", fp, InProgress}),
		"bad-status":              frame(ledgerRecord{1, "intent", key, fp, Completed}),
		"unknown-key":             rawFrame([]byte(strings.Replace(string(payload), "\"version\":1", "\"version\":1,\"extra\":0", 1))),
		"duplicate-key":           rawFrame([]byte(strings.Replace(string(payload), "\"version\":1", "\"version\":1,\"version\":1", 1))),
		"case-alias":              rawFrame([]byte(strings.Replace(string(payload), "\"version\"", "\"Version\"", 1))),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			e, alert, client, _, _ := executorFixture(t)
			writeJournal(t, e.config.JournalPath, raw)
			if _, err := e.Handle(alert, false); !errors.Is(err, ErrStorage) || client.count() != 0 {
				t.Fatalf("corrupt journal executed: %v", err)
			}
			after, err := os.ReadFile(e.config.JournalPath)
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("corrupt journal changed")
			}
		})
	}
}

func TestPrivateJournalPathAndPermissions(t *testing.T) {
	for _, kind := range []string{"directory-mode", "file-mode", "symlink-file", "symlink-parent", "hardlink", "fifo", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			e, alert, client, _, dir := executorFixture(t)
			switch kind {
			case "directory-mode":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				writeJournal(t, e.config.JournalPath, nil)
				if err := os.Chmod(e.config.JournalPath, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				target := filepath.Join(dir, "target")
				writeJournal(t, target, nil)
				if err := os.Symlink(target, e.config.JournalPath); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				real := filepath.Join(dir, "real")
				if err := os.Mkdir(real, 0700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(dir, "link")
				if err := os.Symlink(real, link); err != nil {
					t.Fatal(err)
				}
				e.config.JournalPath = filepath.Join(link, "journal")
			case "hardlink":
				target := filepath.Join(dir, "target")
				writeJournal(t, target, nil)
				if err := os.Link(target, e.config.JournalPath); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(e.config.JournalPath, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				writeJournal(t, e.config.JournalPath, nil)
				if err := os.Truncate(e.config.JournalPath, maxLedgerBytes+1); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.Handle(alert, false); !errors.Is(err, ErrStorage) || client.count() != 0 {
				t.Fatalf("unsafe path accepted: %v", err)
			}
		})
	}
}

func TestJournalCapacityDoesNotEvictExistingAlerts(t *testing.T) {
	e, alert, client, _, _ := executorFixture(t)
	key, fp := journalKey(t, e, alert)
	var raw []byte
	for i := 0; i < maxKeys; i++ {
		k := digest(fmt.Sprintf("capacity-%d", i))
		if i == 0 {
			k = key
		}
		raw = append(raw, frame(ledgerRecord{1, "intent", k, fp, InProgress})...)
		raw = append(raw, frame(ledgerRecord{1, "complete", k, fp, Completed})...)
	}
	writeJournal(t, e.config.JournalPath, raw)
	result, err := e.Handle(alert, false)
	if err != nil || !result.NoOp || client.count() != 0 {
		t.Fatalf("existing capacity entry lost: %+v %v", result, err)
	}
	fresh := alert
	fresh.ID = "fresh-alert"
	if _, err = e.Handle(fresh, false); !errors.Is(err, ErrCapacity) || client.count() != 0 {
		t.Fatalf("capacity not enforced: %v", err)
	}
	if result, err = e.Handle(alert, false); err != nil || !result.NoOp {
		t.Fatalf("capacity evicted prior entry: %+v %v", result, err)
	}
	after, _ := os.ReadFile(e.config.JournalPath)
	if !bytes.Equal(raw, after) {
		t.Fatal("capacity changed disk state")
	}
}

func TestIntentReservesCompletionSpace(t *testing.T) {
	e, alert, client, _, _ := executorFixture(t)
	l := attachLedger(t, e)
	l.size = maxLedgerBytes - maxFrameBytes
	if _, err := e.Handle(alert, false); !errors.Is(err, ErrCapacity) || client.count() != 0 {
		t.Fatalf("completion space not reserved: %v", err)
	}
	info, err := l.file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("capacity check wrote before rejection")
	}
}

func TestPartialWriteAndSyncFailuresSuppressAttempts(t *testing.T) {
	for _, kind := range []string{"intent-write", "intent-sync", "completion-write", "completion-sync"} {
		t.Run(kind, func(t *testing.T) {
			e, alert, client, _, _ := executorFixture(t)
			l := attachLedger(t, e)
			writes, syncs := 0, 0
			write, syncFile := l.write, l.sync
			l.write = func(raw []byte) (int, error) {
				writes++
				if (kind == "intent-write" && writes == 1) || (kind == "completion-write" && writes == 2) {
					n, _ := write(raw[:7])
					return n, errors.New("secret-storage-error")
				}
				return write(raw)
			}
			l.sync = func() error {
				syncs++
				if (kind == "intent-sync" && syncs == 1) || (kind == "completion-sync" && syncs == 2) {
					return errors.New("secret-storage-error")
				}
				return syncFile()
			}
			result, err := e.Handle(alert, false)
			wantCalls := 0
			if strings.HasPrefix(kind, "completion") {
				wantCalls = 1
			}
			if err == nil || strings.Contains(err.Error(), "secret") || client.count() != wantCalls || !e.poisoned {
				t.Fatalf("I/O failure unsafe: %+v %v calls=%d", result, err, client.count())
			}
			if wantCalls == 1 && (result.Status != Unknown || !errors.Is(err, ErrOutcomeUnknown)) {
				t.Fatal("post-call failure not Unknown")
			}
			if _, err = e.Handle(alert, false); !errors.Is(err, ErrStorage) || client.count() != wantCalls {
				t.Fatal("poisoned executor retried")
			}
			if err = e.Close(); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(e.config.JournalPath)
			reopened, err := New(e.config)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			result, err = reopened.Handle(alert, false)
			if client.count() != wantCalls {
				t.Fatal("reopen retried ambiguous attempt")
			}
			if err == nil && !result.NoOp {
				t.Fatal("reopen invented a new attempt")
			}
			after, _ := os.ReadFile(e.config.JournalPath)
			if !bytes.Equal(before, after) {
				t.Fatal("reopen repaired or appended after uncertain I/O")
			}
		})
	}
}

func TestClientSeesDurableIntentAndJournalExcludesSecrets(t *testing.T) {
	e, alert, client, _, _ := executorFixture(t)
	l := attachLedger(t, e)
	syncs := 0
	syncFile := l.sync
	l.sync = func() error {
		err := syncFile()
		if err == nil {
			syncs++
		}
		return err
	}
	client.run = func(context.Context, string) error {
		if syncs != 1 {
			t.Errorf("client called before durable intent: syncs=%d", syncs)
		}
		raw, err := os.ReadFile(e.config.JournalPath)
		if err != nil || len(raw) == 0 {
			t.Error("intent absent before client")
		}
		for _, secret := range []string{alert.RequesterCredential, alert.ApprovalProof, alert.ID, alert.TenantID, alert.RuleID, e.config.Playbook.ID} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("journal contains raw input %q", secret)
			}
		}
		return nil
	}
	if _, err := e.Handle(alert, false); err != nil || syncs != 2 {
		t.Fatalf("sync ordering: %v syncs=%d", err, syncs)
	}
}

func TestJournalCreationDurabilityBeforeClient(t *testing.T) {
	for _, scenario := range []string{"failure", "success"} {
		t.Run(scenario, func(t *testing.T) {
			e, alert, client, _, _ := executorFixture(t)
			type opened struct {
				ledger *ledger
				err    error
			}
			created := make(chan bool, 1)
			release := make(chan struct{})
			done := make(chan opened, 1)
			expired := make(chan struct{}, 1)
			barrierCtx, cancelBarrier := context.WithTimeout(context.Background(), 3*time.Second)
			go func() {
				l, err := openLedgerWithInit(e.config.JournalPath, ledgerInit{
					beforeLock: func(newFile bool) {
						created <- newFile
						select {
						case <-release:
						case <-barrierCtx.Done():
							expired <- struct{}{}
						}
					},
				})
				done <- opened{l, err}
			}()
			reaped := false
			// Always release/reap the creator before the fixture closes the
			// winning executor. Kernel I/O still requires cooperative storage.
			defer func() {
				close(release)
				defer cancelBarrier()
				if reaped {
					return
				}
				select {
				case result := <-done:
					if result.ledger != nil {
						if err := result.ledger.file.Close(); err != nil {
							t.Errorf("SETUP_OR_CLEANUP_FAILURE creator close: %v", err)
						}
					}
				case <-time.After(3 * time.Second):
					t.Error("SETUP_OR_CLEANUP_FAILURE creator did not finish")
				}
			}()
			select {
			case newFile := <-created:
				if !newFile {
					t.Fatal("SETUP_OR_CLEANUP_FAILURE creator did not create a fresh file")
				}
			case result := <-done:
				reaped = true
				if result.ledger != nil {
					result.ledger.file.Close()
				}
				t.Fatalf("SETUP_OR_CLEANUP_FAILURE creator exited before barrier: %v", result.err)
			case <-barrierCtx.Done():
				t.Fatal("SETUP_OR_CLEANUP_FAILURE creator did not reach barrier")
			}
			existing := false
			dirSyncs := 0
			synced := false
			e.initial = ledgerInit{
				beforeLock: func(newFile bool) { existing = !newFile },
				syncDir: func(fd int) error {
					dirSyncs++
					info, err := os.Stat(e.config.JournalPath)
					if err != nil || info.Size() != 0 {
						return errors.New("intent preceded initialization sync")
					}
					if scenario == "failure" {
						return errors.New("injected parent directory sync failure")
					}
					if err := syscall.Fsync(fd); err != nil {
						return err
					}
					synced = true
					return nil
				},
			}
			client.run = func(context.Context, string) error {
				if !synced || dirSyncs != 1 {
					return errors.New("client preceded successful directory sync")
				}
				return nil
			}
			result, err := e.Handle(alert, false)
			select {
			case <-expired:
				t.Fatal("SETUP_OR_CLEANUP_FAILURE creator barrier expired")
			default:
			}
			if !existing {
				t.Fatal("SETUP_OR_CLEANUP_FAILURE second opener did not use existing file")
			}
			if scenario == "failure" {
				if !errors.Is(err, ErrStorage) || client.count() != 0 || dirSyncs != 1 {
					t.Fatalf("FIX1_RED_REQUIRED existing-path directory sync failure must block intent/client: result=%+v err=%v syncs=%d mutations=%d", result, err, dirSyncs, client.count())
				}
				info, statErr := os.Stat(e.config.JournalPath)
				if statErr != nil || info.Size() != 0 {
					t.Fatal("FIX1_RED_REQUIRED failed directory sync must leave the journal empty")
				}
			} else if err != nil || result.Status != Completed || result.NoOp || !synced || dirSyncs != 1 || client.count() != 1 {
				t.Fatalf("FIX1_RED_REQUIRED successful existing-path directory sync must precede intent/client: result=%+v err=%v syncs=%d synced=%v mutations=%d", result, err, dirSyncs, synced, client.count())
			}
		})
	}
}
