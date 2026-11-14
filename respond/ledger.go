package respond

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	maxKeys        = 1024
	maxLedgerBytes = 1024 * 1024
	maxRecordBytes = 512
	maxFrameBytes  = 4 + maxRecordBytes + sha256.Size
)

type ledgerEntry struct {
	fingerprint string
	status      Status
}

type ledgerRecord struct {
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	Status      Status `json:"status"`
}

// Narrow package-private I/O fault seams; production always uses file.Write/Sync.
// The executor mutex owns entries, reservations and append order.
type ledger struct {
	file         *os.File
	write        func([]byte) (int, error)
	sync         func() error
	entries      map[string]ledgerEntry
	size         int64
	reservations int
}

// Initialization-only, per-instance test seams; zero values use real operations.
// Neither hook is exported, globally mutable, or configurable through Config.
type ledgerInit struct {
	beforeLock func(created bool)
	syncDir    func(int) error
}

func privateDir(path string) (int, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrStorage
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			syscall.Close(fd)
			return -1, ErrStorage
		}
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return -1, ErrStorage
		}
		fd = next
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Getuid()) || st.Mode&07777 != 0700 {
		syscall.Close(fd)
		return -1, ErrStorage
	}
	return fd, nil
}

func openLedger(path string) (*ledger, error) {
	return openLedgerWithInit(path, ledgerInit{})
}

func openLedgerWithInit(path string, initial ledgerInit) (*ledger, error) {
	dir, err := privateDir(filepath.Dir(path))
	if err != nil {
		return nil, ErrStorage
	}
	defer syscall.Close(dir)
	flags := syscall.O_RDWR | syscall.O_APPEND | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	fd, err := syscall.Openat(dir, filepath.Base(path), flags|syscall.O_CREAT|syscall.O_EXCL, 0600)
	created := err == nil
	if err == syscall.EEXIST {
		fd, err = syscall.Openat(dir, filepath.Base(path), flags, 0)
	}
	if err != nil {
		return nil, ErrStorage
	}
	f := os.NewFile(uintptr(fd), "response-journal")
	good := false
	defer func() {
		if !good {
			f.Close()
		}
	}()
	if initial.beforeLock != nil {
		initial.beforeLock(created)
	}
	var st syscall.Stat_t
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil || syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 || st.Size > maxLedgerBytes {
		return nil, ErrStorage
	}
	syncDir := initial.syncDir
	if syncDir == nil {
		syncDir = syscall.Fsync
	}
	if created && f.Sync() != nil {
		return nil, ErrStorage
	}
	// Every locked, validated opener must establish directory-entry durability.
	if syncDir(dir) != nil {
		return nil, ErrStorage
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxLedgerBytes+1))
	if err != nil || len(raw) > maxLedgerBytes || int64(len(raw)) != st.Size {
		return nil, ErrStorage
	}
	l := &ledger{file: f, write: f.Write, sync: f.Sync, entries: make(map[string]ledgerEntry), size: int64(len(raw))}
	if l.replay(raw) != nil {
		return nil, ErrStorage
	}
	good = true
	return l, nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (l *ledger) replay(raw []byte) error {
	records := 0
	for len(raw) != 0 {
		records++
		if len(raw) < 4 || records > 2*maxKeys {
			return ErrStorage
		}
		n := int(binary.BigEndian.Uint32(raw[:4]))
		if n == 0 || n > maxRecordBytes || len(raw) < 4+n+sha256.Size {
			return ErrStorage
		}
		payload := raw[4 : 4+n]
		sum := sha256.Sum256(payload)
		if string(sum[:]) != string(raw[4+n:4+n+sha256.Size]) {
			return ErrStorage
		}
		var record ledgerRecord
		if strictJSON(payload, &record) != nil || record.Version != 1 || !validDigest(record.Key) || !validDigest(record.Fingerprint) {
			return ErrStorage
		}
		if _, ok := jsonObject(payload, "version", "kind", "key", "fingerprint", "status"); !ok {
			return ErrStorage
		}
		prior, exists := l.entries[record.Key]
		switch record.Kind {
		case "intent":
			if exists || record.Status != InProgress || len(l.entries) >= maxKeys {
				return ErrStorage
			}
			l.entries[record.Key] = ledgerEntry{record.Fingerprint, InProgress}
		case "complete":
			if !exists || prior.status != InProgress || prior.fingerprint != record.Fingerprint || (record.Status != Completed && record.Status != Unknown && record.Status != Cancelled) {
				return ErrStorage
			}
			l.entries[record.Key] = ledgerEntry{record.Fingerprint, record.Status}
		default:
			return ErrStorage
		}
		raw = raw[4+n+sha256.Size:]
	}
	for key, entry := range l.entries {
		if entry.status == InProgress {
			entry.status = Unknown
			l.entries[key] = entry
		}
	}
	return nil
}

func frame(record ledgerRecord) []byte {
	raw, _ := json.Marshal(record)
	if len(raw) > maxRecordBytes {
		return nil
	}
	result := make([]byte, 4+len(raw)+sha256.Size)
	binary.BigEndian.PutUint32(result, uint32(len(raw)))
	copy(result[4:], raw)
	sum := sha256.Sum256(raw)
	copy(result[4+len(raw):], sum[:])
	return result
}

func (l *ledger) appendFrame(raw []byte) error {
	for rest := raw; len(rest) != 0; {
		n, err := l.write(rest)
		if err != nil || n <= 0 || n > len(rest) {
			return ErrStorage
		}
		rest = rest[n:]
	}
	if l.sync() != nil {
		return ErrStorage
	}
	l.size += int64(len(raw))
	return nil
}

func (l *ledger) intent(key, fingerprint string) error {
	if !validDigest(key) || !validDigest(fingerprint) {
		return ErrStorage
	}
	if _, exists := l.entries[key]; exists {
		return ErrConflict
	}
	raw := frame(ledgerRecord{1, "intent", key, fingerprint, InProgress})
	if len(l.entries) >= maxKeys || l.size+int64(len(raw))+(int64(l.reservations)+1)*maxFrameBytes > maxLedgerBytes {
		return ErrCapacity
	}
	if len(raw) == 0 || l.appendFrame(raw) != nil {
		return ErrStorage
	}
	l.entries[key] = ledgerEntry{fingerprint, InProgress}
	l.reservations++
	return nil
}

func (l *ledger) complete(key, fingerprint string, status Status) error {
	prior, exists := l.entries[key]
	if !exists || prior.status != InProgress || prior.fingerprint != fingerprint || (status != Completed && status != Unknown && status != Cancelled) {
		return ErrStorage
	}
	raw := frame(ledgerRecord{1, "complete", key, fingerprint, status})
	if len(raw) == 0 || l.reservations <= 0 || l.size+int64(len(raw)) > maxLedgerBytes || l.appendFrame(raw) != nil {
		return ErrStorage
	}
	l.entries[key] = ledgerEntry{fingerprint, status}
	l.reservations--
	return nil
}
