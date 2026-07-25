package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry is a structured log entry for a cross-node service request.
// Every Authorize() call produces one entry regardless of outcome.
//
// Format per ARCHITECTURE.md Decision E:
//
//	{
//	  "timestamp": "ISO8601",
//	  "sequence": 1,
//	  "prev_hash": "sha256hex",
//	  "source_peer": "<WireGuard public key>",
//	  "source_ip": "192.168.1.10",
//	  "requested_capability": "ssh_proxy",
//	  "target_resource": "node-03:/bin/bash",
//	  "result": "allow" | "deny",
//	  "reason": "explicit_allow" | "no_capability" | "revoked" | ...
//	}
type AuditEntry struct {
	Sequence            uint64 `json:"sequence"`
	PrevHash            string `json:"prev_hash"`
	Timestamp           string `json:"timestamp"`
	SourcePeer          string `json:"source_peer"`
	SourceIP            string `json:"source_ip,omitempty"`
	RequestedCapability string `json:"requested_capability"`
	TargetResource      string `json:"target_resource"`
	Result              string `json:"result"` // "allow" or "deny"
	Reason              string `json:"reason"`
}

// Default audit rotation constants.
const (
	DefaultAuditMaxBytes    int64 = 100 * 1024 * 1024 // 100 MB
	DefaultAuditMaxRotates int   = 5
)

// rotator is the rotation backend used by AuditLogger when writing to
// files. If nil, no rotation is performed (e.g. when writing to an
// in-memory buffer for tests).
type rotator struct {
	dir         string
	baseName    string
	maxBytes    int64
	maxBackups  int
	currentFile *os.File
}

func (r *rotator) Write(p []byte) (int, error) {
	if r.currentFile == nil {
		return 0, fmt.Errorf("rotator: no file open")
	}
	n, err := r.currentFile.Write(p)
	if err != nil {
		return n, err
	}
	r.maybeRotate()
	return n, nil
}

func (r *rotator) Close() error {
	if r.currentFile != nil {
		return r.currentFile.Close()
	}
	return nil
}

// maybeRotate checks if the current file exceeds maxBytes and rotates
// if so. Rotated files are named <baseName>.1, <baseName>.2, etc.
// The oldest backup (>maxBackups) is deleted.
func (r *rotator) maybeRotate() {
	if r.currentFile == nil || r.maxBytes <= 0 {
		return
	}
	info, err := r.currentFile.Stat()
	if err != nil {
		return
	}
	if info.Size() < r.maxBytes {
		return
	}

	_ = r.currentFile.Close()

	// Shift backups: .4 -> .5 (delete old .5), ..., .1 -> .2
	for i := r.maxBackups; i > 0; i-- {
		src := filepath.Join(r.dir, fmt.Sprintf("%s.%d", r.baseName, i))
		if _, err := os.Stat(src); os.IsNotExist(err) {
			continue
		}
		if i == r.maxBackups {
			_ = os.Remove(src)
			continue
		}
		dst := filepath.Join(r.dir, fmt.Sprintf("%s.%d", r.baseName, i+1))
		_ = os.Rename(src, dst)
	}

	// Rotate current -> .1
	current := filepath.Join(r.dir, r.baseName)
	rotated := filepath.Join(r.dir, r.baseName+".1")
	_ = os.Rename(current, rotated)

	// Open fresh file
	f, err := os.OpenFile(current, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	r.currentFile = f
}

// AuditLogger writes structured audit entries to an io.Writer.
// Entries are JSON-encoded, one per line (JSONL format), making them
// easy to parse with standard tools (jq, grep, log aggregators).
//
// The logger is thread-safe. Writes are flushed on each Log() call
// to ensure durability (an audit entry should survive a crash).
//
// Tamper-evidence: every entry carries a Sequence number and a
// PrevHash that is the SHA-256 of the previous entry's canonical
// JSON. This creates a hash chain so that any insertion, deletion,
// or modification of an entry can be detected by walking the chain.
//
// Log rotation: when configured with NewAuditFileLoggerWithRotation,
// the log file is rotated when it exceeds maxBytes. The last
// maxBackups rotated files are retained.
type AuditLogger struct {
	mu       sync.Mutex
	writer   io.Writer
	closer   io.Closer
	rot      *rotator
	sequence uint64
	prevHash string
}

// NewAuditLogger creates a logger that writes to the given writer.
// If the writer implements io.Closer, Close() will close it.
// No rotation is performed.
func NewAuditLogger(w io.Writer) *AuditLogger {
	return &AuditLogger{writer: w}
}

// NewAuditFileLogger creates a logger that appends to a file.
// The file is opened with O_APPEND|O_CREATE|O_WRONLY, mode 0600
// (owner read/write only — audit logs may contain peer IDs).
//
// No rotation is performed. For log rotation, use
// NewAuditFileLoggerWithRotation instead.
func NewAuditFileLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	a := &AuditLogger{writer: f, closer: f}
	a.recoverChain(path)
	return a, nil
}

// NewAuditFileLoggerWithRotation creates a file-based logger with
// automatic rotation. When the log file exceeds maxBytes, it is
// rotated to <path>.1, and the previous <path>.1 becomes <path>.2,
// etc. At most maxBackups rotated files are kept; older ones are
// deleted.
//
// On startup, the hash chain is recovered by scanning existing
// entries in the current file (and rotated files if needed), so
// that sequence numbers and prev_hash continue seamlessly across
// restarts.
func NewAuditFileLoggerWithRotation(path string, maxBytes int64, maxBackups int) (*AuditLogger, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultAuditMaxBytes
	}
	if maxBackups <= 0 {
		maxBackups = DefaultAuditMaxRotates
	}

	dir := filepath.Dir(path)
	baseName := filepath.Base(path)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	r := &rotator{
		dir:         dir,
		baseName:    baseName,
		maxBytes:    maxBytes,
		maxBackups:  maxBackups,
		currentFile: f,
	}

	a := &AuditLogger{
		writer: r,
		closer: r,
		rot:    r,
	}
	a.recoverChain(path)
	return a, nil
}

// recoverChain scans existing log file(s) to recover the sequence
// counter and prev_hash so they continue seamlessly across restarts.
// It reads the current file and, if the chain is empty (no entries
// yet in the current file), reads the most recent rotated backup.
func (a *AuditLogger) recoverChain(path string) {
	dir := filepath.Dir(path)
	baseName := filepath.Base(path)

	// Try the current file first.
	seq, hash, ok := scanChain(path)
	if ok {
		a.sequence = seq
		a.prevHash = hash
		return
	}

	// Current file empty — try rotated backups from newest to oldest.
	for i := 1; i <= DefaultAuditMaxRotates; i++ {
		rotated := filepath.Join(dir, fmt.Sprintf("%s.%d", baseName, i))
		seq, hash, ok = scanChain(rotated)
		if ok {
			a.sequence = seq
			a.prevHash = hash
			return
		}
	}
	// No existing entries — start fresh at sequence 0, prev_hash "".
}

// scanChain reads a file line by line and returns the sequence
// number and prev_hash of the LAST valid entry. Returns ok=false
// if the file has no valid entries or doesn't exist.
func scanChain(path string) (seq uint64, prevHash string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", false
	}
	lines := splitLines(data)
	var lastSeq uint64
	var lastHash string
	found := false
	for _, line := range lines {
		line = trimSpace(line)
		if len(line) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip malformed lines
		}
		lastSeq = entry.Sequence
		// The prev_hash of the last entry is NOT what we need —
		// we need the hash of the last entry itself, which becomes
		// the prev_hash for the NEXT entry.
		lastHash = hashEntry(line)
		found = true
	}
	if !found {
		return 0, "", false
	}
	return lastSeq, lastHash, true
}

// Log writes a single audit entry as a JSON line.
func (a *AuditLogger) Log(entry AuditEntry) {
	if a == nil || a.writer == nil {
		return // no-op if no logger or writer configured
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.sequence++
	entry.Sequence = a.sequence
	entry.PrevHash = a.prevHash

	data, err := json.Marshal(entry)
	if err != nil {
		// Fall back to a minimal entry — never fail silently
		data = []byte(fmt.Sprintf(`{"timestamp":"%s","sequence":%d,"prev_hash":"%s","error":"marshal failed: %v"}`,
			entry.Timestamp, entry.Sequence, entry.PrevHash, err))
	}
	data = append(data, '\n')

	// Compute hash of this entry's JSON for the next entry's prev_hash.
	// We hash the marshaled JSON bytes (without the trailing newline).
	a.prevHash = hashEntry(data[:len(data)-1])

	if _, err := a.writer.Write(data); err != nil {
		// Log write failure to stderr — never silently drop.
		fmt.Fprintf(os.Stderr, "audit: write failed: %v\n", err)
	}
}

// Close closes the underlying writer if it implements io.Closer.
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// ParseAuditEntry parses a single JSONL audit line.
func ParseAuditEntry(line []byte) (AuditEntry, error) {
	var entry AuditEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return AuditEntry{}, fmt.Errorf("parse audit entry: %w", err)
	}
	return entry, nil
}

// VerifyHashChain reads a log file and verifies that the hash chain
// is intact: each entry's prev_hash matches the SHA-256 of the
// previous entry's JSON. Returns nil if the chain is valid, or an
// error describing the first broken link.
func VerifyHashChain(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	lines := splitLines(data)
	var expectedPrev string
	var expectedSeq uint64 = 1 // sequence starts at 1
	for i, line := range lines {
		line = trimSpace(line)
		if len(line) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return fmt.Errorf("line %d: parse error: %w", i+1, err)
		}
		if entry.PrevHash != expectedPrev {
			return fmt.Errorf("line %d: prev_hash mismatch (expected %q, got %q)",
				i+1, expectedPrev, entry.PrevHash)
		}
		if entry.Sequence != expectedSeq {
			return fmt.Errorf("line %d: sequence mismatch (expected %d, got %d)",
				i+1, expectedSeq, entry.Sequence)
		}
		expectedPrev = hashEntry(line)
		expectedSeq++
	}
	return nil
}
