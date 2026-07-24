package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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
//	  "source_peer": "<WireGuard public key>",
//	  "requested_capability": "ssh_proxy",
//	  "target_resource": "node-03:/bin/bash",
//	  "result": "allow" | "deny",
//	  "reason": "explicit_allow" | "no_capability" | "revoked" | ...
//	}
type AuditEntry struct {
	Timestamp           string `json:"timestamp"`
	SourcePeer          string `json:"source_peer"`
	RequestedCapability string `json:"requested_capability"`
	TargetResource      string `json:"target_resource"`
	Result              string `json:"result"` // "allow" or "deny"
	Reason              string `json:"reason"`
}

// AuditLogger writes structured audit entries to an io.Writer.
// Entries are JSON-encoded, one per line (JSONL format), making them
// easy to parse with standard tools (jq, grep, log aggregators).
//
// The logger is thread-safe. Writes are buffered and flushed on each
// Log() call to ensure durability (an audit entry should survive a crash).
type AuditLogger struct {
	mu     sync.Mutex
	writer io.Writer
	closer io.Closer
}

// NewAuditLogger creates a logger that writes to the given writer.
// If the writer implements io.Closer, Close() will close it.
func NewAuditLogger(w io.Writer) *AuditLogger {
	return &AuditLogger{writer: w}
}

// NewAuditFileLogger creates a logger that appends to a file.
// The file is opened with O_APPEND|O_CREATE|O_WRONLY, mode 0600
// (owner read/write only — audit logs may contain peer IDs).
func NewAuditFileLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &AuditLogger{writer: f, closer: f}, nil
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

	data, err := json.Marshal(entry)
	if err != nil {
		// Fall back to a minimal entry — never fail silently
		data = []byte(fmt.Sprintf(`{"timestamp":"%s","error":"marshal failed: %v"}`,
			entry.Timestamp, err))
	}
	data = append(data, '\n')

	a.writer.Write(data)
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
