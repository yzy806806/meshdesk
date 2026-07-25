package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// --- Sequence number and hash chain tests ---

func TestAuditSequenceNumbers(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	for i := 0; i < 5; i++ {
		logger.Log(AuditEntry{
			SourcePeer: "peer-test",
			Result:     "allow",
			Reason:     "test",
		})
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(lines))
	}

	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: parse error: %v", i+1, err)
		}
		if entry.Sequence != uint64(i+1) {
			t.Errorf("entry %d: expected sequence %d, got %d", i+1, i+1, entry.Sequence)
		}
	}
}

func TestAuditHashChain(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	for i := 0; i < 5; i++ {
		logger.Log(AuditEntry{
			SourcePeer: "peer-test",
			Result:     "allow",
			Reason:     "test",
		})
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(lines))
	}

	var expectedPrevHash string
	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: parse error: %v", i+1, err)
		}

		if entry.PrevHash != expectedPrevHash {
			t.Errorf("entry %d: prev_hash mismatch — expected %q, got %q",
				i+1, expectedPrevHash, entry.PrevHash)
		}

		// The hash for the next entry should be SHA-256 of this entry's JSON (without trailing newline)
		expectedPrevHash = hashEntry([]byte(line))
	}
}

func TestAuditHashChainFirstEntry(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	logger.Log(AuditEntry{
		SourcePeer: "first-peer",
		Result:     "allow",
		Reason:     "test",
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(lines))
	}

	var entry AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if entry.Sequence != 1 {
		t.Errorf("first entry sequence should be 1, got %d", entry.Sequence)
	}
	if entry.PrevHash != "" {
		t.Errorf("first entry prev_hash should be empty, got %q", entry.PrevHash)
	}
}

func TestAuditNilLogger(t *testing.T) {
	var logger *AuditLogger
	logger.Log(AuditEntry{SourcePeer: "test"}) // should not panic
}

func TestAuditNilWriter(t *testing.T) {
	logger := NewAuditLogger(nil)
	logger.Log(AuditEntry{SourcePeer: "test"}) // should not panic
}

// --- Write error handling test ---

type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("simulated disk full")
}

func TestAuditWriteFailureLoggedToStderr(t *testing.T) {
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	logger := NewAuditLogger(&failingWriter{})
	logger.Log(AuditEntry{
		SourcePeer: "test-peer",
		Result:     "allow",
		Reason:     "test",
	})

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "audit: write failed") {
		t.Errorf("expected 'audit: write failed' in stderr, got: %s", output)
	}
}

// --- Source IP test ---

func TestAuditSourceIP(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	logger.Log(AuditEntry{
		SourcePeer: "peer-test",
		SourceIP:   "192.168.1.100",
		Result:     "allow",
		Reason:     "test",
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(lines))
	}

	var entry AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if entry.SourceIP != "192.168.1.100" {
		t.Errorf("expected source_ip '192.168.1.100', got %q", entry.SourceIP)
	}
}

func TestAuthorizeWithSourceIP(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{PublicKey: "peer-ip-test", Capabilities: []string{CapSSHProxy}},
		},
	}
	engine := NewCapabilityEngine(cfg, logger)

	result := engine.AuthorizeWithSourceIP("peer-ip-test", CapSSHProxy, "", "10.0.0.5")
	if !result.Allowed {
		t.Errorf("expected allow, got reason: %s", result.Reason)
	}
	if result.SourceIP != "10.0.0.5" {
		t.Errorf("expected SourceIP '10.0.0.5', got %q", result.SourceIP)
	}

	// Verify the audit entry has the source IP
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(lines))
	}
	var entry AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if entry.SourceIP != "10.0.0.5" {
		t.Errorf("audit entry source_ip = %q, want '10.0.0.5'", entry.SourceIP)
	}
}

// --- Log rotation tests ---

func TestAuditRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Use a very small max size so rotation triggers quickly
	logger, err := NewAuditFileLoggerWithRotation(logPath, 200, 3)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	defer logger.Close()

	// Write enough entries to trigger at least one rotation
	for i := 0; i < 50; i++ {
		logger.Log(AuditEntry{
			SourcePeer: fmt.Sprintf("peer-%02d-aaaaaaaaaaaaaaaa", i),
			Result:     "allow",
			Reason:     "test",
		})
	}

	// The current file should exist
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("current log file should exist: %v", err)
	}

	// At least one rotated backup should exist
	rotated1 := logPath + ".1"
	if _, err := os.Stat(rotated1); err != nil {
		t.Errorf("expected rotated backup %s to exist: %v", rotated1, err)
	}
}

func TestAuditRotationMaxBackups(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Small max size and only 2 backups
	logger, err := NewAuditFileLoggerWithRotation(logPath, 100, 2)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	defer logger.Close()

	// Write many entries to trigger multiple rotations
	for i := 0; i < 200; i++ {
		logger.Log(AuditEntry{
			SourcePeer: fmt.Sprintf("peer-%03d-aaaaaaaaaaaaaaaaaaaa", i),
			Result:     "allow",
			Reason:     "test",
		})
	}

	// Verify we don't have more than 2 backups
	for i := 3; i <= 5; i++ {
		backup := fmt.Sprintf("%s.%d", logPath, i)
		if _, err := os.Stat(backup); err == nil {
			t.Errorf("backup %s should have been deleted (maxBackups=2)", backup)
		}
	}
}

// --- Hash chain verification (VerifyHashChain) ---

func TestVerifyHashChainValid(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	logger, err := NewAuditFileLoggerWithRotation(logPath, 1<<20, 5)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	for i := 0; i < 10; i++ {
		logger.Log(AuditEntry{
			SourcePeer: fmt.Sprintf("peer-%02d-aaaaaaaaaaaaaaaa", i),
			Result:     "allow",
			Reason:     "test",
		})
	}
	logger.Close()

	if err := VerifyHashChain(logPath); err != nil {
		t.Errorf("hash chain verification failed: %v", err)
	}
}

func TestVerifyHashChainTampered(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	logger, err := NewAuditFileLoggerWithRotation(logPath, 1<<20, 5)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	for i := 0; i < 5; i++ {
		logger.Log(AuditEntry{
			SourcePeer: fmt.Sprintf("peer-%02d-aaaaaaaaaaaaaaaa", i),
			Result:     "allow",
			Reason:     "test",
		})
	}
	logger.Close()

	// Tamper with the second line
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(string(data), "\n")
	var entry AuditEntry
	json.Unmarshal([]byte(lines[1]), &entry)
	entry.Reason = "tampered"
	tampered, _ := json.Marshal(entry)
	lines[1] = string(tampered)
	os.WriteFile(logPath, []byte(strings.Join(lines, "\n")), 0600)

	err = VerifyHashChain(logPath)
	if err == nil {
		t.Error("expected hash chain verification to fail on tampered entry")
	}
	if !strings.Contains(err.Error(), "prev_hash mismatch") {
		t.Errorf("expected prev_hash mismatch error, got: %v", err)
	}
}

func TestVerifyHashChainDeletedEntry(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	logger, err := NewAuditFileLoggerWithRotation(logPath, 1<<20, 5)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	for i := 0; i < 5; i++ {
		logger.Log(AuditEntry{
			SourcePeer: fmt.Sprintf("peer-%02d-aaaaaaaaaaaaaaaa", i),
			Result:     "allow",
			Reason:     "test",
		})
	}
	logger.Close()

	// Delete the third line (index 2)
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(string(data), "\n")
	// Remove line at index 2
	tamperedLines := append(lines[:2], lines[3:]...)
	os.WriteFile(logPath, []byte(strings.Join(tamperedLines, "\n")), 0600)

	err = VerifyHashChain(logPath)
	if err == nil {
		t.Error("expected hash chain verification to fail on deleted entry")
	}
}

// --- Chain recovery across restarts ---

func TestAuditChainRecovery(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// First session: write 5 entries
	logger1, err := NewAuditFileLoggerWithRotation(logPath, 1<<20, 5)
	if err != nil {
		t.Fatalf("create logger 1: %v", err)
	}
	for i := 0; i < 5; i++ {
		logger1.Log(AuditEntry{
			SourcePeer: fmt.Sprintf("peer-%02d-aaaaaaaaaaaaaaaa", i),
			Result:     "allow",
			Reason:     "test",
		})
	}
	logger1.Close()

	// Second session: write 3 more entries — sequence should continue from 6
	logger2, err := NewAuditFileLoggerWithRotation(logPath, 1<<20, 5)
	if err != nil {
		t.Fatalf("create logger 2: %v", err)
	}
	for i := 0; i < 3; i++ {
		logger2.Log(AuditEntry{
			SourcePeer: fmt.Sprintf("peer-%02d-bbbbbbbbbbbbbbbb", i),
			Result:     "deny",
			Reason:     "test",
		})
	}
	logger2.Close()

	// Read all entries and verify sequence numbers are contiguous
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 8 {
		t.Fatalf("expected 8 entries total, got %d", len(lines))
	}

	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: parse error: %v", i+1, err)
		}
		if entry.Sequence != uint64(i+1) {
			t.Errorf("entry %d: expected sequence %d, got %d", i+1, i+1, entry.Sequence)
		}
	}

	// The hash chain should also be intact
	if err := VerifyHashChain(logPath); err != nil {
		t.Errorf("hash chain broken across restart: %v", err)
	}
}

// --- Existing test update: verify new fields in audit output ---

func TestAuditEntryContainsNewFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	logger.Log(AuditEntry{
		SourcePeer: "peer-test",
		SourceIP:   "10.0.0.1",
		Result:     "allow",
		Reason:     "test",
	})

	var entry AuditEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if entry.Sequence == 0 {
		t.Error("expected non-zero sequence number")
	}
	// First entry should have empty prev_hash
	if entry.PrevHash != "" {
		t.Errorf("first entry prev_hash should be empty, got %q", entry.PrevHash)
	}
	if entry.SourceIP != "10.0.0.1" {
		t.Errorf("expected source_ip '10.0.0.1', got %q", entry.SourceIP)
	}
}
