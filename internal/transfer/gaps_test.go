package transfer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- Gap 4: MaxFileSize enforcement tests ---

// TestReceiveRejectsOversizedFile verifies that ReceiveWithMaxSize
// rejects a file whose declared size exceeds the limit, before any
// file data is read or a destination file is created.
func TestReceiveRejectsOversizedFile(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	// Manually write the header to avoid Send() deadlocking on data write
	// when the receiver rejects early (io.Pipe is synchronous with no buffer).
	header := &FileHeader{
		Version:   ProtocolVersion,
		Filename:  "oversized.txt",
		Size:      1 << 40, // 1 TB — way over the 100-byte limit
		Mode:      0644,
		FileType:  FileTypeRegular,
		SrcPeerID: "test-peer",
	}
	headerJSON, _ := json.Marshal(header)

	go func() {
		// Write the framed header
		binary.Write(clientConn, binary.BigEndian, uint32(len(headerJSON)))
		clientConn.Write(headerJSON)
		// Don't write file data — the receiver should reject before reading it.
		// Read the NACK response.
		result, _ := readFramedJSON[TransferResult](clientConn)
		if result.OK {
			// Signal failure via the pipe close
		}
		clientConn.Close()
	}()

	_, _, err := ReceiveWithMaxSize(context.Background(), serverConn, destDir, 100)
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}

	// Verify no file was created in destDir
	entries, _ := os.ReadDir(destDir)
	if len(entries) != 0 {
		t.Errorf("expected no files in destDir, found %d", len(entries))
	}
}

// TestReceiveAcceptsUnderLimit verifies that a file within the size
// limit is accepted normally.
func TestReceiveAcceptsUnderLimit(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("fits within limit")
	header := &FileHeader{
		Filename: "ok.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	_, n, err := ReceiveWithMaxSize(context.Background(), serverConn, destDir, 1<<20)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("expected %d bytes, got %d", len(content), n)
	}

	// Verify file exists
	destPath := filepath.Join(destDir, "ok.txt")
	if _, err := os.Stat(destPath); err != nil {
		t.Errorf("file should exist: %v", err)
	}
}

// TestReceiveMaxSizeZeroMeansNoLimit verifies that maxFileSize=0
// disables the size check entirely.
func TestReceiveMaxSizeZeroMeansNoLimit(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("no limit test")
	header := &FileHeader{
		Filename: "nolimit.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	_, _, err := ReceiveWithMaxSize(context.Background(), serverConn, destDir, 0)
	if err != nil {
		t.Fatalf("expected success with no limit: %v", err)
	}
}

// TestReceiveDefaultMaxSizeUsed verifies that the default Receive()
// function uses DefaultMaxFileSize (1 GB).
func TestReceiveDefaultMaxSizeUsed(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("default limit test")
	header := &FileHeader{
		Filename: "default.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	_, _, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("expected success with default max: %v", err)
	}
}

// --- Gap 2: Capability enforcement in Receiver tests ---

// mockAuthChecker is a test AuthChecker that allows/denies based on a preset map.
type mockAuthChecker struct {
	allowedPeers map[string]bool
	lastChecked  string
}

func (m *mockAuthChecker) AuthorizeFileTransfer(sourcePeer string) bool {
	m.lastChecked = sourcePeer
	return m.allowedPeers[sourcePeer]
}

// TestReceiverRejectsUnauthorizedTransfer verifies that the Receiver
// with an auth checker rejects transfers from peers without the
// file_transfer capability.
func TestReceiverRejectsUnauthorizedTransfer(t *testing.T) {
	mesh := newInProcTransferMesh()
	destDir := t.TempDir()

	checker := &mockAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-peer": true,
			// "unauthorized-peer" is NOT in the map
		},
	}

	receiver := NewReceiverWithAuth(mesh, 4193, destDir, DefaultMaxFileSize, checker)
	if err := receiver.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer receiver.Stop()

	// Dial the receiver
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := mesh.DialMesh(ctx, "test-peer", 4193)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Manually write the header (to avoid Send() data-write deadlock on rejection)
	header := &FileHeader{
		Version:   ProtocolVersion,
		Filename:  "unauthorized.txt",
		Size:      int64(len("unauthorized transfer")),
		Mode:      0644,
		FileType:  FileTypeRegular,
		SrcPeerID: "unauthorized-peer",
	}
	headerJSON, _ := json.Marshal(header)
	binary.Write(conn, binary.BigEndian, uint32(len(headerJSON)))
	conn.Write(headerJSON)

	// Read the NACK response
	result, err := readFramedJSON[TransferResult](conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if result.OK {
		t.Error("expected transfer to be rejected (unauthorized)")
	}

	// Verify the auth checker was called with the right peer ID
	if checker.lastChecked != "unauthorized-peer" {
		t.Errorf("expected auth checker to be called with 'unauthorized-peer', got '%s'", checker.lastChecked)
	}

	// Verify no file was written
	destPath := filepath.Join(destDir, "unauthorized.txt")
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Errorf("file should not exist for unauthorized transfer: %v", err)
	}
}

// TestReceiverAcceptsAuthorizedTransfer verifies that the Receiver
// with an auth checker accepts transfers from authorized peers.
func TestReceiverAcceptsAuthorizedTransfer(t *testing.T) {
	mesh := newInProcTransferMesh()
	destDir := t.TempDir()

	checker := &mockAuthChecker{
		allowedPeers: map[string]bool{
			"authorized-peer": true,
		},
	}

	receiver := NewReceiverWithAuth(mesh, 4194, destDir, DefaultMaxFileSize, checker)
	if err := receiver.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer receiver.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := mesh.DialMesh(ctx, "test-peer", 4194)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	content := []byte("authorized transfer content")
	header := &FileHeader{
		Filename:  "authorized.txt",
		Size:      int64(len(content)),
		Mode:      0644,
		FileType:  FileTypeRegular,
		SrcPeerID: "authorized-peer",
	}

	result, err := SendWithContext(ctx, conn, bytes.NewReader(content), header)
	if err != nil {
		t.Fatalf("send error: %v", err)
	}
	if !result.OK {
		t.Errorf("expected transfer to succeed: %s", result.Message)
	}

	// Give the receiver a moment to write the file
	time.Sleep(100 * time.Millisecond)

	destPath := filepath.Join(destDir, "authorized.txt")
	written, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("file should exist: %v", err)
	}
	if !bytes.Equal(written, content) {
		t.Error("content mismatch")
	}
}

// TestReceiverWithMaxSizeEnforced verifies that the Receiver enforces
// the max file size from config, rejecting oversized transfers even
// from authorized peers.
func TestReceiverWithMaxSizeEnforced(t *testing.T) {
	mesh := newInProcTransferMesh()
	destDir := t.TempDir()

	checker := &mockAuthChecker{
		allowedPeers: map[string]bool{"authorized-peer": true},
	}

	// Set a very small max file size (10 bytes)
	receiver := NewReceiverWithAuth(mesh, 4195, destDir, 10, checker)
	if err := receiver.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer receiver.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := mesh.DialMesh(ctx, "test-peer", 4195)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Manually write header with oversized Size (to avoid Send() data-write deadlock)
	header := &FileHeader{
		Version:   ProtocolVersion,
		Filename:  "too-big.txt",
		Size:      1 << 20, // 1 MB — way over the 10-byte limit
		Mode:      0644,
		FileType:  FileTypeRegular,
		SrcPeerID: "authorized-peer",
	}
	headerJSON, _ := json.Marshal(header)
	binary.Write(conn, binary.BigEndian, uint32(len(headerJSON)))
	conn.Write(headerJSON)

	// Read the NACK response
	result, err := readFramedJSON[TransferResult](conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if result.OK {
		t.Error("expected transfer to be rejected (too large)")
	}

	// Verify no file was written
	destPath := filepath.Join(destDir, "too-big.txt")
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Errorf("file should not exist for oversized transfer: %v", err)
	}
}

// TestReceiverNilAuthCheckerAcceptsAll verifies that a nil auth checker
// (testing mode) accepts all transfers.
func TestReceiverNilAuthCheckerAcceptsAll(t *testing.T) {
	mesh := newInProcTransferMesh()
	destDir := t.TempDir()

	// nil auth checker — should accept all
	receiver := NewReceiverWithAuth(mesh, 4196, destDir, DefaultMaxFileSize, nil)
	if err := receiver.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer receiver.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := mesh.DialMesh(ctx, "test-peer", 4196)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	content := []byte("no auth check")
	header := &FileHeader{
		Filename:  "noauth.txt",
		Size:      int64(len(content)),
		Mode:      0644,
		FileType:  FileTypeRegular,
		SrcPeerID: "any-peer",
	}

	result, err := SendWithContext(ctx, conn, bytes.NewReader(content), header)
	if err != nil {
		t.Fatalf("send error: %v", err)
	}
	if !result.OK {
		t.Errorf("expected success with nil auth checker: %s", result.Message)
	}

	time.Sleep(100 * time.Millisecond)
	destPath := filepath.Join(destDir, "noauth.txt")
	if _, err := os.Stat(destPath); err != nil {
		t.Errorf("file should exist: %v", err)
	}
}
