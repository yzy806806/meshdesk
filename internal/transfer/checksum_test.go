package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestChecksumComputationInSend verifies that Send computes a SHA-256
// checksum when none is provided in the header, and the receiver verifies it.
func TestChecksumComputationInSend(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("checksum test content")
	header := &FileHeader{
		Filename: "checksum.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
		// Checksum intentionally left empty — Send should compute it
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	_, n, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("expected %d bytes, got %d", len(content), n)
	}

	// Verify file was written correctly
	destPath := filepath.Join(destDir, "checksum.txt")
	written, _ := os.ReadFile(destPath)
	if !bytes.Equal(written, content) {
		t.Errorf("content mismatch")
	}

	// Verify checksum was computed and is correct
	if header.Checksum == "" {
		t.Error("Send did not compute checksum — Checksum field is empty")
	}
	expected := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expected[:])
	if header.Checksum != expectedHex {
		t.Errorf("checksum mismatch: got %s, want %s", header.Checksum, expectedHex)
	}
}

// TestChecksumVerificationPasses verifies that Receive accepts a file
// when the checksum is correct.
func TestChecksumVerificationPasses(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("valid checksum data")
	hash := sha256.Sum256(content)
	header := &FileHeader{
		Filename: "valid.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
		Checksum: hex.EncodeToString(hash[:]),
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	_, n, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("receive should succeed with valid checksum: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("expected %d bytes, got %d", len(content), n)
	}
}

// TestChecksumVerificationFails verifies that Receive rejects a file
// when the checksum is wrong, and deletes the written file.
func TestChecksumVerificationFails(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("tampered content")
	header := &FileHeader{
		Filename: "tampered.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
		Checksum: "deadbeef0000000000000000000000000000000000000000000000000000dead",
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	_, _, err := Receive(serverConn, destDir)
	if err == nil {
		t.Fatal("receive should fail with wrong checksum")
	}

	// Verify the file was deleted (checksum mismatch cleanup)
	destPath := filepath.Join(destDir, "tampered.txt")
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Errorf("corrupted file should have been deleted, stat err: %v", err)
	}
}

// TestMakeFileHeaderComputesChecksum verifies that MakeFileHeader
// computes and sets the SHA-256 checksum.
func TestMakeFileHeaderComputesChecksum(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "checksum-header.txt")
	content := []byte("header checksum test")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	header, f, err := MakeFileHeader(tmpFile, "sender-peer")
	if err != nil {
		t.Fatalf("make header: %v", err)
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	if header.Checksum == "" {
		t.Fatal("MakeFileHeader should compute checksum, got empty string")
	}

	// Verify the checksum is correct
	expected := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expected[:])
	if header.Checksum != expectedHex {
		t.Errorf("checksum mismatch: got %s, want %s", header.Checksum, expectedHex)
	}
}

// TestSendWithContextWithDeadline verifies that SendWithContext
// applies the context deadline to the connection and still works.
func TestSendWithContextWithDeadline(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("context deadline test")
	header := &FileHeader{
		Filename: "deadline.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		SendWithContext(ctx, clientConn, bytes.NewReader(content), header)
	}()

	_, _, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}

	// Verify file content
	destPath := filepath.Join(destDir, "deadline.txt")
	written, _ := os.ReadFile(destPath)
	if !bytes.Equal(written, content) {
		t.Errorf("content mismatch")
	}
}

// TestReceiverAcceptsFile tests the Receiver (mesh listener pattern)
// by using net.Pipe to simulate mesh connections.
func TestReceiverAcceptsFile(t *testing.T) {
	mesh := newInProcTransferMesh()
	destDir := t.TempDir()

	// Start a receiver
	receiver := NewReceiver(mesh, 4193, destDir)
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

	// Send a file
	content := []byte("receiver test file")
	header := &FileHeader{
		Filename: "recv-test.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	result, err := SendWithContext(ctx, conn, bytes.NewReader(content), header)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !result.OK {
		t.Errorf("send result not OK: %s", result.Message)
	}

	// Give the receiver a moment to write the file
	time.Sleep(100 * time.Millisecond)

	// Verify file was written
	destPath := filepath.Join(destDir, "recv-test.txt")
	written, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if !bytes.Equal(written, content) {
		t.Errorf("content mismatch")
	}
}

// --- In-memory mesh for testing file transfer ---

// inProcTransferMesh simulates mesh-internal connections using net.Pipe.
type inProcTransferMesh struct {
	listeners map[int]chan net.Conn
}

func newInProcTransferMesh() *inProcTransferMesh {
	return &inProcTransferMesh{
		listeners: make(map[int]chan net.Conn),
	}
}

func (m *inProcTransferMesh) ListenMesh(port int) (net.Listener, error) {
	if _, exists := m.listeners[port]; exists {
		return nil, errTransferAlreadyListening
	}
	ch := make(chan net.Conn, 64)
	m.listeners[port] = ch
	return &inProcTransferListener{mesh: m, port: port, ch: ch}, nil
}

func (m *inProcTransferMesh) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	ch, ok := m.listeners[port]
	if !ok {
		return nil, errTransferNoListener
	}

	c1, c2 := net.Pipe()
	select {
	case ch <- c2:
		return c1, nil
	case <-ctx.Done():
		c1.Close()
		c2.Close()
		return nil, ctx.Err()
	}
}

type inProcTransferListener struct {
	mesh *inProcTransferMesh
	port int
	ch   chan net.Conn
}

func (l *inProcTransferListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, errTransferListenerClosed
	}
	return conn, nil
}

func (l *inProcTransferListener) Close() error {
	delete(l.mesh.listeners, l.port)
	close(l.ch)
	return nil
}

func (l *inProcTransferListener) Addr() net.Addr {
	return &dummyAddr{}
}

type dummyAddr struct{}

func (d *dummyAddr) String() string  { return "test" }
func (d *dummyAddr) Network() string  { return "test" }

var errTransferAlreadyListening = &transferTestError{"port already in use"}
var errTransferNoListener = &transferTestError{"no listener"}
var errTransferListenerClosed = &transferTestError{"listener closed"}

type transferTestError struct{ msg string }

func (e *transferTestError) Error() string { return e.msg }

// Ensure we satisfy the io import for potential future use
var _ io.Reader = (*bytes.Reader)(nil)
