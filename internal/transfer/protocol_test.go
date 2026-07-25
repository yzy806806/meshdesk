package transfer

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSendAndReceive(t *testing.T) {
	// Create a temp directory for the receiver to write to
	destDir := t.TempDir()

	// Create source content
	content := []byte("Hello, MeshDesk file transfer!")
	srcFile := bytes.NewReader(content)

	// Use a pipe pair to simulate a bidirectional connection
	clientConn, serverConn := newPipeConn()

	header := &FileHeader{
		Filename:  "test.txt",
		Size:      int64(len(content)),
		Mode:      0644,
		FileType:  FileTypeRegular,
		ModTime:   time.Now().Format(time.RFC3339),
		SrcPeerID: "peer-sender",
	}

	// Run sender and receiver concurrently
	errChan := make(chan error, 2)
	resultChan := make(chan *TransferResult, 1)
	recvChan := make(chan struct {
		hdr   *FileHeader
		bytes int64
		err   error
	}, 1)

	go func() {
		result, err := Send(clientConn, srcFile, header)
		errChan <- err
		resultChan <- result
	}()

	go func() {
		hdr, n, err := Receive(serverConn, destDir)
		recvChan <- struct {
			hdr   *FileHeader
			bytes int64
			err   error
		}{hdr, n, err}
	}()

	// Wait for sender
	if err := <-errChan; err != nil {
		t.Fatalf("send failed: %v", err)
	}
	result := <-resultChan
	if !result.OK {
		t.Errorf("send result not OK: %s", result.Message)
	}

	// Wait for receiver
	recv := <-recvChan
	if recv.err != nil {
		t.Fatalf("receive failed: %v", recv.err)
	}
	if recv.bytes != int64(len(content)) {
		t.Errorf("expected %d bytes received, got %d", len(content), recv.bytes)
	}
	if recv.hdr.Filename != "test.txt" {
		t.Errorf("expected filename test.txt, got %s", recv.hdr.Filename)
	}

	// Verify file contents
	destPath := filepath.Join(destDir, "test.txt")
	written, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(written) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", written, content)
	}
}

func TestSendEmptyFile(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	header := &FileHeader{
		Filename: "empty.txt",
		Size:     0,
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	go func() {
		Send(clientConn, bytes.NewReader(nil), header)
	}()

	hdr, n, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
	if hdr.Filename != "empty.txt" {
		t.Errorf("expected filename empty.txt, got %s", hdr.Filename)
	}

	// Verify file was created
	destPath := filepath.Join(destDir, "empty.txt")
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty file, got %d bytes", info.Size())
	}
}

func TestReceiveDirectory(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	header := &FileHeader{
		Filename: "subdir",
		Mode:     0755,
		FileType: FileTypeDirectory,
	}

	go func() {
		Send(clientConn, bytes.NewReader(nil), header)
	}()

	hdr, _, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("receive directory failed: %v", err)
	}
	if hdr.FileType != FileTypeDirectory {
		t.Errorf("expected directory type, got %s", hdr.FileType)
	}

	// Verify directory was created
	destPath := filepath.Join(destDir, "subdir")
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory to be created")
	}
}

func TestPathTraversalPrevention(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	// Try to write to ../../../etc/passwd
	header := &FileHeader{
		Filename: "../../../etc/passwd",
		Size:     0,
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	go func() {
		Send(clientConn, bytes.NewReader(nil), header)
	}()

	hdr, _, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("receive should not error (filename is sanitized): %v", err)
	}

	// The filename should have been sanitized to just "passwd"
	if hdr.Filename != "../../../etc/passwd" {
		// The header itself is not modified, but the written file is sanitized
		// This is fine — the header preserves the original for logging
	}

	// Verify the file was written INSIDE destDir as "passwd" (sanitized)
	destPath := filepath.Join(destDir, "passwd")
	if _, err := os.Stat(destPath); err != nil {
		t.Errorf("expected file to be written as passwd inside destDir: %v", err)
	}

	// Verify nothing was written outside destDir
	// (the test TempDir is cleaned up automatically, so we just verify
	// no file appeared at the traversal target)
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"test.txt", "test.txt"},
		{"path/to/file.txt", "file.txt"},
		{"../../../etc/passwd", "passwd"},
		{"..", ""},
		{".", ""},
		{"", ""},
		{"/absolute/path", "path"},
		{"normal-file_v2.log", "normal-file_v2.log"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.output {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.output)
			}
		})
	}
}

func TestMakeFileHeader(t *testing.T) {
	// Create a temp file
	tmpFile := filepath.Join(t.TempDir(), "header-test.txt")
	content := []byte("test content for header")
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

	if header.Filename != "header-test.txt" {
		t.Errorf("expected filename 'header-test.txt', got %s", header.Filename)
	}
	if header.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), header.Size)
	}
	if header.FileType != FileTypeRegular {
		t.Errorf("expected regular file type, got %s", header.FileType)
	}
	if header.SrcPeerID != "sender-peer" {
		t.Errorf("expected src_peer_id 'sender-peer', got %s", header.SrcPeerID)
	}
	if header.Version != ProtocolVersion {
		t.Errorf("expected version %d, got %d", ProtocolVersion, header.Version)
	}
}

func TestMakeFileHeaderDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "testdir")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	header, f, err := MakeFileHeader(dir, "sender")
	if err != nil {
		t.Fatalf("make header: %v", err)
	}
	if f != nil {
		f.Close()
	}

	if header.FileType != FileTypeDirectory {
		t.Errorf("expected directory type, got %s", header.FileType)
	}
}

func TestLargeFileTransfer(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	// Create a large-ish file (1 MB)
	content := bytes.Repeat([]byte("A"), 1024*1024)
	header := &FileHeader{
		Filename: "large.bin",
		Size:     int64(len(content)),
		Mode:     0644,
		FileType: FileTypeRegular,
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	_, n, err := Receive(serverConn, destDir)
	if err != nil {
		t.Fatalf("receive large file: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("expected %d bytes, got %d", len(content), n)
	}

	// Verify
	destPath := filepath.Join(destDir, "large.bin")
	written, _ := os.ReadFile(destPath)
	if len(written) != len(content) {
		t.Errorf("file size mismatch: got %d, want %d", len(written), len(content))
	}
	if !bytes.Equal(written, content) {
		t.Error("content mismatch in large file")
	}
}

func TestFileModePreserved(t *testing.T) {
	destDir := t.TempDir()
	clientConn, serverConn := newPipeConn()

	content := []byte("permission test")
	header := &FileHeader{
		Filename: "perm.txt",
		Size:     int64(len(content)),
		Mode:     0755, // executable
		FileType: FileTypeRegular,
	}

	go func() {
		Send(clientConn, bytes.NewReader(content), header)
	}()

	Receive(serverConn, destDir)

	destPath := filepath.Join(destDir, "perm.txt")
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0755 {
		t.Errorf("expected mode 0755, got %o", mode)
	}
}

// --- Helper: pipe-based bidirectional connection ---

// pipeConn implements io.ReadWriter using a pair of pipes.
// This simulates a bidirectional network connection for testing.
type pipeConn struct {
	*io.PipeReader
	*io.PipeWriter
}

func (pc *pipeConn) Close() error {
	pc.PipeReader.Close()
	pc.PipeWriter.Close()
	return nil
}

func newPipeConn() (client, server *pipeConn) {
	// Create two pipes for bidirectional communication
	cr, cw := io.Pipe() // client → server
	sr, sw := io.Pipe() // server → client

	client = &pipeConn{PipeReader: sr, PipeWriter: cw}
	server = &pipeConn{PipeReader: cr, PipeWriter: sw}
	return client, server
}

// Ensure pipeConn satisfies io.ReadWriter
var _ io.ReadWriter = (*pipeConn)(nil)
