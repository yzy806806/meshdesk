package mesh

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runFileServerConn pairs the FileServer handler with a client over
// net.Pipe, bypassing the mesh layer. A writer goroutine sends the
// request (and optional write payload); the main goroutine reads the
// response — avoiding net.Pipe's synchronous read/write deadlock.
func runFileServerConn(t *testing.T, cfg FileServerConfig, req FileRequest, writePayload []byte) (FileResponse, []byte) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	fs := &FileServer{cfg: cfg}
	done := make(chan struct{})
	go func() {
		fs.handle(server)
		close(done)
	}()

	werr := make(chan error, 1)
	go func() {
		if err := json.NewEncoder(client).Encode(req); err != nil {
			werr <- err
			return
		}
		if writePayload != nil {
			if _, err := client.Write(writePayload); err != nil {
				werr <- err
				return
			}
		}
		werr <- nil
	}()

	var resp FileResponse
	if err := json.NewDecoder(io.LimitReader(client, 64<<10)).Decode(&resp); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	if err := <-werr; err != nil {
		t.Fatalf("writer: %v", err)
	}
	var payload []byte
	if resp.OK && req.Op == "read" {
		payload, _ = io.ReadAll(io.LimitReader(client, resp.Size))
	}
	<-done
	return resp, payload
}

// TestFileServer_WriteReadRoundTrip writes, reads, stats, lists, deletes.
func TestFileServer_WriteReadRoundTrip(t *testing.T) {
	root := t.TempDir()
	cfg := FileServerConfig{AllowedPaths: []string{root}}
	path := filepath.Join(root, "sub", "hello.txt")

	// Write with payload.
	resp, _ := runFileServerConn(t, cfg, FileRequest{Op: "write", Path: path, Size: 5}, []byte("hello"))
	if !resp.OK || resp.Written != 5 {
		t.Fatalf("write failed: %+v", resp)
	}

	// Read back.
	rresp, payload := runFileServerConn(t, cfg, FileRequest{Op: "read", Path: path}, nil)
	if !rresp.OK || string(payload) != "hello" {
		t.Fatalf("read failed: %+v payload=%q", rresp, payload)
	}

	// Stat.
	sresp, _ := runFileServerConn(t, cfg, FileRequest{Op: "stat", Path: path}, nil)
	if !sresp.OK || sresp.Size != 5 {
		t.Fatalf("stat failed: %+v", sresp)
	}

	// List root.
	lresp, _ := runFileServerConn(t, cfg, FileRequest{Op: "list", Path: root}, nil)
	if !lresp.OK || len(lresp.Entries) < 1 {
		t.Fatalf("list failed: %+v", lresp)
	}

	// Delete.
	dresp, _ := runFileServerConn(t, cfg, FileRequest{Op: "delete", Path: path}, nil)
	if !dresp.OK {
		t.Fatalf("delete failed: %+v", dresp)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after delete")
	}
}

// TestFileServer_PathTraversal rejects ../ escapes.
func TestFileServer_PathTraversal(t *testing.T) {
	root := t.TempDir()
	cfg := FileServerConfig{AllowedPaths: []string{root}}
	esc := filepath.Join(root, "..", "..")
	resp, _ := runFileServerConn(t, cfg, FileRequest{Op: "list", Path: esc}, nil)
	if resp.OK {
		t.Fatalf("traversal should be rejected, got OK")
	}
	if !strings.Contains(resp.Error, "outside allowed") && !strings.Contains(resp.Error, "traversal") {
		t.Fatalf("unexpected error: %q", resp.Error)
	}
}

// TestFileServer_AllowedRootRejectsOutside denies paths outside roots.
func TestFileServer_AllowedRootRejectsOutside(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir() // sibling, not under root
	cfg := FileServerConfig{AllowedPaths: []string{root}}
	resp, _ := runFileServerConn(t, cfg, FileRequest{Op: "list", Path: outside}, nil)
	if resp.OK {
		t.Fatalf("outside path should be rejected")
	}
}

// TestFileServer_SizeLimit rejects oversized writes.
func TestFileServer_SizeLimit(t *testing.T) {
	root := t.TempDir()
	cfg := FileServerConfig{AllowedPaths: []string{root}, MaxWriteSize: 10}
	path := filepath.Join(root, "big.bin")
	resp, _ := runFileServerConn(t, cfg, FileRequest{Op: "write", Path: path, Size: 999}, nil)
	if resp.OK {
		t.Fatalf("oversized write should be rejected")
	}
}
