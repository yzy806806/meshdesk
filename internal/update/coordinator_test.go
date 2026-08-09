package update

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockSvc implements FileSvc + CommandSvc against a fake node that
// "executes" commands in-process and stores written files. Storage is
// keyed by nodeID so concurrent node updates don't collide on the
// shared staging path.
type mockSvc struct {
	mu      sync.Mutex
	files   map[string][]byte // nodeID|path → content
	install map[string][]byte // nodeID|path → installed binary
	backup  map[string][]byte // nodeID|path → backup
	health  bool
	logs    []string
}

func newMockSvc() *mockSvc {
	return &mockSvc{
		files:   make(map[string][]byte),
		install: make(map[string][]byte),
		backup:  make(map[string][]byte),
		health:  true,
	}
}

func (m *mockSvc) fkey(nodeID, path string) string { return nodeID + "|" + path }

// DialFile handles a FileServer write by capturing the payload.
func (m *mockSvc) DialFile(ctx context.Context, nodeID string) (io.ReadWriteCloser, error) {
	client, server := net.Pipe()
	go func() {
		var req map[string]any
		json.NewDecoder(server).Decode(&req)
		path := req["path"].(string)
		size := int64(req["size"].(float64))
		payload := make([]byte, size)
		io.ReadFull(server, payload)
		m.mu.Lock()
		m.files[m.fkey(nodeID, path)] = payload
		m.mu.Unlock()
		json.NewEncoder(server).Encode(map[string]any{"ok": true, "written": size})
		server.Close()
	}()
	return client, nil
}

// DialCommand handles one command.
func (m *mockSvc) DialCommand(ctx context.Context, nodeID string) (io.ReadWriteCloser, error) {
	client, server := net.Pipe()
	go func() {
		var req map[string]any
		json.NewDecoder(server).Decode(&req)
		cmd := req["cmd"].(string)
		out, exit := m.exec(nodeID, cmd)
		json.NewEncoder(server).Encode(map[string]any{
			"ok": true, "stdout": out, "exit": exit,
		})
		server.Close()
	}()
	return client, nil
}

// exec simulates shell commands on the fake node (split on &&).
func (m *mockSvc) exec(nodeID, cmd string) (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, cmd)

	var out strings.Builder
	for _, sub := range strings.Split(cmd, " && ") {
		sub = strings.TrimSpace(sub)
		switch {
		case strings.HasPrefix(sub, "md5sum"):
			p := strings.Fields(sub)[1]
			data := m.files[m.fkey(nodeID, p)]
			return fmt.Sprintf("%x", md5.Sum(data)), 0
		case strings.HasPrefix(sub, "cp -f"):
			parts := strings.Fields(sub)
			src, dst := parts[2], parts[3]
			fk, dk := m.fkey(nodeID, src), m.fkey(nodeID, dst)
			if strings.Contains(dst, ".bak") {
				m.backup[dk] = m.install[fk]
			} else if data, ok := m.backup[fk]; ok {
				// rollback: restore from backup
				m.install[dk] = data
			} else {
				m.install[dk] = m.files[fk]
			}
		case strings.HasPrefix(sub, "mv -f"):
			parts := strings.Fields(sub)
			src, dst := parts[2], parts[3]
			fk, dk := m.fkey(nodeID, src), m.fkey(nodeID, dst)
			m.install[dk] = m.files[fk]
			delete(m.files, fk)
		case strings.HasPrefix(sub, "chmod"):
			// no-op
		case sub == "sync":
			// no-op
		case strings.HasPrefix(sub, "pgrep"):
			if m.health {
				return "UP", 0
			}
			return "DOWN", 1
		case strings.HasPrefix(sub, "rm -f"):
			delete(m.files, m.fkey(nodeID, strings.Fields(sub)[2]))
		case strings.HasPrefix(sub, "systemctl restart"):
			// no-op
		default:
			out.WriteString(sub + "\n")
		}
	}
	return out.String(), 0
}

// TestCoordinator_EndToEnd runs the full happy-path update.
func TestCoordinator_EndToEnd(t *testing.T) {
	svc := newMockSvc()
	svc.mu.Lock()
	svc.install[svc.fkey("node-a", "/usr/local/bin/meshdesk")] = []byte("old-binary")
	svc.install[svc.fkey("node-b", "/usr/local/bin/meshdesk")] = []byte("old-binary")
	svc.mu.Unlock()

	local := filepath.Join(t.TempDir(), "meshdesk")
	os.WriteFile(local, []byte("new-binary-v2"), 0o755)

	c := NewCoordinator(svc, svc, Options{
		Nodes:        []string{"node-a", "node-b"},
		BinaryPath:   local,
		RestartDelay: 100 * time.Millisecond,
	})
	results := c.Run(context.Background())

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.OK {
			t.Fatalf("node %s update failed: %s (%s)", r.NodeID, r.Message, r.Phase)
		}
		if r.Phase != PhaseDone {
			t.Fatalf("node %s phase=%s want done", r.NodeID, r.Phase)
		}
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if string(svc.install[svc.fkey("node-a", "/usr/local/bin/meshdesk")]) != "new-binary-v2" {
		t.Fatalf("installed binary wrong: %q", svc.install[svc.fkey("node-a", "/usr/local/bin/meshdesk")])
	}
}

// TestCoordinator_RollbackOnHealthFail verifies restore + restart.
func TestCoordinator_RollbackOnHealthFail(t *testing.T) {
	svc := newMockSvc()
	svc.mu.Lock()
	svc.install[svc.fkey("node-a", "/usr/local/bin/meshdesk")] = []byte("old-binary")
	svc.install[svc.fkey("node-b", "/usr/local/bin/meshdesk")] = []byte("old-binary")
	svc.health = false // health check will fail
	svc.mu.Unlock()

	local := filepath.Join(t.TempDir(), "meshdesk")
	os.WriteFile(local, []byte("new-broken"), 0o755)

	c := NewCoordinator(svc, svc, Options{
		Nodes:        []string{"node-a"},
		BinaryPath:   local,
		RestartDelay: 100 * time.Millisecond,
	})
	results := c.Run(context.Background())
	r := results[0]
	if r.OK {
		t.Fatalf("expected failure, got OK")
	}
	if r.Phase != PhaseRollback {
		t.Fatalf("phase=%s want rollback", r.Phase)
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if string(svc.install[svc.fkey("node-a", "/usr/local/bin/meshdesk")]) != "old-binary" {
		t.Fatalf("rollback did not restore: %q", svc.install[svc.fkey("node-a", "/usr/local/bin/meshdesk")])
	}
}

// TestCoordinator_MD5MismatchFails rejects wrong binaries.
func TestCoordinator_MD5MismatchFails(t *testing.T) {
	svc := newMockSvc()
	local := filepath.Join(t.TempDir(), "meshdesk")
	os.WriteFile(local, []byte("payload"), 0o755)

	c := NewCoordinator(svc, svc, Options{
		Nodes:        []string{"node-a"},
		BinaryPath:   local,
		RestartDelay: 100 * time.Millisecond,
		ExpectedMD5:  strings.Repeat("0", 32), // wrong
	})
	results := c.Run(context.Background())
	r := results[0]
	if r.OK {
		t.Fatalf("md5 mismatch should fail")
	}
	if !strings.Contains(r.Message, "md5") {
		t.Fatalf("message should mention md5: %q", r.Message)
	}
}
