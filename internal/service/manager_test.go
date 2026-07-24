package service

import (
	"strings"
	"testing"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
)

// --- MockBackend tests ---

func TestMockStart(t *testing.T) {
	mb := NewMockBackend()
	if err := mb.Start("nginx"); err != nil {
		t.Fatalf("start nginx: %v", err)
	}
	status, err := mb.Status("nginx")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.ActiveState != "active" {
		t.Errorf("expected active, got %s", status.ActiveState)
	}
}

func TestMockStop(t *testing.T) {
	mb := NewMockBackend()
	if err := mb.Stop("nginx"); err != nil {
		t.Fatalf("stop nginx: %v", err)
	}
	status, _ := mb.Status("nginx")
	if status.ActiveState != "inactive" {
		t.Errorf("expected inactive, got %s", status.ActiveState)
	}
}

func TestMockRestart(t *testing.T) {
	mb := NewMockBackend()
	if err := mb.Restart("nginx"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	status, _ := mb.Status("nginx")
	if status.ActiveState != "active" {
		t.Errorf("expected active after restart, got %s", status.ActiveState)
	}
}

func TestMockStatusNotFound(t *testing.T) {
	mb := NewMockBackend()
	_, err := mb.Status("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent service")
	}
}

func TestMockList(t *testing.T) {
	mb := NewMockBackend()
	services, err := mb.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(services) != 3 {
		t.Errorf("expected 3 services, got %d", len(services))
	}
}

func TestMockLogs(t *testing.T) {
	mb := NewMockBackend()
	reader, err := mb.Logs("nginx", false)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	defer reader.Close()

	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	logText := string(buf[:n])
	if !strings.Contains(logText, "nginx") {
		t.Errorf("expected logs to mention nginx, got: %s", logText)
	}
}

func TestMockAddRemoveService(t *testing.T) {
	mb := NewMockBackend()
	mb.AddService(ServiceStatus{
		Name: "redis", LoadState: "loaded", ActiveState: "active", SubState: "running",
	})
	services, _ := mb.List()
	if len(services) != 4 {
		t.Errorf("expected 4 services, got %d", len(services))
	}

	mb.RemoveService("redis")
	services, _ = mb.List()
	if len(services) != 3 {
		t.Errorf("expected 3 services after remove, got %d", len(services))
	}
}

func TestMockStartNotFound(t *testing.T) {
	mb := NewMockBackend()
	err := mb.Start("nonexistent")
	if err == nil {
		t.Error("expected error for starting nonexistent service")
	}
}

func TestMockCustomServices(t *testing.T) {
	mb := NewMockBackend(ServiceStatus{
		Name: "custom-svc", LoadState: "loaded", ActiveState: "active", SubState: "running",
	})
	if _, err := mb.Status("custom-svc"); err != nil {
		t.Errorf("expected custom service to exist: %v", err)
	}
	// default services should not be present when custom is provided
	if _, err := mb.Status("nginx"); err == nil {
		t.Error("expected nginx to not exist when custom services provided")
	}
}

// --- parseSystemctlShow test ---

func TestParseSystemctlShow(t *testing.T) {
	output := `Id=nginx.service
LoadState=loaded
ActiveState=active
SubState=running
Description=The nginx HTTP and reverse proxy server
ExecMainPID=1234
MemoryCurrent=4567890
`
	status := parseSystemctlShow(output)
	if status.LoadState != "loaded" {
		t.Errorf("expected loaded, got %s", status.LoadState)
	}
	if status.ActiveState != "active" {
		t.Errorf("expected active, got %s", status.ActiveState)
	}
	if status.SubState != "running" {
		t.Errorf("expected running, got %s", status.SubState)
	}
	if status.Description != "The nginx HTTP and reverse proxy server" {
		t.Errorf("unexpected description: %s", status.Description)
	}
	if status.ExecMainPID != 1234 {
		t.Errorf("expected PID 1234, got %d", status.ExecMainPID)
	}
	if status.MemoryBytes != 4567890 {
		t.Errorf("expected memory 4567890, got %d", status.MemoryBytes)
	}
}

func TestParseSystemctlShowEmpty(t *testing.T) {
	status := parseSystemctlShow("")
	if status.LoadState != "" {
		t.Error("expected empty load state")
	}
}

// --- AuthorizedServiceManager tests ---

func newAuthTestEngine(t *testing.T) *auth.CapabilityEngine {
	t.Helper()
	cfg := &config.Config{
		Peers: []config.PeerConfig{
			{
				PublicKey:     "auth-peer-1",
				Capabilities:  []string{auth.CapServiceManage},
				ServiceManage: []string{"nginx", "meshdesk"},
			},
			{
				PublicKey:    "auth-peer-2",
				Capabilities: []string{auth.CapMonitorRead}, // no service_manage
			},
		},
	}
	return auth.NewCapabilityEngine(cfg, auth.NewAuditLogger(nil))
}

func TestAuthorizedStartAllowed(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	err := asm.Start("nginx")
	if err != nil {
		t.Errorf("expected authorized start to succeed: %v", err)
	}
}

func TestAuthorizedStartDenied(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-2")

	err := asm.Start("nginx")
	if err == nil {
		t.Error("expected unauthorized start to fail")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected 'unauthorized' in error, got: %v", err)
	}
}

func TestAuthorizedStartServiceNotScoped(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	// peer-1 is scoped to nginx and meshdesk, not ssh
	err := asm.Start("ssh")
	if err == nil {
		t.Error("expected start ssh to fail (not scoped)")
	}
}

func TestAuthorizedStopAllowed(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	err := asm.Stop("nginx")
	if err != nil {
		t.Errorf("expected stop to succeed: %v", err)
	}
}

func TestAuthorizedRestartAllowed(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	err := asm.Restart("meshdesk")
	if err != nil {
		t.Errorf("expected restart to succeed: %v", err)
	}
}

func TestAuthorizedStatusAllowed(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	status, err := asm.Status("nginx")
	if err != nil {
		t.Errorf("expected status to succeed: %v", err)
	}
	if status == nil {
		t.Error("expected non-nil status")
	}
}

func TestAuthorizedLogsAllowed(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	reader, err := asm.Logs("nginx", false)
	if err != nil {
		t.Fatalf("expected logs to succeed: %v", err)
	}
	defer reader.Close()
}

func TestAuthorizedListAllowed(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	services, err := asm.List()
	if err != nil {
		t.Errorf("expected list to succeed: %v", err)
	}
	if len(services) != 3 {
		t.Errorf("expected 3 services, got %d", len(services))
	}
}

func TestAuthorizedListDenied(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)
	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-2")

	_, err := asm.List()
	if err == nil {
		t.Error("expected list to fail for peer without service_manage")
	}
}

func TestAuthorizedStatusRevoked(t *testing.T) {
	mb := NewMockBackend()
	engine := newAuthTestEngine(t)

	// Revoke the peer
	engine.Revoke("auth-peer-1", "revoker", "sig", "test")

	asm := NewAuthorizedServiceManager(mb, engine, "auth-peer-1")

	_, err := asm.Status("nginx")
	if err == nil {
		t.Error("expected status to fail for revoked peer")
	}
}
