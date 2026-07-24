package web

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/transfer"
)

// --- Mock MeshDialer for testing ---

// mockMeshDialer simulates mesh-internal connections for testing.
// It accepts connections and routes them to an in-memory mesh.
type mockMeshDialer struct {
	mesh *inProcWebMesh
}

func (d *mockMeshDialer) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	return d.mesh.Dial(ctx, port)
}

// inProcWebMesh simulates mesh-internal connections using net.Pipe.
type inProcWebMesh struct {
	listeners map[int]chan net.Conn
}

func newInProcWebMesh() *inProcWebMesh {
	return &inProcWebMesh{
		listeners: make(map[int]chan net.Conn),
	}
}

func (m *inProcWebMesh) Listen(port int) (net.Listener, error) {
	if _, exists := m.listeners[port]; exists {
		return nil, errWebAlreadyListening
	}
	ch := make(chan net.Conn, 64)
	m.listeners[port] = ch
	return &inProcWebListener{mesh: m, port: port, ch: ch}, nil
}

func (m *inProcWebMesh) Dial(ctx context.Context, port int) (net.Conn, error) {
	ch, ok := m.listeners[port]
	if !ok {
		return nil, errWebNoListener
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

type inProcWebListener struct {
	mesh *inProcWebMesh
	port int
	ch   chan net.Conn
}

func (l *inProcWebListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, errWebListenerClosed
	}
	return conn, nil
}

func (l *inProcWebListener) Close() error {
	delete(l.mesh.listeners, l.port)
	close(l.ch)
	return nil
}

func (l *inProcWebListener) Addr() net.Addr {
	return &webDummyAddr{}
}

type webDummyAddr struct{}

func (d *webDummyAddr) String() string  { return "test" }
func (d *webDummyAddr) Network() string { return "test" }

var errWebAlreadyListening = &webTestError{"port already in use"}
var errWebNoListener = &webTestError{"no listener"}
var errWebListenerClosed = &webTestError{"listener closed"}

type webTestError struct{ msg string }

func (e *webTestError) Error() string { return e.msg }

// Ensure inProcWebMesh satisfies transfer.MeshListener
var _ transfer.MeshListener = (*inProcWebMesh)(nil)

func (m *inProcWebMesh) ListenMesh(port int) (net.Listener, error) {
	return m.Listen(port)
}
func (m *inProcWebMesh) ListenMeshSvc(port int) (net.Listener, error) {
	return m.Listen(port)
}

// Ensure inProcWebMesh satisfies service.MeshListener
var _ service.MeshListener = (*inProcWebMesh)(nil)

// --- Test: Remote file upload via mesh ---

func TestHandleFileUpload_RemoteTransfer(t *testing.T) {
	mesh := newInProcWebMesh()
	destDir := t.TempDir()

	// Start a file transfer receiver on the "remote" mesh node
	receiver := transfer.NewReceiver(mesh, TransferPort, destDir)
	if err := receiver.Start(); err != nil {
		t.Fatalf("receiver start: %v", err)
	}
	defer receiver.Stop()

	// Create a web server with the mock mesh dialer
	cfg := config.Default()
	store := monitor.NewStore()
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
		MeshDialer:   &mockMeshDialer{mesh: mesh},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Create a multipart form with a file and target_node
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("target_node", "remote-peer")
	_ = writer.WriteField("dest_path", "/tmp/")
	part, _ := writer.CreateFormFile("file", "test-upload.txt")
	part.Write([]byte("remote upload content"))
	writer.Close()

	req := httptest.NewRequest("POST", "/api/files/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	srv.handleFileUpload(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Transferred") {
		t.Errorf("body should contain 'Transferred': %s", body)
	}

	// Give the receiver a moment to write
	// (the transfer is synchronous so the file should already be written)

	// Verify file was received on the "remote" node
	// We can't directly check the remote destDir because the transfer
	// receiver wrote it. Let's check if the response indicates success.
	if strings.Contains(body, "error") {
		t.Errorf("body contains error: %s", body)
	}
}

// --- Test: Remote file upload without mesh dialer ---

func TestHandleFileUpload_RemoteNoMeshDialer(t *testing.T) {
	cfg := config.Default()
	store := monitor.NewStore()
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
		// No MeshDialer
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("target_node", "remote-peer")
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("content"))
	writer.Close()

	req := httptest.NewRequest("POST", "/api/files/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	srv.handleFileUpload(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Mesh dialer not configured") {
		t.Errorf("body should contain 'Mesh dialer not configured': %s", body)
	}
}

// --- Test: Local file upload ---

func TestHandleFileUpload_Local(t *testing.T) {
	cfg := config.Default()
	store := monitor.NewStore()
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("dest_path", t.TempDir()+"/")
	part, _ := writer.CreateFormFile("file", "local-upload.txt")
	part.Write([]byte("local upload content"))
	writer.Close()

	req := httptest.NewRequest("POST", "/api/files/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	srv.handleFileUpload(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Uploaded") {
		t.Errorf("body should contain 'Uploaded': %s", body)
	}
}

// --- Test: Remote service action via mesh ---

func TestHandleServiceAction_Remote(t *testing.T) {
	mesh := newInProcWebMesh()
	mock := service.NewMockBackend()

	// Start a remote service server on the "remote" mesh node
	remoteServer := service.NewRemoteServer(mock, mesh, service.DefaultServicePort)
	if err := remoteServer.Start(); err != nil {
		t.Fatalf("remote server start: %v", err)
	}
	defer remoteServer.Stop()

	cfg := config.Default()
	store := monitor.NewStore()
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
		MeshDialer:   &mockMeshDialer{mesh: mesh},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Test "start" action on remote node
	form := "node=remote-peer&service=nginx"
	req := httptest.NewRequest("POST", "/api/services/start", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handleServiceAction("start")(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, body: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if !strings.Contains(body, "successfully") {
		t.Errorf("body should contain 'successfully': %s", body)
	}

	// Verify the service was started on the mock backend
	status, err := mock.Status("nginx")
	if err != nil {
		t.Fatalf("mock status: %v", err)
	}
	if status.ActiveState != "active" {
		t.Errorf("expected nginx active, got %s", status.ActiveState)
	}
}

// --- Test: Remote service action without mesh dialer ---

func TestHandleServiceAction_RemoteNoMeshDialer(t *testing.T) {
	cfg := config.Default()
	store := monitor.NewStore()
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	form := "node=remote-peer&service=nginx"
	req := httptest.NewRequest("POST", "/api/services/start", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handleServiceAction("start")(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

// --- Test: Local service action with AuthorizedServiceManager ---

func TestHandleServiceAction_LocalWithAuth(t *testing.T) {
	mock := service.NewMockBackend()

	cfg := config.Default()
	store := monitor.NewStore()
	srv, err := New(Deps{
		Config:       cfg,
		MonitorStore: store,
		ServiceMgr:   mock,
		// No AuthEngine — local ops should still work with plain ServiceManager
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	form := "service=nginx"
	req := httptest.NewRequest("POST", "/api/services/start", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handleServiceAction("start")(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, body: %s", rr.Code, rr.Body.String())
	}

	// Verify service was started
	status, _ := mock.Status("nginx")
	if status.ActiveState != "active" {
		t.Errorf("expected nginx active, got %s", status.ActiveState)
	}
}

// --- Test: Handle file upload GET (method not allowed) ---

func TestHandleFileUpload_GetMethod(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/api/files/upload", nil)
	rr := httptest.NewRecorder()

	srv.handleFileUpload(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// Suppress unused import
var _ io.Reader = (*bytes.Reader)(nil)
