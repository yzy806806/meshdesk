package webssh

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// startTestSSHServer starts an SSH server on a random localhost port
// and returns its address and a cleanup function.
func startTestSSHServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()

	srv, err := NewSSHServer("", "/bin/cat")
	if err != nil {
		t.Fatalf("NewSSHServer failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.Serve(ctx, ln)
		close(done)
	}()

	cleanup = func() {
		cancel()
		srv.Close()
		ln.Close()
		<-done
	}

	return ln.Addr().String(), cleanup
}

// startTestHTTPServer starts an HTTP server with the WebSocket handler
// and returns its base URL and cleanup.
func startTestHTTPServer(t *testing.T, sshAddr string) (baseURL string, cleanup func()) {
	t.Helper()

	resolver := &staticResolver{ip: sshAddr}
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	hub := NewHub(sshClient, resolver, 22, 64, 30*time.Second, 5*time.Second)
	handler := NewHandler(hub)

	// We need a custom port — parse from sshAddr
	host, portStr, _ := net.SplitHostPort(sshAddr)
	_ = host
	port := 22
	fmt.Sscanf(portStr, "%d", &port)
	hub.sshPort = port

	mux := http.NewServeMux()
	mux.Handle("/ws/terminal", handler)

	srv := httptest.NewServer(mux)
	cleanup = func() {
		srv.Close()
		hub.CloseAll()
	}

	return srv.URL, cleanup
}

type staticResolver struct {
	ip string
}

func (r *staticResolver) ResolvePeerMeshIP(peerID string) (string, error) {
	// Return the host portion of the test SSH server address
	host, _, _ := net.SplitHostPort(r.ip)
	return host, nil
}

// dialWS dials a WebSocket to the test HTTP server
func dialWS(t *testing.T, baseURL, peerID string) *websocket.Conn {
	t.Helper()
	url := fmt.Sprintf("%s/ws/terminal?node=%s&cols=80&rows=24", baseURL, peerID)
	wsURL := strings.Replace(url, "http://", "ws://", 1)

	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WebSocket dial failed: %v", err)
	}
	return ws
}

// waitForMessageType reads messages until it finds one of the given type
// or times out. Returns the message.
func waitForMessageType(t *testing.T, ws *websocket.Conn, msgType MsgType, timeout time.Duration) (Message, error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ws.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			return Message{}, err
		}
		msg, err := DecodeMessage(raw)
		if err != nil {
			continue
		}
		if msg.Type == msgType {
			return msg, nil
		}
	}
	return Message{}, fmt.Errorf("timeout waiting for %s", msgType)
}

func TestEndToEndTerminalSession(t *testing.T) {
	// Start a test SSH server that runs /bin/cat (echoes stdin to stdout)
	sshAddr, sshCleanup := startTestSSHServer(t)
	defer sshCleanup()

	// Start HTTP server with WebSocket handler
	baseURL, httpCleanup := startTestHTTPServer(t, sshAddr)
	defer httpCleanup()

	// Dial WebSocket
	ws := dialWS(t, baseURL, "testpeer123")
	defer ws.Close()

	// Wait for connected message
	_, err := waitForMessageType(t, ws, MsgConnected, 5*time.Second)
	if err != nil {
		// Try reading status or error
		ws.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, raw, _ := ws.ReadMessage()
		t.Fatalf("did not receive connected message: %v (last msg: %s)", err, string(raw))
	}

	// Send input (echo it via /bin/cat)
	inputData, _ := EncodeMessage(MsgInput, "aGVsbG8K") // "hello\n" base64
	ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := ws.WriteMessage(websocket.TextMessage, inputData); err != nil {
		t.Fatalf("write input failed: %v", err)
	}

	// Read output — /bin/cat should echo it back
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	found := false
	for i := 0; i < 10; i++ {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			break
		}
		msg, _ := DecodeMessage(raw)
		if msg.Type == MsgOutput {
			data, _ := DecodeBase64(msg.Data)
			if strings.Contains(string(data), "hello") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("expected to receive 'hello' in output")
	}
}

func TestTerminalResize(t *testing.T) {
	sshAddr, sshCleanup := startTestSSHServer(t)
	defer sshCleanup()

	baseURL, httpCleanup := startTestHTTPServer(t, sshAddr)
	defer httpCleanup()

	ws := dialWS(t, baseURL, "testpeer456")
	defer ws.Close()

	// Wait for connected
	_, err := waitForMessageType(t, ws, MsgConnected, 5*time.Second)
	if err != nil {
		t.Fatalf("did not receive connected: %v", err)
	}

	// Send resize message
	resizeMsg, _ := NewResizeMessage(120, 40)
	ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := ws.WriteMessage(websocket.TextMessage, resizeMsg); err != nil {
		t.Fatalf("write resize failed: %v", err)
	}

	// The session should not error — resize was accepted
	// Give it a moment, then verify the session is still alive
	time.Sleep(500 * time.Millisecond)

	// Send input to verify session is still active
	inputData, _ := EncodeMessage(MsgInput, "dGVzdAo=") // "test\n"
	ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := ws.WriteMessage(websocket.TextMessage, inputData); err != nil {
		t.Fatalf("write after resize failed: %v", err)
	}

	// Should still get output
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	gotOutput := false
	for i := 0; i < 10; i++ {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			break
		}
		msg, _ := DecodeMessage(raw)
		if msg.Type == MsgOutput {
			gotOutput = true
			break
		}
	}
	if !gotOutput {
		t.Error("session not responsive after resize")
	}
}

func TestSessionCleanupOnDisconnect(t *testing.T) {
	sshAddr, sshCleanup := startTestSSHServer(t)
	defer sshCleanup()

	// We need access to the hub to check session count
	resolver := &staticResolver{ip: sshAddr}
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	hub := NewHub(sshClient, resolver, 22, 64, 30*time.Second, 5*time.Second)
	// Set the port from sshAddr
	_, portStr, _ := net.SplitHostPort(sshAddr)
	fmt.Sscanf(portStr, "%d", &hub.sshPort)

	handler := NewHandler(hub)
	mux := http.NewServeMux()
	mux.Handle("/ws/terminal", handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer hub.CloseAll()

	// Connect
	ws := dialWS(t, srv.URL, "cleanup_peer")
	// Wait for connected
	waitForMessageType(t, ws, MsgConnected, 5*time.Second)

	// Verify session exists
	time.Sleep(200 * time.Millisecond)
	if hub.SessionCount() != 1 {
		t.Errorf("expected 1 session, got %d", hub.SessionCount())
	}

	// Abruptly close WebSocket (simulates browser tab close)
	ws.Close()

	// Wait for cleanup
	time.Sleep(1 * time.Second)

	if hub.SessionCount() != 0 {
		t.Errorf("expected 0 sessions after disconnect, got %d", hub.SessionCount())
	}
}

func TestMaxSessionsEnforced(t *testing.T) {
	sshAddr, sshCleanup := startTestSSHServer(t)
	defer sshCleanup()

	resolver := &staticResolver{ip: sshAddr}
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	// maxSessions = 2
	hub := NewHub(sshClient, resolver, 22, 2, 30*time.Second, 5*time.Second)
	_, portStr, _ := net.SplitHostPort(sshAddr)
	fmt.Sscanf(portStr, "%d", &hub.sshPort)

	handler := NewHandler(hub)
	mux := http.NewServeMux()
	mux.Handle("/ws/terminal", handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer hub.CloseAll()

	// Open 2 sessions
	ws1 := dialWS(t, srv.URL, "peer1")
	defer ws1.Close()
	waitForMessageType(t, ws1, MsgConnected, 5*time.Second)

	ws2 := dialWS(t, srv.URL, "peer2")
	defer ws2.Close()
	waitForMessageType(t, ws2, MsgConnected, 5*time.Second)

	if hub.SessionCount() != 2 {
		t.Errorf("expected 2 sessions, got %d", hub.SessionCount())
	}

	// 3rd should be rejected
	ws3URL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/ws/terminal?node=peer3"
	ws3, _, err := websocket.DefaultDialer.Dial(ws3URL, nil)
	if err == nil {
		// Read messages — should get an error then close
		ws3.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, raw, _ := ws3.ReadMessage()
		msg, _ := DecodeMessage(raw)
		if msg.Type != MsgError {
			t.Errorf("expected error message for max sessions, got %s", msg.Type)
		}
		ws3.Close()
	}
}

func TestStatusBarUpdates(t *testing.T) {
	sshAddr, sshCleanup := startTestSSHServer(t)
	defer sshCleanup()

	baseURL, httpCleanup := startTestHTTPServer(t, sshAddr)
	defer httpCleanup()

	ws := dialWS(t, baseURL, "statuspeer")
	defer ws.Close()

	// Should receive connecting → connected messages
	gotConnected := false
	deadline := time.Now().Add(5 * time.Second)
	ws.SetReadDeadline(deadline)

	for time.Now().Before(deadline) {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			break
		}
		msg, _ := DecodeMessage(raw)
		if msg.Type == MsgStatus {
			if strings.Contains(msg.Data, "connected") {
				gotConnected = true
			}
		}
		if msg.Type == MsgConnected {
			gotConnected = true
		}
		if gotConnected {
			break
		}
	}

	if !gotConnected {
		t.Error("expected to receive connected status")
	}
}

func TestCloseAllSessions(t *testing.T) {
	sshAddr, sshCleanup := startTestSSHServer(t)
	defer sshCleanup()

	resolver := &staticResolver{ip: sshAddr}
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	hub := NewHub(sshClient, resolver, 22, 64, 30*time.Second, 5*time.Second)
	_, portStr, _ := net.SplitHostPort(sshAddr)
	fmt.Sscanf(portStr, "%d", &hub.sshPort)

	handler := NewHandler(hub)
	mux := http.NewServeMux()
	mux.Handle("/ws/terminal", handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Open a few sessions
	for i := 0; i < 3; i++ {
		ws := dialWS(t, srv.URL, fmt.Sprintf("peer%d", i))
		defer ws.Close()
		waitForMessageType(t, ws, MsgConnected, 5*time.Second)
	}

	time.Sleep(300 * time.Millisecond)
	if hub.SessionCount() != 3 {
		t.Errorf("expected 3 sessions, got %d", hub.SessionCount())
	}

	// Close all
	hub.CloseAll()
	time.Sleep(500 * time.Millisecond)

	if hub.SessionCount() != 0 {
		t.Errorf("expected 0 sessions after CloseAll, got %d", hub.SessionCount())
	}
}

func TestPeerResolverError(t *testing.T) {
	resolver := &errorResolver{}
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	hub := NewHub(sshClient, resolver, 2222, 64, 30*time.Second, 5*time.Second)

	handler := NewHandler(hub)
	mux := http.NewServeMux()
	mux.Handle("/ws/terminal", handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer hub.CloseAll()

	ws := dialWS(t, srv.URL, "unknown_peer")
	defer ws.Close()

	// Should receive error message
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	foundError := false
	for i := 0; i < 5; i++ {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			break
		}
		msg, _ := DecodeMessage(raw)
		if msg.Type == MsgError {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Error("expected error message for unresolvable peer")
	}
}

type errorResolver struct{}

func (r *errorResolver) ResolvePeerMeshIP(peerID string) (string, error) {
	return "", fmt.Errorf("peer not found: %s", peerID)
}

func TestPinnedHostKey(t *testing.T) {
	// Test that PinnedHostKey returns a non-nil callback
	cb := PinnedHostKey([]byte{1, 2, 3, 4})
	if cb == nil {
		t.Fatal("PinnedHostKey returned nil")
	}
}

func TestSSHServerGeneration(t *testing.T) {
	// Test host key generation
	pem, err := GenerateHostKeyPEM()
	if err != nil {
		t.Fatalf("GenerateHostKeyPEM failed: %v", err)
	}
	if pem == "" {
		t.Fatal("GenerateHostKeyPEM returned empty string")
	}
	if !strings.Contains(pem, "-----BEGIN") {
		t.Errorf("expected PEM format, got: %s", pem[:50])
	}

	// Test that we can create a server with this key
	srv, err := NewSSHServer(pem, "/bin/sh")
	if err != nil {
		t.Fatalf("NewSSHServer with generated key failed: %v", err)
	}
	if srv.Shell() != "/bin/sh" {
		t.Errorf("shell mismatch: got %s, want /bin/sh", srv.Shell())
	}
}

func TestSSHServerShellDetection(t *testing.T) {
	srv, err := NewSSHServer("", "")
	if err != nil {
		t.Fatalf("NewSSHServer failed: %v", err)
	}
	shell := srv.Shell()
	if shell == "" {
		t.Error("auto-detected shell is empty")
	}
	// Should be a valid path
	if !strings.HasPrefix(shell, "/") {
		t.Errorf("shell should be an absolute path, got %s", shell)
	}
}

func TestSSHServerPublicKey(t *testing.T) {
	srv, err := NewSSHServer("", "/bin/sh")
	if err != nil {
		t.Fatalf("NewSSHServer failed: %v", err)
	}
	pub := srv.HostSignerPublicKey()
	if pub == "" {
		t.Error("HostSignerPublicKey returned empty string")
	}
}

func TestSShServerCloseWithoutServe(t *testing.T) {
	srv, err := NewSSHServer("", "/bin/sh")
	if err != nil {
		t.Fatalf("NewSSHServer failed: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
	// Double close should be safe
	if err := srv.Close(); err != nil {
		t.Errorf("double Close failed: %v", err)
	}
}

func TestNetDialer(t *testing.T) {
	d := &NetDialer{Timeout: 1 * time.Second}
	// Try connecting to a bad address
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialMesh(ctx, "tcp", "127.0.0.1:1") // port 1 should refuse
	if err == nil {
		t.Error("expected error connecting to port 1")
	}
}

func TestHubUpgrader(t *testing.T) {
	resolver := &staticResolver{ip: "127.0.0.1:22"}
	dialer := &NetDialer{Timeout: 5 * time.Second}
	sshClient := NewSSHClient(dialer, 5*time.Second, nil)
	hub := NewHub(sshClient, resolver, 2222, 64, 30*time.Second, 5*time.Second)

	upgrader := hub.Upgrader()
	if upgrader == nil {
		t.Fatal("Upgrader returned nil")
	}
}

// Test that the WSRequest struct exists and has the right fields
func TestWSRequestFields(t *testing.T) {
	req := WSRequest{PeerID: "abc", Cols: 80, Rows: 24}
	if req.PeerID != "abc" || req.Cols != 80 || req.Rows != 24 {
		t.Error("WSRequest fields not set correctly")
	}
}
