package webssh

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

const (
	// SessionIDLen is the length of generated session IDs.
	SessionIDLen = 16

	// writeBufferSize is the buffer size for WebSocket writes.
	writeBufferSize = 4096

	// readBufferSize is the buffer size for PTY reads.
	readBufferSize = 8192
)

// PeerResolver looks up a peer's mesh IP from its peer ID.
// In production this is backed by the mesh routing table.
type PeerResolver interface {
	// ResolvePeerMeshIP returns the mesh IP for the given peer ID.
	ResolvePeerMeshIP(peerID string) (string, error)
}

// Hub manages all active WebSSH sessions. It enforces the max-sessions
// limit and provides goroutine-per-session lifecycle management.
//
// Each session runs two goroutines:
//  1. wsToSSH: reads WebSocket messages → writes to SSH stdin / handles resize
//  2. sshToWS: reads SSH stdout → writes as output messages to WebSocket
//
// When either goroutine exits, the session is torn down: SSH connection
// closed, PTY killed, WebSocket closed. This guarantees no zombie PTYs
// or SSH connections survive a WebSocket disconnect.
type Hub struct {
	mu          sync.Mutex
	sessions    map[string]*Session
	maxSessions int

	// Dependencies (injected)
	sshClient  *SSHClient
	resolver   PeerResolver
	sshPort    int

	// Timeouts
	readDeadline  time.Duration
	writeDeadline time.Duration

	// WebSocket upgrader
	upgrader *websocket.Upgrader
}

// NewHub creates a session hub.
func NewHub(sshClient *SSHClient, resolver PeerResolver, sshPort int, maxSessions int, readDeadline, writeDeadline time.Duration) *Hub {
	return &Hub{
		sessions:      make(map[string]*Session),
		maxSessions:   maxSessions,
		sshClient:     sshClient,
		resolver:      resolver,
		sshPort:       sshPort,
		readDeadline:  readDeadline,
		writeDeadline: writeDeadline,
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  readBufferSize,
			WriteBufferSize: writeBufferSize,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
}

// Upgrader returns the WebSocket upgrader for use by HTTP handlers.
func (h *Hub) Upgrader() *websocket.Upgrader { return h.upgrader }

// SessionCount returns the number of active sessions.
func (h *Hub) SessionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

// Session represents a single WebSSH terminal session.
type Session struct {
	ID          string
	PeerID      string
	MeshIP      string
	ws          *websocket.Conn
	remote      *RemoteSession
	hub         *Hub
	cancel      context.CancelFunc
	closeOnce   sync.Once
	mu          sync.Mutex
	cols        int
	rows        int
}

// HandleWebSocket upgrades the HTTP connection to a WebSocket and starts
// a terminal session to the specified peer.
//
// peerID: the target node's WireGuard public key (hex)
// cols, rows: initial terminal dimensions
func (h *Hub) HandleWebSocket(ctx context.Context, ws *websocket.Conn, peerID string, cols, rows int) {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	sess := &Session{
		ID:     generateSessionID(),
		PeerID: peerID,
		ws:     ws,
		hub:    h,
		cols:   cols,
		rows:   rows,
	}

	// Enforce max sessions
	h.mu.Lock()
	if len(h.sessions) >= h.maxSessions {
		h.mu.Unlock()
		h.sendError(ws, "maximum concurrent sessions reached")
		ws.Close()
		return
	}
	h.sessions[sess.ID] = sess
	h.mu.Unlock()

	// Ensure cleanup on exit
	defer func() {
		h.removeSession(sess.ID)
		sess.close()
	}()

	// Send "connecting" status
	h.sendStatus(ws, StatusConnecting, fmt.Sprintf("Connecting to %s…", shortID(peerID)))

	// Resolve peer mesh IP
	meshIP, err := h.resolver.ResolvePeerMeshIP(peerID)
	if err != nil {
		h.sendError(ws, fmt.Sprintf("cannot resolve peer %s: %v", shortID(peerID), err))
		return
	}
	sess.MeshIP = meshIP

	// Connect to target SSH server over mesh
	dialCtx, dialCancel := context.WithTimeout(ctx, h.sshClient.dialTimeout)
	defer dialCancel()

	remote, err := h.sshClient.Connect(dialCtx, meshIP, h.sshPort, cols, rows, "xterm-256color")
	if err != nil {
		h.sendError(ws, fmt.Sprintf("cannot connect to %s: %v", meshIP, err))
		return
	}
	sess.remote = remote

	// Send "connected" status
	connectedMsg, _ := NewConnectedMessage(peerID, meshIP, cols, rows)
	h.safeWrite(ws, connectedMsg)

	h.sendStatus(ws, StatusConnected, fmt.Sprintf("Connected to %s via mesh", shortID(peerID)))

	// Run the bridge
	sessionCtx, cancel := context.WithCancel(ctx)
	sess.cancel = cancel
	defer cancel()

	h.bridge(sessionCtx, sess)
}

// bridge runs the two-goroutine pump: WebSocket→SSH and SSH→WebSocket.
// When either side closes, the session is torn down.
func (h *Hub) bridge(ctx context.Context, sess *Session) {
	done := make(chan struct{}, 2)

	// wsToSSH: read WebSocket messages, dispatch to SSH stdin / resize
	go func() {
		defer func() { done <- struct{}{} }()
		h.wsToSSH(ctx, sess)
	}()

	// sshToWS: read SSH stdout, write as output messages to WebSocket
	go func() {
		defer func() { done <- struct{}{} }()
		h.sshToWS(ctx, sess)
	}()

	// Wait for either side to finish, then cleanup
	<-done
	sess.close()
}

// wsToSSH reads WebSocket messages and dispatches them:
//   - input: base64-encoded keystrokes → SSH stdin
//   - resize: {cols, rows} → SSH window-change (SIGWINCH)
//   - clipboard: paste content → SSH stdin
//   - close: explicit close → terminate session
func (h *Hub) wsToSSH(ctx context.Context, sess *Session) {
	stdin := sess.remote.StdinPipe()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sess.ws.SetReadDeadline(time.Now().Add(h.readDeadline))
		_, raw, err := sess.ws.ReadMessage()
		if err != nil {
			return
		}

		msg, err := DecodeMessage(raw)
		if err != nil {
			continue
		}

		switch msg.Type {
		case MsgInput:
			data, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				continue
			}
			stdin.Write(data)

		case MsgClipboard:
			// Clipboard paste: write to shell stdin
			data, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				continue
			}
			stdin.Write(data)

		case MsgResize:
			cols, rows, err := ParseResize(msg.Data)
			if err != nil {
				continue
			}
			sess.mu.Lock()
			sess.cols = cols
			sess.rows = rows
			sess.mu.Unlock()
			sess.remote.Resize(cols, rows)

		case MsgClose:
			return
		}
	}
}

// sshToWS reads SSH stdout and sends output messages to the WebSocket.
func (h *Hub) sshToWS(ctx context.Context, sess *Session) {
	stdout := sess.remote.StdoutPipe()

	buf := make([]byte, readBufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := stdout.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			msg, _ := NewOutputMessage(data)
			sess.ws.SetWriteDeadline(time.Now().Add(h.writeDeadline))
			if err := sess.ws.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				// Connection lost — send disconnect status
				h.sendStatus(sess.ws, StatusDisconnected, "Connection lost")
			} else {
				h.sendStatus(sess.ws, StatusDisconnected, "Session ended")
			}
			return
		}
	}
}

// sendStatus sends a status bar update to the WebSocket.
func (h *Hub) sendStatus(ws *websocket.Conn, status SessionStatus, message string) {
	msg, _ := NewStatusMessage(status, message)
	h.safeWrite(ws, msg)
}

// sendError sends a fatal error message to the WebSocket.
func (h *Hub) sendError(ws *websocket.Conn, message string) {
	msg, _ := NewErrorMessage(message)
	h.safeWrite(ws, msg)
}

// safeWrite writes a message to the WebSocket, ignoring errors (best-effort).
func (h *Hub) safeWrite(ws *websocket.Conn, msg []byte) {
	ws.SetWriteDeadline(time.Now().Add(h.writeDeadline))
	ws.WriteMessage(websocket.TextMessage, msg)
}

// removeSession removes a session from the hub's map.
func (h *Hub) removeSession(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, id)
}

// CloseAll closes all active sessions. Used for graceful shutdown.
func (h *Hub) CloseAll() {
	h.mu.Lock()
	sessions := make([]*Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()

	for _, s := range sessions {
		s.close()
	}
}

// close tears down the session: closes SSH connection and WebSocket.
func (s *Session) close() {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.remote != nil {
			s.remote.Close()
		}
		if s.ws != nil {
			s.ws.Close()
		}
	})
}

// generateSessionID generates a short hex session ID.
func generateSessionID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// shortID returns a truncated peer ID for display (first 8 chars or full if shorter).
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// ParseRequest extracts peer_id, cols, rows from WebSocket query params.
// Returns peerID, cols, rows, error.
type WSRequest struct {
	PeerID string
	Cols   int
	Rows   int
}

// PinnedHostKey returns a HostKeyCallback that accepts only the given public key.
// This prevents MITM attacks after the first connection.
func PinnedHostKey(pinnedKey []byte) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, remote ssh.PublicKey) error {
		remoteBytes := remote.Marshal()
		if len(remoteBytes) != len(pinnedKey) {
			return fmt.Errorf("host key mismatch: expected %d bytes, got %d", len(pinnedKey), len(remoteBytes))
		}
		for i := range pinnedKey {
			if pinnedKey[i] != remoteBytes[i] {
				return fmt.Errorf("host key mismatch: key fingerprint differs")
			}
		}
		return nil
	}
}
