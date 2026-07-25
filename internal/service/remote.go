package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
)

// DefaultServicePort is the mesh-internal port for the service management RPC.
// It listens on the mesh VPN and accepts service commands from authorized peers.
const DefaultServicePort = 4192

// ServiceRequest is a JSON command sent from the web server to a remote node.
type ServiceRequest struct {
	PeerID     string `json:"peer_id"`          // caller's peer ID (for capability checks)
	Action     string `json:"action"`           // "start", "stop", "restart", "status", "list"
	Service    string `json:"service"`          // service name (empty for "list")
	FollowLogs bool   `json:"follow,omitempty"` // for "logs" action
}

// ServiceResponse is the JSON response from the remote node.
type ServiceResponse struct {
	OK      bool            `json:"ok"`
	Message string          `json:"message,omitempty"`
	Status  *ServiceStatus  `json:"status,omitempty"`
	List    []ServiceStatus `json:"list,omitempty"`
}

// RemoteClient calls service management operations on a remote mesh node.
// It dials the target node's mesh IP on the service RPC port and sends
// a JSON request, then reads the JSON response.
type RemoteClient struct {
	dialer  MeshDialer
	port    int
	timeout time.Duration
}

// MeshDialer abstracts mesh-internal dialing. In production this wraps
// mesh.MeshNode.Dial(). The interface allows testing without a real mesh.
type MeshDialer interface {
	DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error)
}

// NewRemoteClient creates a client for remote service management.
func NewRemoteClient(dialer MeshDialer, port int, timeout time.Duration) *RemoteClient {
	if port == 0 {
		port = DefaultServicePort
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &RemoteClient{dialer: dialer, port: port, timeout: timeout}
}

// Call sends a service request to a remote node and returns the response.
func (c *RemoteClient) Call(ctx context.Context, peerID string, req *ServiceRequest) (*ServiceResponse, error) {
	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := c.dialer.DialMesh(dialCtx, peerID, c.port)
	if err != nil {
		return nil, fmt.Errorf("dial peer %s: %w", peerID, err)
	}
	defer conn.Close()

	// Set deadline on the connection
	if nc, ok := conn.(interface{ SetDeadline(t time.Time) error }); ok {
		nc.SetDeadline(time.Now().Add(c.timeout))
	}

	// Send request as framed JSON
	if err := writeFramedJSON(conn, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// Read response as framed JSON
	resp, err := readFramedSvcJSON[ServiceResponse](conn)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}

// RemoteServer listens on a mesh-internal port and handles incoming service
// management requests. If an authEngine is provided, each request is wrapped
// in an AuthorizedServiceManager scoped to the caller's PeerID so that
// capability checks are enforced per-peer. If no authEngine is set
// (testing/development mode), the raw ServiceManager is used directly.
type RemoteServer struct {
	mgr        ServiceManager
	listener   MeshListener
	port       int
	authEngine *auth.CapabilityEngine

	stopCh chan struct{}
}

// MeshListener abstracts mesh-internal listening (for the server side).
type MeshListener interface {
	ListenMesh(port int) (net.Listener, error)
}

// NewRemoteServer creates a server that accepts service management RPC calls
// on the mesh. The provided ServiceManager is used directly without
// capability enforcement — use NewRemoteServerWithAuth for per-peer auth.
func NewRemoteServer(mgr ServiceManager, listener MeshListener, port int) *RemoteServer {
	if port == 0 {
		port = DefaultServicePort
	}
	return &RemoteServer{
		mgr:      mgr,
		listener: listener,
		port:     port,
		stopCh:   make(chan struct{}),
	}
}

// NewRemoteServerWithAuth creates a server that enforces per-peer capability
// checks. Each incoming request's PeerID field is used to construct an
// AuthorizedServiceManager, so capability checks are scoped to the caller.
// The underlying ServiceManager should be the raw (non-authorized) backend.
func NewRemoteServerWithAuth(mgr ServiceManager, engine *auth.CapabilityEngine, listener MeshListener, port int) *RemoteServer {
	if port == 0 {
		port = DefaultServicePort
	}
	return &RemoteServer{
		mgr:        mgr,
		listener:   listener,
		port:       port,
		authEngine: engine,
		stopCh:     make(chan struct{}),
	}
}

// Start begins accepting connections on the mesh port.
func (s *RemoteServer) Start() error {
	ln, err := s.listener.ListenMesh(s.port)
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", s.port, err)
	}

	go func() {
		<-s.stopCh
		ln.Close()
	}()

	go s.acceptLoop(ln)
	return nil
}

// Stop halts the server.
func (s *RemoteServer) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *RemoteServer) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}
		go s.handleConn(conn)
	}
}

func (s *RemoteServer) handleConn(conn net.Conn) {
	defer conn.Close()

	// Set a generous deadline for the full operation
	if nc, ok := conn.(interface{ SetDeadline(t time.Time) error }); ok {
		nc.SetDeadline(time.Now().Add(60 * time.Second))
	}

	// Read request
	req, err := readFramedSvcJSON[ServiceRequest](conn)
	if err != nil {
		writeFramedJSON(conn, &ServiceResponse{OK: false, Message: fmt.Sprintf("read request: %v", err)})
		return
	}

	// If auth is enabled, wrap the backend in an AuthorizedServiceManager
	// scoped to the caller's PeerID for per-request capability enforcement.
	mgr := s.mgr
	if s.authEngine != nil {
		if req.PeerID == "" {
			writeFramedJSON(conn, &ServiceResponse{OK: false, Message: "unauthorized: missing peer_id in request"})
			return
		}
		mgr = NewAuthorizedServiceManager(s.mgr, s.authEngine, req.PeerID)
	}

	// Execute the request
	resp := s.execute(mgr, req)

	// Send response
	writeFramedJSON(conn, resp)
}

func (s *RemoteServer) execute(mgr ServiceManager, req *ServiceRequest) *ServiceResponse {
	switch req.Action {
	case "start":
		if err := mgr.Start(req.Service); err != nil {
			return &ServiceResponse{OK: false, Message: err.Error()}
		}
		return &ServiceResponse{OK: true, Message: "started"}

	case "stop":
		if err := mgr.Stop(req.Service); err != nil {
			return &ServiceResponse{OK: false, Message: err.Error()}
		}
		return &ServiceResponse{OK: true, Message: "stopped"}

	case "restart":
		if err := mgr.Restart(req.Service); err != nil {
			return &ServiceResponse{OK: false, Message: err.Error()}
		}
		return &ServiceResponse{OK: true, Message: "restarted"}

	case "status":
		st, err := mgr.Status(req.Service)
		if err != nil {
			return &ServiceResponse{OK: false, Message: err.Error()}
		}
		return &ServiceResponse{OK: true, Status: st}

	case "list":
		list, err := mgr.List()
		if err != nil {
			return &ServiceResponse{OK: false, Message: err.Error()}
		}
		return &ServiceResponse{OK: true, List: list}

	default:
		return &ServiceResponse{OK: false, Message: fmt.Sprintf("unknown action: %s", req.Action)}
	}
}

// --- Framed JSON helpers (shared between client and server) ---

func writeFramedJSON(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readFramedSvcJSON[T any](r io.Reader) (*T, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if length > 1<<20 { // 1 MB max
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var result T
	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &result, nil
}
