package xray

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// --- Constants ---

// DefaultHealthCheckInterval is how often the background health
// monitor polls xray-core's gRPC API port.
const DefaultHealthCheckInterval = 10 * time.Second

// DefaultHealthCheckTimeout is the per-probe connection timeout.
const DefaultHealthCheckTimeout = 3 * time.Second

// DefaultReadinessTimeout is how long Start() waits for xray-core
// to become healthy before returning an error. If xray doesn't pass
// a health check within this window, Start() returns an error
// (the process keeps running — the monitor will keep checking).
const DefaultReadinessTimeout = 15 * time.Second

// DefaultApiPort is the default gRPC API port for xray-core's
// internal API inbound (dokodemo-door). Chosen to avoid collision
// with common xray inbound ports.
const DefaultApiPort = 8421

// DefaultApiListen is the default listen address for the API inbound.
const DefaultApiListen = "127.0.0.1"

// h2Preface is the HTTP/2 connection preface that a client sends
// to initiate an HTTP/2 connection. gRPC runs over HTTP/2, so if
// xray-core's API port accepts a TCP connection and we can send
// this preface without error, the gRPC server is alive.
var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// h2SettingsFrame is a minimal HTTP/2 SETTINGS frame (empty, length 0).
// After the preface, the client must send a SETTINGS frame.
var h2SettingsFrame = []byte{
	0x00, 0x00, 0x00, // length: 0
	0x04,       // type: SETTINGS
	0x00,       // flags: none
	0x00, 0x00, 0x00, 0x00, // stream ID: 0
}

// --- HealthState ---

// HealthState represents the health status of the xray-core subprocess
// as determined by gRPC self-check.
type HealthState int

const (
	// HealthUnknown means no health check has been performed yet.
	HealthUnknown HealthState = iota
	// HealthHealthy means the last gRPC self-check succeeded.
	HealthHealthy
	// HealthUnhealthy means the last gRPC self-check failed.
	HealthUnhealthy
)

func (s HealthState) String() string {
	switch s {
	case HealthHealthy:
		return "healthy"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

func (s HealthState) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// HealthStatus is a snapshot of the xray-core health state,
// exposed via the API and used by the readiness gate.
type HealthStatus struct {
	State        HealthState `json:"state"`
	LastChecked  time.Time   `json:"last_checked,omitempty"`
	LastHealthy  time.Time   `json:"last_healthy,omitempty"`
	LastFailure  string      `json:"last_failure,omitempty"`
	CheckCount   int64       `json:"check_count"`
	FailureCount int64       `json:"failure_count"`
}

// --- HealthChecker ---

// HealthChecker probes xray-core's gRPC API port to determine
// whether the subprocess is truly ready to serve traffic.
//
// It uses a lightweight HTTP/2 preface exchange rather than
// full gRPC+protobuf. The rationale:
//   - gRPC runs over HTTP/2. If xray-core's API port accepts a
//     TCP connection and responds to the HTTP/2 preface, the
//     gRPC server is initialized and ready.
//   - This avoids adding google.golang.org/grpc and protobuf as
//     dependencies just for a liveness probe.
//   - The preface exchange is what every gRPC client does first;
//     a server that can't handle it is not ready.
type HealthChecker struct {
	mu sync.Mutex

	addr        string        // host:port of the gRPC API
	timeout     time.Duration // per-probe timeout
	lastStatus  HealthStatus
}

// NewHealthChecker creates a HealthChecker for the given address.
func NewHealthChecker(addr string, timeout time.Duration) *HealthChecker {
	if timeout <= 0 {
		timeout = DefaultHealthCheckTimeout
	}
	return &HealthChecker{
		addr:    addr,
		timeout: timeout,
		lastStatus: HealthStatus{
			State: HealthUnknown,
		},
	}
}

// Check performs a single health probe against the gRPC API port.
// Returns nil if healthy, or an error describing the failure.
//
// The probe:
//  1. Opens a TCP connection to the API port (with timeout).
//  2. Sends the HTTP/2 connection preface + an empty SETTINGS frame.
//  3. Reads back a SETTINGS frame from the server (any response
//     means the HTTP/2 endpoint is alive).
//  4. If both succeed, xray-core's gRPC API is ready.
func (h *HealthChecker) Check(ctx context.Context) error {
	dialer := net.Dialer{Timeout: h.timeout}

	conn, err := dialer.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return fmt.Errorf("dial gRPC API %s: %w", h.addr, err)
	}
	defer conn.Close()

	// Set write deadline
	_ = conn.SetWriteDeadline(time.Now().Add(h.timeout))

	// Send HTTP/2 preface
	if _, err := conn.Write(h2Preface); err != nil {
		return fmt.Errorf("send HTTP/2 preface: %w", err)
	}

	// Send empty SETTINGS frame
	if _, err := conn.Write(h2SettingsFrame); err != nil {
		return fmt.Errorf("send SETTINGS frame: %w", err)
	}

	// Set read deadline and read the server's response.
	// A gRPC (HTTP/2) server will respond with its own SETTINGS frame.
	_ = conn.SetReadDeadline(time.Now().Add(h.timeout))

	// Read at least the frame header (9 bytes).
	// We don't need to parse it — any response means the server
	// is alive and speaking HTTP/2.
	header := make([]byte, 9)
	n, err := readFull(conn, header)
	if err != nil {
		return fmt.Errorf("read HTTP/2 response: %w (read %d bytes)", err, n)
	}

	// Verify it looks like an HTTP/2 frame (type field at offset 3).
	// SETTINGS = 0x04, WINDOW_UPDATE = 0x08, etc.
	// Any valid frame type (1-12) means the server is speaking HTTP/2.
	frameType := header[3]
	if frameType == 0 || frameType > 12 {
		return fmt.Errorf("unexpected HTTP/2 frame type: %d", frameType)
	}

	return nil
}

// CheckAndUpdate performs a health check and updates the internal
// status. Returns the result.
func (h *HealthChecker) CheckAndUpdate(ctx context.Context) error {
	err := h.Check(ctx)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastStatus.CheckCount++
	h.lastStatus.LastChecked = time.Now()

	if err != nil {
		h.lastStatus.State = HealthUnhealthy
		h.lastStatus.FailureCount++
		h.lastStatus.LastFailure = err.Error()
	} else {
		h.lastStatus.State = HealthHealthy
		h.lastStatus.LastHealthy = time.Now()
		h.lastStatus.LastFailure = ""
	}

	return err
}

// Status returns the last known health status.
func (h *HealthChecker) Status() HealthStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastStatus
}

// IsHealthy returns true if the last health check succeeded.
func (h *HealthChecker) IsHealthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastStatus.State == HealthHealthy
}

// --- Helpers ---

// readFull reads exactly len(buf) bytes from conn.
// Returns the number of bytes read and any error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// formatAPIAddr formats host and port into a "host:port" string.
func formatAPIAddr(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// defaultAPIAddr returns the API address based on the listen address
// and port. If port is 0, the default is used.
func defaultAPIAddr(listen string, port int) string {
	if listen == "" {
		listen = DefaultApiListen
	}
	if port <= 0 {
		port = DefaultApiPort
	}
	return formatAPIAddr(listen, port)
}

// readFrameHeader reads a 9-byte HTTP/2 frame header from conn.
// Returns (length, type, flags, streamID, error).
func readFrameHeader(conn net.Conn) (uint32, byte, byte, uint32, error) {
	header := make([]byte, 9)
	if _, err := readFull(conn, header); err != nil {
		return 0, 0, 0, 0, err
	}
	// HTTP/2 frame length is 24-bit big-endian (3 bytes)
	length := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
	frameType := header[3]
	flags := header[4]
	// Stream ID is 32-bit, top bit reserved
	streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF
	return length, frameType, flags, streamID, nil
}

// logHealthChange logs a state transition if it's meaningful.
func logHealthChange(oldState, newState HealthState) {
	if oldState != newState {
		log.Printf("[xray] health state: %s → %s", oldState.String(), newState.String())
	}
}
