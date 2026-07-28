// Package handshake provides the Layer 1 transport contract for MeshDesk v2.
//
// The HandshakeLayer interface is frozen — implementations may be added
// (TCP Reality, QUIC Reality) but the interface itself does not change.
//
// The HandshakeLayer establishes encrypted, authenticated byte streams
// between mesh nodes. The returned net.Conn carries opaque application
// data — no transport metadata, no peer routing info.
package handshake

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// HandshakeLayer establishes encrypted connections between mesh nodes.
//
// Implementations:
//   - RealityHandshake (TCP): reuses reality_transport.go from v1, stripped
//     of WireGuard framing. TLS 1.3 + REALITY authentication over TCP.
//     Returns *tls.Conn (a net.Conn) indistinguishable from HTTPS.
//   - QUICHandshake (UDP, deferred): same interface, QUIC Short Header
//     packets with REALITY-style auth over UDP. Drop-in replacement.
//
// The returned net.Conn is the raw encrypted byte stream — the caller
// receives TLS application data (for TCP) or QUIC stream data (for UDP).
// No protocol framing, no transport metadata — just bytes.
type HandshakeLayer interface {
	// Connect establishes an outbound encrypted connection to addr.
	// addr format: "host:port" (e.g., "1.2.3.4:443").
	// The returned net.Conn is a bidirectional encrypted byte stream.
	// Context cancellation aborts the connection attempt.
	Connect(ctx context.Context, addr string) (net.Conn, error)

	// Listen starts an inbound listener on addr.
	// addr format: "host:port" (e.g., "0.0.0.0:443").
	// The returned net.Listener produces net.Conn values from Accept().
	// Context cancellation closes the listener.
	Listen(ctx context.Context, addr string) (net.Listener, error)

	// Close shuts down the handshake layer and releases all resources
	// (listeners, etc.). It is idempotent.
	Close() error
}

// HandshakeConfig configures a HandshakeLayer implementation.
// Only fields relevant to the handshake itself — no peer management,
// no connection limits, no health probes.
type HandshakeConfig struct {
	// ListenAddr is the address for Listen(). Default: "0.0.0.0:443".
	ListenAddr string

	// DialTimeout is the max time for Connect to establish. Default: 30s.
	DialTimeout time.Duration

	// ── Reality-specific fields ──────────────────────────────────────

	// RealityDest is the camouflage target (e.g., "www.apple.com:443").
	RealityDest string

	// RealityPrivateKey is the X25519 private key (hex) for server-side.
	RealityPrivateKey string

	// RealityPublicKey is the X25519 public key (hex) for client-side.
	RealityPublicKey string

	// RealityShortID is the per-client short ID (hex, max 8 bytes).
	RealityShortID string

	// RealityServerNames is the list of accepted SNI values for server-side.
	RealityServerNames []string

	// ServerName is the SNI hostname sent in the TLS ClientHello (client-side).
	// If empty, the host portion of the connect address is used.
	ServerName string

	// TLSFingerprint is the uTLS ClientHello fingerprint to mimic.
	// Default: "chrome".
	TLSFingerprint string
}

// HandshakeError classifies connect/listen errors.
// Preserved from v1 TransportError — renamed to avoid confusion.
type HandshakeError struct {
	Op    string // "connect" or "listen"
	Addr  string // target address
	Err   error  // underlying error
	Retry bool   // true = transient, may succeed on retry
}

func (e *HandshakeError) Error() string {
	s := e.Op
	if e.Addr != "" {
		s += " " + e.Addr
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *HandshakeError) Unwrap() error { return e.Err }

// IsRetryable returns true if the error is transient and a retry may succeed.
func (e *HandshakeError) IsRetryable() bool { return e.Retry }

// NewHandshakeError creates a classified handshake error.
func NewHandshakeError(op, addr string, err error, retryable bool) *HandshakeError {
	return &HandshakeError{
		Op:    op,
		Addr:  addr,
		Err:   err,
		Retry: retryable,
	}
}

// ConfigError is returned when HandshakeConfig is invalid.
// It is always a permanent error — fix the config, retrying won't help.
type ConfigError struct {
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return "invalid handshake config field " + e.Field + ": " + e.Reason
}

// ErrShutdown is returned when attempting to use a HandshakeLayer after
// Close has been called.
var ErrShutdown = &HandshakeError{
	Op:  "shutdown",
	Err: errors.New("handshake layer has been shut down"),
}

// isTransientError classifies an error as transient (retry-able) or permanent.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
		if netErr.Temporary() {
			return true
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsNotFound == false
	}
	return true
}

// fmtAddr ensures an address always has a host:port format.
func fmtAddr(addr string) string {
	if addr == "" {
		return "(unknown)"
	}
	return addr
}

// ensureErr wraps a nil error as nil (no-op) to avoid wrapping nils.
func ensureErr(err error) error {
	if err == nil {
		return fmt.Errorf("unknown error")
	}
	return err
}
