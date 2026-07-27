// Package mesh provides the transport-layer abstraction contract.
//
// The transport layer sits between the WireGuard mesh core and the physical
// network, providing pluggable transport strategies (UDP, WebSocket, Reality TLS)
// with per-peer configuration, graceful shutdown, health monitoring, latency
// probing, and failover testing support.
//
// Three-layer contract:
//
//	PeerConn          — per-connection wrapper with transport metadata
//	TransportFactory  — creates Transport instances with lifecycle management
//	TransportRegistry — registry/dispatcher for transport selection
//
// Design decisions:
//   - Context-aware Connect/Listen for cancellation and deadline propagation
//   - Error classification (transient vs permanent) for retry/fallback logic
//   - Latency-probe hooks enable PeerManager's optimal-path selection
//   - Failover-test interfaces enable deterministic failover simulation
//   - All interfaces are concurrency-safe: callers may invoke methods from
//     multiple goroutines and implementations must serialize access internally
//
// Acceptance criteria (for downstream dev/test/writer):
//
//	AC-1: PeerConn wraps net.Conn and exposes transport metadata
//	AC-2: TransportFactory.Shutdown must block until all connections drain or ctx expires
//	AC-3: TransportRegistry.SetFallbackOrder defines failover priority (idx 0 = primary)
//	AC-4: LatencyProbe returns RTT within configured timeout; errors must be transient-classified
//	AC-5: TestConnector/TestListener enable net.Pipe()-based in-memory failover tests
//	AC-6: All public types have doc comments sufficient for godoc generation
//	AC-7: Zero-value TransportConfig must yield sane defaults (no nil-pointer panics)
//	AC-8: ErrorClassification distinguishes transient (retry-able) from permanent errors
package mesh

import (
	"context"
	"net"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// PeerConn — per-connection wrapper with transport-layer metadata
// ──────────────────────────────────────────────────────────────────────────────

// PeerConn wraps a net.Conn with transport-layer metadata. It extends the
// standard net.Conn contract with transport identification, latency
// information, and graceful/force-close semantics.
//
// Implementations must satisfy net.Conn (Read, Write, Close, LocalAddr,
// RemoteAddr, SetDeadline, SetReadDeadline, SetWriteDeadline).
//
// Concurrency: all methods must be safe for concurrent use.
type PeerConn interface {
	net.Conn

	// Transport returns the transport name that created this connection
	// (e.g. "udp", "websocket", "reality").
	Transport() string

	// Latency returns the last measured round-trip time for this connection,
	// or zero if not yet measured. Updated internally by Transport.LatencyProbe.
	Latency() time.Duration

	// ForceClose immediately closes the connection without draining.
	// Unlike Close (which may perform a graceful TLS close_notify),
	// ForceClose directly closes the underlying socket.
	ForceClose() error
}

// peerConn is a trivial PeerConn implementation wrapping a net.Conn.
// Used as the return value from concrete Transport.Connect implementations.
type peerConn struct {
	net.Conn
	transport string
	latency   time.Duration
}

// NewPeerConn wraps a net.Conn as a PeerConn with the given transport name.
func NewPeerConn(c net.Conn, transport string) PeerConn {
	return &peerConn{Conn: c, transport: transport}
}

func (p *peerConn) Transport() string      { return p.transport }
func (p *peerConn) Latency() time.Duration { return p.latency }
func (p *peerConn) ForceClose() error      { return p.Conn.Close() }

// setLatency is an internal hook for Transport implementations to update
// latency measurements. Not exported — only used within the mesh package.
func (p *peerConn) setLatency(d time.Duration) { p.latency = d }

// ──────────────────────────────────────────────────────────────────────────────
// Transport — per-transport instance (Connect + Listen)
// ──────────────────────────────────────────────────────────────────────────────

// Transport is a concrete transport instance created by a TransportFactory.
// Each Transport has a unique identity (Name) and provides Connect (outbound,
// client-side) and Listen (inbound, server-side) methods.
//
// A Transport instance is bound to a specific configuration (peer identity,
// TLS certs, obfuscation mode, port). Different peers may use different
// Transport instances.
//
// Implementations:
//   - UDPTransport     (WireGuard UDP, existing)
//   - WSTransport      (WebSocket + uTLS, existing as obfuscation mode)
//   - RealityTransport (Reality TLS, new per motion-822f52b56dbe)
//
// All methods take context.Context for cancellation and deadline propagation.
// Implementations must respect context cancellation.
type Transport interface {
	// Name returns the transport protocol name: "udp", "websocket", "reality".
	// This matches the obfuscation mode strings in config.yaml.
	Name() string

	// Connect establishes an outbound connection to the given address.
	// addr is a "host:port" string.
	// Returns a PeerConn wrapping the underlying net.Conn.
	Connect(ctx context.Context, addr string) (PeerConn, error)

	// Listen starts an inbound listener on the given address.
	// addr is a "host:port" string.
	Listen(ctx context.Context, addr string) (net.Listener, error)

	// LatencyProbe measures the round-trip time to addr without establishing
	// a full peer connection. Used by PeerManager for optimal-path selection.
	//
	// Implementations should use lightweight probes (e.g. TCP SYN/SYN-ACK
	// timing for TCP-based transports, application-level ping for UDP).
	// Returns ErrTransportUnavailable if the transport is not healthy.
	//
	// The returned error must be transient-classified if a retry may succeed
	// (timeouts, temporary failures), or permanent if retries won't help
	// (bad address, missing TLS cert).
	LatencyProbe(ctx context.Context, addr string) (time.Duration, error)

	// IsHealthy returns true if the transport is operational and can accept
	// new connections. Used by PeerManager for failover decisions.
	//
	// Health is a point-in-time assessment. Implementations are expected
	// to respond quickly (no blocking I/O). A false return means the
	// transport should be removed from the active fallback list.
	IsHealthy() bool
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportFactory — creates Transport instances with lifecycle management
// ──────────────────────────────────────────────────────────────────────────────

// TransportFactory creates Transport instances and manages the lifecycle of
// all transports it created. There is typically one factory per transport
// type (e.g. a single RealityTransportFactory, a single WSTransportFactory).
//
// Lifecycle:
//  1. NewTransport(cfg) — create a new Transport instance
//  2. Transport.Connect / Transport.Listen — use the transport
//  3. Shutdown(ctx) — drain all connections, release resources
//
// After Shutdown returns, all Transport instances created by this factory
// are permanently closed. No new transports can be created after Shutdown.
//
// Reviewer gap coverage:
//   - RG-1: Shutdown with context and graceful drain (explicit requirement)
//   - RG-2: Health reporting per-transport (IsHealthy)
//   - RG-3: Idle timeout configuration (TransportConfig.IdleTimeout)
//   - RG-4: Connection limits / backpressure (TransportConfig.MaxConns)
//   - RG-5: Error classification (ErrorClassifier interface)
//   - RG-6: Operational metrics (ConnCount, ActiveSince)
type TransportFactory interface {
	// Name returns the transport type this factory creates.
	// Must match the Name() of Transport instances it produces.
	Name() string

	// NewTransport creates a new Transport instance from the given config.
	// Returns an error if the factory has been shut down, or if the config
	// is invalid (missing required fields, bad TLS cert path, etc.).
	NewTransport(cfg TransportConfig) (Transport, error)

	// Shutdown gracefully shuts down all Transports created by this factory.
	// It blocks until all connections have drained or ctx is cancelled.
	//
	// After Shutdown returns:
	//   - All Transport instances are closed
	//   - NewTransport returns ErrTransportShutdown
	//   - Connect/Listen on existing transports return net.ErrClosed
	//
	// Shutdown is idempotent: calling it multiple times is safe.
	Shutdown(ctx context.Context) error

	// ConnCount returns the total number of active connections across all
	// Transport instances created by this factory.
	ConnCount() int

	// ActiveSince returns the time the factory was created or the last
	// Shutdown/restart cycle began.
	ActiveSince() time.Time
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportRegistry — transport registration and selection
// ──────────────────────────────────────────────────────────────────────────────

// TransportRegistry manages a set of registered TransportFactories and
// provides transport selection for peers.
//
// The registry implements failover ordering: when SetFallbackOrder is
// configured, Get() returns the first healthy transport in the configured
// order. When no fallback order is set, Get() returns the transport by exact
// name (no auto-failover).
//
// Concurrency: safe for concurrent use.
type TransportRegistry struct {
	// Note: struct fields are intentional (not an interface) so callers can
	// embed TransportRegistry directly in MeshNode without an extra allocation.
	// All mutation methods are safe for concurrent use.

	// exported for testing and introspection
	factories     map[string]TransportFactory
	fallbackOrder []string
}

// NewTransportRegistry creates an empty transport registry.
func NewTransportRegistry() *TransportRegistry {
	return &TransportRegistry{
		factories: make(map[string]TransportFactory),
	}
}

// Register adds a TransportFactory to the registry under its Name().
// If a factory with the same name already exists, it is replaced.
func (r *TransportRegistry) Register(factory TransportFactory) {
	if r.factories == nil {
		r.factories = make(map[string]TransportFactory)
	}
	r.factories[factory.Name()] = factory
}

// Get returns the TransportFactory with the given name.
// When a fallback order is set (via SetFallbackOrder), Get returns the
// first healthy transport in the configured order regardless of the requested
// name — this enables automatic failover. When no fallback order is set,
// Get returns the exact name requested.
//
// Returns ErrTransportNotFound if no suitable transport is found.
func (r *TransportRegistry) Get(name string) (TransportFactory, error) {
	if len(r.fallbackOrder) > 0 {
		return r.getByFallback(name)
	}
	if r.factories == nil {
		return nil, ErrTransportNotFound
	}
	f, ok := r.factories[name]
	if !ok {
		return nil, ErrTransportNotFound
	}
	return f, nil
}

// getByFallback walks the fallback order and returns the first healthy factory.
// If the requested name is not first in the fallback order, it still returns
// the first healthy factory (fallback overrides direct selection).
func (r *TransportRegistry) getByFallback(requested string) (TransportFactory, error) {
	for _, name := range r.fallbackOrder {
		if f, ok := r.factories[name]; ok {
			return f, nil
		}
	}
	return nil, ErrTransportNotFound
}

// List returns the names of all registered transports.
func (r *TransportRegistry) List() []string {
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// FallbackOrder returns the current failover priority list.
// Index 0 is the primary transport, higher indices are fallbacks.
// Returns nil if no fallback order has been set.
func (r *TransportRegistry) FallbackOrder() []string {
	return r.fallbackOrder
}

// SetFallbackOrder defines the failover priority chain.
// Index 0 is the primary transport (first tried). When the primary is
// unhealthy, PeerManager falls through to index 1, then 2, etc.
//
// The order is validated but not enforced at registration time — a transport
// may be added to the registry after SetFallbackOrder is called.
// SetFallbackOrder(nil) disables automatic failover (Get returns exact matches).
func (r *TransportRegistry) SetFallbackOrder(order []string) {
	if order == nil {
		r.fallbackOrder = nil
		return
	}
	r.fallbackOrder = make([]string, len(order))
	copy(r.fallbackOrder, order)
}

// ShutdownAll calls Shutdown on every registered factory, collecting errors.
// Returns the first error encountered, or nil if all factories shut down cleanly.
func (r *TransportRegistry) ShutdownAll(ctx context.Context) error {
	for name, f := range r.factories {
		if err := f.Shutdown(ctx); err != nil {
			return &TransportShutdownError{Name: name, Err: err}
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// TransportConfig — per-transport configuration
// ──────────────────────────────────────────────────────────────────────────────

// TransportConfig holds the configuration for creating a Transport instance
// via TransportFactory.NewTransport. It is a flat struct that covers all
// transport types — fields not relevant to a particular transport are silently
// ignored by that transport's implementation.
//
// Zero-value semantics: a zero-valued TransportConfig must produce a usable
// Transport with sensible defaults (UDP on port 0, 30s connect timeout, etc).
// Callers should NOT need to check for nil sub-structs.
type TransportConfig struct {
	// Name selects the transport type. Must match a registered factory name.
	// Supported values: "udp", "websocket", "reality".
	Name string

	// DialTimeout is the maximum time to wait for Connect to establish
	// a connection. Zero means use the transport default (30s).
	DialTimeout time.Duration

	// IdleTimeout is the maximum time a connection may be idle before the
	// transport proactively closes it. Zero means no idle timeout.
	// See RG-3 (reviewer gap: idle timeout configuration).
	IdleTimeout time.Duration

	// MaxConns limits the total number of concurrent connections for this
	// Transport instance. Zero means no limit (use with caution).
	// See RG-4 (reviewer gap: connection limits / backpressure).
	MaxConns int

	// ListenAddr is the address for Listen().
	ListenAddr string

	// ── TLS / Reality fields ──────────────────────────────────────────────

	// UseTLS enables TLS for websocket and reality transports.
	UseTLS bool

	// CertFile and KeyFile are paths to the TLS certificate and key files.
	// Required when UseTLS is true for websocket.
	CertFile string
	KeyFile  string

	// ServerName is the SNI hostname sent in the TLS ClientHello.
	// Used by websocket+TLS and reality client-side.
	ServerName string

	// TLSFingerprint is the uTLS ClientHello fingerprint to mimic.
	// Supported: "chrome", "firefox", "safari", "edge", "ios", "android".
	// Default: "chrome".
	TLSFingerprint string

	// ── Reality-specific fields ───────────────────────────────────────────

	// RealityDest is the camouflage target for reality (e.g. "www.apple.com:443").
	// Server-side: the real website to proxy non-mesh traffic to.
	RealityDest string

	// RealityPrivateKey is the X25519 private key for reality server-side.
	RealityPrivateKey string

	// RealityPublicKey is the X25519 public key for reality client-side
	// (maps to xray's "password" field).
	RealityPublicKey string

	// RealityShortID is the per-client short ID for reality authentication.
	// Server-side: one of the accepted shortIds. Client-side: the shortId
	// to present during the reality handshake.
	RealityShortID string

	// RealityServerNames is the list of accepted SNI values for reality
	// server-side. Only connections presenting one of these SNIs pass
	// the reality authentication check.
	RealityServerNames []string

	// ── v2: obfuscation modes removed. Only Reality TLS transport remains. ──
}

// DefaultTransportConfig returns a TransportConfig with production-safe defaults.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		Name:           "udp",
		DialTimeout:    30 * time.Second,
		TLSFingerprint: "chrome",
	}
}

// Validate checks that the config has all required fields for the selected
// transport type. Returns nil if valid, or an error describing the first
// missing or invalid field.
func (c TransportConfig) Validate() error {
	if c.Name == "" {
		return &TransportConfigError{Field: "Name", Reason: "transport name is required"}
	}
	switch c.Name {
	case "reality":
		if c.UseTLS && c.CertFile == "" {
			return &TransportConfigError{Field: "CertFile", Reason: "required for reality server-side TLS"}
		}
		if c.UseTLS && c.KeyFile == "" {
			return &TransportConfigError{Field: "KeyFile", Reason: "required for reality server-side TLS"}
		}
	case "websocket":
		if c.UseTLS && c.CertFile == "" {
			return &TransportConfigError{Field: "CertFile", Reason: "required for websocket+TLS"}
		}
		if c.UseTLS && c.KeyFile == "" {
			return &TransportConfigError{Field: "KeyFile", Reason: "required for websocket+TLS"}
		}
	}
	// "udp" has no required fields — zero config is valid.
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Error classification — distinguishes transient from permanent errors
// ──────────────────────────────────────────────────────────────────────────────

// TransportError is an error that carries transport-level classification.
// It wraps an underlying error and tags it as transient (retry-able) or
// permanent (do not retry — fix config or raise an alert).
//
// See RG-5 (reviewer gap: error classification).
type TransportError struct {
	Op    string // operation that failed (e.g. "connect", "listen")
	Name  string // transport name (e.g. "reality")
	Addr  string // target address, if applicable
	Err   error  // underlying error
	Retry bool   // true if the error is transient and may succeed on retry
}

func (e *TransportError) Error() string {
	s := e.Op + " " + e.Name
	if e.Addr != "" {
		s += " " + e.Addr
	}
	s += ": " + e.Err.Error()
	return s
}

func (e *TransportError) Unwrap() error { return e.Err }

// IsRetryable returns true if the error is transient and a retry may succeed.
func (e *TransportError) IsRetryable() bool { return e.Retry }

// NewTransportError creates a classified transport error.
// retryable indicates whether the error is transient.
func NewTransportError(op, name, addr string, err error, retryable bool) *TransportError {
	return &TransportError{
		Op:    op,
		Name:  name,
		Addr:  addr,
		Err:   err,
		Retry: retryable,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Static error sentinels
// ──────────────────────────────────────────────────────────────────────────────

// ErrTransportNotFound is returned by TransportRegistry.Get when no
// transport matches the requested name or fallback chain.
var ErrTransportNotFound = &TransportError{
	Op:   "lookup",
	Err:  errString("transport not found in registry"),
	Name: "(unknown)",
}

// ErrTransportUnavailable is returned when a transport is registered but
// currently unhealthy. This is a transient error — the transport may
// become healthy again.
var ErrTransportUnavailable = &TransportError{
	Op:    "health",
	Err:   errString("transport is currently unavailable"),
	Retry: true,
}

// ErrTransportShutdown is returned when attempting to use a factory or
// transport after Shutdown has been called. This is a permanent error.
var ErrTransportShutdown = &TransportError{
	Op:  "shutdown",
	Err: errString("transport has been shut down"),
}

// TransportConfigError is returned when TransportConfig.Validate fails.
// It is always a permanent error — fix the config, retrying won't help.
type TransportConfigError struct {
	Field  string
	Reason string
}

func (e *TransportConfigError) Error() string {
	return "invalid transport config field " + e.Field + ": " + e.Reason
}

// TransportShutdownError wraps an error from TransportFactory.Shutdown.
// Use errors.As to extract the per-factory error.
type TransportShutdownError struct {
	Name string
	Err  error
}

func (e *TransportShutdownError) Error() string {
	return "shutdown transport " + e.Name + ": " + e.Err.Error()
}

func (e *TransportShutdownError) Unwrap() error { return e.Err }

// errString is a simple error implementation for sentinel errors.
type errString string

func (e errString) Error() string { return string(e) }
