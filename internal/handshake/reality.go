// Package handshake provides the concrete RealityHandshake implementation
// of the HandshakeLayer interface. It reuses the REALITY TLS 1.3 handshake
// core from v1's reality_transport.go, stripped of WireGuard framing,
// factory, peer management, and health probes.
//
// Protocol summary (from xray-core transport/internet/reality/reality.go):
//
//  1. Client builds a uTLS UConn with the specified browser fingerprint.
//  2. BuildHandshakeState() prepares the ClientHello message.
//  3. SessionId[0:4] = xray version, SessionId[4:8] = unix timestamp,
//     SessionId[8:16] = shortId (client identity).
//  4. Client performs ECDH between its ephemeral key share (from the
//     ClientHello key_share extension) and the server's X25519 public key
//     to derive an auth key.
//  5. HKDF-SHA256(salt=ClientHello.Random[:20], ikm=authKey, info="REALITY")
//     produces the final auth key.
//  6. AES-GCM seals SessionId[:16] with nonce=Random[20:] and AAD=entire
//     ClientHello raw bytes, producing the authentication tag that replaces
//     SessionId[:16].
//  7. The modified ClientHello is sent to the server.
//  8. Server-side: reality.Server() processes the ClientHello, extracts the
//     key share, performs ECDH with its private key, derives the same auth
//     key, and verifies the AES-GCM authentication tag. If valid, the
//     connection is authenticated; if not, traffic is forwarded to dest.
package handshake

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"

	realitypkg "github.com/xtls/reality"
)

// ──────────────────────────────────────────────────────────────────────────────
// RealityHandshake — HandshakeLayer implementation for TCP Reality TLS
// ──────────────────────────────────────────────────────────────────────────────

// RealityHandshake implements HandshakeLayer over TCP with REALITY TLS 1.3
// authentication. It is the v2 replacement for v1's RealityTransport +
// RealityTransportFactory, stripped of WireGuard framing, connection limits,
// health probes, and latency measurement.
//
// One RealityHandshake instance per node — no factory pattern. The same
// instance handles both Connect (client-side) and Listen (server-side)
// using the keys in HandshakeConfig. A node typically has a server-side
// RealityPrivateKey (for Listen) and peers' RealityPublicKey (for Connect).
type RealityHandshake struct {
	cfg HandshakeConfig

	// closed is set when Close() is called.
	closed atomic.Bool

	// listeners tracks active listeners for graceful shutdown.
	mu        sync.Mutex
	listeners map[*realityListener]struct{}
}

// NewRealityHandshake creates a new RealityHandshake with the given config.
// Applies defaults for zero-value fields.
func NewRealityHandshake(cfg HandshakeConfig) *RealityHandshake {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	if cfg.TLSFingerprint == "" {
		cfg.TLSFingerprint = "chrome"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:443"
	}
	return &RealityHandshake{
		cfg:       cfg,
		listeners: make(map[*realityListener]struct{}),
	}
}

// Compile-time check: RealityHandshake satisfies HandshakeLayer.
var _ HandshakeLayer = (*RealityHandshake)(nil)

// Connect establishes an outbound Reality TLS connection to the given address.
// addr is a "host:port" string. The returned net.Conn is a *utls.UConn
// that has completed the REALITY handshake with the server.
//
// Context cancellation aborts the connection attempt.
func (h *RealityHandshake) Connect(ctx context.Context, addr string) (net.Conn, error) {
	if h.closed.Load() {
		return nil, NewHandshakeError("connect", addr, ErrShutdown, false)
	}

	// Validate required Reality fields.
	if h.cfg.RealityPublicKey == "" {
		return nil, NewHandshakeError("connect", addr,
			&ConfigError{Field: "RealityPublicKey", Reason: "required for reality client-side"}, false)
	}

	conn, err := h.dialReality(ctx, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// dialReality performs the TCP dial + uTLS REALITY client handshake.
// It returns the established net.Conn (a *utls.UConn) on success.
func (h *RealityHandshake) dialReality(ctx context.Context, addr string) (net.Conn, error) {
	// Dial the underlying TCP connection.
	dialer := net.Dialer{Timeout: h.cfg.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		retryable := isTransientError(err)
		return nil, NewHandshakeError("connect", addr, err, retryable)
	}

	// Determine SNI.
	sni := h.cfg.ServerName
	if sni == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			sni = host
		}
	}

	// Decode the server's X25519 public key.
	pubKeyBytes, err := decodeHexKey(h.cfg.RealityPublicKey)
	if err != nil {
		rawConn.Close()
		return nil, NewHandshakeError("connect", addr,
			fmt.Errorf("invalid RealityPublicKey: %w", err), false)
	}
	serverPubKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		rawConn.Close()
		return nil, NewHandshakeError("connect", addr,
			fmt.Errorf("invalid server X25519 public key: %w", err), false)
	}

	// Build the uTLS connection with the specified browser fingerprint.
	helloID := fingerprintToHelloID(h.cfg.TLSFingerprint)
	utlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // REALITY uses its own auth, not cert verification
		// REALITY auth lives in the SessionId of the ClientHello.
		// A TLS 1.3 session-ticket resumption replays a cached
		// ClientHello without our SessionId injection — the server
		// would fail REALITY auth (or worse, resumption would skip
		// the auth path entirely). xray sets this on the client too.
		SessionTicketsDisabled: true,
		// Verify the server presented a plausible certificate chain
		// for the SNI. InsecureSkipVerify stays on because REALITY
		// proxies the real site's cert (hostname mismatch is normal),
		// but VerifyPeerCertificate below still pins the chain.
		VerifyPeerCertificate: verifyRealityServerCert(sni),
	}
	uConn := utls.UClient(rawConn, utlsConfig, helloID)

	// Build the handshake state so we can modify the ClientHello before sending.
	if err := uConn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, NewHandshakeError("connect", addr,
			fmt.Errorf("uTLS BuildHandshakeState: %w", err), false)
	}

	// Perform the REALITY authentication tag injection.
	hello := uConn.HandshakeState.Hello

	// Set SessionId: [version(4)][timestamp(4)][shortId(8)][padding(16)]
	// REALITY protocol: the first 16 bytes of SessionId will be overwritten
	// by the AES-GCM auth tag. The remaining 16 bytes are padding.
	hello.SessionId = make([]byte, 32)
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	shortIDBytes, _ := decodeHexKey(h.cfg.RealityShortID)
	copy(hello.SessionId[8:], shortIDBytes)

	// CRITICAL: The REALITY server authenticates with AAD = the original
	// ClientHello bytes AFTER zeroing the sessionId. In the patched server
	// (third_party/reality-patched/tls.go:236-239) the clientHello.sessionId
	// slice points INTO original[39:], so `copy(sessionId, plainText)` zeroes
	// original[39:71] in place, and then `aead.Open(..., original)` uses the
	// ZEROED bytes as AAD:
	//   copy(ciphertext, hs.clientHello.sessionId)
	//   copy(hs.clientHello.sessionId, plainText)   // zeroes original[39:71] in place
	//   aead.Open(plainText[:0], nonce, ciphertext, hs.clientHello.original) // AAD = zeroed
	// The client must match: zero the sessionId in hello.Raw BEFORE using it
	// as AAD for Seal. The plaintext (SessionId[:16]) carries our custom
	// version+timestamp+shortId, but the AAD must have sessionId=ZEROED.
	copy(hello.Raw[39:71], make([]byte, 32))

	// Get the client's ephemeral ECDHE private key from the handshake state.
	ecdhe := getEcdheKey(&uConn.HandshakeState)
	if ecdhe == nil {
		rawConn.Close()
		return nil, NewHandshakeError("connect", addr,
			errors.New("uTLS fingerprint does not support TLS 1.3 key share (X25519)"), false)
	}

	// ECDH with server's public key to derive the shared auth key.
	authKey, err := ecdhe.ECDH(serverPubKey)
	if err != nil {
		rawConn.Close()
		return nil, NewHandshakeError("connect", addr,
			fmt.Errorf("ECDH with server public key: %w", err), false)
	}

	// HKDF-SHA256: salt=Random[:20], ikm=authKey, info="REALITY"
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		rawConn.Close()
		return nil, NewHandshakeError("connect", addr,
			fmt.Errorf("HKDF derive auth key: %w", err), false)
	}

	// AES-GCM seal: seal SessionId[:16] with nonce=Random[20:] and
	// AAD=the ORIGINAL raw ClientHello (sessionId NOT zeroed).
	aead, err := newAESGCM(authKey)
	if err != nil {
		rawConn.Close()
		return nil, NewHandshakeError("connect", addr,
			fmt.Errorf("AES-GCM init: %w", err), false)
	}
	// Seal in-place: the tag (16 bytes) overwrites SessionId[:16].
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)

	// Patch the raw ClientHello bytes with the modified SessionId.
	copy(hello.Raw[39:], hello.SessionId)

	// Perform the TLS handshake with the modified ClientHello.
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		retryable := isTransientError(err)
		return nil, NewHandshakeError("connect", addr,
			fmt.Errorf("REALITY handshake: %w", err), retryable)
	}

	return uConn, nil
}

// Listen starts an inbound Reality TLS listener on the given address.
// addr is a "host:port" string.
//
// The returned net.Listener wraps reality.Listen, which accepts TCP
// connections and performs the REALITY server-side handshake. Non-mesh
// traffic (failing REALITY auth) is forwarded to the configured camouflage
// destination (RealityDest).
//
// Context cancellation closes the listener.
func (h *RealityHandshake) Listen(ctx context.Context, addr string) (net.Listener, error) {
	if h.closed.Load() {
		return nil, NewHandshakeError("listen", addr, ErrShutdown, false)
	}

	// Validate required server-side fields.
	if h.cfg.RealityPrivateKey == "" {
		return nil, NewHandshakeError("listen", addr,
			&ConfigError{Field: "RealityPrivateKey", Reason: "required for reality server-side"}, false)
	}
	if h.cfg.RealityDest == "" {
		return nil, NewHandshakeError("listen", addr,
			&ConfigError{Field: "RealityDest", Reason: "required for reality server-side camouflage"}, false)
	}

	// Build the reality.Config.
	realityCfg, err := h.buildRealityConfig()
	if err != nil {
		return nil, NewHandshakeError("listen", addr, err, false)
	}

	// Use reality.Listen to create the listener.
	innerListener, err := realitypkg.Listen("tcp", addr, realityCfg)
	if err != nil {
		retryable := isTransientError(err)
		return nil, NewHandshakeError("listen", addr, err, retryable)
	}

	return h.wrapListener(ctx, innerListener), nil
}

// ListenWithListener wraps an existing net.Listener with REALITY TLS
// authentication. This is used when the TCP listener is shared between
// multiple protocols (e.g., MuxTransport demuxing gossip and Reality TLS
// on the same port).
//
// The caller provides the inner listener (typically a MuxTransport's
// RealityListener), and this method wraps it with reality.NewListener
// to perform the REALITY server-side handshake on each accepted connection.
//
// Context cancellation closes the listener.
func (h *RealityHandshake) ListenWithListener(ctx context.Context, inner net.Listener) (net.Listener, error) {
	if h.closed.Load() {
		return nil, NewHandshakeError("listen", inner.Addr().String(), ErrShutdown, false)
	}

	// Validate required server-side fields.
	if h.cfg.RealityPrivateKey == "" {
		return nil, NewHandshakeError("listen", inner.Addr().String(),
			&ConfigError{Field: "RealityPrivateKey", Reason: "required for reality server-side"}, false)
	}
	if h.cfg.RealityDest == "" {
		return nil, NewHandshakeError("listen", inner.Addr().String(),
			&ConfigError{Field: "RealityDest", Reason: "required for reality server-side camouflage"}, false)
	}

	// Build the reality.Config.
	realityCfg, err := h.buildRealityConfig()
	if err != nil {
		return nil, NewHandshakeError("listen", inner.Addr().String(), err, false)
	}

	// Wrap the existing listener with reality.NewListener.
	// This applies REALITY auth to each accepted connection.
	wrapped := realitypkg.NewListener(inner, realityCfg)

	return h.wrapListener(ctx, wrapped), nil
}

// wrapListener creates a realityListener wrapper around a net.Listener
// that is already producing REALITY-authenticated connections. It starts
// the accept loop and registers the listener for graceful shutdown.
func (h *RealityHandshake) wrapListener(ctx context.Context, inner net.Listener) net.Listener {
	l := &realityListener{
		listener: inner,
		hs:       h,
		acceptCh: make(chan net.Conn, 64),
		closeCh:  make(chan struct{}),
		ctx:      ctx,
	}

	h.mu.Lock()
	h.listeners[l] = struct{}{}
	h.mu.Unlock()

	// Start the accept loop.
	go l.acceptLoop()

	return l
}

// Close shuts down the handshake layer and all active listeners.
// It is idempotent.
func (h *RealityHandshake) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}

	h.mu.Lock()
	listeners := make([]*realityListener, 0, len(h.listeners))
	for l := range h.listeners {
		listeners = append(listeners, l)
	}
	h.listeners = make(map[*realityListener]struct{})
	h.mu.Unlock()

	for _, l := range listeners {
		l.closeLocked()
	}
	return nil
}

// buildRealityConfig constructs a *reality.Config from the HandshakeConfig.
func (h *RealityHandshake) buildRealityConfig() (*realitypkg.Config, error) {
	privKeyBytes, err := decodeHexKey(h.cfg.RealityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid RealityPrivateKey: %w", err)
	}

	cfg := &realitypkg.Config{
		Show:                   false,
		Type:                   "tcp",
		Dest:                   h.cfg.RealityDest,
		Xver:                   0,
		ServerNames:            make(map[string]bool),
		PrivateKey:             privKeyBytes,
		ShortIds:               make(map[[8]byte]bool),
		SessionTicketsDisabled: true,
	}

	// Populate accepted server names.
	for _, sn := range h.cfg.RealityServerNames {
		cfg.ServerNames[sn] = true
	}
	// If no server names configured, accept any SNI matching the dest host.
	if len(cfg.ServerNames) == 0 {
		host, _, _ := net.SplitHostPort(h.cfg.RealityDest)
		if host != "" {
			cfg.ServerNames[host] = true
		}
	}

	// Populate accepted short IDs.
	if h.cfg.RealityShortID != "" {
		shortIDBytes, err := decodeHexKey(h.cfg.RealityShortID)
		if err != nil {
			return nil, fmt.Errorf("invalid RealityShortID: %w", err)
		}
		var sid [8]byte
		copy(sid[:], shortIDBytes)
		cfg.ShortIds[sid] = true
	}
	// Match xray semantics: an empty shortId is accepted ONLY when the
	// configured shortId is empty (i.e. the operator opted in). The
	// previous unconditional empty-shortId acceptance let any client
	// that knew the SNI pass the REALITY gate with sid="".
	if h.cfg.RealityShortID == "" {
		cfg.ShortIds[[8]byte{}] = true
	}

	// DialContext for forwarding non-authenticated traffic to dest.
	cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: h.cfg.DialTimeout}
		return d.DialContext(ctx, network, address)
	}

	// Reality's Listen() checks Certificates/GetCertificate like tls.Listen.
	// Reality doesn't actually use the certificate content — it proxies the
	// real site's cert during handshake — but the field must be non-empty.
	// Generate a throwaway self-signed cert to satisfy the check.
	cert, err := generateRealityPlaceholderCert()
	if err != nil {
		return nil, fmt.Errorf("generate reality placeholder cert: %w", err)
	}
	cfg.Certificates = []realitypkg.Certificate{cert}

	return cfg, nil
}

// generateRealityPlaceholderCert creates a throwaway self-signed TLS certificate.
// Used only to satisfy reality.Listen's non-empty Certificates check.
// Reality proxies the real dest site's certificate during handshake,
// so this cert is never presented to clients.
func generateRealityPlaceholderCert() (realitypkg.Certificate, error) {
	// Generate ECDSA P-256 key pair (implements crypto.Signer).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return realitypkg.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	// Build a minimal x509 template.
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MeshDesk Reality"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return realitypkg.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	return realitypkg.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// realityListener — net.Listener wrapping reality.Listen
// ──────────────────────────────────────────────────────────────────────────────

// realityListener implements net.Listener for Reality TLS transport.
// It wraps the reality.Listener and provides an accept loop that delivers
// authenticated REALITY connections as net.Conn.
type realityListener struct {
	listener net.Listener
	hs       *RealityHandshake

	acceptCh chan net.Conn
	closeCh  chan struct{}
	closed   atomic.Bool
	ctx      context.Context
}

// Accept waits for and returns the next inbound REALITY connection.
// The returned net.Conn is an authenticated REALITY connection.
func (l *realityListener) Accept() (net.Conn, error) {
	// Check context cancellation first.
	if err := l.ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	case <-l.ctx.Done():
		l.Close()
		return nil, l.ctx.Err()
	}
}

// Close closes the listener and stops accepting new connections.
func (l *realityListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.closeCh)
	l.closeLocked()
	l.hs.mu.Lock()
	delete(l.hs.listeners, l)
	l.hs.mu.Unlock()
	return l.listener.Close()
}

// closeLocked closes the listener without closing the underlying socket.
// Called by the handshake layer during Close().
func (l *realityListener) closeLocked() {
	l.closed.Store(true)
	select {
	case <-l.closeCh:
	default:
		close(l.closeCh)
	}
}

// Addr returns the listener's network address.
func (l *realityListener) Addr() net.Addr {
	return l.listener.Addr()
}

// acceptLoop accepts inbound REALITY connections from the underlying
// reality.Listener and delivers them via the accept channel.
func (l *realityListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			// Check context cancellation.
			if l.ctx.Err() != nil {
				l.Close()
				return
			}
			// Transient error — brief pause and retry.
			select {
			case <-l.closeCh:
				return
			case <-l.ctx.Done():
				l.Close()
				return
			case <-time.After(1 * time.Millisecond):
			}
			continue
		}

		// Deliver the connection via the accept channel.
		select {
		case l.acceptCh <- conn:
		case <-l.closeCh:
			conn.Close()
			return
		case <-l.ctx.Done():
			conn.Close()
			l.Close()
			return
		default:
			// Accept queue full — drop the connection (backpressure).
			conn.Close()
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// REALITY crypto helpers
// ──────────────────────────────────────────────────────────────────────────────

// getEcdheKey extracts the ephemeral X25519 private key from the uTLS
// handshake state's key share. This is used to perform ECDH with the
// server's Reality public key.
func getEcdheKey(hs *utls.PubClientHandshakeState) *ecdh.PrivateKey {
	if hs == nil || hs.State13.KeyShareKeys == nil {
		return nil
	}
	if hs.State13.KeyShareKeys.Ecdhe != nil {
		return hs.State13.KeyShareKeys.Ecdhe
	}
	if hs.State13.KeyShareKeys.MlkemEcdhe != nil {
		return hs.State13.KeyShareKeys.MlkemEcdhe
	}
	return nil
}

// newAESGCM creates an AES-GCM AEAD from a 16/24/32-byte key.
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// decodeHexKey decodes a hex-encoded key string to raw bytes.
// Returns an empty byte slice (not error) for empty input.
func decodeHexKey(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// ──────────────────────────────────────────────────────────────────────────────
// Key generation utility (for setup/testing)
// ──────────────────────────────────────────────────────────────────────────────

// verifyRealityServerCert returns a VerifyPeerCertificate callback that
// checks the server presented a non-empty certificate chain whose leaf is
// a plausible certificate for the SNI (xray's VerifyPeerCertificate does
// the same: full chain verification against the real DNS name is skipped
// because REALITY proxies the target site's cert, but a bare / empty chain
// or a self-signed impostor leaf is rejected). This raises the bar for an
// active MITM pretending to be the REALITY server: it must possess a real
// certificate chain for the camouflage site, which the camouflage site's
// own TLS endpoint will happily present to anyone — so the real protection
// remains the SessionId auth; this only weeds out lazy impostors that
// present garbage certs.
func verifyRealityServerCert(sni string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("reality: server presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("reality: parse server certificate: %w", err)
		}
		// The camouflage site's real certificate must look like a real
		// end-entity cert: currently valid, with a DNS SAN covering the
		// SNI (big CAs require SANs; a self-signed impostor rarely has
		// a matching SAN for an SNI it does not own).
		if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
			return fmt.Errorf("reality: server certificate not currently valid (%s..%s)",
				leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
		}
		if err := leaf.VerifyHostname(sni); err != nil {
			return fmt.Errorf("reality: server certificate does not cover SNI %q: %w", sni, err)
		}
		return nil
	}
}

// GenerateRealityKeyPair generates a new X25519 key pair for Reality transport.
// Returns (privateKeyHex, publicKeyHex, error).
// The private key is used server-side; the public key is used client-side.
func GenerateRealityKeyPair() (string, string, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate X25519 key pair: %w", err)
	}
	pubKey := privKey.PublicKey()
	return hex.EncodeToString(privKey.Bytes()), hex.EncodeToString(pubKey.Bytes()), nil
}

// fingerprintToHelloID converts a fingerprint name string to a utls.ClientHelloID.
func fingerprintToHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(fp) {
	case "", "chrome":
		// Use Chrome 120 (not Auto) to avoid X25519MLKEM768 which
		// causes REALITY TLS handshake failures with the xtls/reality
		// library's internal TLS implementation.
		return utls.HelloChrome_120
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	default:
		return utls.HelloChrome_120
	}
}
