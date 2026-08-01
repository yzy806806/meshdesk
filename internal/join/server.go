package join

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/identity"
)

// ConfigBundle is the configuration payload distributed to joining nodes
// after successful token validation. It contains everything the new node
// needs to connect to the mesh: identity material, REALITY keys, and the
// collector list.
type ConfigBundle struct {
	// BootstrapPublicKey is the shared node's Ed25519 public key (hex).
	BootstrapPublicKey string `json:"bootstrap_pubkey"`

	// BootstrapEndpoint is the shared node's mesh endpoint (host:port).
	BootstrapEndpoint string `json:"bootstrap_endpoint"`

	// GossipPort is the gossip port on the shared node.
	GossipPort int `json:"gossip_port"`

	// RealityPublicKey is the shared node's X25519 REALITY public key (hex).
	// The joiner uses this to connect via Reality TLS.
	RealityPublicKey string `json:"reality_pubkey"`

	// RealityShortID is the short ID the joiner should use.
	RealityShortID string `json:"reality_short_id"`

	// RealityServerName is the SNI for REALITY TLS.
	RealityServerName string `json:"reality_server_name"`

	// Collectors is the list of collector peer IDs (hex pubkeys).
	Collectors []string `json:"collectors"`

	// KnownPeers is the list of known peer metadata for immediate mesh view.
	KnownPeers []PeerInfo `json:"known_peers"`

	// IssuedAt is when this bundle was generated (Unix timestamp).
	IssuedAt int64 `json:"issued_at"`
}

// PeerInfo is a lightweight peer descriptor for the known-peers list.
type PeerInfo struct {
	PublicKey string `json:"pubkey"`
	Hostname string `json:"hostname"`
	Role     string `json:"role"`
	Endpoint string `json:"endpoint,omitempty"`
}

// JoinRequest is the request body sent by the joining node.
type JoinRequest struct {
	// Token is the base64-encoded join token (HMAC-signed, with nonce + expiry).
	Token string `json:"token"`

	// JoinerPublicKey is the joining node's Ed25519 public key (hex).
	JoinerPublicKey string `json:"joiner_pubkey"`

	// JoinerHostname is the joining node's hostname (for registration).
	JoinerHostname string `json:"joiner_hostname,omitempty"`

	// JoinerEndpoint is the joining node's reachable endpoint (if any).
	JoinerEndpoint string `json:"joiner_endpoint,omitempty"`
}

// JoinResponse is the response sent back to the joining node.
type JoinResponse struct {
	// Success indicates whether the join was accepted.
	Success bool `json:"success"`

	// Error is a human-readable error message (when Success is false).
	Error string `json:"error,omitempty"`

	// Bundle is the config bundle (when Success is true).
	Bundle *ConfigBundle `json:"bundle,omitempty"`

	// Challenge is a random hex challenge for joiner identity verification.
	// The joiner must sign this with its Ed25519 private key to prove
	// ownership of the public key it claims.
	Challenge string `json:"challenge,omitempty"`
}

// ServerConfig holds the configuration for the join server.
type ServerConfig struct {
	// Secret is the HMAC key used to validate tokens.
	Secret []byte

	// ServerIdentity is the shared node's Ed25519 identity.
	// Used to sign challenges and verify joiner signatures.
	ServerIdentity *identity.Identity

	// BootstrapEndpoint is this node's mesh endpoint (host:port).
	BootstrapEndpoint string

	// GossipPort is the gossip port on this node.
	GossipPort int

	// RealityPublicKey is this node's X25519 REALITY public key (hex).
	RealityPublicKey string

	// RealityShortID is the short ID the joiner should use.
	RealityShortID string

	// RealityServerName is the SNI for REALITY TLS.
	RealityServerName string

	// Collectors is the list of collector peer IDs.
	Collectors []string

	// MaxJoinRequests limits concurrent join requests per minute.
	// Default: 10.
	MaxJoinRequests int

	// TokenLifetime is how long generated tokens are valid.
	// Default: 30 minutes.
	TokenLifetime time.Duration
}

// JoinServer handles the HTTP endpoint for the auto-join protocol.
// It runs on the shared/bootstrap node and validates join tokens,
// then distributes the config bundle to authorized joiners.
type JoinServer struct {
	cfg        ServerConfig
	replay     *ReplayCache
	httpServer *http.Server
	listener   net.Listener

	// rateLimiter tracks join requests per client IP.
	mu         sync.Mutex
	rateLimit  map[string]*rateBucket

	// knownPeersFunc returns the current known-peers list for the bundle.
	knownPeersFunc func() []PeerInfo
}

type rateBucket struct {
	count    int
	windowStart time.Time
}

// NewJoinServer creates a new join server with the given config.
func NewJoinServer(cfg ServerConfig) *JoinServer {
	if cfg.TokenLifetime == 0 {
		cfg.TokenLifetime = TokenLifetime
	}
	if cfg.MaxJoinRequests == 0 {
		cfg.MaxJoinRequests = 10
	}
	return &JoinServer{
		cfg:       cfg,
		replay:    NewReplayCache(cfg.TokenLifetime * 2),
		rateLimit: make(map[string]*rateBucket),
	}
}

// Handler returns the http.Handler for the join endpoint.
// This can be mounted on any http.ServeMux.
func (s *JoinServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/join", s.handleJoin)
	return mux
}

// Start starts the HTTP server on the given address.
// The server should be behind TLS (use ListenAndServeTLS via StartTLS).
func (s *JoinServer) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("join server listen: %w", err)
	}
	s.listener = ln
	s.httpServer = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[join] server error: %v", err)
		}
	}()
	log.Printf("[join] server listening on %s", addr)
	return nil
}

// StartTLS starts the HTTPS server with the given TLS cert and key files.
func (s *JoinServer) StartTLS(addr, certFile, keyFile string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("join server TLS listen: %w", err)
	}
	s.listener = ln
	s.httpServer = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		if err := s.httpServer.ServeTLS(ln, certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Printf("[join] TLS server error: %v", err)
		}
	}()
	log.Printf("[join] TLS server listening on %s", addr)
	return nil
}

// Stop shuts down the join server.
func (s *JoinServer) Stop() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(ctx)
	}
}

// handleJoin is the HTTP handler for POST /api/join.
func (s *JoinServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	// Only accept POST.
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit by client IP.
	clientIP := clientIP(r)
	if !s.allowRequest(clientIP) {
		writeJSON(w, http.StatusTooManyRequests, JoinResponse{
			Success: false,
			Error:   "rate limit exceeded",
		})
		return
	}

	// Read and parse the request body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024)) // 64KB max
	if err != nil {
		writeJSON(w, http.StatusBadRequest, JoinResponse{
			Success: false,
			Error:   fmt.Sprintf("read body: %v", err),
		})
		return
	}

	var req JoinRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, JoinResponse{
			Success: false,
			Error:   fmt.Sprintf("parse request: %v", err),
		})
		return
	}

	// Validate the token.
	token, err := ParseToken(req.Token, s.cfg.Secret)
	if err != nil {
		log.Printf("[join] token validation failed from %s: %v", clientIP, err)
		writeJSON(w, http.StatusUnauthorized, JoinResponse{
			Success: false,
			Error:   "invalid token",
		})
		return
	}

	// Check server fingerprint matches (TLS pinning).
	if token.ServerFP != "" && token.ServerFP != s.cfg.ServerIdentity.PublicKey {
		log.Printf("[join] token server fingerprint mismatch from %s: token=%s local=%s",
			clientIP, token.ServerFP[:min(16, len(token.ServerFP))],
			s.cfg.ServerIdentity.PublicKey[:min(16, len(s.cfg.ServerIdentity.PublicKey))])
		writeJSON(w, http.StatusUnauthorized, JoinResponse{
			Success: false,
			Error:   "token not issued for this server",
		})
		return
	}

	// Replay protection: check and mark the nonce.
	if err := s.replay.CheckAndMark(token.Nonce, token.ExpiresAt); err != nil {
		log.Printf("[join] replay detected from %s: %v", clientIP, err)
		writeJSON(w, http.StatusUnauthorized, JoinResponse{
			Success: false,
			Error:   "token already used",
		})
		return
	}

	// Verify joiner identity: generate a challenge, sign it, embed in response.
	// The joiner must prove it owns the claimed Ed25519 public key.
	challenge := make([]byte, 32)
	if _, err := readRandom(challenge); err != nil {
		writeJSON(w, http.StatusInternalServerError, JoinResponse{
			Success: false,
			Error:   "internal error",
		})
		return
	}
	challengeHex := hex.EncodeToString(challenge)

	// For now, we trust the joiner's claimed public key. In a stricter
	// mode, the joiner would sign the challenge and the server would
	// verify before responding. This is a two-step flow that can be
	// added later. The token already authenticates the joiner.

	// Build the config bundle.
	bundle := s.buildBundle(req)

	log.Printf("[join] accepted join from %s (pubkey=%s, hostname=%s)",
		clientIP,
		shortHex(req.JoinerPublicKey),
		req.JoinerHostname)

	writeJSON(w, http.StatusOK, JoinResponse{
		Success:   true,
		Bundle:     bundle,
		Challenge: challengeHex,
	})
}

// buildBundle constructs the config bundle to send to the joiner.
func (s *JoinServer) buildBundle(req JoinRequest) *ConfigBundle {
	knownPeers := []PeerInfo{}
	if s.knownPeersFunc != nil {
		knownPeers = s.knownPeersFunc()
	}
	return &ConfigBundle{
		BootstrapPublicKey: s.cfg.ServerIdentity.PublicKey,
		BootstrapEndpoint:  s.cfg.BootstrapEndpoint,
		GossipPort:         s.cfg.GossipPort,
		RealityPublicKey:   s.cfg.RealityPublicKey,
		RealityShortID:     s.cfg.RealityShortID,
		RealityServerName:  s.cfg.RealityServerName,
		Collectors:         s.cfg.Collectors,
		KnownPeers:         knownPeers,
		IssuedAt:           time.Now().Unix(),
	}
}

// SetKnownPeersFunc allows the caller to provide a function that returns
// the current known-peers list. This is called on each successful join
// to populate the bundle's KnownPeers field.
func (s *JoinServer) SetKnownPeersFunc(fn func() []PeerInfo) {
	s.mu.Lock()
	s.knownPeersFunc = fn
	s.mu.Unlock()
}

func (s *JoinServer) allowRequest(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.rateLimit[ip]
	if !ok {
		s.rateLimit[ip] = &rateBucket{count: 1, windowStart: time.Now()}
		return true
	}

	// Reset the window every minute.
	if time.Since(bucket.windowStart) > time.Minute {
		bucket.count = 1
		bucket.windowStart = time.Now()
		return true
	}

	bucket.count++
	return bucket.count <= s.cfg.MaxJoinRequests
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP extracts the client IP from a request, accounting for X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain.
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// shortHex returns the first 16 chars of a hex string + "..." for logging.
func shortHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

// readRandom fills b with cryptographically random bytes.
func readRandom(b []byte) (int, error) {
	return rand.Read(b)
}