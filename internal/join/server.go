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
	Hostname  string `json:"hostname"`
	Role      string `json:"role"`
	Endpoint  string `json:"endpoint,omitempty"`
}

// JoinRequest is the request body sent by the joining node.
//
// The join protocol is a two-step challenge-response flow:
//  1. Initial request (ChallengeResponse empty): server validates the
//     token, generates a random challenge, and returns it.
//  2. Challenge response (ChallengeResponse set): the joiner signs the
//     challenge with its Ed25519 private key and sends it back. The
//     server verifies the signature against the joiner's claimed public
//     key before distributing the config bundle.
type JoinRequest struct {
	// Token is the base64-encoded join token (HMAC-signed, with nonce + expiry).
	Token string `json:"token"`

	// JoinerPublicKey is the joining node's Ed25519 public key (hex).
	JoinerPublicKey string `json:"joiner_pubkey"`

	// JoinerHostname is the joining node's hostname (for registration).
	JoinerHostname string `json:"joiner_hostname,omitempty"`

	// JoinerEndpoint is the joining node's reachable endpoint (if any).
	JoinerEndpoint string `json:"joiner_endpoint,omitempty"`

	// Challenge is the hex-encoded challenge the server sent in step 1.
	// Empty on the initial request (step 1).
	Challenge string `json:"challenge,omitempty"`

	// ChallengeResponse is the hex-encoded Ed25519 signature of the challenge,
	// signed by the joiner's private key. Present only in step 2.
	// Empty on the initial request (step 1).
	ChallengeResponse string `json:"challenge_response,omitempty"`
}

// JoinResponse is the response sent back to the joining node.
type JoinResponse struct {
	// Success indicates whether the join step was accepted.
	Success bool `json:"success"`

	// Error is a human-readable error message (when Success is false).
	Error string `json:"error,omitempty"`

	// Bundle is the config bundle (when Success is true AND the challenge
	// has been verified). Nil during step 1 (challenge issued).
	Bundle *ConfigBundle `json:"bundle,omitempty"`

	// Challenge is a random hex challenge for joiner identity verification.
	// The joiner must sign this with its Ed25519 private key to prove
	// ownership of the public key it claims. Present in step 1 only.
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
	mu        sync.Mutex
	rateLimit map[string]*rateBucket

	// knownPeersFunc returns the current known-peers list for the bundle.
	knownPeersFunc func() []PeerInfo

	// challengeCache stores issued challenges pending response.
	// challenge hex → joiner public key (hex).
	// Entries expire after challengeTTL.
	challengeCache map[string]challengeEntry
}

type challengeEntry struct {
	joinerPubKey string
	expiresAt    time.Time
}

// challengeTTL is how long an issued challenge remains valid for
// the joiner to respond. Short window to prevent replay.
const challengeTTL = 60 * time.Second

type rateBucket struct {
	count       int
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
		cfg:            cfg,
		replay:         NewReplayCache(cfg.TokenLifetime * 2),
		rateLimit:      make(map[string]*rateBucket),
		challengeCache: make(map[string]challengeEntry),
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
//
// The protocol is a two-step challenge-response flow:
//
//	Step 1 (challenge issuance): The joiner sends a JoinRequest with token
//	+ joiner pubkey but NO ChallengeResponse. The server validates the
//	token, generates a random 32-byte challenge, caches it, and returns
//	it in the JoinResponse. No bundle is returned yet.
//
//	Step 2 (challenge verification): The joiner signs the challenge with
//	its Ed25519 private key and sends a second JoinRequest with the same
//	token + the Challenge and ChallengeResponse fields set. The server
//	verifies the signature against the joiner's claimed public key. If
//	valid, the config bundle is returned. If invalid, an error is returned.
//
// This proves the joiner actually possesses the private key
// corresponding to the public key it claims — preventing impersonation
// even if an attacker intercepts a valid token.
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
	// NOTE: The token nonce is marked on the FIRST request (step 1).
	// The second request (step 2) reuses the same token. To allow this,
	// we only check replay on the first step (when ChallengeResponse is
	// empty). On the second step, the challenge cache serves as the
	// replay guard.
	if req.ChallengeResponse == "" {
		if err := s.replay.CheckAndMark(token.Nonce, token.ExpiresAt); err != nil {
			log.Printf("[join] replay detected from %s: %v", clientIP, err)
			writeJSON(w, http.StatusUnauthorized, JoinResponse{
				Success: false,
				Error:   "token already used",
			})
			return
		}
	}

	// Step dispatch: if no ChallengeResponse, this is step 1 (issue challenge).
	if req.ChallengeResponse == "" {
		s.handleChallengeStep(w, req, clientIP)
		return
	}

	// Step 2: verify challenge response and return bundle.
	s.handleChallengeResponseStep(w, req, clientIP, token)
}

// handleChallengeStep generates a random challenge, caches it, and returns
// it to the joiner. No config bundle is returned in this step.
func (s *JoinServer) handleChallengeStep(w http.ResponseWriter, req JoinRequest, clientIP string) {
	challenge := make([]byte, 32)
	if _, err := readRandom(challenge); err != nil {
		writeJSON(w, http.StatusInternalServerError, JoinResponse{
			Success: false,
			Error:   "internal error",
		})
		return
	}
	challengeHex := hex.EncodeToString(challenge)

	// Cache the challenge with the joiner's claimed public key.
	// The challenge must be redeemed by this specific joiner within
	// challengeTTL.
	s.mu.Lock()
	s.challengeCache[challengeHex] = challengeEntry{
		joinerPubKey: req.JoinerPublicKey,
		expiresAt:    time.Now().Add(challengeTTL),
	}
	// GC expired challenges.
	now := time.Now()
	for k, v := range s.challengeCache {
		if v.expiresAt.Before(now) {
			delete(s.challengeCache, k)
		}
	}
	s.mu.Unlock()

	log.Printf("[join] challenge issued to %s (pubkey=%s, hostname=%s)",
		clientIP, shortHex(req.JoinerPublicKey), req.JoinerHostname)

	writeJSON(w, http.StatusOK, JoinResponse{
		Success:   true,
		Challenge: challengeHex,
	})
}

// handleChallengeResponseStep verifies the joiner's Ed25519 signature
// over the challenge and, if valid, returns the config bundle.
func (s *JoinServer) handleChallengeResponseStep(w http.ResponseWriter, req JoinRequest, clientIP string, token *Token) {
	// Look up the cached challenge.
	s.mu.Lock()
	entry, exists := s.challengeCache[req.Challenge]
	if exists {
		// Challenge is single-use: remove it regardless of outcome.
		delete(s.challengeCache, req.Challenge)
	}
	s.mu.Unlock()

	if !exists {
		log.Printf("[join] challenge not found or expired from %s", clientIP)
		writeJSON(w, http.StatusUnauthorized, JoinResponse{
			Success: false,
			Error:   "challenge not found or expired",
		})
		return
	}

	// Check challenge TTL.
	if time.Now().After(entry.expiresAt) {
		log.Printf("[join] challenge expired from %s", clientIP)
		writeJSON(w, http.StatusUnauthorized, JoinResponse{
			Success: false,
			Error:   "challenge expired",
		})
		return
	}

	// Verify the joiner's public key matches the one from step 1.
	if req.JoinerPublicKey != entry.joinerPubKey {
		log.Printf("[join] public key mismatch on challenge from %s: step1=%s step2=%s",
			clientIP, shortHex(entry.joinerPubKey), shortHex(req.JoinerPublicKey))
		writeJSON(w, http.StatusUnauthorized, JoinResponse{
			Success: false,
			Error:   "public key mismatch",
		})
		return
	}

	// Verify the Ed25519 signature.
	// The joiner signed the challenge hex string bytes.
	challengeBytes := []byte(req.Challenge)
	if !identity.Verify(req.JoinerPublicKey, challengeBytes, req.ChallengeResponse) {
		log.Printf("[join] challenge signature verification failed from %s (pubkey=%s)",
			clientIP, shortHex(req.JoinerPublicKey))
		writeJSON(w, http.StatusUnauthorized, JoinResponse{
			Success: false,
			Error:   "challenge signature verification failed",
		})
		return
	}

	// Challenge verified! Build and return the config bundle.
	bundle := s.buildBundle(req)

	log.Printf("[join] accepted join from %s (pubkey=%s, hostname=%s) — challenge verified",
		clientIP, shortHex(req.JoinerPublicKey), req.JoinerHostname)

	writeJSON(w, http.StatusOK, JoinResponse{
		Success: true,
		Bundle:  bundle,
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

	// Periodic cleanup of stale rate limit entries (prevents unbounded growth).
	if len(s.rateLimit) > 1000 {
		cutoff := time.Now().Add(-5 * time.Minute)
		for addr, b := range s.rateLimit {
			if b.windowStart.Before(cutoff) {
				delete(s.rateLimit, addr)
			}
		}
	}

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

// clientIP extracts the client IP from a request for rate limiting.
//
// X-Forwarded-For is deliberately NOT trusted: it is client-controlled,
// so honoring it would let an attacker rotate forged XFF values to
// bypass the join rate limit entirely. When the join server sits behind
// a proxy (e.g. Cloudflare Tunnel), all clients share the proxy's
// RemoteAddr — the rate limit then applies globally, which still
// throttles brute force.
func clientIP(r *http.Request) string {
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
