package join

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/identity"
)

// newE2EServer is like newTestServer in join_test.go but returns the TS URL.
func newE2EServer(t *testing.T, opts *e2eServerOpts) (*JoinServer, []byte, *identity.Identity) {
	t.Helper()
	id, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	secret := []byte(opts.Secret)
	cfg := ServerConfig{
		Secret:            secret,
		ServerIdentity:    id,
		BootstrapEndpoint: opts.BootstrapEndpoint,
		GossipPort:        opts.GossipPort,
		RealityPublicKey:  opts.RealityPublicKey,
		RealityShortID:    opts.RealityShortID,
		RealityServerName: opts.RealityServerName,
		Collectors:        opts.Collectors,
		TokenLifetime:     opts.TokenLifetime,
	}
	if opts.MaxJoinRequests > 0 {
		cfg.MaxJoinRequests = opts.MaxJoinRequests
	}
	return NewJoinServer(cfg), secret, id
}

type e2eServerOpts struct {
	Secret            string
	BootstrapEndpoint string
	GossipPort        int
	RealityPublicKey  string
	RealityShortID    string
	RealityServerName string
	Collectors        []string
	MaxJoinRequests   int
	TokenLifetime     time.Duration
}

func defaultE2EOpts() *e2eServerOpts {
	return &e2eServerOpts{
		Secret:            "e2e-shared-secret",
		BootstrapEndpoint: "bootstrap.example.com:52888",
		GossipPort:        7946,
		RealityPublicKey:  "deadbeef12345678",
		RealityShortID:    "a1b2c3d4e5f6a7b8",
		RealityServerName: "reality-sni.example.com",
		Collectors:        []string{"collector-alicloud", "collector-tencent"},
		TokenLifetime:     5 * time.Minute,
	}
}

// e2eJoinClient creates a JoinClient configured for plain HTTP test servers.
func e2eJoinClient(ts *httptest.Server, token string, joiner *identity.Identity, hostname string) *JoinClient {
	return NewJoinClient(ClientConfig{
		ServerURL:       ts.URL,
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  hostname,
		JoinerSigner:    joiner,
		Timeout:         5 * time.Second,
		AllowPlainHTTP:  true,
	})
}

// e2eJoinClientTLS creates a JoinClient configured for TLS test servers.
func e2eJoinClientTLS(ts *httptest.Server, tlsConfig *tls.Config, token string, joiner *identity.Identity, hostname string) *JoinClient {
	return NewJoinClient(ClientConfig{
		ServerURL:       ts.URL,
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  hostname,
		JoinerSigner:    joiner,
		TLSConfig:       tlsConfig,
		Timeout:         5 * time.Second,
	})
}

// =============================================================================
// E2E Test 1: Full join flow over HTTPS (TLS) with challenge-response
// =============================================================================
// Validates the complete auto-join protocol with Ed25519 challenge-response:
//  1. Server generates token → 2. Client sends over TLS → 3. Server validates
//     → 4. Server issues challenge → 5. Client signs challenge → 6. Server verifies
//     → 7. Returns ConfigBundle with reality config + collectors → 8. Client applies it
func TestE2E_FullJoinFlowWithTLS(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	srv.SetKnownPeersFunc(func() []PeerInfo {
		return []PeerInfo{
			{PublicKey: "peer-existing-1", Hostname: "node-veteran", Role: "agent", Endpoint: "10.0.0.1:52888"},
			{PublicKey: "peer-existing-2", Hostname: "node-relay", Role: "relay", Endpoint: "10.0.0.2:52888"},
		}
	})

	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()

	// Trust the test server's certificate.
	certPool := x509.NewCertPool()
	certPool.AddCert(ts.Certificate())
	tlsConfig := &tls.Config{RootCAs: certPool}

	token, err := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	joiner, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	client := e2eJoinClientTLS(ts, tlsConfig, token, joiner, "new-node-e2e")

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin over TLS failed: %v", err)
	}

	// Verify all bundle fields.
	assertBundle(t, bundle, id.PublicKey, opts, 2, 2)

	// Replay protection: same token must be rejected.
	_, err = client.RequestJoin(context.Background())
	if err == nil {
		t.Error("replay should have been rejected")
	}
}

// =============================================================================
// E2E Test 2: Token expiry prevents join
// =============================================================================
func TestE2E_TokenExpiry(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, err := GenerateToken(secret, id.PublicKey, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	time.Sleep(10 * time.Millisecond) // Let it expire.

	joiner, _ := identity.GenerateIdentity()
	client := e2eJoinClient(ts, token, joiner, "expired-node")

	_, err = client.RequestJoin(context.Background())
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "join rejected") {
		t.Errorf("expected 'join rejected', got: %v", err)
	}
}

// =============================================================================
// E2E Test 3: Challenge-response enforcement (Ed25519 verification)
// =============================================================================
// Validates that the server enforces the Ed25519 challenge-response:
//   - Step 1 returns a challenge (no bundle)
//   - Step 2 with a valid signature returns the bundle
//   - Step 2 with an invalid signature is rejected
//   - Step 2 with a different public key is rejected
func TestE2E_ChallengeResponseEnforced(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()

	// Step 1: Request challenge.
	jr1, status1 := doJoinRequest(t, ts, JoinRequest{
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "challenge-node",
	})
	if status1 != http.StatusOK {
		t.Fatalf("step 1: expected 200, got %d", status1)
	}
	if !jr1.Success {
		t.Fatalf("step 1: join not successful: %s", jr1.Error)
	}
	if jr1.Challenge == "" {
		t.Fatal("step 1: Challenge is empty — server did not issue a challenge")
	}
	if jr1.Bundle != nil {
		t.Fatal("step 1: server returned a bundle before challenge verification — security gap!")
	}
	t.Logf("Step 1: Challenge issued (len=%d) ✓", len(jr1.Challenge))

	// Step 2: Sign challenge and request bundle.
	sig, err := joiner.Sign([]byte(jr1.Challenge))
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	jr2, status2 := doJoinRequest(t, ts, JoinRequest{
		Token:             token,
		JoinerPublicKey:   joiner.PublicKey,
		JoinerHostname:    "challenge-node",
		Challenge:         jr1.Challenge,
		ChallengeResponse: sig,
	})
	if status2 != http.StatusOK {
		t.Fatalf("step 2: expected 200, got %d: %s", status2, jr2.Error)
	}
	if jr2.Bundle == nil {
		t.Fatal("step 2: bundle is nil after valid challenge response")
	}
	if jr2.Bundle.BootstrapPublicKey != id.PublicKey {
		t.Errorf("step 2: BootstrapPublicKey mismatch")
	}
	t.Log("Step 2: Valid signature → bundle returned ✓")

	// Step 2b: Invalid signature should be rejected.
	token2, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner2, _ := identity.GenerateIdentity()
	jr3, _ := doJoinRequest(t, ts, JoinRequest{
		Token:           token2,
		JoinerPublicKey: joiner2.PublicKey,
		JoinerHostname:  "bad-sig-node",
	})
	// Use a fake signature (not signed by joiner2).
	_, status4 := doJoinRequest(t, ts, JoinRequest{
		Token:             token2,
		JoinerPublicKey:   joiner2.PublicKey,
		JoinerHostname:    "bad-sig-node",
		Challenge:         jr3.Challenge,
		ChallengeResponse: "deadbeef" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	})
	if status4 != http.StatusUnauthorized {
		t.Errorf("step 2b: expected 401 for invalid signature, got %d", status4)
	}
	t.Log("Step 2b: Invalid signature → rejected ✓")

	// Step 2c: Different public key should be rejected.
	token3, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner3, _ := identity.GenerateIdentity()
	jr5, _ := doJoinRequest(t, ts, JoinRequest{
		Token:           token3,
		JoinerPublicKey: joiner3.PublicKey,
		JoinerHostname:  "key-mismatch-node",
	})
	// Sign with joiner3's key but claim joiner4's public key.
	sig3, _ := joiner3.Sign([]byte(jr5.Challenge))
	joiner4, _ := identity.GenerateIdentity()
	_, status6 := doJoinRequest(t, ts, JoinRequest{
		Token:             token3,
		JoinerPublicKey:   joiner4.PublicKey, // Different key!
		JoinerHostname:    "key-mismatch-node",
		Challenge:         jr5.Challenge,
		ChallengeResponse: sig3,
	})
	if status6 != http.StatusUnauthorized {
		t.Errorf("step 2c: expected 401 for public key mismatch, got %d", status6)
	}
	t.Log("Step 2c: Public key mismatch → rejected ✓")

	// Step 2d: Expired challenge should be rejected.
	// We can't easily test TTL expiry in a fast test, but we verify the
	// challenge is single-use: reusing a challenge that was already
	// consumed should fail.
	token4, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner5, _ := identity.GenerateIdentity()
	jr7, _ := doJoinRequest(t, ts, JoinRequest{
		Token:           token4,
		JoinerPublicKey: joiner5.PublicKey,
		JoinerHostname:  "reuse-challenge-node",
	})
	sig5, _ := joiner5.Sign([]byte(jr7.Challenge))
	// First use: should succeed.
	jr8, status8 := doJoinRequest(t, ts, JoinRequest{
		Token:             token4,
		JoinerPublicKey:   joiner5.PublicKey,
		JoinerHostname:    "reuse-challenge-node",
		Challenge:         jr7.Challenge,
		ChallengeResponse: sig5,
	})
	if status8 != http.StatusOK || jr8.Bundle == nil {
		t.Fatalf("challenge reuse first use: expected bundle, got status=%d", status8)
	}
	// Second use: same challenge should be rejected.
	_, status9 := doJoinRequest(t, ts, JoinRequest{
		Token:             token4,
		JoinerPublicKey:   joiner5.PublicKey,
		JoinerHostname:    "reuse-challenge-node",
		Challenge:         jr7.Challenge,
		ChallengeResponse: sig5,
	})
	if status9 != http.StatusUnauthorized {
		t.Errorf("challenge reuse: expected 401, got %d", status9)
	}
	t.Log("Step 2d: Challenge single-use enforcement ✓")
}

// =============================================================================
// E2E Test 4: Server fingerprint binding (cross-server token rejection)
// =============================================================================
func TestE2E_ServerFingerprintBinding(t *testing.T) {
	opts1 := defaultE2EOpts()
	srv1, secret, id1 := newE2EServer(t, opts1)
	defer srv1.Stop()

	id2, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	opts2 := defaultE2EOpts()
	opts2.BootstrapEndpoint = "other.example.com:52888"
	srv2 := NewJoinServer(ServerConfig{
		Secret:            []byte(opts2.Secret),
		ServerIdentity:    id2,
		BootstrapEndpoint: opts2.BootstrapEndpoint,
		GossipPort:        opts2.GossipPort,
		RealityPublicKey:  opts2.RealityPublicKey,
		RealityShortID:    opts2.RealityShortID,
		RealityServerName: opts2.RealityServerName,
		Collectors:        opts2.Collectors,
		TokenLifetime:     opts2.TokenLifetime,
	})
	defer srv2.Stop()

	ts1 := httptest.NewServer(srv1.Handler())
	defer ts1.Close()
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()

	// Token for server 1.
	tokenForS1, _ := GenerateToken(secret, id1.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()

	// Use it against server 2 → rejected.
	client := e2eJoinClient(ts2, tokenForS1, joiner, "cross-server")
	_, err = client.RequestJoin(context.Background())
	if err == nil {
		t.Fatal("cross-server token should be rejected")
	}

	// Same token against server 1 → succeeds (use a fresh token since nonce was consumed).
	tokenFresh, _ := GenerateToken(secret, id1.PublicKey, 5*time.Minute)
	joiner2, _ := identity.GenerateIdentity()
	client2 := e2eJoinClient(ts1, tokenFresh, joiner2, "correct-server")
	bundle, err := client2.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("correct server join failed: %v", err)
	}
	if bundle.BootstrapPublicKey != id1.PublicKey {
		t.Errorf("BootstrapPublicKey mismatch: got %s, want %s",
			bundle.BootstrapPublicKey, id1.PublicKey)
	}
}

// =============================================================================
// E2E Test 5: Rate limiting with burst joiners
// =============================================================================
func TestE2E_RateLimitingWithBurstJoiners(t *testing.T) {
	opts := defaultE2EOpts()
	opts.MaxJoinRequests = 50
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	numCallers := 10
	var wg sync.WaitGroup
	results := make(chan error, numCallers)

	for i := 0; i < numCallers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token, genErr := GenerateToken(secret, id.PublicKey, 5*time.Minute)
			if genErr != nil {
				results <- genErr
				return
			}
			joiner, _ := identity.GenerateIdentity()
			client := e2eJoinClient(ts, token, joiner, fmt.Sprintf("burst-node-%d", idx))
			_, err := client.RequestJoin(context.Background())
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	successes, rateLimited, other := 0, 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if strings.Contains(err.Error(), "join rejected") {
			rateLimited++
		} else {
			other++
			t.Logf("unexpected error: %v", err)
		}
	}
	t.Logf("Burst %d joiners: %d success, %d rate-limited, %d other", numCallers, successes, rateLimited, other)
	if successes == 0 {
		t.Error("expected at least some successful joins")
	}
}

// =============================================================================
// E2E Test 6: Empty collectors list
// =============================================================================
func TestE2E_EmptyCollectors(t *testing.T) {
	opts := defaultE2EOpts()
	opts.Collectors = nil
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()
	client := e2eJoinClient(ts, token, joiner, "empty-collector-node")

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin: %v", err)
	}
	if len(bundle.Collectors) != 0 {
		t.Errorf("Collectors = %v, want empty", bundle.Collectors)
	}
}

// =============================================================================
// E2E Test 7: Joiner without endpoint (NAT scenario)
// =============================================================================
func TestE2E_JoinerWithoutEndpoint(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, _ := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, srv.cfg.ServerIdentity.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()
	client := e2eJoinClient(ts, token, joiner, "nat-node")
	// JoinerEndpoint intentionally empty — NAT'd nodes often don't know their public endpoint
	client.cfg.JoinerEndpoint = ""

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin without endpoint: %v", err)
	}
	if len(bundle.Collectors) != 2 {
		t.Errorf("Collectors len = %d, want 2", len(bundle.Collectors))
	}
}

// =============================================================================
// E2E Test 8: Server shutdown during request
// =============================================================================
func TestE2E_ServerShutdownDuringRequest(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	// Don't defer Stop here — we control shutdown.

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if err := srv.Start(addr); err != nil {
		t.Fatalf("Start: %v", err)
	}

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)

	// Shut down, then try to request.
	srv.Stop()

	joiner, _ := identity.GenerateIdentity()
	client := NewJoinClient(ClientConfig{
		ServerURL:       "http://" + addr,
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "post-shutdown",
		JoinerSigner:    joiner,
		Timeout:         2 * time.Second,
		AllowPlainHTTP:  true,
	})

	_, err = client.RequestJoin(context.Background())
	if err == nil {
		t.Error("expected error after server shutdown")
	}
	t.Logf("Post-shutdown error (expected): %v", err)
}

// =============================================================================
// E2E Test 9: Plain HTTP refused by default
// =============================================================================
// Validates that the client refuses non-HTTPS URLs by default.
// The client must only proceed if AllowPlainHTTP is explicitly set to true.
func TestE2E_PlainHTTPRefusedByDefault(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()

	// Client WITHOUT AllowPlainHTTP — should refuse.
	client := NewJoinClient(ClientConfig{
		ServerURL:       ts.URL, // http:// URL
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "http-refused",
		JoinerSigner:    joiner,
		Timeout:         5 * time.Second,
		// AllowPlainHTTP not set — defaults to false
	})

	_, err := client.RequestJoin(context.Background())
	if err == nil {
		t.Fatal("expected error for plain HTTP URL, got nil — client should refuse by default")
	}
	if !strings.Contains(err.Error(), "refusing to use non-HTTPS") {
		t.Errorf("expected 'refusing to use non-HTTPS' error, got: %v", err)
	}
	t.Log("Plain HTTP refused by default ✓")

	// Client WITH AllowPlainHTTP — should succeed.
	token2, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner2, _ := identity.GenerateIdentity()
	client2 := e2eJoinClient(ts, token2, joiner2, "http-allowed")

	bundle, err := client2.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin with AllowPlainHTTP failed: %v", err)
	}
	if bundle == nil {
		t.Fatal("bundle is nil")
	}
	t.Log("Plain HTTP allowed with AllowPlainHTTP=true ✓")
}

// =============================================================================
// E2E Test 10: Missing JoinerSigner is rejected
// =============================================================================
func TestE2E_MissingSignerRejected(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)

	// Client WITHOUT JoinerSigner — should fail.
	client := NewJoinClient(ClientConfig{
		ServerURL:       ts.URL,
		Token:           token,
		JoinerPublicKey: "some-pubkey",
		JoinerHostname:  "no-signer",
		Timeout:         5 * time.Second,
		AllowPlainHTTP:  true,
		// JoinerSigner not set
	})

	_, err := client.RequestJoin(context.Background())
	if err == nil {
		t.Fatal("expected error for missing JoinerSigner, got nil")
	}
	if !strings.Contains(err.Error(), "JoinerSigner is required") {
		t.Errorf("expected 'JoinerSigner is required' error, got: %v", err)
	}
	t.Log("Missing JoinerSigner rejected ✓")
}

// =============================================================================
// E2E Test 11: Malformed requests
// =============================================================================
func TestE2E_MalformedRequests(t *testing.T) {
	opts := defaultE2EOpts()
	srv, _, _ := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tests := []struct {
		name        string
		body        string
		contentType string
		wantCode    int
	}{
		{"empty body", "", "application/json", http.StatusBadRequest},
		{"invalid JSON", "{broken", "application/json", http.StatusBadRequest},
		{"missing token", `{"joiner_pubkey":"pk","joiner_hostname":"h"}`, "application/json", http.StatusUnauthorized},
		{"empty token", `{"token":"","joiner_pubkey":"pk"}`, "application/json", http.StatusUnauthorized},
		{"wrong content type", "raw text", "text/plain", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/api/join", tt.contentType, strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantCode {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantCode)
			}
		})
	}
}

// =============================================================================
// E2E Test 12: Bundle application simulation (main.go:1114-1151)
// =============================================================================
func TestE2E_BundleApplicationSimulation(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	srv.SetKnownPeersFunc(func() []PeerInfo {
		return []PeerInfo{
			{PublicKey: "mesh-peer-abc", Hostname: "node-a", Role: "agent", Endpoint: "node-a:52888"},
			{PublicKey: "mesh-peer-def", Hostname: "node-b", Role: "relay", Endpoint: "node-b:52888"},
		}
	})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()
	client := e2eJoinClient(ts, token, joiner, "applying-node")
	client.cfg.JoinerEndpoint = "applying-node:52888"

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin: %v", err)
	}

	// Simulate main.go:1114-1151 — the joiner applies the bundle.
	// 1. Use bootstrap public key
	if bundle.BootstrapPublicKey == "" {
		t.Error("bootstrap key is empty — joiner can't connect")
	}
	// 2. Use bootstrap endpoint
	if bundle.BootstrapEndpoint == "" {
		t.Error("bootstrap endpoint is empty — joiner can't connect")
	}
	// 3. Use gossip port
	if bundle.GossipPort == 0 {
		t.Error("gossip port is zero — joiner can't configure gossip")
	}
	// 4. Apply collectors
	if len(bundle.Collectors) == 0 {
		t.Error("collectors are empty — joiner has no monitoring targets")
	}
	// 5. Configure REALITY peer
	if bundle.RealityPublicKey != "" {
		// The joiner can add a peer with REALITY config (main.go:1128-1141)
		peerConfigValid := bundle.BootstrapPublicKey != "" &&
			bundle.BootstrapEndpoint != "" &&
			bundle.RealityServerName != "" &&
			bundle.RealityShortID != ""
		if !peerConfigValid {
			t.Error("REALITY peer config is incomplete")
		}
	}
	// 6. KnownPeers for immediate mesh view
	if len(bundle.KnownPeers) != 2 {
		t.Errorf("KnownPeers len = %d, want 2", len(bundle.KnownPeers))
	}

	// 7. IssuedAt timestamp
	if bundle.IssuedAt <= 0 {
		t.Error("IssuedAt is missing")
	}

	t.Log("Bundle application: all required fields present for peer config + collector setup")
}

// =============================================================================
// E2E Test 13: Many concurrent unique joiners
// =============================================================================
func TestE2E_ManyConcurrentUniqueJoiners(t *testing.T) {
	opts := defaultE2EOpts()
	opts.MaxJoinRequests = 100 // high limit to avoid rate-limiting
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	numJoiners := 10
	var wg sync.WaitGroup
	errCh := make(chan error, numJoiners)

	for i := 0; i < numJoiners; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token, genErr := GenerateToken(secret, id.PublicKey, 5*time.Minute)
			if genErr != nil {
				errCh <- genErr
				return
			}
			joiner, _ := identity.GenerateIdentity()
			client := e2eJoinClient(ts, token, joiner, fmt.Sprintf("concurrent-node-%d", idx))
			_, err := client.RequestJoin(context.Background())
			errCh <- err
		}(i)
	}
	wg.Wait()
	close(errCh)

	successes, failures := 0, 0
	for err := range errCh {
		if err != nil {
			failures++
			t.Logf("joiner error: %v", err)
		} else {
			successes++
		}
	}
	t.Logf("Concurrent unique joiners: %d/%d successes", successes, numJoiners)
	if successes == 0 {
		t.Error("expected at least some successful joins")
	}
	if failures > 0 {
		t.Logf("%d failures — may be rate-limiting or contention", failures)
	}
}

// =============================================================================
// E2E Test 14: ConfigBundle completeness check
// =============================================================================
func TestE2E_ConfigBundleCompleteness(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	srv.SetKnownPeersFunc(func() []PeerInfo {
		return []PeerInfo{
			{PublicKey: "peer-1", Hostname: "h1", Role: "agent"},
			{PublicKey: "peer-2", Hostname: "h2", Role: "agent"},
			{PublicKey: "peer-3", Hostname: "h3", Role: "relay"},
		}
	})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()
	client := e2eJoinClient(ts, token, joiner, "completeness-node")

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin: %v", err)
	}

	// The bundle MUST have all required fields for peer configuration.
	required := []struct {
		field string
		value string
	}{
		{"BootstrapPublicKey", bundle.BootstrapPublicKey},
		{"BootstrapEndpoint", bundle.BootstrapEndpoint},
		{"RealityPublicKey", bundle.RealityPublicKey},
		{"RealityShortID", bundle.RealityShortID},
		{"RealityServerName", bundle.RealityServerName},
	}
	for _, r := range required {
		if r.value == "" {
			t.Errorf("%s is empty — joiner can't configure peer", r.field)
		}
	}

	// Collectors may be empty but must be non-nil (JSON marshals as [] not null).
	if bundle.Collectors == nil {
		t.Error("Collectors is nil — should be empty slice when no collectors configured")
	}

	// KnownPeers may be empty/nil if no KnownPeersFunc is set.
	// GossipPort must be > 0.
	if bundle.GossipPort == 0 {
		t.Error("GossipPort is 0 — joiner needs a gossip port")
	}

	// IssuedAt must be set.
	if bundle.IssuedAt <= 0 {
		t.Error("IssuedAt is zero")
	}
}

// =============================================================================
// E2E Test 15: verify blocker C1 (private key leaked as public key)
// =============================================================================
// This test validates that the ConfigBundle.RealityPublicKey field is correctly
// populated. The parent audit flagged main.go:783 where cfg.Reality.PrivateKey
// (a private key) is assigned to this field instead of the X25519 public key.
// We can't directly test main.go wiring from this package, so we verify that
// the server-side struct correctly passes through whatever key is given.
func TestE2E_BlockerC1_RealityKeyPassthrough(t *testing.T) {
	// The server forwards whatever RealityPublicKey is in ServerConfig.
	// If a caller (like main.go) passes PrivateKey, that's what appears in the bundle.
	// This test confirms the passthrough behavior that makes C1 a critical bug.
	privateKeyValue := "this-is-supposed-to-be-private-key-not-public"
	opts := defaultE2EOpts()
	opts.RealityPublicKey = privateKeyValue
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()
	client := e2eJoinClient(ts, token, joiner, "c1-node")

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin: %v", err)
	}

	// The bundle leaks whatever was passed as RealityPublicKey — including a private key.
	if bundle.RealityPublicKey != privateKeyValue {
		t.Errorf("RealityPublicKey = %s, want %s (passthrough broken)", bundle.RealityPublicKey, privateKeyValue)
	}
	t.Log("C1 BLOCKER CONFIRMED: ServerConfig.RealityPublicKey is passed through " +
		"to ConfigBundle.RealityPublicKey without transformation. " +
		"If main.go:783 passes cfg.Reality.PrivateKey, the X25519 private key " +
		"is distributed in the config bundle — a critical security leak.")
}

// =============================================================================
// E2E Test 16: No KnownPeers function set
// =============================================================================
func TestE2E_NoKnownPeersFunc(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()
	// Intentionally do NOT set KnownPeersFunc.

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	joiner, _ := identity.GenerateIdentity()
	client := e2eJoinClient(ts, token, joiner, "no-peers-node")

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin: %v", err)
	}

	if len(bundle.KnownPeers) != 0 {
		t.Errorf("KnownPeers len = %d, want 0 (no KnownPeersFunc set)", len(bundle.KnownPeers))
	}
}

// =============================================================================
// E2E Test 17: Step 1 does not return bundle (security enforcement)
// =============================================================================
// Validates that the server NEVER returns a config bundle in step 1.
// The bundle must only be returned after the challenge is verified.
func TestE2E_Step1NoBundle(t *testing.T) {
	opts := defaultE2EOpts()
	srv, secret, id := newE2EServer(t, opts)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)

	// Raw HTTP call for step 1 only (no challenge response).
	jr, status := doJoinRequest(t, ts, JoinRequest{
		Token:           token,
		JoinerPublicKey: "step1-only-pubkey",
		JoinerHostname:  "step1-only-node",
	})
	if status != http.StatusOK {
		t.Fatalf("step 1: expected 200, got %d", status)
	}
	if !jr.Success {
		t.Fatalf("step 1: not successful: %s", jr.Error)
	}
	if jr.Challenge == "" {
		t.Fatal("step 1: challenge is empty")
	}
	if jr.Bundle != nil {
		t.Fatal("SECURITY GAP: server returned bundle in step 1 — " +
			"bundle must only be returned after challenge verification")
	}
	t.Log("Step 1 correctly returns challenge without bundle ✓")
}

// =============================================================================
// Helpers
// =============================================================================

// assertBundle verifies all fields in a ConfigBundle match expectations.
func assertBundle(t *testing.T, bundle *ConfigBundle, expectedPubKey string, opts *e2eServerOpts, wantCollectors, wantPeers int) {
	t.Helper()
	if bundle.BootstrapPublicKey != expectedPubKey {
		t.Errorf("BootstrapPublicKey = %s, want %s", bundle.BootstrapPublicKey, expectedPubKey)
	}
	if bundle.BootstrapEndpoint != opts.BootstrapEndpoint {
		t.Errorf("BootstrapEndpoint = %s, want %s", bundle.BootstrapEndpoint, opts.BootstrapEndpoint)
	}
	if bundle.GossipPort != opts.GossipPort {
		t.Errorf("GossipPort = %d, want %d", bundle.GossipPort, opts.GossipPort)
	}
	if bundle.RealityPublicKey != opts.RealityPublicKey {
		t.Errorf("RealityPublicKey = %s, want %s", bundle.RealityPublicKey, opts.RealityPublicKey)
	}
	if bundle.RealityShortID != opts.RealityShortID {
		t.Errorf("RealityShortID = %s, want %s", bundle.RealityShortID, opts.RealityShortID)
	}
	if bundle.RealityServerName != opts.RealityServerName {
		t.Errorf("RealityServerName = %s, want %s", bundle.RealityServerName, opts.RealityServerName)
	}
	if len(bundle.Collectors) != wantCollectors {
		t.Errorf("Collectors len = %d, want %d: %v", len(bundle.Collectors), wantCollectors, bundle.Collectors)
	}
	if len(bundle.KnownPeers) != wantPeers {
		t.Errorf("KnownPeers len = %d, want %d", len(bundle.KnownPeers), wantPeers)
	}
	if bundle.IssuedAt <= 0 {
		t.Error("IssuedAt is zero or negative")
	}
}
