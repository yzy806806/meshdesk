package join

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/identity"
)

// --- Token Tests ---

func TestGenerateAndParseToken(t *testing.T) {
	secret := []byte("test-secret-key")
	serverFP := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	raw, err := GenerateToken(secret, serverFP, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if raw == "" {
		t.Fatal("GenerateToken returned empty token")
	}

	token, err := ParseToken(raw, secret)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}
	if token.Version != TokenVersion {
		t.Errorf("version = %d, want %d", token.Version, TokenVersion)
	}
	if token.ServerFP != serverFP {
		t.Errorf("ServerFP = %s, want %s", token.ServerFP, serverFP)
	}
	if token.Nonce == "" {
		t.Error("Nonce is empty")
	}

	// Token should not be expired (expires in ~5 min).
	if time.Now().Unix() >= token.ExpiresAt {
		t.Error("Token is already expired")
	}
}

func TestParseToken_WrongSecret(t *testing.T) {
	secret1 := []byte("secret-one")
	secret2 := []byte("secret-two")
	serverFP := "abc123"

	raw, _ := GenerateToken(secret1, serverFP, 5*time.Minute)

	_, err := ParseToken(raw, secret2)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestParseToken_Expired(t *testing.T) {
	secret := []byte("test-secret")
	serverFP := "fp"

	// Generate a token with very short lifetime, then let it expire.
	raw, _ := GenerateToken(secret, serverFP, 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	_, err := ParseToken(raw, secret)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestParseToken_TamperedToken(t *testing.T) {
	secret := []byte("test-secret")
	serverFP := "fp"

	raw, _ := GenerateToken(secret, serverFP, 5*time.Minute)

	// Tamper with the token by flipping a character.
	if len(raw) > 10 {
		tampered := raw[:10]
		if tampered[9] == 'A' {
			tampered = tampered[:8] + "B" + tampered[9:]
		} else {
			tampered = tampered[:8] + "A" + tampered[9:]
		}
		tampered += raw[10:]
		raw = tampered
	}

	_, err := ParseToken(raw, secret)
	if err == nil {
		t.Error("expected error for tampered token, got nil")
	}
}

func TestParseToken_InvalidBase64(t *testing.T) {
	_, err := ParseToken("!!!invalid-base64!!!", []byte("secret"))
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

// --- Replay Cache Tests ---

func TestReplayCache_CheckAndMark(t *testing.T) {
	cache := NewReplayCache(5 * time.Minute)

	// First use: should succeed.
	err := cache.CheckAndMark("nonce-1", time.Now().Add(5*time.Minute).Unix())
	if err != nil {
		t.Errorf("first CheckAndMark failed: %v", err)
	}

	// Replay: should fail.
	err = cache.CheckAndMark("nonce-1", time.Now().Add(5*time.Minute).Unix())
	if err != ErrTokenReplayed {
		t.Errorf("expected ErrTokenReplayed, got %v", err)
	}

	// Different nonce: should succeed.
	err = cache.CheckAndMark("nonce-2", time.Now().Add(5*time.Minute).Unix())
	if err != nil {
		t.Errorf("second CheckAndMark failed: %v", err)
	}

	if cache.EntryCount() != 2 {
		t.Errorf("EntryCount = %d, want 2", cache.EntryCount())
	}
}

func TestReplayCache_ExpiredEntries(t *testing.T) {
	cache := NewReplayCache(1 * time.Millisecond)

	cache.CheckAndMark("old-nonce", time.Now().Unix()) // already expired
	time.Sleep(5 * time.Millisecond)

	// After expiry, the same nonce should be accepted again.
	err := cache.CheckAndMark("old-nonce", time.Now().Add(5*time.Minute).Unix())
	if err != nil {
		t.Errorf("CheckAndMark after expiry failed: %v", err)
	}
}

// --- Server Tests ---

// newTestServer creates a JoinServer with a real identity for signing/verifying.
func newTestServer(t *testing.T) (*JoinServer, []byte, *identity.Identity) {
	t.Helper()
	id, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	secret := []byte("test-hmac-secret")
	cfg := ServerConfig{
		Secret:            secret,
		ServerIdentity:    id,
		BootstrapEndpoint: "127.0.0.1:52888",
		GossipPort:        7946,
		RealityPublicKey:  "deadbeef",
		RealityShortID:    "0123456789abcdef",
		RealityServerName: "www.example.com",
		Collectors:        []string{"collector1", "collector2"},
		TokenLifetime:     30 * time.Minute,
	}
	return NewJoinServer(cfg), secret, id
}

// newTestJoiner creates a fresh identity for a joining node.
func newTestJoiner(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

// doJoinRequest performs a raw HTTP POST to the join server.
// Returns the parsed JoinResponse and HTTP status code.
func doJoinRequest(t *testing.T, ts *httptest.Server, req JoinRequest) (JoinResponse, int) {
	t.Helper()
	bodyBytes, _ := json.Marshal(req)
	resp, err := http.Post(ts.URL+"/api/join", "application/json", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var jr JoinResponse
	if err := json.Unmarshal(body, &jr); err != nil {
		t.Fatalf("decode response (status=%d): %v: %s", resp.StatusCode, err, body)
	}
	return jr, resp.StatusCode
}

// doFullJoin performs the two-step challenge-response join flow using
// the JoinClient and returns the config bundle.
func doFullJoin(t *testing.T, ts *httptest.Server, token string, joiner *identity.Identity, hostname string) *ConfigBundle {
	t.Helper()
	client := NewJoinClient(ClientConfig{
		ServerURL:       ts.URL,
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  hostname,
		JoinerSigner:    joiner,
		Timeout:         5 * time.Second,
		AllowPlainHTTP:  true, // test servers use plain HTTP
	})
	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin failed: %v", err)
	}
	return bundle
}

func TestJoinServer_ValidToken(t *testing.T) {
	srv, secret, id := newTestServer(t)
	defer srv.Stop()

	// Generate a token.
	token, err := GenerateToken(secret, id.PublicKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// Create a test HTTP server.
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	joiner := newTestJoiner(t)
	bundle := doFullJoin(t, ts, token, joiner, "test-joiner")

	if bundle.BootstrapPublicKey != id.PublicKey {
		t.Errorf("BootstrapPublicKey = %s, want %s",
			bundle.BootstrapPublicKey, id.PublicKey)
	}
	if len(bundle.Collectors) != 2 {
		t.Errorf("Collectors len = %d, want 2", len(bundle.Collectors))
	}
	if bundle.RealityPublicKey != "deadbeef" {
		t.Errorf("RealityPublicKey = %s, want deadbeef", bundle.RealityPublicKey)
	}
}

func TestJoinServer_ReplayedToken(t *testing.T) {
	srv, secret, id := newTestServer(t)
	defer srv.Stop()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	joiner := newTestJoiner(t)

	// First request: step 1 (challenge).
	jr1, _ := doJoinRequest(t, ts, JoinRequest{
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "test-replay",
	})
	if !jr1.Success || jr1.Challenge == "" {
		t.Fatalf("first request: expected challenge, got: %+v", jr1)
	}

	// Sign the challenge and complete step 2.
	sig, err := joiner.Sign([]byte(jr1.Challenge))
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	jr2, _ := doJoinRequest(t, ts, JoinRequest{
		Token:             token,
		JoinerPublicKey:   joiner.PublicKey,
		JoinerHostname:    "test-replay",
		Challenge:         jr1.Challenge,
		ChallengeResponse: sig,
	})
	if !jr2.Success || jr2.Bundle == nil {
		t.Fatalf("second request: expected bundle, got: %+v", jr2)
	}

	// Third request with same token: should be rejected (replay).
	// The token nonce was already marked in step 1.
	_, status3 := doJoinRequest(t, ts, JoinRequest{
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "test-replay-3",
	})
	if status3 != http.StatusUnauthorized {
		t.Errorf("third request: expected 401, got %d", status3)
	}
}

func TestJoinServer_InvalidToken(t *testing.T) {
	srv, _, _ := newTestServer(t)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	reqBody := JoinRequest{
		Token:           "invalid-token-data",
		JoinerPublicKey: "joiner-pubkey",
		JoinerHostname:  "test-invalid",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/api/join", "application/json", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestJoinServer_WrongServerFP(t *testing.T) {
	srv, secret, _ := newTestServer(t)
	defer srv.Stop()

	// Generate token with wrong server fingerprint.
	token, _ := GenerateToken(secret, "wrong-fingerprint", 5*time.Minute)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	reqBody := JoinRequest{
		Token:           token,
		JoinerPublicKey: "joiner-pubkey",
		JoinerHostname:  "test-wrong-fp",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	resp, err := http.Post(ts.URL+"/api/join", "application/json", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong server FP, got %d", resp.StatusCode)
	}
}

func TestJoinServer_MethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/join")
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestJoinServer_RateLimit(t *testing.T) {
	srv, secret, id := newTestServer(t)
	srv.cfg.MaxJoinRequests = 2 // low limit for testing
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Make 3 requests with different tokens (to avoid replay rejection).
	// Only step 1 (challenge) is sent — each uses 1 rate-limit slot.
	// With MaxJoinRequests=2, the 3rd should be rate-limited.
	for i := 0; i < 3; i++ {
		token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)
		reqBody := JoinRequest{
			Token:           token,
			JoinerPublicKey: fmt.Sprintf("joiner-%d-pubkey", i),
			JoinerHostname:  "test-rate-limit",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		resp, err := http.Post(ts.URL+"/api/join", "application/json", strings.NewReader(string(bodyBytes)))
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}

		if i < 2 {
			if resp.StatusCode != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", i, resp.StatusCode)
			}
		} else {
			// Third request should be rate-limited.
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Errorf("request %d: expected 429, got %d", i, resp.StatusCode)
			}
		}
		resp.Body.Close()
	}
}

func TestJoinServer_KnownPeersFunc(t *testing.T) {
	srv, secret, id := newTestServer(t)
	defer srv.Stop()

	srv.SetKnownPeersFunc(func() []PeerInfo {
		return []PeerInfo{
			{PublicKey: "peer1", Hostname: "node1", Role: "agent"},
			{PublicKey: "peer2", Hostname: "node2", Role: "relay"},
		}
	})

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	joiner := newTestJoiner(t)
	bundle := doFullJoin(t, ts, token, joiner, "test-peers")

	if len(bundle.KnownPeers) != 2 {
		t.Errorf("KnownPeers len = %d, want 2", len(bundle.KnownPeers))
	}
	if bundle.KnownPeers[0].PublicKey != "peer1" {
		t.Errorf("KnownPeers[0].PublicKey = %s, want peer1", bundle.KnownPeers[0].PublicKey)
	}
}

func TestJoinServer_StartAndStop(t *testing.T) {
	srv, _, _ := newTestServer(t)
	defer srv.Stop()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if err := srv.Start(addr); err != nil {
		t.Fatalf("Start: %v", err)
	}

	resp, err := http.Get("http://" + addr + "/api/join")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// --- Client Tests ---

func TestJoinClient_RequestJoin(t *testing.T) {
	srv, secret, id := newTestServer(t)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token, _ := GenerateToken(secret, id.PublicKey, 5*time.Minute)

	joiner := newTestJoiner(t)

	client := NewJoinClient(ClientConfig{
		ServerURL:       ts.URL,
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "client-host",
		JoinerSigner:    joiner,
		Timeout:         5 * time.Second,
		AllowPlainHTTP:  true,
	})

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin failed: %v", err)
	}

	if bundle.BootstrapPublicKey != id.PublicKey {
		t.Errorf("BootstrapPublicKey = %s, want %s",
			bundle.BootstrapPublicKey, id.PublicKey)
	}
}

func TestJoinClient_RejectedToken(t *testing.T) {
	srv, _, _ := newTestServer(t)
	defer srv.Stop()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	joiner := newTestJoiner(t)

	client := NewJoinClient(ClientConfig{
		ServerURL:       ts.URL,
		Token:           "invalid-token",
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "client-host",
		JoinerSigner:    joiner,
		Timeout:         5 * time.Second,
		AllowPlainHTTP:  true,
	})

	_, err := client.RequestJoin(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
	if !strings.Contains(err.Error(), "join rejected") {
		t.Errorf("expected 'join rejected' error, got: %v", err)
	}
}

// --- Integration test: full token-based join flow ---

func TestFullJoinFlow(t *testing.T) {
	// Set up the join server.
	srv, secret, id := newTestServer(t)
	defer srv.Stop()

	srv.SetKnownPeersFunc(func() []PeerInfo {
		return []PeerInfo{
			{PublicKey: "existing-peer-1", Hostname: "node1", Role: "agent"},
		}
	})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Step 1: Generate a token (as the server operator would).
	token, err := GenerateToken(secret, id.PublicKey, 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// Step 2: Client requests join.
	joiner := newTestJoiner(t)
	client := NewJoinClient(ClientConfig{
		ServerURL:       ts.URL,
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "new-node",
		JoinerSigner:    joiner,
		Timeout:         5 * time.Second,
		AllowPlainHTTP:  true,
	})

	bundle, err := client.RequestJoin(context.Background())
	if err != nil {
		t.Fatalf("RequestJoin: %v", err)
	}

	// Step 3: Verify the bundle contains expected data.
	if bundle.BootstrapPublicKey != id.PublicKey {
		t.Errorf("BootstrapPublicKey mismatch")
	}
	if bundle.BootstrapEndpoint != "127.0.0.1:52888" {
		t.Errorf("BootstrapEndpoint = %s, want 127.0.0.1:52888", bundle.BootstrapEndpoint)
	}
	if bundle.RealityPublicKey != "deadbeef" {
		t.Errorf("RealityPublicKey = %s, want deadbeef", bundle.RealityPublicKey)
	}
	if len(bundle.Collectors) != 2 {
		t.Errorf("Collectors len = %d, want 2", len(bundle.Collectors))
	}
	if len(bundle.KnownPeers) != 1 {
		t.Errorf("KnownPeers len = %d, want 1", len(bundle.KnownPeers))
	}

	// Step 4: Verify the token can't be replayed.
	_, err = client.RequestJoin(context.Background())
	if err == nil {
		t.Error("replay should fail but succeeded")
	}
}
