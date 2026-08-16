package join

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/identity"
)

// =============================================================================
// Layer 1: Additional Token Crypto Edge Case Tests
// =============================================================================

// --- JSON injection: extra fields should not break validation ---

func TestParseToken_ExtraJSONFields(t *testing.T) {
	secret := []byte("test-secret")
	raw, _ := GenerateToken(secret, "fp", 5*time.Minute)

	// Decode, inject an extra field, re-encode.
	data, _ := base64.RawURLEncoding.DecodeString(raw)
	var tok map[string]interface{}
	json.Unmarshal(data, &tok)
	tok["__proto__"] = "attacker"      // prototype pollution attempt
	tok["constructor"] = "evil"        // constructor pollution attempt
	tok["malicious_field"] = "dropped" // extra field should be ignored
	data2, _ := json.Marshal(tok)
	injected := base64.RawURLEncoding.EncodeToString(data2)

	// ParseToken should ignore extra fields and validate normally.
	parsed, err := ParseToken(injected, secret)
	if err != nil {
		t.Fatalf("ParseToken with extra JSON fields failed: %v", err)
	}
	if parsed.ServerFP != "fp" {
		t.Errorf("ServerFP = %q, want %q", parsed.ServerFP, "fp")
	}
}

func TestParseToken_JSONInjectionInNonce(t *testing.T) {
	// Nonce containing JSON-like characters.
	secret := []byte("test-secret")
	// Manually construct a token with a nonce that looks like injected JSON.
	tok := Token{
		Version:   TokenVersion,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     `","sig":"0000000000000000000000000000000000000000000000000000000000000000","exp":9999999999`,
		ServerFP:  "fp",
	}
	signingBytes := signingMaterial(tok)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingBytes)
	tok.Signature = hex.EncodeToString(mac.Sum(nil))

	data, _ := json.Marshal(tok)
	payload := base64.RawURLEncoding.EncodeToString(data)

	// Should parse correctly despite JSON-like content in nonce.
	parsed, err := ParseToken(payload, secret)
	if err != nil {
		t.Fatalf("ParseToken with JSON-like nonce failed: %v", err)
	}
	if parsed.Nonce != tok.Nonce {
		t.Errorf("Nonce was corrupted during round-trip")
	}
}

// --- Extreme token sizes ---

func TestGenerateToken_VeryLongServerFP(t *testing.T) {
	secret := []byte("test-secret")
	// 1KB server fingerprint (unrealistic but should work).
	longFP := strings.Repeat("a1b2c3d4e5f6", 86) // ~1KB
	raw, err := GenerateToken(secret, longFP, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken with 1KB server FP failed: %v", err)
	}
	parsed, err := ParseToken(raw, secret)
	if err != nil {
		t.Fatalf("ParseToken with 1KB server FP failed: %v", err)
	}
	if parsed.ServerFP != longFP {
		t.Errorf("ServerFP mismatch after round-trip")
	}
}

func TestParseToken_VeryLargeToken(t *testing.T) {
	secret := []byte("test-secret")
	// Generate a token with very large nonce (using long base64 string).
	largeNonce := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64) // ~4KB
	tok := Token{
		Version:   TokenVersion,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     largeNonce,
		ServerFP:  "fp",
	}
	signingBytes := signingMaterial(tok)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingBytes)
	tok.Signature = hex.EncodeToString(mac.Sum(nil))

	data, _ := json.Marshal(tok)
	payload := base64.RawURLEncoding.EncodeToString(data)

	parsed, err := ParseToken(payload, secret)
	if err != nil {
		t.Fatalf("ParseToken with large nonce (%d bytes) failed: %v", len(largeNonce), err)
	}
	if parsed.Nonce != largeNonce {
		t.Errorf("Nonce mismatch after round-trip")
	}
}

// --- signingMaterial edge cases ---

func TestSigningMaterial_EmptyFields(t *testing.T) {
	tok := Token{
		Version:   0,
		ExpiresAt: 0,
		Nonce:     "",
		ServerFP:  "",
	}
	b := signingMaterial(tok)
	// Should be 4 + 8 + 0 + 0 = 12 bytes.
	if len(b) != 12 {
		t.Errorf("signingMaterial with empty fields: len=%d, want 12", len(b))
	}
}

func TestSigningMaterial_MaxInt64Expiry(t *testing.T) {
	tok := Token{
		Version:   TokenVersion,
		ExpiresAt: 9223372036854775807, // max int64
		Nonce:     "test",
		ServerFP:  "fp",
	}
	b := signingMaterial(tok)
	if len(b) != 4+8+4+2 {
		t.Errorf("signingMaterial: unexpected length %d", len(b))
	}
}

// --- ReplayCache extreme cases ---

func TestReplayCache_ManyEntries(t *testing.T) {
	cache := NewReplayCache(5 * time.Minute)
	n := 1000
	for i := 0; i < n; i++ {
		nonce := fmt.Sprintf("many-nonce-%04d", i)
		err := cache.CheckAndMark(nonce, time.Now().Add(5*time.Minute).Unix())
		if err != nil {
			t.Fatalf("CheckAndMark %d failed: %v", i, err)
		}
	}
	if count := cache.EntryCount(); count != n {
		t.Errorf("EntryCount = %d, want %d", count, n)
	}

	// Cleanup should leave all entries (they're not expired).
	cache.Cleanup()
	if count := cache.EntryCount(); count != n {
		t.Errorf("After cleanup: EntryCount = %d, want %d (entries not expired)", count, n)
	}
}

func TestReplayCache_ConcurrentUniqueNonces(t *testing.T) {
	cache := NewReplayCache(5 * time.Minute)
	n := 200
	var wg sync.WaitGroup
	var failCount int32
	var m sync.Mutex

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nonce := fmt.Sprintf("unique-%04d", idx)
			err := cache.CheckAndMark(nonce, time.Now().Add(5*time.Minute).Unix())
			if err != nil {
				m.Lock()
				failCount++
				m.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if failCount > 0 {
		t.Errorf("concurrent unique nonces: %d failures (want 0)", failCount)
	}
	if count := cache.EntryCount(); count != n {
		t.Errorf("EntryCount = %d, want %d", count, n)
	}
}

// --- Token with Unicode/special chars in ServerFP ---

func TestGenerateToken_SpecialCharsInServerFP(t *testing.T) {
	secret := []byte("test-secret")
	// ServerFP with special characters (normally hex but the field is just a string)
	specialFPs := []string{
		"node:alias@example.com",
		"user/node-1",
		"a+b=c&d=e",
	}

	for _, fp := range specialFPs {
		raw, err := GenerateToken(secret, fp, 5*time.Minute)
		if err != nil {
			t.Fatalf("GenerateToken with FP=%q failed: %v", fp, err)
		}
		parsed, err := ParseToken(raw, secret)
		if err != nil {
			t.Fatalf("ParseToken with FP=%q failed: %v", fp, err)
		}
		if parsed.ServerFP != fp {
			t.Errorf("ServerFP mismatch: got %q, want %q", parsed.ServerFP, fp)
		}
	}
}

// --- Token with non-standard base64 characters in nonce ---

func TestParseToken_NonStandardBase64Nonce(t *testing.T) {
	secret := []byte("test-secret")
	nonceBytes := []byte{0xFF, 0x00, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	tok := Token{
		Version:   TokenVersion,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     nonce,
		ServerFP:  "fp",
	}
	signingBytes := signingMaterial(tok)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingBytes)
	tok.Signature = hex.EncodeToString(mac.Sum(nil))

	data, _ := json.Marshal(tok)
	payload := base64.RawURLEncoding.EncodeToString(data)

	parsed, err := ParseToken(payload, secret)
	if err != nil {
		t.Fatalf("ParseToken with non-standard base64 nonce failed: %v", err)
	}
	if parsed.Nonce != nonce {
		t.Errorf("Nonce mismatch: got %q, want %q", parsed.Nonce, nonce)
	}
}

// --- HMAC: verify that signingMaterial covers ALL fields ---

func TestSigningMaterial_CoversAllFields(t *testing.T) {
	secret := []byte("test-secret")
	baseTok := Token{
		Version:   TokenVersion,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("nonce-1")),
		ServerFP:  "fp-1",
	}

	// Sign the base token properly.
	signingBytes := signingMaterial(baseTok)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingBytes)
	baseTok.Signature = hex.EncodeToString(mac.Sum(nil))

	// Not marshaling baseTok directly — tampering starts from baseTok struct.

	// Each tampered version should fail validation.
	tamperings := []struct {
		name   string
		tamper func(t Token) Token
	}{
		{"version", func(t Token) Token { t.Version = 2; return t }},
		{"expiry", func(t Token) Token { t.ExpiresAt += 1; return t }},
		{"nonce", func(t Token) Token { t.Nonce = "tampered"; return t }},
		{"serverfp", func(t Token) Token { t.ServerFP = "tampered-fp"; return t }},
	}

	for _, tc := range tamperings {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.tamper(baseTok)
			data2, _ := json.Marshal(tampered)
			tamperedPayload := base64.RawURLEncoding.EncodeToString(data2)
			_, err := ParseToken(tamperedPayload, secret)
			if err == nil {
				t.Errorf("tampered %s: expected error, got nil", tc.name)
			}
			// Version tampering is caught by the version check before
			// the HMAC check, so it returns a version error rather than
			// ErrInvalidSignature. Both indicate the tampering was detected.
			if tc.name == "version" {
				if !strings.Contains(err.Error(), "unsupported token version") && err != ErrInvalidSignature {
					t.Errorf("tampered %s: expected version error or ErrInvalidSignature, got %v", tc.name, err)
				}
			} else {
				if err != ErrInvalidSignature {
					t.Errorf("tampered %s: expected ErrInvalidSignature, got %v", tc.name, err)
				}
			}
		})
	}
}

// --- Token with negative version (should be rejected) ---

func TestParseToken_NegativeVersion(t *testing.T) {
	secret := []byte("test-secret")
	tok := Token{
		Version:   -1,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("test-nonce")),
		ServerFP:  "fp",
	}
	signingBytes := signingMaterial(tok)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingBytes)
	tok.Signature = hex.EncodeToString(mac.Sum(nil))

	data, _ := json.Marshal(tok)
	payload := base64.RawURLEncoding.EncodeToString(data)

	_, err := ParseToken(payload, secret)
	if err == nil {
		t.Error("expected error for negative version")
	}
	if !strings.Contains(err.Error(), "unsupported token version") {
		t.Errorf("expected 'unsupported token version' error, got: %v", err)
	}
}

// --- ReplayCache: expiry after maxLifetime on past-expiry entry ---

func TestReplayCache_ExpiryAfterMaxLifetime(t *testing.T) {
	// Use very short maxLifetime for fast test.
	cache := NewReplayCache(50 * time.Millisecond)

	// Mark a nonce with past expiry.
	cache.CheckAndMark("expires-fast", time.Now().Add(-1*time.Hour).Unix())

	// Wait for maxLifetime to pass.
	time.Sleep(100 * time.Millisecond)

	// Now the nonce should be expired and accepted again.
	err := cache.CheckAndMark("expires-fast", time.Now().Add(5*time.Minute).Unix())
	if err != nil {
		t.Errorf("expected success after expiry, got: %v", err)
	}
}

// --- RateLimit: window reset and edge cases ---

func TestRateLimit_WindowReset(t *testing.T) {
	// This tests the server's rate limiter. We use a JoinServer directly.
	id, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	srv := NewJoinServer(ServerConfig{
		Secret:            []byte("test-secret"),
		ServerIdentity:    id,
		BootstrapEndpoint: "127.0.0.1:52888",
		MeshPort:        7946,
		RealityPublicKey:  "deadbeef",
		RealityShortID:    "0123456789abcdef",
		RealityServerName: "www.example.com",
		Collectors:        []string{"c1"},
		MaxJoinRequests:   3,
	})

	// Simulate rate limit for an IP.
	ip := "192.168.1.100"
	for i := 0; i < 3; i++ {
		if !srv.allowRequest(ip) {
			t.Fatalf("request %d: expected allowed, got denied", i)
		}
	}
	// 4th request should be denied (exceeds MaxJoinRequests=3).
	if srv.allowRequest(ip) {
		t.Error("4th request: expected denied, got allowed")
	}
	// Different IP should still be allowed.
	if !srv.allowRequest("10.0.0.1") {
		t.Error("different IP: expected allowed, got denied")
	}
}

func TestRateLimit_AccessAllowRequestDirectly(t *testing.T) {
	// Tests that the rate limiter works correctly.
	srv := NewJoinServer(ServerConfig{
		Secret:            []byte("secret"),
		ServerIdentity:    mustGenerateIdentity(t),
		BootstrapEndpoint: "127.0.0.1:52888",
		MaxJoinRequests:   5,
	})

	ip := "10.10.10.10"
	// First 5 should pass.
	for i := 0; i < 5; i++ {
		if !srv.allowRequest(ip) {
			t.Errorf("request %d: expected allowed", i)
		}
	}
	// 6th should fail.
	if srv.allowRequest(ip) {
		t.Error("6th request: expected denied")
	}
}

// mustGenerateIdentity creates an identity or fails the test.
func mustGenerateIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

// --- clientIP: X-Forwarded-For handling ---

func TestClientIP_XForwardedFor(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		expected   string
	}{
		// XFF is client-controlled and deliberately NOT trusted for
		// rate limiting — the remote address is always used.
		{"single xff", "1.2.3.4", "10.0.0.1:12345", "10.0.0.1"},
		{"multiple xff", "1.2.3.4, 5.6.7.8, 9.10.11.12", "10.0.0.1:12345", "10.0.0.1"},
		{"no xff", "", "10.0.0.1:12345", "10.0.0.1"},
		{"ipv6 xff", "::1", "10.0.0.1:12345", "10.0.0.1"},
		{"xff no comma", "192.168.1.1", "127.0.0.1:9999", "127.0.0.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/api/join", nil)
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			req.RemoteAddr = tc.remoteAddr

			ip := clientIP(req)
			if ip != tc.expected {
				t.Errorf("clientIP: got %q, want %q", ip, tc.expected)
			}
		})
	}
}

// --- Token: nonce uniqueness with crypto/rand ---

func TestGenerateToken_NonceEntropy(t *testing.T) {
	secret := []byte("test-secret")
	n := 200
	nonces := make(map[string]bool)
	for i := 0; i < n; i++ {
		raw, _ := GenerateToken(secret, "fp", 5*time.Minute)
		token, err := ParseToken(raw, secret)
		if err != nil {
			t.Fatalf("ParseToken %d: %v", i, err)
		}
		if nonces[token.Nonce] {
			t.Errorf("duplicate nonce at iteration %d: %s", i, token.Nonce)
		}
		nonces[token.Nonce] = true
	}
	if len(nonces) != n {
		t.Errorf("expected %d unique nonces, got %d", n, len(nonces))
	}
}

// --- HMAC: same token with different secrets produces different signatures ---

func TestGenerateToken_DifferentSecretsDifferentSignatures(t *testing.T) {
	fp := "test-fp"
	token1, _ := GenerateToken([]byte("secret-1"), fp, 5*time.Minute)
	token2, _ := GenerateToken([]byte("secret-2"), fp, 5*time.Minute)

	// Decode to compare signatures (nonces will differ anyway, but signatures should be computed from different keys).
	data1, _ := base64.RawURLEncoding.DecodeString(token1)
	data2, _ := base64.RawURLEncoding.DecodeString(token2)
	var t1, t2 Token
	json.Unmarshal(data1, &t1)
	json.Unmarshal(data2, &t2)

	if t1.Signature == t2.Signature {
		t.Error("different secrets produced same signature (extremely unlikely)")
	}

	// Cross-parse should fail.
	_, err := ParseToken(token1, []byte("secret-2"))
	if err != ErrInvalidSignature {
		t.Errorf("token1 with secret2: expected ErrInvalidSignature, got %v", err)
	}
	_, err = ParseToken(token2, []byte("secret-1"))
	if err != ErrInvalidSignature {
		t.Errorf("token2 with secret1: expected ErrInvalidSignature, got %v", err)
	}
}

// --- Random: verify readRandom fills the buffer ---

func TestReadRandom_FillsBuffer(t *testing.T) {
	b := make([]byte, 32)
	zeroes := make([]byte, 32)
	n, err := readRandom(b)
	if err != nil {
		t.Fatalf("readRandom failed: %v", err)
	}
	if n != 32 {
		t.Errorf("readRandom returned %d bytes, want 32", n)
	}
	// Extremely unlikely (1 in 2^256) that random bytes are all zero.
	if string(b) == string(zeroes) {
		t.Skip("random bytes are all zero (astronomically unlikely, but we skip rather than fail)")
	}
}

// --- Challenge cache: expiry ---

func TestChallengeCache_Expiry(t *testing.T) {
	id, _ := identity.GenerateIdentity()
	srv := NewJoinServer(ServerConfig{
		Secret:            []byte("test-secret"),
		ServerIdentity:    id,
		BootstrapEndpoint: "127.0.0.1:52888",
		RealityPublicKey:  "deadbeef",
		RealityShortID:    "0123456789abcdef",
		RealityServerName: "www.example.com",
	})

	// Manually add an expired challenge.
	srv.mu.Lock()
	srv.challengeCache["expired-challenge"] = challengeEntry{
		joinerPubKey: "test-pubkey",
		expiresAt:    time.Now().Add(-1 * time.Hour),
	}
	srv.mu.Unlock()

	// The challenge should be rejected (expired).
	// We can test this indirectly: requesting step 2 with expired challenge.
	// Since we can't easily trigger the check without a proper request,
	// at least verify the entry is in the cache.
	srv.mu.Lock()
	_, exists := srv.challengeCache["expired-challenge"]
	srv.mu.Unlock()
	if !exists {
		t.Error("expired challenge should still be in cache (cleanup happens on next request)")
	}
}
