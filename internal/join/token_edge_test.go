package join

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Token Crypto Edge Case Tests
// =============================================================================

// --- GenerateToken edge cases ---

func TestGenerateToken_EmptySecret(t *testing.T) {
	// Generating a token with an empty secret should still work
	// (HMAC with empty key), but the security is negligible.
	raw, err := GenerateToken([]byte{}, "some-fp", 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken with empty secret failed: %v", err)
	}
	if raw == "" {
		t.Fatal("token is empty")
	}
	// Parsing with the same empty secret should succeed.
	token, err := ParseToken(raw, []byte{})
	if err != nil {
		t.Fatalf("ParseToken with empty secret failed: %v", err)
	}
	if token.Version != TokenVersion {
		t.Errorf("version = %d, want %d", token.Version, TokenVersion)
	}
}

func TestGenerateToken_EmptyServerFP(t *testing.T) {
	secret := []byte("test-secret")
	raw, err := GenerateToken(secret, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken with empty server FP failed: %v", err)
	}
	token, err := ParseToken(raw, secret)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if token.ServerFP != "" {
		t.Errorf("ServerFP = %q, want empty", token.ServerFP)
	}
}

func TestGenerateToken_ZeroLifetime(t *testing.T) {
	// Zero lifetime should produce a token that is immediately expired.
	secret := []byte("test-secret")
	raw, err := GenerateToken(secret, "fp", 0)
	if err != nil {
		t.Fatalf("GenerateToken with zero lifetime failed: %v", err)
	}
	time.Sleep(1 * time.Millisecond)
	_, err = ParseToken(raw, secret)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired for zero-lifetime token, got %v", err)
	}
}

func TestGenerateToken_NegativeLifetime(t *testing.T) {
	// Negative lifetime: the expiry is set in the past.
	secret := []byte("test-secret")
	raw, err := GenerateToken(secret, "fp", -1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken with negative lifetime failed: %v", err)
	}
	_, err = ParseToken(raw, secret)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired for negative-lifetime token, got %v", err)
	}
}

func TestGenerateToken_VeryLongLifetime(t *testing.T) {
	// Tokens can have very long lifetimes (e.g., 365 days).
	secret := []byte("test-secret")
	raw, err := GenerateToken(secret, "fp", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken with 365-day lifetime failed: %v", err)
	}
	token, err := ParseToken(raw, secret)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	// Should expire roughly a year from now.
	expectedMin := time.Now().Add(364 * 24 * time.Hour).Unix()
	if token.ExpiresAt < expectedMin {
		t.Errorf("ExpiresAt = %d, want >= %d", token.ExpiresAt, expectedMin)
	}
}

func TestGenerateToken_LongSecret(t *testing.T) {
	// HMAC-SHA256 handles arbitrary-length keys.
	secret := make([]byte, 1024)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	raw, err := GenerateToken(secret, "fp", 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken with 1KB secret failed: %v", err)
	}
	_, err = ParseToken(raw, secret)
	if err != nil {
		t.Fatalf("ParseToken with 1KB secret failed: %v", err)
	}
}

// --- Token uniqueness ---

func TestGenerateToken_UniqueNonces(t *testing.T) {
	secret := []byte("test-secret")
	fp := "abcdef"
	seen := make(map[string]bool)
	n := 50
	for i := 0; i < n; i++ {
		raw, err := GenerateToken(secret, fp, 5*time.Minute)
		if err != nil {
			t.Fatalf("GenerateToken %d: %v", i, err)
		}
		token, err := ParseToken(raw, secret)
		if err != nil {
			t.Fatalf("ParseToken %d: %v", i, err)
		}
		if seen[token.Nonce] {
			t.Errorf("duplicate nonce found: %s", token.Nonce)
		}
		seen[token.Nonce] = true
	}
	if len(seen) != n {
		t.Errorf("expected %d unique nonces, got %d", n, len(seen))
	}
}

// --- ParseToken error paths ---

func TestParseToken_EmptyString(t *testing.T) {
	_, err := ParseToken("", []byte("secret"))
	if err == nil {
		t.Error("expected error for empty token string")
	}
}

func TestParseToken_ValidBase64_InvalidJSON(t *testing.T) {
	// base64 of a non-JSON string.
	payload := base64.RawURLEncoding.EncodeToString([]byte("this is not json"))
	_, err := ParseToken(payload, []byte("secret"))
	if err == nil {
		t.Error("expected error for valid base64 but invalid JSON")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("expected unmarshal error, got: %v", err)
	}
}

func TestParseToken_ValidJSON_MissingFields(t *testing.T) {
	// Manually construct a token without the signature field.
	tok := Token{
		Version:   TokenVersion,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("test-nonce")),
		ServerFP:  "fp",
	}
	data, _ := json.Marshal(tok)
	payload := base64.RawURLEncoding.EncodeToString(data)
	_, err := ParseToken(payload, []byte("secret"))
	// Should fail because signature is empty (not valid hex).
	if err == nil {
		t.Error("expected error for token with missing signature")
	}
}

func TestParseToken_MalformedSignatureHex(t *testing.T) {
	secret := []byte("test-secret")
	fp := "fp"
	raw, _ := GenerateToken(secret, fp, 5*time.Minute)

	// Decode, corrupt the signature to non-hex, re-encode.
	data, _ := base64.RawURLEncoding.DecodeString(raw)
	var tok Token
	json.Unmarshal(data, &tok)
	tok.Signature = "GGGGGGGG" // invalid hex
	data2, _ := json.Marshal(tok)
	tampered := base64.RawURLEncoding.EncodeToString(data2)

	_, err := ParseToken(tampered, secret)
	if err == nil {
		t.Error("expected error for malformed signature hex")
	}
}

func TestParseToken_WrongVersion(t *testing.T) {
	secret := []byte("test-secret")
	// Manually construct token with unsupported version.
	tok := Token{
		Version:   99,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("test-nonce")),
		ServerFP:  "fp",
	}
	// Sign it properly.
	signingBytes := signingMaterial(tok)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingBytes)
	tok.Signature = hex.EncodeToString(mac.Sum(nil))

	data, _ := json.Marshal(tok)
	payload := base64.RawURLEncoding.EncodeToString(data)

	_, err := ParseToken(payload, secret)
	if err == nil {
		t.Error("expected error for unsupported version")
	}
	if !strings.Contains(err.Error(), "unsupported token version") {
		t.Errorf("expected 'unsupported token version' error, got: %v", err)
	}
}

// --- signingMaterial determinism ---

func TestSigningMaterial_Deterministic(t *testing.T) {
	tok1 := Token{
		Version:   1,
		ExpiresAt: 1700000000,
		Nonce:     "abc123",
		ServerFP:  "deadbeef",
	}
	tok2 := Token{
		Version:   1,
		ExpiresAt: 1700000000,
		Nonce:     "abc123",
		ServerFP:  "deadbeef",
	}
	b1 := signingMaterial(tok1)
	b2 := signingMaterial(tok2)
	if len(b1) != len(b2) {
		t.Errorf("signingMaterial length differs: %d vs %d", len(b1), len(b2))
	}
	for i := range b1 {
		if b1[i] != b2[i] {
			t.Errorf("signingMaterial differs at byte %d: %02x vs %02x", i, b1[i], b2[i])
			break
		}
	}
}

func TestSigningMaterial_DifferentTokensProduceDifferentOutput(t *testing.T) {
	tok1 := Token{
		Version:   1,
		ExpiresAt: 1700000000,
		Nonce:     "nonce-1",
		ServerFP:  "fp-1",
	}
	tok2 := Token{
		Version:   1,
		ExpiresAt: 1700000000,
		Nonce:     "nonce-2", // Different nonce
		ServerFP:  "fp-1",
	}
	b1 := signingMaterial(tok1)
	b2 := signingMaterial(tok2)

	// They should not be equal.
	equal := len(b1) == len(b2)
	if equal {
		for i := range b1 {
			if b1[i] != b2[i] {
				equal = false
				break
			}
		}
	}
	if equal {
		t.Error("signingMaterial produced identical output for different tokens")
	}
}

// --- ParseToken: extreme expiry ---

func TestParseToken_FarFutureExpiry(t *testing.T) {
	secret := []byte("test-secret")
	fp := "fp"
	// Generate token with expiry far in the future.
	raw, _ := GenerateToken(secret, fp, 100*365*24*time.Hour) // 100 years
	token, err := ParseToken(raw, secret)
	if err != nil {
		t.Fatalf("ParseToken for far-future token: %v", err)
	}
	if token.ExpiresAt <= time.Now().Unix() {
		t.Error("far-future token should NOT be expired")
	}
}

func TestParseToken_ExactlyAtExpiry(t *testing.T) {
	// Token with expiry exactly at current time should be rejected
	// (>= comparison, so at expiry == expired).
	// Generate a token that expires right now.
	secret := []byte("test-secret")
	now := time.Now().Unix()

	// Manually build a token with expire = now.
	tok := Token{
		Version:   TokenVersion,
		ExpiresAt: now,
		Nonce:     base64.StdEncoding.EncodeToString([]byte("exact-expiry-nonce")),
		ServerFP:  "fp",
	}
	signingBytes := signingMaterial(tok)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingBytes)
	tok.Signature = hex.EncodeToString(mac.Sum(nil))

	data, _ := json.Marshal(tok)
	payload := base64.RawURLEncoding.EncodeToString(data)

	_, err := ParseToken(payload, secret)
	if err != ErrTokenExpired {
		t.Errorf("token exactly at expiry: expected ErrTokenExpired, got %v", err)
	}
}

// =============================================================================
// ReplayCache Edge Case Tests
// =============================================================================

func TestReplayCache_ZeroMaxLifetime(t *testing.T) {
	// Zero maxLifetime defaults to 2*TokenLifetime (1 hour).
	cache := NewReplayCache(0)
	if cache.maxLifetime != 2*TokenLifetime {
		t.Errorf("maxLifetime = %v, want %v", cache.maxLifetime, 2*TokenLifetime)
	}
}

func TestReplayCache_EmptyNonce(t *testing.T) {
	cache := NewReplayCache(5 * time.Minute)
	err := cache.CheckAndMark("", time.Now().Add(5*time.Minute).Unix())
	if err != nil {
		t.Fatalf("empty nonce should be accepted: %v", err)
	}
	// Replay should be caught.
	err = cache.CheckAndMark("", time.Now().Add(5*time.Minute).Unix())
	if err != ErrTokenReplayed {
		t.Errorf("expected ErrTokenReplayed for empty nonce replay, got %v", err)
	}
}

func TestReplayCache_PastExpiry(t *testing.T) {
	// Mark a nonce with an already-past expiry.
	cache := NewReplayCache(1 * time.Second)
	err := cache.CheckAndMark("past-nonce", time.Now().Add(-1*time.Hour).Unix())
	if err != nil {
		t.Fatalf("CheckAndMark with past expiry: %v", err)
	}
	// Even with past expiry, the nonce is marked (stored with maxLifetime).
	// So a second attempt should be rejected.
	err = cache.CheckAndMark("past-nonce", time.Now().Add(5*time.Minute).Unix())
	if err != ErrTokenReplayed {
		t.Errorf("expected ErrTokenReplayed, got %v", err)
	}
}

func TestReplayCache_ConcurrentAccess(t *testing.T) {
	cache := NewReplayCache(5 * time.Minute)
	n := 100
	var wg sync.WaitGroup
	results := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nonce := "concurrent-nonce"
			err := cache.CheckAndMark(nonce, time.Now().Add(5*time.Minute).Unix())
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	successCount := 0
	replayCount := 0
	for err := range results {
		if err == nil {
			successCount++
		} else if err == ErrTokenReplayed {
			replayCount++
		}
	}

	// Exactly one goroutine should succeed; the rest should see replay.
	if successCount != 1 {
		t.Errorf("concurrent CheckAndMark: %d successes, want 1", successCount)
	}
	if replayCount != n-1 {
		t.Errorf("concurrent CheckAndMark: %d replays, want %d", replayCount, n-1)
	}
}

func TestReplayCache_DifferentNonces_Concurrent(t *testing.T) {
	cache := NewReplayCache(5 * time.Minute)
	n := 100
	var wg sync.WaitGroup
	results := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nonce := fmt.Sprintf("unique-nonce-%d", idx)
			err := cache.CheckAndMark(nonce, time.Now().Add(5*time.Minute).Unix())
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	failures := 0
	for err := range results {
		if err != nil {
			failures++
			t.Logf("unexpected error: %v", err)
		}
	}
	if failures > 0 {
		t.Errorf("concurrent different nonces: %d failures", failures)
	}
}

func TestReplayCache_Cleanup(t *testing.T) {
	cache := NewReplayCache(1 * time.Millisecond)
	// Add several entries.
	for i := 0; i < 5; i++ {
		cache.CheckAndMark("cleanup-nonce-"+string(rune('A'+i)), time.Now().Add(-1*time.Hour).Unix())
	}
	time.Sleep(10 * time.Millisecond)

	// Cleanup should remove expired entries.
	cache.Cleanup()
	if count := cache.EntryCount(); count != 0 {
		t.Errorf("after cleanup expected 0 entries, got %d", count)
	}
}

func TestReplayCache_EntryCountAccuracy(t *testing.T) {
	cache := NewReplayCache(5 * time.Minute)
	// Add 3 unique nonces.
	cache.CheckAndMark("count-1", time.Now().Add(5*time.Minute).Unix())
	cache.CheckAndMark("count-2", time.Now().Add(5*time.Minute).Unix())
	cache.CheckAndMark("count-3", time.Now().Add(5*time.Minute).Unix())

	if count := cache.EntryCount(); count != 3 {
		t.Errorf("EntryCount = %d, want 3", count)
	}

	// Re-adding count-1 should be rejected (replay), count stays at 3.
	cache.CheckAndMark("count-1", time.Now().Add(5*time.Minute).Unix())
	if count := cache.EntryCount(); count != 3 {
		t.Errorf("EntryCount after replay attempt = %d, want 3", count)
	}
}

// =============================================================================
// ParseToken: large non-zero server fingerprint
// =============================================================================

func TestGenerateToken_LongServerFP(t *testing.T) {
	secret := []byte("test-secret")
	longFP := strings.Repeat("abcdef0123456789", 8) // 128 hex chars (64 bytes)
	raw, err := GenerateToken(secret, longFP, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken with long server FP: %v", err)
	}
	token, err := ParseToken(raw, secret)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if token.ServerFP != longFP {
		t.Errorf("ServerFP mismatch: got len=%d, want len=%d", len(token.ServerFP), len(longFP))
	}
}

// =============================================================================
// HMAC correctness: token integrity verification
// =============================================================================

func TestParseToken_SignatureMismatchOnTamperedNonce(t *testing.T) {
	secret := []byte("test-secret")
	raw, _ := GenerateToken(secret, "fp", 5*time.Minute)

	// Decode, change the nonce, keep old signature.
	data, _ := base64.RawURLEncoding.DecodeString(raw)
	var tok Token
	json.Unmarshal(data, &tok)
	tok.Nonce = "tampered-nonce-value"
	data2, _ := json.Marshal(tok)
	tampered := base64.RawURLEncoding.EncodeToString(data2)

	_, err := ParseToken(tampered, secret)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for tampered nonce, got %v", err)
	}
}

func TestParseToken_SignatureMismatchOnTamperedExpiry(t *testing.T) {
	secret := []byte("test-secret")
	raw, _ := GenerateToken(secret, "fp", 5*time.Minute)

	data, _ := base64.RawURLEncoding.DecodeString(raw)
	var tok Token
	json.Unmarshal(data, &tok)
	tok.ExpiresAt += 100000 // Extend expiry
	data2, _ := json.Marshal(tok)
	tampered := base64.RawURLEncoding.EncodeToString(data2)

	_, err := ParseToken(tampered, secret)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for tampered expiry, got %v", err)
	}
}

func TestParseToken_SignatureMismatchOnTamperedServerFP(t *testing.T) {
	secret := []byte("test-secret")
	raw, _ := GenerateToken(secret, "fp", 5*time.Minute)

	data, _ := base64.RawURLEncoding.DecodeString(raw)
	var tok Token
	json.Unmarshal(data, &tok)
	tok.ServerFP = "attacker-fp"
	data2, _ := json.Marshal(tok)
	tampered := base64.RawURLEncoding.EncodeToString(data2)

	_, err := ParseToken(tampered, secret)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for tampered ServerFP, got %v", err)
	}
}
