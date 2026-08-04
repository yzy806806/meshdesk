// Package join implements the auto-join protocol for MeshDesk.
//
// A new node joins the mesh by presenting a join token to an existing
// shared node. The shared node validates the token (checking signature,
// expiration, and replay protection), then distributes the mesh config
// bundle (identity material, REALITY keys, collector list).
//
// Security measures:
//   - Token replay protection: server tracks used nonces, rejects duplicates
//   - Token expiration: tokens carry an expiry timestamp, verified server-side
//   - TLS for join handshake: the join endpoint runs over TLS, preventing
//     MITM and eavesdropping on the distributed config
//   - HMAC signature: tokens are signed with a pre-shared secret, preventing
//     forgery by unauthorized parties
package join

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// TokenVersion is the current join token format version.
const TokenVersion = 1

// TokenLifetime is the default validity period for a join token.
const TokenLifetime = 30 * time.Minute

// nonceLen is the length of the random nonce in bytes (16 = 128 bits).
const nonceLen = 16

// Token is a self-contained, HMAC-signed join token.
//
// Wire format (base64-encoded JSON):
//
//	{
//	  "v": 1,                          // version
//	  "exp": 1700000000,               // Unix timestamp expiry
//	  "n": "base64(16 random bytes)",  // nonce for replay protection
//	  "fp": "hex(pubkey fingerprint)", // server identity fingerprint
//	  "sig": "hex(hmac-sha256)"        // signature over v||exp||n||fp
//	}
type Token struct {
	Version   int    `json:"v"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"n"`
	ServerFP  string `json:"fp"`
	Signature string `json:"sig"`
}

// GenerateToken creates a new join token signed with the given secret.
// The token is valid for the specified duration. The serverFP is the
// hex-encoded Ed25519 public key of the shared node that the joiner
// should connect to (used for TLS certificate pinning).
func GenerateToken(secret []byte, serverFP string, lifetime time.Duration) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	exp := time.Now().Add(lifetime).Unix()

	t := Token{
		Version:   TokenVersion,
		ExpiresAt: exp,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		ServerFP:  serverFP,
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(signingMaterial(t))
	t.Signature = hex.EncodeToString(mac.Sum(nil))

	data, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("marshal token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// ParseToken decodes and verifies a join token's signature and expiration.
// It does NOT check replay protection — that is the server's responsibility.
func ParseToken(raw string, secret []byte) (*Token, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode token base64: %w", err)
	}

	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal token json: %w", err)
	}

	if t.Version != TokenVersion {
		return nil, fmt.Errorf("unsupported token version %d (expected %d)", t.Version, TokenVersion)
	}

	// Verify HMAC signature.
	sigBytes, err := hex.DecodeString(t.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingMaterial(t))
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(sigBytes, expectedMAC) {
		return nil, ErrInvalidSignature
	}

	// Check expiration.
	if time.Now().Unix() >= t.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &t, nil
}

// signingMaterial returns the bytes that are covered by the HMAC signature.
func signingMaterial(t Token) []byte {
	// Version (4 bytes, big-endian) || ExpiresAt (8 bytes, big-endian) ||
	// Nonce (base64 string bytes) || ServerFP (hex string bytes)
	buf := make([]byte, 0, 4+8+len(t.Nonce)+len(t.ServerFP))
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], uint32(t.Version))
	buf = append(buf, v[:]...)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(t.ExpiresAt))
	buf = append(buf, e[:]...)
	buf = append(buf, []byte(t.Nonce)...)
	buf = append(buf, []byte(t.ServerFP)...)
	return buf
}

// Token errors.
var (
	ErrInvalidSignature = fmt.Errorf("join: invalid token signature")
	ErrTokenExpired     = fmt.Errorf("join: token expired")
	ErrTokenReplayed    = fmt.Errorf("join: token already used (replay detected)")
)

// ReplayCache tracks used token nonces to prevent replay attacks.
// Entries expire automatically after maxLifetime (which should be >=
// the maximum token lifetime).
type ReplayCache struct {
	mu          sync.Mutex
	used        map[string]int64 // nonce → expiry UnixNano
	maxLifetime time.Duration
}

// NewReplayCache creates a new replay cache. maxLifetime should be at least
// as long as the longest-valid token. The default TokenLifetime is 30 minutes.
func NewReplayCache(maxLifetime time.Duration) *ReplayCache {
	if maxLifetime == 0 {
		maxLifetime = 2 * TokenLifetime
	}
	return &ReplayCache{
		used:        make(map[string]int64),
		maxLifetime: maxLifetime,
	}
}

// CheckAndMark checks if the nonce has been used before. If not, it marks
// it as used. Returns ErrTokenReplayed if the nonce was already seen.
// The entry is auto-expired after maxLifetime.
func (rc *ReplayCache) CheckAndMark(nonce string, expiresAt int64) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Garbage collect expired entries.
	now := time.Now().UnixNano()
	for n, exp := range rc.used {
		if exp < now {
			delete(rc.used, n)
		}
	}

	if _, exists := rc.used[nonce]; exists {
		return ErrTokenReplayed
	}

	// Store with the token's expiry (converted to UnixNano) or our maxLifetime,
	// whichever is later.
	storeExp := expiresAt * int64(time.Second)
	maxExp := now + int64(rc.maxLifetime)
	if storeExp < maxExp {
		storeExp = maxExp
	}
	rc.used[nonce] = storeExp
	return nil
}

// Cleanup removes expired entries from the cache.
func (rc *ReplayCache) Cleanup() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	now := time.Now().UnixNano()
	for n, exp := range rc.used {
		if exp < now {
			delete(rc.used, n)
		}
	}
}

// EntryCount returns the number of tracked nonces (for testing/monitoring).
func (rc *ReplayCache) EntryCount() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.used)
}
