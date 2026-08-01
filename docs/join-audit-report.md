# Internal/join/ Implementation Audit

**Reviewer:** reviewer  
**Date:** 2026-08-01  
**Task:** t_4f3a78b2  
**Status:** REJECTED — 2 CRITICAL, 3 HIGH, 2 MEDIUM  

Audit of `internal/join/` (server.go, client.go, token.go) against the
auto-join requirements from AGENTS.md Goal 2: join_url + join_token flow,
Reality key distribution, collector list, identity bootstrap.

---

## Gate Table

| Gate | Status | Detail |
|------|--------|--------|
| Build | PASS | `go build ./internal/join/` clean |
| Vet | PASS | `go vet ./internal/join/` clean |
| Tests | PASS | 17/17 tests pass, race detector clean |
| Staticcheck | PASS | No issues |
| Token crypto | PASS | HMAC-SHA256, 128-bit nonce, replay cache |
| Token wire format | PASS | base64 JSON with v/exp/n/fp/sig fields |
| Rate limiting | PASS | Per-IP sliding window (default 10 req/min) |
| TLS channel | PARTIAL | StartTLS available but Start() plaintext fallback is too easy |
| Identity bootstrap | FAIL | CRITICAL: challenge never verified, joiner public key unauthenticated |
| Reality key distribution | FAIL | CRITICAL: server's X25519 private key leaked to joiners |
| Config persistence | N/A | caller's responsibility (main.go) |

---

## CRITICAL Findings

### C1: Server Reality PRIVATE KEY leaked to joiners (main.go:783, server.go:343)

**File:** `cmd/meshdesk/main.go:783`

```go
RealityPublicKey: cfg.Reality.PrivateKey, // X2559 key used for REALITY
```

`cfg.Reality.PrivateKey` is the server's X25519 **private** key (see
config.go:583-584: "PrivateKey is the X25519 private key...server-side for
REALITY ECDH authentication"). This is passed as `RealityPublicKey` in the
ConfigBundle and distributed to every joining node.

The joiner (main.go:1120) stores it as `RealityPeerConfig.PublicKey`, which
the comment (config.go:548-549) says should be the server's X25519 **public**
key.

**Impact:** Every node that successfully joins receives the shared node's
X25519 private key. With this key, they can:
1. Compute the server's static X25519 public key (potentially correct if
   implementation does ScalarBaseMult)
2. OR fail to establish Reality TLS if the implementation treats the value
   as a point (wrong) instead of a scalar

**Fix:** Compute the X25519 public key from the private key before passing
it to the ConfigBundle.  Use `crypto/curve25519.ScalarBaseMult()`:

```go
var privKeyBytes [32]byte
hex.Decode(privKeyBytes[:], []byte(cfg.Reality.PrivateKey))
pubKey, _ := curve25519.X25519(privKeyBytes[:], curve25519.Basepoint)
RealityPublicKey: hex.EncodeToString(pubKey),
```

### C2: Joiner identity challenge never verified (server.go:299-314)

**File:** `internal/join/server.go:299-314`

```go
// Verify joiner identity: generate a challenge, sign it, embed in response.
// The joiner must prove it owns the claimed Ed25519 public key.
challenge := make([]byte, 32)
if _, err := readRandom(challenge); err != nil { ... }
challengeHex := hex.EncodeToString(challenge)

// For now, we trust the joiner's claimed public key. In a stricter
// mode, the joiner would sign the challenge and the server would
// verify before responding. This is a two-step flow that can be
// added later. The token already authenticates the joiner.
```

The server generates a challenge, returns it in the JoinResponse, but
NEVER verifies it. The comment even admits "for now, we trust the joiner's
claimed public key."

**Impact:** Any actor with a valid token can claim to be ANY Ed25519 public
key. This enables:
- Identity spoofing (claim to be an existing collector/dashboard node)
- Unauthorized access to capabilities tied to specific peers
- The joiner's public key in the join log is meaningless (no proof)

**Fix:** Make challenge verification mandatory BEFORE returning the bundle.
Either:
- (Two-step) Require the joiner to sign the challenge and POST a second
  request with the signature
- (One-step) Have the joiner sign a timestamp+nonce in the JoinRequest and
  verify it server-side before building the bundle

The one-step approach avoids the need for session state:

```go
// In JoinRequest, add:
type JoinRequest struct {
    Token           string `json:"token"`
    JoinerPublicKey string `json:"joiner_pubkey"`
    JoinerHostname  string `json:"joiner_hostname,omitempty"`
    JoinerEndpoint  string `json:"joiner_endpoint,omitempty"`
    Signature       string `json:"signature"`      // base64 Ed25519 sig
    SigningData     string `json:"signing_data"`   // hex of what was signed (nonce+timestamp)
}
```

---

## HIGH-Severity Findings

### H1: No Ed25519 proof-of-possession anywhere (client.go:57-125, server.go:266-329)

The client never signs anything with its Ed25519 private key. The server
blindly trusts `JoinerPublicKey`. This means:

1. The joiner's claimed public key is unauthenticated
2. The bootstrap has no cryptographic basis to add the joiner to
   `authorized_keys` or `peers.cache`
3. The joiner's identity in the mesh is only as trustworthy as the join
   token, not its actual key

**Fix:** Same as C2 — require a signature over a challenge or nonce.

### H2: Join secret stored in plaintext config.yaml (config.go:40-44)

```go
// Secret is the HMAC key used to sign and validate join tokens.
// This must be the same on the server and shared out-of-band with
// joining nodes. If empty, a random secret is generated...
Secret string `yaml:"secret,omitempty"`
```

The HMAC secret is stored as a plaintext string in config.yaml, which is
saved with 0600 permissions (config.go:963). This violates the pattern
established by the identity PEM migration (t_fedd16aa): no plaintext
secrets in YAML config.

**Impact:** If config.yaml is leaked (backups, logs, accidentally shared),
the HMAC secret is exposed. Anyone with the secret can:
- Forge valid join tokens (no nonce protection stops this because they'd
  just use a new nonce)
- Authorize phantom nodes on the mesh

**Fix:** Store the join secret in a separate file
(`/etc/meshdesk/join.secret`, 0600 permissions), analogous to
`/etc/meshdesk/identity.pem`. Load it at startup, never write it
to config.yaml.

### H3: Plain HTTP fallback is too easy (server.go:177-196)

```go
func (s *JoinServer) Start(addr string) error {
    // ... plain HTTP listener ...
}
```

`Start()` runs plain HTTP. `StartTLS()` is available but opt-in. In
main.go:827-832, if `cfg.Join.TLSCertFile` is empty, the server falls
back to plain HTTP with only a warning log. The config bundle 
(collector list, Reality keys) is transmitted in plaintext over the
network.

**Fix:** Make TLS mandatory. If no TLS cert is configured, refuse to
start the join server. Remove the `Start()` method or make it panic
with a clear error.

---

## MEDIUM-Severity Findings

### M1: Token consumed on first use — no retry window (token.go:169-197, server.go:290-297)

`CheckAndMark()` stores nonces with expiry `max(expiresAt, now+maxLifetime)`.
The default `maxLifetime` is 2× TokenLifetime (60 minutes). If the joiner's
connection drops after token validation but before config receipt, the
token is consumed for the duration of the maxLifetime. There's no short
retry window.

**Fix:** Add a grace window. On first use, mark as "pending" with a 60s
expiry. On second use within the window, allow retry. After 60s, promote
to "consumed" with full expiry.

### M2: No audit trail for token usage (server.go:319-323)

The join handler logs "accepted join from <ip> (pubkey=..., hostname=...)"
but does not:
- Log which token was used (useful for revocation)
- Store structured audit events (token → pubkey → timestamp → IP)
- Support token revocation (no way to identify which token mapped to which
  joiner)

**Fix:** Add structured audit logging. Include the token nonce in the
accept log (the nonce is unique per token, unlike the token string which
is a full HMAC).

---

## NON-BLOCKING Observations

### N1: min() builtin is Go 1.21+ (server.go:280-281)

`min(16, len(token.ServerFP))` uses the Go 1.21+ builtin. This is fine
for this codebase (go.mod presumably requires ≥1.21) but should be noted
for any downstream packaging.

### N2: KnownPeers may include stale gossip data (server.go:332-335)

`buildBundle()` calls `knownPeersFunc()` which reads from
`gossipLayer.KnownPeers()`. If the join server starts before gossip has
converged, KnownPeers may be empty or incomplete. This is cosmetic — the
joiner learns the full peer list via memberlist push/pull after joining.

### N3: ServerConfig.RealityPublicKey field name is misleading (server.go:109-110)

The field is named `RealityPublicKey` but the sidebar comment says
"X25519 REALITY public key". In Reality TLS protocol, this IS the
public key, not the private key. The bug is in the caller (main.go:783)
which passes the private key.

### N4: Client doesn't log challenge (client.go:118-122)

The client's `RequestJoin()` receives the challenge in the JoinResponse
but never inspects it. This is currently moot since the server doesn't
verify it either, but once C2 is fixed, the client must sign the challenge.

---

## Feature Completeness against AGENTS.md Goal 2

| Requirement | Status | Notes |
|-------------|--------|-------|
| join_url + join_token | IMPLEMENTED | HTTP client/server, token HMAC |
| Token validation (signature) | DONE | HMAC-SHA256 with constant-time compare |
| Token validation (expiry) | DONE | Unix timestamp check |
| Token validation (replay) | DONE | ReplayCache with auto-expiry |
| Token validation (server pin) | DONE | ServerFP check for TLS pinning |
| Reality key distribution | BUG | Server's private key leaked (C1) |
| Collector list distribution | DONE | ConfigBundle.Collectors |
| Identity bootstrap | BUG | Joiner generates identity but no proof (C2, H1) |
| TLS channel for bundle | PARTIAL | StartTLS exists but plain HTTP fallback (H3) |
| Rate limiting | DONE | Per-IP sliding window |
| Join-token CLI | DONE | meshdesk join-token subcommand |
| Join CLI | DONE | meshdesk join --join-url --join-token |

---

## Summary

The internal/join/ package is well-structured with solid crypto design
(token format, HMAC signature, replay cache, server fingerprint pinning).
Tests are comprehensive (17 cases covering happy path, tampering, expiry,
replay, rate limiting, wrong secrets).

However, two CRITICAL issues must be fixed before the auto-join protocol
is production-ready:

1. **C1 — Reality private key leak**: `cfg.Reality.PrivateKey` is the
   server's X25519 private key. Passing it as the "public key" in the
   config bundle leaks the server's private key to every joiner.

2. **C2 — Unverified joiner identity**: The server generates an Ed25519
   challenge but never verifies it. Any token holder can claim any public
   key. This undermines the entire peer identity model.

Verdict: **REJECTED** — fix C1 and C2 before shipping. H1-H3 should be
addressed in the follow-up hardening pass but are not blockers for initial
integration testing.
