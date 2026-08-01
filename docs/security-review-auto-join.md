# Auto-Join Protocol — Security Design Review

**Reviewer:** reviewer  
**Date:** 2026-08-01  
**Task:** t_57b88b96  
**Status:** REVIEW WITH FINDINGS — 2 BLOCKERS, 5 HIGH, 3 MEDIUM  

This is a *design* review of the planned auto-join protocol (AGENTS.md Goal 2):  
"新节点配置 join_url + join_token → 共享节点验证 → 自动分发 identity、reality 密钥、collector 列表"

The protocol does NOT yet exist in code.  Zero references to `join_token`,  
`join_url`, or `auto_join` exist in the codebase.  This review evaluates the  
design against the existing codebase's security model and crypto stack.

---

## 1.  Token Design — BLOCKER

### F1:  Token entropy unspecified (BLOCKER — protocol insecure by design)

The design says "join_token" but specifies nothing about:

* **Generation**:  Must use `crypto/rand` (32+ bytes → 256+ bits of entropy).  
  Anything shorter than 128 bits (16 bytes) enables brute-force within  
  feasible time at typical join request rates.
* **Storage**:  The shared node stores tokens.  Where?  Plaintext in config.yaml  
  would violate the pattern already established by the identity PEM migration  
  (t_fedd16aa verified: no plaintext private keys in YAML).
* **Format**:  Hex-encoded?  Base64?  Raw bytes?  Must be unambiguous.

**Recommendation**:  Generate tokens as `crypto/rand.Read(32 bytes) → hex`  
(64-char hex string).  Store them in a separate file (`/etc/meshdesk/join_tokens`,  
0600 permissions), one per line: `<token_hex> <expiry_unix_optional>`.  
The identity PEM pattern (0600, non-YAML) is the template.

### F2:  Token expiration/revocation missing (HIGH)

No mechanism for token expiry or revocation.  Shared node operators must be  
able to:
* Set a TTL on tokens (e.g., 24h default)
* Revoke a token without restarting
* Audit which token was used by which joiner

**Recommendation**:  Add `join_tokens` config array with expiry:  
```yaml
p2p:
  join_tokens:
    - token: "abc123..."
      expires: "2026-08-02T00:00:00Z"
    - token: "def456..."
      expires: ""  # never expires
```

### F3:  Token replay vulnerability (MEDIUM)

If a token is valid and has no one-time-use semantics, an attacker who  
captures a token (via log files, config leaks, or plaintext transmission)  
can replay it to authorize phantom nodes.

**Recommendation**:  Tokens MUST be single-use.  On first successful join,  
the token is consumed and removed.  Replay of consumed token = rejected +  
security alert.  This also requires idempotency: if the join connection  
drops after token validation but before config delivery, retry with the  
same token should succeed (window: ~60 seconds after first use).

---

## 2.  TLS Channel — BLOCKER

### F4:  TLS bootstrap relies on TOFU (BLOCKER — MITM-enabling design flaw)

The new node connects to `join_url` (shared node address).  How does it  
verify it's talking to the *right* shared node?

If the answer is "TLS server certificate", the joiner needs the server's  
certificate or CA *before* connecting.  The current Reality TLS system  
provides traffic camouflage, not authentication — the Reality "public key"  
is an X25519 key for ECDH obfuscation, not a TLS certificate chain.

The design as stated cannot authenticate the bootstrap on first contact  
without a pre-shared trust anchor.  Options:

**Option A**:  Use the Reality public key as a trust anchor.  The `join_url`  
format becomes `host:port:reality_pubkey_hex` — the joiner connects via  
Reality TLS and verifies the server's Reality public key matches.  This  
reuses the existing Reality infrastructure but requires the shared node's  
Reality pubkey in the join URL.

**Option B**:  Use a TLS PKI certificate (LetsEncrypt).  The shared node  
presents a valid TLS cert for its domain.  The joiner verifies against  
system root CAs.  This requires the shared node to have a domain + public  
TLS cert, which may not always be the case.

**Option C**:  Transmit the shared node's Ed25519 public key out-of-band  
and embed it in the join_url.  Use Noise or a simple ECDH+signing protocol  
over the initial connection.

**Recommendation**:  **Option A** — reuse Reality TLS with the Reality public  
key as a trust anchor embedded in join_url.  This requires:
1. `join_url` format: `host:port?pub=HEX` or `host:port/HEX`
2. Joiner connects via Reality TLS, verifies server's X25519 pubkey matches  
   the `pub` parameter
3. The Reality TLS channel then carries the join protocol messages  
   (JoinRequest with token, JoinAccept with config)

The current gossip-based join protocol (plain TCP memberlist SendReliable)  
is NOT suitable for carrying tokens or private keys.

### F5:  Separate channel vs. gossip (HIGH)

The current JoinProtocol sends all messages (JoinRequest, JoinAccept) via  
memberlist's `SendReliable` over TCP gossip — which is explicitly designed  
as *plain TCP* per GOSSIP_REDESIGN_SPEC.md §3.3.

The auto-join protocol MUST use a separate TLS channel (e.g., a direct TCP  
connection to `join_url` protected by Reality TLS), NOT the gossip transport.  
Transmitting a join_token or an Ed25519 private key over plain TCP is  
unacceptable.

**Recommendation**:  The auto-join protocol messages must flow over the  
TLS channel, not the gossip channel.  Create a new `autojoin` package with:
- `JoinClient`: connects to bootstrap via Reality TLS, sends token, receives config
- `JoinServer`: listens alongside the main Reality listener (or on a dedicated  
  port), validates tokens, distributes config
- Protocol: `TLS handshake → token auth → config response → channel close`

---

## 3.  Config Distribution — HIGH

### F6:  Identity private key distribution is architecturally wrong (HIGH)

The AGENTS.md Goal 2 says the shared node should distribute "identity" to  
the joiner.  The "identity" in meshdesk is an **Ed25519 private key** — the  
node's permanent cryptographic identity.

Distributing a private key from the bootstrap to the joiner is problematic:
1. The bootstrap now knows every joined node's private key — it can  
   impersonate them forever
2. If the bootstrap is compromised, all joined nodes' identities are compromised
3. This creates a single point of identity theft at the shared node

**Recommendation**:  The joiner MUST generate its own Ed25519 keypair locally  
(using `crypto/rand`).  The bootstrap should ONLY:
1. Receive the joiner's Ed25519 **public key** as part of the JoinRequest
2. Add it to `authorized_keys` (if auto mode)
3. Distribute Reality TLS configuration (server's public key, short ID,  
   server name) and collector list
4. Gossip the new member to the cluster

Identity generation already exists: `identity.GenerateIdentity()` uses  
`crypto/rand`.  The joiner generates its identity locally, stores it as  
PEM (0600 perms, per t_fedd16aa), and sends only the public key in the  
join request.

### F7:  Reality key distribution needs structure (MEDIUM)

What Reality keys does the joiner need?  Looking at the code:
- `RealityPeerConfig.ServerName` (SNI to present)
- `RealityPeerConfig.PublicKey` (server's X25519 pubkey)
- `RealityPeerConfig.ShortID` (per-client short ID for auth)

These must be distributed ONLY after token validation, over the TLS channel.

**Recommendation**:  The `JoinAccept` response should include a structured  
`ConfigPayload`:
```go
type ConfigPayload struct {
    MeshPort       int      `msgpack:"mp"`
    GossipPort     int      `msgpack:"gp"`
    Collectors     []string `msgpack:"cols"`    // peer IDs
    RealityServer  *RealityConfig `msgpack:"rs,omitempty"`
}

type RealityConfig struct {
    ServerName string   `msgpack:"sn"`
    PublicKey  string   `msgpack:"pk"`
    ShortID    string   `msgpack:"sid"`
    Dest       string   `msgpack:"dest"`
    ServerNames []string `msgpack:"sns,omitempty"`
}
```

### F8:  Config persistence after join (MEDIUM)

The distributed config must be persisted at 0600 permissions on the joiner:
- `/etc/meshdesk/config.yaml` — mesh + gossip + collector config
- `/etc/meshdesk/identity.pem` — already exists (joiner generates locally)
- Reality keys go into the peer config section with appropriate permissions

---

## 4.  Integration with Existing JoinProtocol

### F9:  Two join paths need consolidation (HIGH)

The existing JoinProtocol (`internal/p2p/join.go`) implements JoinRequest/  
JoinAccept/JoinReject over memberlist gossip with `authorized_keys` auth.  
The new auto-join protocol introduces a parallel path with token auth over TLS.

These must converge:
1. After token validation on the TLS channel, the JoinRequest metadata  
   (NodeMeta) should be fed into the existing JoinProtocol's  
   `handleJoinRequest` to leverage capacity checks, manual approval, etc.
2. The existing JoinProtocol should be extended, not duplicated

**Recommendation**:  Refactor `JoinProtocol.handleJoinRequest` to accept a  
`JoinContext` that abstracts the auth method (token vs. key).  The TLS  
channel handler validates the token, then delegates to the existing join  
logic for authorization, capacity checking, and peer gossiping.

### F10:  No rate limiting on join attempts (HIGH)

Neither the existing JoinProtocol nor the planned auto-join protocol has  
rate limiting.  An attacker can flood JoinRequest messages at line speed.

**Recommendation**:  
- Token-based:  max 1 join attempt per token, max 10 failed token attempts  
  per source IP per minute
- Key-based (existing):  max 1 join request per key per 30 seconds (already  
  partially mitigated by `RetryCooldown`)
- Global:  max 10 pending joins at any time (already partially mitigated by  
  `MaxPeers` capacity check)
- Add a `failedAttempts` map with IP-based and token-based counters, reset  
  on cooldown expiry

---

## 5.  DoS and Edge Cases

### F11:  Join request amplification (MEDIUM)

A JoinAccept response includes `KnownPeers` (the full peer list per the  
existing JoinProtocol).  If the mesh has 100+ peers, each ~300 bytes, the  
response is 30KB+.  This is a potential amplification vector.

**Recommendation**:  Cap `KnownPeers` in JoinAccept to 50 entries.  The  
joiner learns the rest via memberlist push/pull after joining gossip.

### F12:  Token-TLS binding (LOW)

The TLS channel and the token should be cryptographically bound to prevent  
cut-and-paste attacks where a valid token on one TLS channel is replayed  
on another.

**Recommendation**:  The JoinRequest should include a hash of the TLS  
session's Finished message (or the session ID), which the bootstrap  
verifies.  This binds the token to the specific TLS connection.

---

## 6.  Positive Findings

### Existing strengths to preserve:

1. **Identity PEM pattern (t_fedd16aa)**:  0600 permissions, non-YAML storage.  
   Extend this to tokens.
2. **Reality TLS infrastructure**:  Proven GFW evasion.  Reuse for the  
   auto-join TLS channel (Option A for F4).
3. **JoinProtocol's modular design**:  Clean separation of auth  
   (`isAuthorized`), capacity (`maxPeersExceeded`), and alerting  
   (`fireAlert`).  Extend, don't replace.
4. **Ed25519 crypto stack**:  `crypto/ed25519` from stdlib.  No external  
   deps, key generation is solid.  Joiner generates locally.
5. **Config.Save 0600**:  Already uses `os.WriteFile(path, data, 0600)`.  
   Config distribution will inherit this.

---

## 7.  Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| F1 | Token entropy unspecified | BLOCKER | Must fix before implementation |
| F4 | TLS bootstrap TOFU vulnerability | BLOCKER | Must fix before implementation |
| F6 | Private key distribution flawed | HIGH | Must fix before implementation |
| F5 | Channel separation needed | HIGH | Must fix before implementation |
| F9 | Two join paths need consolidation | HIGH | Must fix before implementation |
| F10 | No rate limiting | HIGH | Must fix before implementation |
| F2 | Token expiry/revocation missing | HIGH | Should fix before implementation |
| F3 | Token replay vulnerability | MEDIUM | Should fix before implementation |
| F7 | Reality key structure | MEDIUM | Should fix before implementation |
| F8 | Config persistence perms | MEDIUM | Should fix before implementation |
| F11 | Amplification vector | MEDIUM | Should fix before implementation |
| F12 | Token-TLS binding | LOW | Nice to have |

---

## 8.  Recommended Protocol Flow (revised)

```
Joiner (new node)                        Bootstrap (shared node)
─────────────────                        ────────────────────────
1. Generate Ed25519 identity locally
   (crypto/rand)
2. Connect TCP → join_url
   (Reality TLS, verify server pubkey
    matches embedded pub in join_url)
3. ── [TLS channel established] ──→
4. ── JoinRequest(token=NONCE,        →
      pubkey=PUB_HEX, meta=NodeMeta)
5.                                 Validate token (single-use)
                                    Check capacity (MaxPeers)
                                    Check rate limit (token+IP)
6.                                 ←── JoinAccept(config={
                                        mesh_port, gossip_port,
                                        collectors=[...],
                                        reality={server_name,
                                          pubkey, short_id}
                                    })
7. ── JoinComplete(hash_of_config)  →   (optional: confirms receipt)
8.                                 Add joiner to authorized_keys
                                    Gossip new member to cluster
9.                           ←── [TLS channel closed]
10. Joiner writes config.yaml (0600)
    Joiner writes identity.pem (0600)
    Joiner joins gossip via bootstrap
```

---

**Verdict**:  The design as stated in AGENTS.md Goal 2 has two BLOCKERS  
(F1, F4) that must be resolved before implementation begins, and five  
HIGH-severity issues (F6, F5, F9, F10, F2) that should be addressed in  
the implementation spec.  The protocol is fixable — the crypto infrastructure  
exists, the issues are design-level gaps, not fundamental flaws.
