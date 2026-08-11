# MeshDesk Threat Model

**Version:** 1.1
**Status:** Draft
**Companion to:** [ARCHITECTURE.md](docs/ARCHITECTURE.md) — Decision E (Security Model)

---

## 1. Assets Protected

| Asset | Storage | Access Control | Compromise Impact |
|-------|---------|---------------|-------------------|
| **WireGuard private key** | Plaintext in `config.yaml` (`node.identity`) | File permissions (0600 on save, root-readable) | Full mesh impersonation; decrypt all past/future traffic to this node |
| **Ed25519 signing key** | Generated at runtime via `GenerateRevokerKeyPair()`; not persisted | In-memory only | Forged revocation notices signed in this node's name; impersonated nonce challenges |
| **SSH host key** | `config.yaml` (`webssh.host_key`) or auto-generated Ed25519 on startup | File permissions; regenerated each restart if not configured | MITM on mesh-internal SSH connections |
| **Web UI session tokens** | In-memory `SessionStore` (Go map); `meshdesk_session` cookie | HttpOnly + SameSite=Strict; 24h expiry | Full web UI access as the authenticated user |
| **File transfer data** | `/tmp/meshdesk-uploads/` (default) or configured `upload_dir` | Capability check (`file_transfer`) + optional path-prefix scoping | Read/write arbitrary files if path restriction unset |
| **Service management authority** | Systemd via D-Bus; scoped by `service_manage` capability + per-service whitelist | Capability check + optional service-name scoping | Start/stop/restart arbitrary system services on target node |
| **Monitoring data** | Local ring buffer per node; pushed to aggregator peers | Capability check (`monitor_read` / `monitor_write`) + optional category scoping | Leak system metrics to unauthorized peer |

---

## 2. Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                  Internet / Untrusted Network            │
│                                                         │
│   ┌─────────────────────────────────────────────┐       │
│   │          Mesh Boundary (WireGuard)            │       │
│   │  ┌───────────────────────────────────────┐   │       │
│   │  │   Node Boundary (Capability Engine)    │   │       │
│   │  │  ┌─────────────────────────────────┐  │   │       │
│   │  │  │  Web Boundary (Session Auth)    │  │   │       │
│   │  │  │  ┌───────────────────────────┐  │  │   │       │
│   │  │  │  │ Process Boundary (Root)    │  │  │   │       │
│   │  │  │  │                           │  │  │   │       │
│   │  │  │  │  SSH server, PTY alloc,    │  │  │   │       │
│   │  │  │  │  TUN device, systemd/D-Bus │  │  │   │       │
│   │  │  │  └───────────────────────────┘  │  │   │       │
│   │  │  └─────────────────────────────────┘  │   │       │
│   │  └───────────────────────────────────────┘   │       │
│   └─────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### 2.1 Mesh Boundary — WireGuard Tunnel

WireGuard provides network-layer encryption and peer identity via `Noise_IKpsk2` handshakes. All mesh traffic is encrypted. Peer identity is the WireGuard public key. This boundary separates the mesh from the public internet.

**Assumptions:**
- WireGuard cryptography is sound (Curve25519 + ChaCha20Poly1305)
- The PSK, if configured, is shared only among intended peers
- The obfuscation shim (`padded` / `websocket` modes) prevents GFW from fingerprinting and blocking the WireGuard handshake

**What crosses:** Only mesh-authenticated IP packets. An adversary without a valid WireGuard keypair cannot inject or decrypt traffic.

### 2.2 Node Boundary — Capability Engine Authorization

Inside the mesh, each node enforces authorization via `CapabilityEngine` (implemented in `internal/auth/engine.go`). This is a **zero-trust** model: mesh membership provides connectivity, not authorization. A fresh node denies ALL incoming service requests until the admin explicitly grants capabilities per peer.

**Authorization flow** (implemented in `Authorize()`):
1. Extract source peer ID from WireGuard public key
2. Check revocation list — revoked peers are denied unconditionally
3. Look up peer grant in the capability whitelist
4. If capability is absent → deny ("no_capability")
5. If capability is present → check resource scoping (service names, file paths, metric categories)
6. Log every decision to the audit log (JSONL)

**Critical design property:** Capability checks execute **before** any service handler touches the request. Unauthorized requests are dropped at the auth layer — the service handler never sees them.

### 2.3 Web Boundary — Session Cookie Authentication

The web UI (`--web` mode) authenticates browser users via `meshdesk_session` cookies:
- `HttpOnly` flag prevents JavaScript access
- `SameSite=Strict` mitigates CSRF
- 24-hour expiry with server-side invalidation on logout
- `bcrypt` password verification (`$2b$` prefix check)

**What crosses:** Authenticated browser → web server node. The web server node acts as a trusted proxy — it needs its own capability grants from every node it can act on (SSH proxy, file transfer, service management).

### 2.4 Process Boundary — Root Execution

The MeshDesk binary runs as root. This is a hard requirement for:
- TUN device operations (gVisor netstack avoids kernel module but still needs raw sockets)
- PTY allocation via `creack/pty`
- System metrics collection (`/proc` filesystem)
- Service management via systemd D-Bus

**What crosses:** The binary itself. Any vulnerability in the binary (buffer overflow, command injection, path traversal) can escalate to full root on the host.

---

## 3. Adversaries

### 3.1 Network Adversary (Passive DPI + Active Probing)

**Capabilities:**
- Passive: capture all packets on the wire, perform deep packet inspection
- Active: send probe packets (GFW active probing injects RST or SYN-ACK to terminate connections), throttle UDP, block IPs
- Can fingerprint WireGuard handshakes (148-byte init, 92-byte response)

**Mitigations:**
- Obfuscation shim (`padded` mode: random padding + timing jitter, based on AmneziaWG design)
- `websocket` mode: wraps ciphertext in WebSocket frames over TCP (for UDP-throttled networks)
- TLS fingerprint mimicry via `utls` (`tls_fingerprint` config: chrome/firefox/safari/edge/ios/android)
- Per-peer configurable — LAN peers skip obfuscation entirely

**Residual risk:** The obfuscation shim is unverified against real GFW probing. AmneziaWG proves the design in Russia/Iran, but China's GFW uses different heuristics. A determined adversary with enough training data may still fingerprint the padded WireGuard traffic.

### 3.2 Compromised Mesh Peer

**Capabilities:**
- Has a valid WireGuard keypair (admitted to the mesh)
- Can send packets to any mesh IP
- May lack capabilities beyond basic connectivity

**Mitigations:**
- Zero-trust capability model: mesh membership grants zero service access
- Capability whitelist is per-peer and manually configured
- Revocation: `meshdesk revoke <peer-id>` removes the peer's key and gossips a signed `RevocationNotice`
- Ed25519-signed revocations prevent a compromised peer from revoking others
- Audit log records all denied requests — lateral movement attempts leave a trail

**Residual risk:** If a peer is granted broad capabilities (e.g., `ssh_proxy` to all nodes, `service_manage` with no scope restrictions), compromise of that peer is catastrophic. The capability model constrains damage but is only as strong as the admin's configuration.

### 3.3 Web Attacker

**Capabilities:**
- Can craft HTTP requests to the web server
- CSRF: trick an authenticated admin into submitting a malicious form
- Session prediction: guess valid session tokens
- Path traversal: craft file paths in upload/download requests
- Can probe the WebSocket endpoint

**Mitigations:**
- `SameSite=Strict` cookies — browser won't send the session cookie on cross-site requests
- `HttpOnly` flag — JavaScript cannot read the session token (XSS cannot steal it)
- bcrypt password hashing (with `$2b$` prefix guard against plaintext fallback)

**Residual risks (verified in source):**
- **Session tokens are predictable.** `generateToken()` in `internal/web/server.go` uses `fmt.Sprintf("%x", time.Now().UnixNano())` — a timestamp, not cryptographic randomness. An attacker who can observe a token's creation time can brute-force the nanosecond range.
- **No rate limiting on login attempts.** An attacker can brute-force passwords without lockout or delay.
- **Plaintext password fallback.** If `password_hash` in `config.yaml` does not start with `$2b$`, the password is compared in plaintext (development convenience that persists in production code).

### 3.4 Insider with Config Access

**Capabilities:**
- Can read `config.yaml` (root-readable, contains all secrets)
- Knows WireGuard private keys, peer public keys, bcrypt hashes, SSH host keys

**Mitigations:**
- `config.yaml` saved with mode `0600` (owner read/write only)
- Root access required to read the file

**Residual risk:** This is the highest-impact adversary. With the WireGuard private key and all peer configurations, an insider can impersonate the node, decrypt mesh traffic, and forge capability requests. There is no defense-in-depth against someone with root on the node — the binary must run as root, so root inherently trusts the binary.

---

## 4. Attack Surfaces

| Surface | Port/Binding | Exposure | Authentication |
|---------|-------------|----------|---------------|
| **WireGuard UDP** | 51820 (default) | Public internet | Noise_IKpsk2 handshake (Curve25519) |
| **HTTP web server** | `:8080` (configurable) | Configurable (bind address) | Session cookie (`meshdesk_session`) |
| **WebSocket terminal** | `/ws/terminal?node=<peer-id>` (on HTTP port) | Same as web server | Session cookie + (see note below) |
| **Mesh SSH** | 2222 (configurable) | Mesh-internal (gVisor netstack) | SSH host key + capability check |
| **Monitoring push** | 4191 (configurable) | Mesh-internal (gVisor netstack) | Capability check (`monitor_write`) |
| **File transfer receiver** | 4193 | Mesh-internal (gVisor netstack) | Capability check (`file_transfer`) |
| **`config.yaml`** | `/etc/meshdesk/config.yaml` | Local filesystem (root) | File permissions (0600) |

### Surface-by-Surface Analysis

**WireGuard UDP (51820):**
The primary internet-facing surface. Every packet is encrypted by WireGuard before the obfuscation shim transforms it. The GFW can see that UDP traffic exists on 51820; the obfuscation shim's job is to prevent the GFW from identifying it as WireGuard. Without obfuscation, the WireGuard handshake is trivially fingerprintable.

**HTTP web server (:8080):**
Serves Go `html/template` pages, htmx partials, SSE streams, and JSON API endpoints. All routes except `/login` require a valid session cookie. The login endpoint accepts POST with `username` and `password` form values. No CSRF token on the login form (the `SameSite=Strict` cookie is the primary CSRF defense).

**WebSocket terminal (`/ws/terminal`):**
Upgrades HTTP to WebSocket for xterm.js terminal sessions. The web handler (`handleWebSocketTerminal`) checks the session cookie but delegates to `webssh.NewHandler()` **without** an auth checker — meaning the capability engine (`ssh_proxy` check) is **not enforced** at this boundary. A web-authenticated user can open a terminal to any mesh peer regardless of the capability configuration on the target node. (See Known Limitations section 6.7.)

**Mesh SSH (2222):**
Binds to the gVisor netstack — only mesh peers can reach it. The SSH server authenticates connections using the host key (Ed25519, auto-generated or from config). The target node enforces `ssh_proxy` capability at connection time.

**Monitoring push (4191):**
Agents push metrics to collector nodes over this mesh-internal TCP port. The aggregator checks `monitor_write` capability. Push-only model — no on-demand pull from the collector side.

**`config.yaml`:**
The single most valuable file on the node. Contains the WireGuard private key as a hex string in the `node.identity` field. Also contains all peer public keys, their capability grants, web user bcrypt hashes, SSH host keys, and obfuscation parameters. Stored at `/etc/meshdesk/config.yaml` with mode `0600`. Read at startup by the binary (running as root).

---

## 5. Security Controls

### 5.1 Zero-Trust Capability Model (Default-Deny)

**Implementation:** `internal/auth/engine.go` — `CapabilityEngine`
**Principle:** Mesh membership ≠ trust. A fresh node denies all incoming service requests.

The engine maintains a per-peer capability whitelist loaded from `config.yaml` at startup. Six capability types are recognized:

| Capability | Resource Scoping | Service |
|-----------|-----------------|---------|
| `ssh_proxy` | None | WebSSH terminal |
| `file_transfer` | Directory path prefixes | File transfer |
| `monitor_read` | Metric categories | Monitoring dashboard |
| `monitor_write` | Metric categories | Metric aggregation |
| `service_manage` | Service names | systemd service control |
| `binary_upgrade` | None (nonce challenge adds 2nd factor) | Binary replacement |

**Authorization decision logic:**
1. Is the peer revoked? → deny (immediate, before any other check)
2. Does the peer have a grant? → if no, deny
3. Does the peer have the requested capability? → if no, deny
4. Is the resource within the capability's scope? → if no, deny
5. All checks pass → allow

Every decision (allow or deny) produces a structured JSON audit log entry.

### 5.2 Ed25519-Signed Revocation Notices

**Implementation:** `internal/auth/revocation.go` — `SignRevocation()` / `VerifyRevocation()`

When an admin revokes a peer (`meshdesk revoke <peer-id>`), the node:
1. Removes the peer from its local WireGuard config
2. Drops all active connections to that peer
3. Creates a signed `RevocationNotice` containing the revoked peer ID, timestamp, reason, and an Ed25519 signature
4. Gossips the signed notice to all other mesh nodes

The signing key is **separate** from the WireGuard keypair (`GenerateRevokerKeyPair()` uses Ed25519, while WireGuard uses Curve25519/X25519). This separation prevents a WireGuard key compromise from enabling forged revocations.

Verification: receiving nodes check the signature against the revoker's known public key before accepting the revocation. A malicious node cannot revoke another node's peers.

### 5.3 Nonce Challenge for Binary Upgrades

**Implementation:** `internal/auth/nonce.go` — `NonceChallenge`

Binary upgrades are the highest-impact operation — a backdoored binary compromises the entire node. The nonce challenge adds a second factor beyond the `binary_upgrade` + `service_manage` capability:

1. Requesting node sends upgrade request
2. Target node responds with a 32-byte cryptographic nonce (60-second TTL)
3. Requesting node must sign the nonce with its Ed25519 private key
4. Target verifies the signature before accepting the binary

**Design property:** Each target issues its own unique nonce. A compromised authorized node cannot push a backdoored binary to every peer in one sweep — it must complete a fresh challenge per target. Expired challenges are cleaned up by `CleanupExpired()` (call periodically to prevent memory leaks).

### 5.4 bcrypt Password Hashing

**Implementation:** `internal/web/handlers.go` — `authenticate()`

Web UI passwords are stored as bcrypt hashes in `config.yaml` (`auth.web_users[].password_hash`). The authenticate function checks for the `$2b$` prefix — if present, uses `bcrypt.CompareHashAndPassword`; otherwise falls back to plaintext comparison.

**Warning:** The plaintext fallback exists for development convenience and is a production risk. Any password stored without `$2b$` prefix is compared in plaintext against the submitted form value.

### 5.5 Session Cookie Hardening

**Implementation:** `internal/web/handlers.go` — `handleLogin()`

Session cookies are set with:
- `HttpOnly: true` — JavaScript cannot read the token (mitigates XSS session theft)
- `SameSite: http.SameSiteStrictMode` — browser will not send the cookie on cross-site requests (mitigates CSRF)
- `MaxAge: 86400` — 24-hour expiry
- Server-side invalidation: `sessions.Delete(token)` on logout

### 5.6 TLS Fingerprint Mimicry (utls)

**Implementation:** `internal/config/config.go` — `ObfuscationOpts.TLSFingerprint`

When using WebSocket+TLS mode (`ws_use_tls: true` + `tls_fingerprint`), MeshDesk uses the `utls` library to mimic browser TLS ClientHello fingerprints:
- `chrome`, `firefox`, `safari`, `edge`, `ios`, `android`
- With `tls_sni`, the TLS handshake presents a legitimate SNI hostname
- This makes mesh traffic indistinguishable from normal HTTPS to passive DPI

### 5.7 Obfuscation Registry

**Implementation:** `internal/mesh/obfuscation.go`

Three modes, per-peer configurable:
- `none` — raw WireGuard (trusted LAN)
- `padded` — per-packet random padding + timing jitter + handshake obfuscation (AmneziaWG-style, for internet peers)
- `websocket` — wrap ciphertext in WebSocket frames over TCP (when UDP is throttled)

---

## 6. Known Limitations (Honest Assessment)

### 6.1 Predictable Session Tokens

**Severity:** Medium | **Source:** `internal/web/server.go:506`

```go
func generateToken() string {
    return fmt.Sprintf("%x", time.Now().UnixNano())
}
```

Session tokens are derived from the server's nanosecond clock — not from `crypto/rand`. An attacker who can observe token creation times can brute-force the nanosecond range (approximately 10^9 possibilities). This is computationally feasible with offline brute force. Tokens should be generated via `crypto/rand` (32+ bytes, hex-encoded) to achieve 256 bits of entropy.

### 6.2 WireGuard Private Key in Plaintext Config

**Severity:** High | **Source:** `internal/config/config.go:35`

The `node.identity` field stores the WireGuard private key as a hex string in `config.yaml`. Anyone with root on the node (including the binary itself, and any process running as root) can read it. This is the WireGuard model — it does not provide encrypted-at-rest key storage — but users should understand that `config.yaml` is a single point of compromise for all mesh security.

### 6.3 No Key Rotation

**Severity:** Medium | **Source:** Verified across codebase

There is no mechanism to rotate any key type:
- WireGuard keypairs: generated once via `--gen-key`, no rotation workflow
- Ed25519 signing keys: generated at runtime, not persisted (lost on restart)
- SSH host keys: auto-generated on startup if not in config, no rotation
- Web passwords: no password-change endpoint, no TOTP/2FA

Key rotation requires manual intervention: generate new keys, update `config.yaml` on all peers, restart the service.

### 6.4 Audit Log Not Tamper-Evident

**Severity:** Low-Medium | **Source:** `internal/auth/audit.go`

The audit log is JSONL format — one JSON object per line, appended to a file. This is easy to parse but not tamper-evident:
- No hash chain linking entries (an attacker with root can delete or modify lines without detection)
- No sequence numbers (entries cannot be ordered reliably across restarts)
- No log rotation (unbounded growth)

The task description notes a planned hash-chain fix. Until then, audit logs provide a forensic trail but not a tamper-proof one.

### 6.5 No Rate Limiting on Authentication Failures

**Severity:** Medium | **Source:** Verified across codebase — zero rate-limiting code

There is no rate limiting on:
- Login attempts (POST `/login`)
- WebSocket connection attempts (`/ws/terminal`)
- Any API endpoint

An attacker can brute-force web UI passwords without lockout, delay, or IP-based throttling. Paired with predictable session tokens (6.1), this makes the web authentication surface weaker than it appears.

### 6.6 Plaintext Password Fallback

**Severity:** Medium | **Source:** `internal/web/handlers.go:96-98`

```go
if !strings.HasPrefix(user.PasswordHash, "$2b$") {
    return user.PasswordHash == password
}
```

Passwords stored without the `$2b$` bcrypt prefix are compared in plaintext. This is a development convenience that survives in production code. If an admin stores `password_hash: admin123` (perhaps from a tutorial or copy-paste error), the password is compared literally — no hashing, no salt.

### 6.7 WebSocket Terminal Bypasses Capability Check

**Severity:** High | **Source:** `internal/web/handlers.go:240`

```go
handler := webssh.NewHandler(s.sshHub)  // No auth checker!
```

The web server creates the WebSocket handler with `NewHandler()` (not `NewHandlerWithAuth()`). This means the `ssh_proxy` capability check is **not enforced** at the WebSocket endpoint. A web-authenticated user can open a terminal to **any** mesh peer, regardless of whether the web server node has an `ssh_proxy` capability grant from that peer.

The session cookie check (lines 231-237) still applies — an unauthenticated browser user is denied. But once past the session gate, all peers are accessible. This undermines the zero-trust capability model for the web terminal surface.

### 6.8 Session Tokens In-Memory Only

**Severity:** Low | **Source:** `internal/web/server.go:464`

The `SessionStore` is a `map[string]*Session` held in memory. On process restart, all sessions are lost — all web users must re-authenticate. This is an availability concern, not a security one, but it means restarts are disruptive for operators using the web UI.

### 6.9 No CSRF Token on Forms

**Severity:** Low | **Source:** Verified in login and service forms

The login form and service action forms do not include CSRF tokens. The `SameSite=Strict` cookie flag provides partial CSRF protection for modern browsers, but older browsers or non-browser clients that don't enforce SameSite can still be exploited. A defense-in-depth approach would add per-form CSRF tokens.

### 6.10 SSH Server Runs as Root

**Severity:** Inherent | **Source:** `internal/webssh/sshserver.go`

The SSH server allocates PTYs via `creack/pty` and runs shells as the connecting user (auto-detected via `/etc/passwd`, falling back to `/bin/bash`). The SSH server process itself runs as root (since the MeshDesk binary is root). A vulnerability in the SSH server (channel handling, PTY allocation, shell detection) could lead to root compromise of the target node.

---

## Appendix A: Reference Reconciliation

This document is a companion to [ARCHITECTURE.md](docs/ARCHITECTURE.md) — specifically **Decision E (Security Model)**. Code comments throughout `internal/auth/` reference "ARCHITECTURE.md Decision E," which remains the canonical source for architectural decisions. This THREAT_MODEL.md provides the adversarial analysis and security assessment layered on top of those architectural decisions.

Files referencing "ARCHITECTURE.md Decision E":
- `internal/auth/capabilities.go` — capability constants and zero-trust model
- `internal/auth/engine.go` — `CapabilityEngine` implementation
- `internal/auth/audit.go` — structured audit log format
- `internal/auth/nonce.go` — binary upgrade nonce challenge protocol

These references remain valid. ARCHITECTURE.md describes *what* the security model is; THREAT_MODEL.md describes *what it defends against* and *where it falls short*.

---

## Appendix B: Verification Notes

Every claim in this document was verified against the source code at `internal/auth/` (capabilities.go, engine.go, audit.go, nonce.go, revocation.go, ssh_monitor_checker.go, transfer_checker.go), `internal/web/` (server.go, handlers.go), `internal/config/` (config.go), and `internal/webssh/` (handler.go, hub.go, sshserver.go).

Key verifications:
- Session token generation: `internal/web/server.go:506` — verified predictable
- Capability check bypass: `internal/web/handlers.go:240` — verified NewHandler without auth
- Plaintext password fallback: `internal/web/handlers.go:96` — verified conditional
- Rate limiting: zero occurrences in entire codebase — verified absent
- WireGuard key storage: `internal/config/config.go:35` — verified plaintext hex
- Audit log format: `internal/auth/audit.go:25-31` — verified no hash chain or sequence numbers
- Nonce challenge: `internal/auth/nonce.go:53-111` — verified crypto/rand nonce + ed25519 verify
- Revocation signing: `internal/auth/revocation.go:37-52` — verified ed25519 signature over structured message
- Cookie hardening: `internal/web/handlers.go:50-52` — verified HttpOnly + SameSite Strict
## Zone-Aware Transport Considerations (v1.5.8+)

- **Cross-zone (Reality TLS)**: the only permitted transport across the
  GFW boundary. Reality's full TLS 1.3 fallback (to the configured dest)
  defeats active probing; wire bytes are indistinguishable from HTTPS.
- **Same-zone (UDP P2P)**: fast multipath/ARQ on links that do not cross
  the boundary. UDP datagrams carry Ed25519-authenticated first frames
  (anti-injection); payloads are NOT encrypted — only use same-zone UDP
  where the channel is not an attack surface (or add upper-layer
  encryption if the threat model requires it).
- **Unknown zone**: conservative — treated as cross-zone (Reality only).
- **Operational**: all nodes must run the same binary version; mixed
  versions break the data plane (protocol drift).
