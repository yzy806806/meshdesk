# MeshDesk v2 — WireGuard → Reality Migration Guide

**Status:** DRAFT (sections 1-5 complete; will be updated as Phase 1-10 development progresses)
**Date:** 2026-07-28
**Author:** writer
**Motion:** motion-856c071ce5a9
**Task:** t_6d0e90d0 (Action item 9/10)

---

## 1. What Changes

### 1.1 Removed Components

| v1 Component | v2 Replacement | Why |
|---|---|---|
| **WireGuard (`wireguard-go`)** | Reality TLS 1.3 handshake | WireGuard's endpoint binding, handshake storms, and routing table were the root cause of connectivity bugs |
| **gVisor netstack** | `net.Conn`-based smux streams | gVisor existed solely to provide virtual IPs for WireGuard; no longer needed |
| **Mesh IP / `deriveMeshIP`** | Ed25519 public key as node ID | Mesh IPs created an unnecessary addressing layer; peer ID is simpler and more stable |
| **`obfuscatingBind` (none/padded/websocket)** | Reality TLS only (www.apple.com camouflage) | Three obfuscation modes created complexity; Reality is the proven path |
| **Curve25519 identity** | Ed25519 identity | Curve25519 can't sign — no gossip auth, no session proof-of-ownership |
| **`TransportFactory` / `Transport` / `PeerConn`** | `handshake.HandshakeLayer` interface | Factory was WireGuard's shape leaking into the abstraction — v2 is single-instance |
| **`PeerHandshakeInfo` (WireGuard handshake polling)** | Session-layer key exchange + heartbeat | Direct WG device polling replaced by protocol-native handshake |
| **`AllowedIPs` on peer configs** | Role-based routing (entry/exit/relay) | AllowedIPs was a WireGuard routing artifact |

### 1.2 Kept Components (Refactored)

| Component | Reuse Strategy | Lines Kept |
|---|---|---|
| **Reality TLS transport core** | Ported from `reality_transport.go` to `handshake/reality.go` | ~500 / 941 lines |
| **Gossip discovery (memberlist)** | Simplified — mesh IP dependency removed, Ed25519-signed NodeMeta | ~500 / 800 lines |
| **PeerManager** | Refactored — WG transport replaced by `handshake.Connect()` | ~800 / 1273 lines |
| **Dashboard config API** | Extended with RPC remote-config system | ~3000 lines + additions |
| **x-ui proxy management** | Panic fixed, Reality config remote-deployed | ~2900 lines |
| **anime.js / anim.js topology** | Unchanged | All lines |
| **WebSSH (xterm.js)** | Rebuilt over smux stream instead of mesh IP | Rewrite |
| **File transfer** | Rebuilt over smux stream with chunking | Rewrite |

### 1.3 Key Type Migration

```
v1 Identity                          v2 Identity
═══════════                          ═══════════
Key type:  Curve25519 (X25519 DH)    Key type:  Ed25519 (signing)
Stdlib:    golang.org/x/crypto       Stdlib:    crypto/ed25519
Signing:   NOT POSSIBLE              Signing:   Sign() / Verify()
Key size:  32B private, 32B public   Key size:  64B private, 32B public
Clamping:  Required (3 bitwise ops)  Clamping:  Not required
Encoding:  Hex (64 chars public)     Encoding:  Hex (64 chars public)
File:      identity.json (v1)        File:      identity.json (v2, version: 2)
```

The keys are **NOT interchangeable**. v1 Curve25519 keys CANNOT be converted
to Ed25519 — it's a completely different cryptographic primitive. Migration
is key rotation, not key derivation.

---

## 2. Config Migration: v1 → v2

### 2.1 v1 `config.yaml` (Before)

```yaml
node:
  identity: "a1b2c3d4e5...32 hex bytes"  # Curve25519 private key
  hostname: "node1"
  listen: ":51820"                        # WireGuard listen port

mesh:
  port: 51820
  subnet: "10.0.0.0/16"
  mtu: 1420

peers:
  - public_key: "f6e5d4c3...32 hex bytes"
    endpoint: "1.2.3.4:51820"
    allowed_ips:
      - "10.0.0.2/32"

obfuscation:
  mode: "reality"                         # or "none", "padded", "websocket"
  reality:
    dest: "www.apple.com:443"
    server_names: ["www.apple.com"]
    private_key: "reality-x25519-key"
    short_ids: ["abc123"]
```

### 2.2 v2 `config.yaml` (After)

```yaml
node:
  identity: "d4e5f6a7...128 hex bytes"    # NEW: Ed25519 private key (64 bytes hex)
  hostname: "node1"
  listen: ":443"                          # Reality TLS listen port (was WG 51820)

# WireGuard 'mesh' block REMOVED entirely
# WireGuard 'obfuscation' block REMOVED (Reality is the only transport)

reality:                                  # NEW top-level block
  dest: "www.apple.com:443"
  server_names: ["www.apple.com"]
  private_key: "reality-x25519-key"       # Kept from v1 obfuscation.reality
  short_ids: ["abc123"]                   # Kept from v1

peers:
  - endpoint: "1.2.3.4:443"              # Port changed: 51820 → 443
    public_key: "d4e5f6...64 hex chars"   # Ed25519 public key (was Curve25519)

exit:                                     # NEW block
  enabled: false
  allowed_ports: [80, 443]

web:
  port: 18080

udp:
  port: 51820                             # UDP punch-through port (not WireGuard)
```

### 2.3 Config Mapping Table

| v1 Field | v2 Field | Action |
|----------|----------|--------|
| `node.identity` | `node.identity` | **Rotate**: generate new Ed25519 key |
| `node.listen` | `node.listen` | **Change**: `:51820` → `:443` (or custom) |
| `mesh.port` | — | **Remove** |
| `mesh.subnet` | — | **Remove** |
| `mesh.mtu` | — | **Remove** |
| `obfuscation.mode` | — | **Remove** (only Reality in v2) |
| `obfuscation.reality.*` | `reality.*` | **Promote** to top-level block |
| `peers[].public_key` | `peers[].public_key` | **Rotate**: all peers generate new Ed25519 keys |
| `peers[].endpoint` | `peers[].endpoint` | **Change**: port `51820` → `443` |
| `peers[].allowed_ips` | — | **Remove** |
| — | `exit.*` | **Add** if this node is an exit |
| — | `udp.port` | **Add** for UDP punch-through |

---

## 3. Step-by-Step Migration Procedure

### 3.1 Pre-Migration Checklist

Before starting migration, verify:

```
[ ] All nodes running v1.0.0-beta.1 or later (v2 migration is only supported from here)
[ ] At least one node has a public IP (shared node / relay)
[ ] You have SSH access to every node in the mesh
[ ] Dashboard is accessible on each node
[ ] You have a backup of /etc/meshdesk/ on every node
[ ] All peers' public keys are documented
[ ] Reality TLS is currently working in v1 (if using obfuscation.mode: reality)
```

### 3.2 Migration Order

Migration must be done in a specific order to avoid mesh partition:

```
Step 1: Shared node (has public IP, listens on :443)
  → Step 2: Exit nodes (exit.enabled: true)
    → Step 3: Entry / leaf nodes (connect outbound only)
      → Step 4: Verify full mesh connectivity
```

**Reason:** Shared nodes are the bootstrap anchors. If leaf nodes migrate
first, they have no one to connect to — the shared nodes still speak v1.

### 3.3 Step-by-Step

#### Step 1: Backup and Stop (All Nodes)

On every node in the mesh:

```bash
# Backup v1 config and identity
cp -r /etc/meshdesk /etc/meshdesk.v1.backup

# Stop the meshdesk service
systemctl stop meshdesk
```

#### Step 2: Install v2 Binary

```bash
# Download v2 binary (replace URL with actual release)
wget -O /usr/local/bin/meshdesk https://github.com/yzy806806/meshdesk/releases/download/v2.0.0/meshdesk-linux-amd64
chmod +x /usr/local/bin/meshdesk
```

#### Step 3: Generate New Identity (All Nodes)

```bash
# v2 provides a subcommand to generate an Ed25519 identity
meshdesk identity generate > /etc/meshdesk/identity.json
# Output: {"private_key": "...128 hex...", "public_key": "...64 hex...", "version": 2}

# Record the public key — you'll need this for peer configs
cat /etc/meshdesk/identity.json | jq -r '.public_key'
```

**CRITICAL:** Record every node's new Ed25519 public key. The old Curve25519
keys are useless in v2 — peer identification is done entirely through the
new public key. A node whose public key isn't in any peer list will be
isolated.

#### Step 4: Rewrite Config (All Nodes)

Edit `/etc/meshdesk/config.yaml` for v2:

1. Replace `node.identity` with the new Ed25519 private key from identity.json.
2. Change `node.listen` from `:51820` to `:443` (or custom Reality port).
3. Delete the `mesh:` block entirely.
4. Delete the `obfuscation:` block entirely.
5. Create a `reality:` block — move `obfuscation.reality.*` values there.
6. For each peer, update:
   - `public_key`: replace with the peer's new Ed25519 public key.
   - `endpoint`: change port from 51820 to 443.
   - Delete `allowed_ips`.
7. Add `exit:` block if this node serves as an exit (see §4.1).
8. Add `udp:` block (keep port 51820 for UDP punch-through — different purpose).

#### Step 5: Start Shared Node First

```bash
# On the shared node (has public IP, listens on :443)
systemctl start meshdesk

# Verify Reality TLS listener is up
tail -f /var/log/meshdesk/meshdesk.log | grep "REALITY"
# Expected: "REALITY listener ready on 0.0.0.0:443"
```

#### Step 6: Start Exit Nodes

```bash
# On each exit node
systemctl start meshdesk

# Verify connectivity to shared node
meshdesk ping <shared-node-public-key>
# Expected: "PONG from <shared-node> in 15ms"
```

#### Step 7: Start Leaf Nodes

```bash
# On each leaf / entry node
systemctl start meshdesk

# Verify connectivity
meshdesk ping <shared-node-public-key>
meshdesk ping <exit-node-public-key>
# Expected: pongs from both
```

#### Step 8: Verify Full Mesh

```bash
# From any node, check the mesh topology
meshdesk status

# Expected output:
# Peers: N/14 connected
# Gossip: N nodes visible
# Reality: OK (443)
# Exit nodes: N available
```

### 3.4 Post-Migration Validation

```bash
# 1. Gossip discovery
meshdesk peers list
# → All expected peers appear with Ed25519 public keys (64 hex chars)

# 2. WebSSH
# Open Dashboard → Terminal → select a remote node
# → Terminal session opens successfully

# 3. File transfer
# Dashboard → Files → select remote node → browse /root
# → Directory listing succeeds

# 4. Proxy (if configured)
# Configure VLESS+Reality inbound on an entry node
# Connect from a client → traffic flows to exit node
```

---

## 4. Special Cases

### 4.1 Configuring an Exit Node

An exit node is one that reaches the public internet on behalf of
proxied traffic. In v1 this was implicit — any node could be an exit.
In v2 it must be explicitly declared:

```yaml
exit:
  enabled: true
  allowed_ports:
    - 80
    - 443
    - 22    # optional: allow SSH exit
```

The `allowed_ports` is a security boundary — the exit node will only
open TCP connections to those ports. Connections to other ports are
rejected regardless of what the entry node requests.

In v1 exit capability was implicit (any node with internet access acted
as an exit if traffic was routed to it). v2 makes it explicit so that
operators can designate dedicated exit nodes and leaf nodes that
should never serve as exits.

### 4.2 NAT Nodes (No Public IP)

v1 required every node to have a WireGuard listen port, even behind
NAT. v2 handles NAT nodes naturally:

```yaml
node:
  identity: "...Ed25519 key..."
  hostname: "amd1-behind-nat"
  listen: ""                            # Empty = no inbound listener

peers:
  - endpoint: "shared.example.com:443"  # Connect outbound to shared node
    public_key: "...shared node key..."
```

The node connects outbound via Reality TLS to the shared node. The shared
node learns the NAT-mapped endpoint and gossips it so other nodes can
attempt UDP punch-through. No special NAT traversal config — Reality TLS
over TCP works through most NATs without modification.

### 4.3 Multiple Shared Nodes

For resilience, deploy 2 shared nodes with public IPs:

```yaml
peers:
  - endpoint: "shared-1.example.com:443"
    public_key: "...shared-1 key..."
  - endpoint: "shared-2.example.com:443"
    public_key: "...shared-2 key..."
```

Both are tried during bootstrap. If one is down, the other serves.
The gossip protocol distributes endpoint information — leaf nodes
learn about each other through any connected shared node.

### 4.4 Dashboard-Only Node

A node that serves only the Dashboard and doesn't participate in
traffic relay:

```yaml
node:
  identity: "..."
  hostname: "dashboard"
  listen: ""                            # No Reality listener

web:
  port: 18080

peers:
  - endpoint: "shared.example.com:443"  # Just enough to join gossip
    public_key: "...shared node key..."
```

---

## 5. Rollback Procedure

If migration fails and you must revert:

### 5.1 Rollback Steps

```bash
# 1. Stop v2 on all nodes
systemctl stop meshdesk

# 2. Restore v1 config and identity
rm -rf /etc/meshdesk
cp -r /etc/meshdesk.v1.backup /etc/meshdesk

# 3. Restore v1 binary
# (depends on how you installed v1 — typically apt, manual download, etc.)

# 4. Start v1 on shared node first
systemctl start meshdesk
# Wait for WireGuard handshake to complete (~30s)

# 5. Start remaining nodes
# WireGuard re-establishes connections automatically — same keys, same endpoints
```

### 5.2 What Rollback Doesn't Restore

- v2 Ed25519 identity files are lost (they're in the deleted `/etc/meshdesk`).
  These are disposable — you'll generate new ones on re-migration.
- Any v2-only features used during migration (WebSSH over smux, RPC config)
  are unavailable in v1.

### 5.3 When NOT to Roll Back

Do not roll back nodes one at a time while others remain on v2. This creates
a split mesh where v1 nodes (WireGuard) and v2 nodes (Reality TLS) cannot
communicate. If you roll back, roll back every node.

---

## 6. Common Migration Issues

### 6.1 "REALITY listener: permission denied" (Port 443)

Port 443 requires root or `CAP_NET_BIND_SERVICE`. Solutions:

```bash
# Option A: Run as root
systemctl edit meshdesk  # ensure User=root

# Option B: Grant capability (preferred)
setcap 'cap_net_bind_service=+ep' /usr/local/bin/meshdesk

# Option C: Use a non-privileged port
# Change node.listen to ":8443" and update peer endpoints accordingly
```

### 6.2 Peer Not Appearing in Gossip

```
Symptoms: meshdesk peers list shows fewer peers than expected.
Causes:
  1. Peer's public key not in any node's peers list → isolated, no one tells gossip about it.
  2. Shared node not started first → no bootstrap anchor.
  3. Reality TLS handshake failing (wrong private_key or short_ids).

Diagnosis:
  tail -f /var/log/meshdesk/meshdesk.log | grep -E "REALITY|gossip|peer"
```

### 6.3 "identity.json: unknown version 2"

```
Cause: Running v1 binary with a v2 identity file.
Fix: Restore the v1 identity from backup, or install the v2 binary.
```

### 6.4 WireGuard Processes Persisting

```
Symptoms: After v2 migration, `wg show` still shows active interfaces.
Cause: v1 meshdesk didn't shut down cleanly or wg-quick is running independently.

Fix:
  systemctl stop meshdesk
  wg-quick down wg0   # if using wg-quick
  ip link delete wg0   # force-remove the interface
  systemctl start meshdesk  # v2 starts cleanly
```

---

## 7. Architecture Migration Map

```
v1 Stack                              v2 Stack
════════                              ═══════
Application                           Application
  ├── WebSSH (mesh IP)                  ├── WebSSH (smux stream)
  ├── File transfer (mesh IP)           ├── File transfer (smux stream)
  ├── Proxy (SS/VLESS entry)            ├── Proxy (VLESS+Reality entry)
  └── Dashboard                         └── Dashboard (+ RPC remote-config)
                                         │
gVisor netstack (virtual IP layer)    Layer 3: MultiPathSession (smux pool)
WireGuard device (handshake+encrypt)  Layer 2b: smux (stream multiplex)
  │                                   Layer 2a: Session (key exchange + AES-GCM)
Obfuscation (none/padded/ws/reality)  Layer 1: Reality TLS 1.3 (handshake)
  │                                   Layer 0: Ed25519 Identity
UDP/TCP socket                             │
                                      TCP/UDP socket
```

Every layer in v1 (WireGuard device, gVisor, virtual IPs) has been replaced
by a simpler, narrower, purpose-built v2 equivalent. The result is fewer
moving parts, less code (~8000 lines removed), and a stack where each layer
can be tested, swapped, and understood in isolation.

---

## 8. Related Documents

| Document | Relevance |
|----------|-----------|
| `docs/V2_INTERFACE_CONTRACT.md` | Frozen interface signatures for all layers |
| `docs/LAYER0_LAYER1_SPEC.md` | Detailed L0 (Identity) + L1 (Handshake) spec with ACs |
| `docs/MULTIPATH_SESSION_SPEC.md` | Layer 3 multi-path session design |
| `docs/MESHDESK_V2_DESIGN.md` | Overall v2 architecture and decisions |
| `docs/CONFIG_INVENTORY.md` | v1 config field inventory |
| `docs/ARCHITECTURE_REFACTOR.md` | v1 architecture refactoring plan |
| `docs/PROXY_DESIGN.md` | Multi-path proxy design (v2) |

---

## 9. Change History

| Date | Change | Author |
|------|--------|--------|
| 2026-07-28 | Initial: WireGuard→Reality migration path, config mapping, step-by-step procedure | writer |
| — | Update after Phase 1 (v1 code removal) | (pending) |
| — | Update after Phase 2 (protocol core implementation) | (pending) |
| — | Update after Phase 10 (real-machine testing feedback) | (pending) |