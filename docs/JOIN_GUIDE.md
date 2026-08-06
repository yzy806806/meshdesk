# MeshDesk One-Click Join Guide

**Version:** 1.1
**Status:** Beta
**Last updated:** 2026-08-06

## Overview

MeshDesk's one-click join lets you add a new node to the mesh with a single
command — no manual config file editing, no key generation, no peer discovery
configuration. Copy one line from the Dashboard, paste it into the new node's
SSH, and it joins automatically.

## How It Works

```
Dashboard (Bootstrap)              New Node (Joiner)
┌──────────────────────┐           ┌──────────────────────┐
│ 1. Generate token    │           │                      │
│    (HMAC-Ed25519)    │           │  curl ... | sh       │
│                      │──token──→│ 2. Generate Ed25519  │
│                      │          │    identity           │
│                      │←─pubkey──│ 3. POST /join/request│
│                      │          │    (token + pubkey)   │
│ 4. Validate token    │          │                      │
│    Return challenge  │──chal───→│ 5. Sign challenge    │
│                      │          │    (Ed25519 private)  │
│                      │←─sign────│ 6. POST /join/verify │
│ 7. Verify signature  │          │                      │
│    Return config     │──bundle─→│ 8. Write config       │
│    bundle            │          │    Start meshdesk     │
└──────────────────────┘           └──────────────────────┘
```

The protocol is a two-step HMAC-Ed25519 challenge-response:

1. **Request:** New node sends the join token + its Ed25519 public key. Bootstrap
   validates the token's HMAC signature and expiration.
2. **Challenge:** Bootstrap returns a random challenge. New node signs it with
   its Ed25519 private key, proving ownership.
3. **Verify:** Bootstrap verifies the signature. If valid, returns a full config
   bundle: identity, peers, collectors, reality keys.

This proves the joiner owns the key it claims, preventing impersonation even if
an attacker intercepts the token.

## Step 1: Generate Join Token on Dashboard

1. Open the Dashboard: `http://<bootstrap-node>:8080`
2. Navigate to **Nodes** → **Add Node** → **Generate Join Token**
3. Configure (all optional):
   - **Token expiry:** Default 1 hour. Max 24 hours.
   - **Hostname:** Pre-set the new node's hostname
   - **Capabilities:** Pre-set peer capabilities (monitor, SSH, file transfer)
   - **Exit node:** Pre-configure as SOCKS5 exit
4. Click **Generate**

The Dashboard displays a one-line command:

```bash
# Legacy web port (8080)
curl -fsSL http://<bootstrap>:8080/join?token=<base64-token> | sh

# Single-port path (52888) — v1.2.1+, no separate web port needed
curl -fsSL http://<bootstrap>:52888/join?token=<base64-token> | sh
```

This command:
- Downloads meshdesk binary for the target platform
- Generates an Ed25519 identity
- Performs the challenge-response join protocol
- Writes the config bundle to `/etc/meshdesk/config.yaml`
- Starts meshdesk as a systemd service

## Step 2: Execute on New Node

SSH into the new node and paste the command:

```bash
ssh root@new-node
# Legacy web port (8080)
curl -fsSL http://aliyun.example.com:8080/join?token=ZXhhbXBsZS10b2tlbg== | sh

# Single-port path (52888) — v1.2.1+
curl -fsSL http://aliyun.example.com:52888/join?token=ZXhhbXBsZS10b2tlbg== | sh
```

The install script:

```
[meshdesk] Downloading binary for linux/amd64...
[meshdesk] Binary downloaded: /usr/local/bin/meshdesk (v2.0.0)
[meshdesk] Generating Ed25519 identity...
[meshdesk] Identity: de52c6daa76948b1e3f2...
[meshdesk] Requesting join...
[meshdesk] Challenge received, signing...
[meshdesk] Config bundle received
[meshdesk] Writing config to /etc/meshdesk/config.yaml
[meshdesk] Starting meshdesk service...
[meshdesk] Done! Node joined as 'node3'.
[meshdesk] Dashboard: http://aliyun.example.com:52888
```

That's it. The new node is now part of the mesh.

## What Happens Under the Hood

### 1. Binary Download

The install script detects the system architecture and downloads the matching
meshdesk binary from the bootstrap node (or GitHub releases).

### 2. Identity Generation

```bash
meshdesk --gen-key
```

Generates an Ed25519 keypair. The public key becomes the node's mesh identity.

### 3. Join Protocol

The join client (`internal/join/client.go`) performs:

```
POST /api/join  (step 1)  {"token": "<base64>", "joiner_pubkey": "<hex>"}
→  200 {"success": true, "challenge": "<random-hex>"}

POST /api/join  (step 2)  {"token": "<base64>", "joiner_pubkey": "<hex>", "challenge": "<hex>", "challenge_response": "<ed25519-signature>"}
→  200 {"success": true, "bundle": {...}}
```

**v1.2.1+**: The `/api/join` endpoint (POST) serves the same two-step challenge-response protocol on the mesh port (52888) — step 1 (`token` + `joiner_pubkey`, no `challenge_response`) returns a challenge, step 2 adds the Ed25519 signature and returns the config bundle. Example (step 1):

```bash
curl -X POST http://gateway:52888/api/join \
  -H "Content-Type: application/json" \
  -d '{"token":"xxx","joiner_pubkey":"..."}'
# → {"success":true,"challenge":"<hex>"}

# Step 2: sign the challenge and send it back
curl -X POST http://gateway:52888/api/join \
  -H "Content-Type: application/json" \
  -d '{"token":"xxx","joiner_pubkey":"...","challenge":"<hex>","challenge_response":"<ed25519-signature>"}'
# → {"success":true,"bundle":{...}}
```

The config bundle contains:
- `identity`: Ed25519 keypair
- `mesh.reality`: Reality TLS server keys and configuration
- `p2p.seeds`: Bootstrap node endpoints
- `monitoring.collectors`: Collector node public keys
- `peers`: Initial peer list from gossip discovery

### 4. Service Start

The script creates a systemd service:

```ini
[Unit]
Description=MeshDesk Mesh Node
After=network.target

[Service]
ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

And enables it:

```bash
systemctl enable --now meshdesk
```

## Manual Join (Without One-Click)

If you prefer to run the steps manually:

```bash
# 1. Get the binary
wget https://github.com/yzy806806/meshdesk/releases/latest/download/meshdesk-linux-amd64 -O /usr/local/bin/meshdesk
chmod +x /usr/local/bin/meshdesk

# 2. Generate identity
meshdesk --gen-key
# Output: public_key: de52c6daa76948b1...

# 3. Join
# NOTE: the mesh-port HTTP endpoint (52888) is plain HTTP, so --insecure-tls
# is required (--insecure-tls also enables AllowPlainHTTP for http:// URLs).
# In production, prefer the TLS join server at https://bootstrap:8443.
meshdesk join --join-url http://bootstrap:52888 --join-token "<token-from-dashboard>" --insecure-tls
# This writes /etc/meshdesk/config.yaml automatically

# 4. Start
meshdesk --config /etc/meshdesk/config.yaml
```

## Token Security

### Token Format

```
base64(version || expiry_ts || random_nonce || HMAC-SHA256(key, version || expiry_ts || random_nonce))
```

- **version:** Token format version (1 byte)
- **expiry_ts:** Unix timestamp when the token expires (8 bytes)
- **random_nonce:** Random bytes to prevent token reuse (16 bytes)
- **HMAC:** Ed25519 signature over the token payload

### Security Properties

- **Time-limited:** Tokens expire after the configured duration (default 1 hour)
- **Single-use:** Each token has a unique nonce; the bootstrap node tracks used
  tokens and rejects replays
- **Challenge-response:** Even if a token is stolen, the attacker cannot complete
  the join without the claimed Ed25519 private key
- **Transport security:** The join protocol uses Ed25519 challenge-response for authentication, so the config bundle is cryptographically protected even over plain HTTP. When joining via the mesh port (52888), plain HTTP is supported. For production deployments, TLS (Reality TLS on port 8443, or a TLS reverse proxy) is still recommended.

## Revoking a Join Token

From the Dashboard: **Nodes** → **Join Tokens** → click **Revoke** on any
unused token. Used tokens are automatically invalidated after the first
successful join.

## Troubleshooting

### "token expired"

Join tokens have a limited lifetime (default 1 hour). Generate a new token
from the Dashboard.

### "token already used"

Each token can only be used once. Generate a new token.

### "signature verification failed"

The joiner's Ed25519 private key doesn't match the public key it claimed.
This can happen if:
- The identity was generated on a different machine
- The `/var/lib/meshdesk/identity` file was corrupted

Delete the identity and rejoin:
```bash
rm /var/lib/meshdesk/identity.key
meshdesk --gen-key
# Re-run the join command
```

### "connection refused" on port 8443

The bootstrap node's join endpoint is not running. Ensure the bootstrap node
has `--web` flag and Reality TLS configured. The join endpoint runs on the
same MuxTransport port as the mesh, using a dedicated virtual port.

**v1.2.1+**: With single-port HTTP demux, the join endpoint is also available on port 52888 (no separate web port needed). Try:

```bash
curl http://<bootstrap>:52888/join?token=<base64-token>
```

### "unsupported platform"

The one-click install script supports linux/amd64 and linux/arm64. For other
platforms, use the manual join method and build from source.

## Dashboard Management

### View Join History

Dashboard → **Nodes** → **Join History** shows:
- All nodes that joined via the one-click protocol
- Join timestamp
- Token used
- Current status (online/offline)

### Pre-configure Node Settings

When generating a join token, you can pre-set:
- **Hostname:** The new node's display name
- **Capabilities:** Enable monitor, SSH, file_transfer, service_manage per peer
- **Collector assignment:** Which collectors this node should push metrics to
- **SOCKS5 exit:** Pre-configure as an exit node for the SOCKS5 proxy

These settings are embedded in the config bundle and applied automatically.

## Limitations

- **Beta status:** The one-click join has been unit-tested but not yet
  validated on fresh cloud VMs with the full curl-pipe workflow
- **No approval gate:** Currently, all valid tokens are accepted automatically.
  Manual approval (requiring a Dashboard admin to click "Approve") is planned.
- **No auto-update:** The installed binary is not auto-updated. Nodes must be
  updated manually or via the Dashboard's remote management.