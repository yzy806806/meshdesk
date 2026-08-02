# MeshDesk Config Security Model — Tiered Access Control

**Version:** 1.0
**Source task:** t_49251780 (Action item 2/5 from motion-c642d60e9a8d)
**Companion to:** [CONFIG_INVENTORY.md](CONFIG_INVENTORY.md), [THREAT_MODEL.md](../THREAT_MODEL.md)
**Auth implementation:** [internal/web/stepup.go](../internal/web/stepup.go)

---

## 1. Tier Definitions

Every config field exposed to the Dashboard Config API is assigned exactly one tier.
The tiers form a strict escalation ladder: Normal < Step-Up < Masked < Read-Only.
When a field fits multiple tiers, assign the highest.

| Tier | Display | Edit gate | Example |
|------|---------|-----------|---------|
| **read-only** | Shown normally (or masked if secret) | **Never editable** via Dashboard API | `node.identity` — WG private key |
| **masked** | Shown as `••••••••` with Show/Hide toggle | Requires **step-up auth** → confirmation dialog → save | `proxy.ss.password` — SS PSK |
| **require-step-up** | Shown normally | Requires **step-up auth** → confirmation dialog → save | `auth.require_2fa` — mandates 2FA |
| **normal** | Shown normally | Editable after login → save (no re-auth) | `node.hostname` — cosmetic label |

**Step-up auth** means: the user must re-enter their password at `/api/stepup/verify?op=settings`
to receive a short-lived step-up token (default 5-minute lifetime). The existing `OpSettings`
constant in `internal/web/stepup.go:18` covers all Dashboard config edits.

**Masked display** means: the API response replaces the value with `"••••••••"` (fixed-length mask).
A dedicated "Reveal" endpoint (`POST /api/config/reveal?field=<path>`) requires step-up and
returns the cleartext ONCE. The cleartext is never cached in the browser.

---

## 2. Complete Field Classification

### 2.1 Node Identity — `node.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 1 | `node.identity` | `node.identity` | string | **read-only** | WireGuard private key. Auto-generated if empty. Changing it breaks all established Noise_IKpsk2 sessions, invalidates the node's mesh identity, and requires all peers to update their configs. |
| 2 | `node.hostname` | `node.hostname` | string | **normal** | Cosmetic label for dashboard/CLI display. Auto-detected from `os.Hostname()` if empty. |
| 3 | `node.web` | `node.web` | string | **require-step-up** | Web dashboard listen address (e.g. `:8080`). Changing this mid-session kills the HTTP listener. If misconfigured (empty string), dashboard access is lost and operator must SSH in to fix. |
| 4 | `node.position.x` | `node.position.x` | float64 | **normal** | 3D topology display coordinate. Purely cosmetic; does not affect routing. |
| 5 | `node.position.y` | `node.position.y` | float64 | **normal** | Same as above. |
| 6 | `node.position.z` | `node.position.z` | float64 | **normal** | Same as above. |

### 2.2 Mesh Networking — `mesh.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 7 | `mesh.port` | `mesh.port` | int | **require-step-up** | WireGuard UDP listen port (default 51820). Changing this kills all active WireGuard sessions and requires a listener restart. Changing the port number does not weaken security, but the disruption is severe. |
| 8 | `mesh.gossip_port` | `mesh.gossip_port` | int | **require-step-up** | Memberlist TCP port (default 7946). Changing this disrupts P2P gossip discovery for all connected peers. |

### 2.3 P2P Dynamic Networking — `p2p.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 9 | `p2p.enabled` | `p2p.enabled` | bool | **require-step-up** | Toggles the entire P2P subsystem (gossip, NAT traversal, dynamic join). Disabling it silently drops all P2P-discovered peers. |
| 10 | `p2p.seeds` | `p2p.seeds` | []string | **normal** | Bootstrap mesh IP:gossip_port addresses. Changing seeds affects new join attempts but established sessions persist. |
| 11 | `p2p.nat_traversal` | `p2p.nat_traversal` | bool | **normal** | Enables STUN discovery and UDP hole-punching. Toggling is safe; the gossip layer re-probes. |
| 12 | `p2p.stun_servers` | `p2p.stun_servers` | []string | **normal** | STUN server list for NAT discovery. Operational tuning. |
| 13 | `p2p.relay_mode` | `p2p.relay_mode` | string | **require-step-up** | Controls relay fallback: `auto`, `manual`, or `disabled`. Setting to `disabled` removes fault tolerance — direct-only peers that can't hole-punch lose connectivity. |
| 14 | `p2p.max_relay_hops` | `p2p.max_relay_hops` | int | **normal** | Tuning parameter. Higher = more latency, more resilience. |
| 15 | `p2p.join_approval` | `p2p.join_approval` | string | **require-step-up** | **Security-relevant.** `auto` = anyone with a key in `authorized_keys` joins. `manual` = admin approval via dashboard. Changing from `manual` to `auto` removes human review. |
| 16 | `p2p.authorized_keys` | `p2p.authorized_keys` | []string | **require-step-up** | **Security-relevant.** List of pre-authorized WG public keys. Adding a malicious key grants mesh access. Removing a key silently drops a node. |
| 17 | `p2p.gossip_interval` | `p2p.gossip_interval` | int | **normal** | Push/Pull interval in seconds. Tuning. |
| 18 | `p2p.gossip_probe_interval` | `p2p.gossip_probe_interval` | int | **normal** | Health check probe interval. Tuning. |
| 19 | `p2p.direct_reprobe_interval` | `p2p.direct_reprobe_interval` | int | **normal** | Relay→direct recheck interval. Tuning. |
| 20 | `p2p.max_peers` | `p2p.max_peers` | int | **normal** | Hard limit on peer count. Resource tuning. |

### 2.4 Monitoring — `monitoring.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 21 | `monitoring.collectors` | `monitoring.collectors` | []string | **normal** | Peer IDs of metric collector nodes. Operational. |
| 22 | `monitoring.interval` | `monitoring.interval` | int | **normal** | Push interval in seconds. Tuning. |
| 23 | `monitoring.port` | `monitoring.port` | int | **normal** | Mesh-internal port for metric pushes (default 4191). Changing requires subsystem restart but not security-sensitive. |

### 2.5 WebSSH — `webssh.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 24 | `webssh.port` | `webssh.port` | int | **normal** | SSH server port on target node (default 2222). Requires webssh subsystem restart but not security-sensitive. |
| 25 | `webssh.host_key` | `webssh.host_key` | string | **read-only** | SSH host private key (Ed25519 PEM). Auto-generated on startup if empty. Changing this breaks SSH host key verification for all clients — they will see a "REMOTE HOST IDENTIFICATION HAS CHANGED" warning. Must be configured once at deployment, never changed via dashboard. |
| 26 | `webssh.shell` | `webssh.shell` | string | **normal** | Default shell path. Auto-detected from `/etc/passwd` if empty. Changing to a non-existent binary breaks terminal sessions but is not a security risk. |
| 27 | `webssh.dial_timeout` | `webssh.dial_timeout` | int | **normal** | SSH dial timeout in seconds. Tuning. |
| 28 | `webssh.read_deadline` | `webssh.read_deadline` | int | **normal** | WebSocket read deadline in seconds. Tuning. |
| 29 | `webssh.write_deadline` | `webssh.write_deadline` | int | **normal** | WebSocket write deadline in seconds. Tuning. |
| 30 | `webssh.max_sessions` | `webssh.max_sessions` | int | **normal** | Concurrent terminal session limit. Resource tuning. |

### 2.6 Authentication — `auth.*`

Web users (`auth.web_users`) are managed as a **separate resource** (CRUD operations on user entries),
not as inline config fields. The per-user fields are:

| Field path | YAML key | Go type | Tier | Rationale |
|-----------|----------|---------|------|-----------|
| `auth.web_users[].username` | `username` | string | **require-step-up** | Creating/deleting users and changing credentials. |
| `auth.web_users[].password_hash` | `password_hash` | string | **masked** | bcrypt hash. Display masked. Edit via password-change flow, never raw bcrypt input. |

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 31 | `auth.totp_issuer` | `auth.totp_issuer` | string | **normal** | Display string in TOTP QR codes (default "MeshDesk"). Cosmetic. |
| 32 | `auth.require_2fa` | `auth.require_2fa` | bool | **require-step-up** | **CRITICAL.** Mandates TOTP 2FA for all web users. Enabling this when no users are enrolled locks out all dashboard access — the operator must SSH in and edit `config.yaml` to recover. The UI MUST check that at least one user has completed TOTP enrollment before allowing this toggle. |
| 33 | `auth.totp_window` | `auth.totp_window` | int | **require-step-up** | ±time-step skew tolerance (default 1 = ±30s). Increasing widens the valid TOTP window (easier brute force). Decreasing causes valid codes to be rejected. |
| 34 | `auth.totp_store_dir` | `auth.totp_store_dir` | string | **require-step-up** | Path to persistent TOTP state (`/var/lib/meshdesk/totp`). Changing this path silently loses all enrolled TOTP secrets — all users are de-enrolled. The UI MUST warn and require confirmation. |
| 35 | `auth.step_up_timeout` | `auth.step_up_timeout` | int | **require-step-up** | Step-up token lifetime in seconds (default 300). Longer = wider window for session hijacking to perform sensitive operations. Shorter = more frequent password prompts. |
| 36 | `auth.alert_webhook_url` | `auth.alert_webhook_url` | string | **require-step-up** | External webhook for security alerts. An attacker who changes this could redirect alert notifications to a malicious endpoint, suppressing breach detection. |

### 2.7 File Transfer — `transfer.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 37 | `transfer.max_file_size` | `transfer.max_file_size` | int64 | **normal** | Max single file size in bytes (default 1 GB). Resource tuning. |
| 38 | `transfer.upload_dir` | `transfer.upload_dir` | string | **normal** | Incoming file destination directory. Path config. |

### 2.8 SOCKS5 Proxy Configuration — `proxy.entry.socks5`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 39 | `proxy.entry.socks5.enabled` | `proxy.entry.socks5.enabled` | bool | **require-step-up** | Enables the SOCKS5 proxy entry listener on the MuxTransport port. When enabled, SOCKS5 clients can connect after Reality TLS handshake. |
| 40 | `proxy.entry.socks5.port` | `proxy.entry.socks5.port` | int | **normal** | SOCKS5 virtual port (default 0x4D=77). Demultiplexed from MuxTransport via 2-byte virtual port frame. Tuning. |
| 41 | `proxy.entry.socks5.auth` | `proxy.entry.socks5.auth` | string | **require-step-up** | SOCKS5 authentication method. Options: `none`, `password`. Password mode requires client credentials. |
| 42 | `proxy.exit.enabled` | `proxy.exit.enabled` | bool | **require-step-up** | Enables exit node functionality. Exit nodes forward traffic to the internet — legal liability for the operator. |
| 43 | `proxy.exit.allowed_ports` | `proxy.exit.allowed_ports` | []int | **require-step-up** | Port allowlist for exit traffic. Default: [80, 443]. Expanding this list increases legal exposure. |
| 44 | `proxy.exit.allow_all_ports` | `proxy.exit.allow_all_ports` | bool | **require-step-up** | If true, bypasses allowed_ports and forwards to any port. Maximum legal risk — enable only if you understand your jurisdiction. |
| 45 | `proxy.relay.enabled` | `proxy.relay.enabled` | bool | **normal** | Enables relay forwarding. Relay nodes carry other users' encrypted traffic. |
| 46 | `proxy.relay.max_circuits` | `proxy.relay.max_circuits` | int | **normal** | Max concurrent relay circuits. Resource limit. |

### 2.9 Reality TLS Server — `reality.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 48 | `reality.enabled` | `reality.enabled` | bool | **require-step-up** | Starts/stops the Reality TLS listener. Enabling exposes a TLS endpoint. Disabling drops all Reality connections. |
| 49 | `reality.listen_addr` | `reality.listen_addr` | string | **require-step-up** | Reality listen address (default `:443`). Changing requires listener restart. |
| 50 | `reality.listen_port` | `reality.listen_port` | int | **require-step-up** | Overrides port in listen_addr. Same disruption as above. |
| 51 | `reality.dest` | `reality.dest` | string | **require-step-up** | Camouflage target (e.g. `www.apple.com:443`). Changing to an implausible target breaks the camouflage — the GFW can distinguish mesh traffic from real traffic. |
| 52 | `reality.server_names` | `reality.server_names` | []string | **normal** | Accepted SNI values. Not secret — these are the hostnames the server claims to be. |
| 53 | `reality.private_key` | `reality.private_key` | string | **masked** | **SECRET.** X25519 private key (hex). Exposure allows an attacker to authenticate as the Reality server and decrypt TLS traffic. |
| 54 | `reality.short_ids` | `reality.short_ids` | []string | **masked** | **SENSITIVE.** Accepted client short IDs (hex). If leaked, an attacker can authenticate as a valid Reality client. |

### 2.10 Proxy — Shadowsocks Entry Point (Legacy) — `proxy.ss.*`

> **DEPRECATED:** SOCKS5 over Reality TLS (virtual port 0x5350) is the default
> proxy entry. The SS listener is only started when `proxy.ss.enabled: true`.

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 55 | `proxy.ss.enabled` | `proxy.ss.enabled` | bool | **normal** | Controls whether the legacy SS listener starts. Default: false. |
| 56 | `proxy.ss.password` | `proxy.ss.password` | string | **masked** | **SECRET.** Shadowsocks pre-shared password for AEAD key derivation. Exposure allows decryption of all SS traffic on this entry node. |
| 57 | `proxy.ss.cipher` | `proxy.ss.cipher` | string | **require-step-up** | AEAD cipher name (currently `chacha20-ietf-poly1305`). Changing the cipher breaks compatibility with existing clients. |
| 58 | `proxy.ss.listen_addr` | `proxy.ss.listen_addr` | string | **require-step-up** | SS listen address. Changing disrupts the proxy entry point. |
| 59 | `proxy.ss.port` | `proxy.ss.port` | int | **require-step-up** | SS listen port (default 8388). Same disruption as above. |

### 2.11 Proxy — Circuit Lifecycle — `proxy.circuit.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 59 | `proxy.circuit.idle_timeout` | `proxy.circuit.idle_timeout` | int | **normal** | Circuit idle timeout in seconds (default 300). Tuning. |
| 60 | `proxy.circuit.keepalive_interval` | `proxy.circuit.keepalive_interval` | int | **normal** | Keepalive interval in seconds (default 30). Tuning. |
| 61 | `proxy.circuit.nack_timeout` | `proxy.circuit.nack_timeout` | int | **normal** | NACK timeout in seconds (default 5). Tuning. |
| 62 | `proxy.circuit.orphan_timeout` | `proxy.circuit.orphan_timeout` | int | **normal** | Reassembly orphan timeout in seconds (default 30). Tuning. |
| 63 | `proxy.circuit.max_reassembly_window` | `proxy.circuit.max_reassembly_window` | int | **normal** | Hard limit on reassembly window size (default 256). Resource tuning. |

### 2.12 Proxy — Top-Level — `proxy.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 64 | `proxy.chunker_strategy` | `proxy.chunker_strategy` | string | **normal** | Chunking strategy: `bounded-4k-64k` (default) or `fixed-16k`. Tuning. |
| 65 | `proxy.debug_fixed_chunks` | `proxy.debug_fixed_chunks` | bool | **require-step-up** | **Security-critical.** Forces uniform 16KB chunks for deterministic testing. **MUST be `false` in production.** Enabling creates uniformly-sized chunks that are trivially fingerprintable by DPI — the multi-path dispersion loses all traffic analysis resistance. The UI MUST show a prominent red warning. When toggled to `true`, the UI MUST require a second confirmation acknowledging the security risk. |
| 66 | `proxy.paths` | `proxy.paths` | [][]string | **normal** | Manually configured relay paths (Phase 1). Only used when `path_selection.mode` is `manual`. |
| 67 | `proxy.exit_addr` | `proxy.exit_addr` | string | **require-step-up** | Mesh address of the exit node (e.g. `10.10.0.5:8388`). Changing this redirects all proxy exit traffic to a different node — potentially one controlled by an attacker if misconfigured. |

### 2.13 Proxy — Path Selection — `proxy.path_selection.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 68 | `proxy.path_selection.mode` | `proxy.path_selection.mode` | string | **normal** | `manual` (Phase 1) or `auto` (Phase 2 dynamic probing). |
| 69 | `proxy.path_selection.strategy` | `proxy.path_selection.strategy` | string | **normal** | Ranking algorithm: `latency`, `random`, or `round-robin`. |
| 70 | `proxy.path_selection.max_relays_per_path` | `proxy.path_selection.max_relays_per_path` | int | **normal** | Max relay hops per path. Tuning. |
| 71 | `proxy.path_selection.probe_timeout_sec` | `proxy.path_selection.probe_timeout_sec` | int | **normal** | Probe timeout. Tuning. |
| 72 | `proxy.path_selection.probe_concurrency` | `proxy.path_selection.probe_concurrency` | int | **normal** | Concurrent probe limit. Tuning. |
| 73 | `proxy.path_selection.max_candidates` | `proxy.path_selection.max_candidates` | int | **normal** | Max relays to probe. Tuning. |
| 74 | `proxy.path_selection.probe_cache_ttl_sec` | `proxy.path_selection.probe_cache_ttl_sec` | int | **normal** | Probe cache TTL. Tuning. |
| 75 | `proxy.path_selection.exit_latency_matrix` | `proxy.path_selection.exit_latency_matrix` | map | **normal** | Exit→region RTT data for exit selection. Populated by probing, rarely edited manually. |

### 2.14 Proxy — Cloudflare Tunnel — `proxy.cf_tunnel.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 76 | `proxy.cf_tunnel.enabled` | `proxy.cf_tunnel.enabled` | bool | **require-step-up** | Starts/stops the CF Tunnel subprocess. When enabled, exposes the SS listener to the public internet via Cloudflare's edge. This is a **significant exposure change.** |
| 77 | `proxy.cf_tunnel.tunnel_id` | `proxy.cf_tunnel.tunnel_id` | string | **normal** | Cloudflare Tunnel UUID. Identifies the tunnel but is not a secret — the credentials file provides authentication. |
| 78 | `proxy.cf_tunnel.credentials_file` | `proxy.cf_tunnel.credentials_file` | string | **normal** | Path to CF tunnel credentials JSON. The path itself is not a secret; the file contents are. |
| 79 | `proxy.cf_tunnel.hostname` | `proxy.cf_tunnel.hostname` | string | **require-step-up** | CF hostname (e.g. `proxy.example.com`). Changing this breaks all client connectivity until DNS propagates. |
| 80 | `proxy.cf_tunnel.origin_server` | `proxy.cf_tunnel.origin_server` | string | **normal** | Local address the tunnel forwards to (default `127.0.0.1:8388`). |
| 81 | `proxy.cf_tunnel.region` | `proxy.cf_tunnel.region` | string | **normal** | CF edge region preference. |
| 82 | `proxy.cf_tunnel.log_level` | `proxy.cf_tunnel.log_level` | string | **normal** | cloudflared logging verbosity. |
| 83 | `proxy.cf_tunnel.metrics_addr` | `proxy.cf_tunnel.metrics_addr` | string | **normal** | cloudflared metrics server address. |
| 84 | `proxy.cf_tunnel.binary_path` | `proxy.cf_tunnel.binary_path` | string | **require-step-up** | Path to cloudflared binary. Could point to a malicious binary. |
| 85 | `proxy.cf_tunnel.reconnect_retries` | `proxy.cf_tunnel.reconnect_retries` | int | **normal** | Connection retry count. Tuning. |
| 86 | `proxy.cf_tunnel.grace_period_sec` | `proxy.cf_tunnel.grace_period_sec` | int | **normal** | Shutdown drain time. Tuning. |

### 2.15 Proxy — Relay Node — `proxy.relay.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 87 | `proxy.relay.enabled` | `proxy.relay.enabled` | bool | **require-step-up** | **Security-relevant.** Enables relay node role. When enabled, this node will blindly forward AEAD-encrypted ciphertext chunks for other nodes. Has legal implications — the node is forwarding traffic it cannot inspect. The UI MUST show a notice about legal exposure. |
| 88 | `proxy.relay.jitter_min_ms` | `proxy.relay.jitter_min_ms` | int | **normal** | Min forwarding delay per chunk. Tuning. |
| 89 | `proxy.relay.jitter_max_ms` | `proxy.relay.jitter_max_ms` | int | **normal** | Max forwarding delay per chunk. Tuning. |
| 90 | `proxy.relay.disable_jitter` | `proxy.relay.disable_jitter` | bool | **require-step-up** | **Security-critical.** When `true`, skips random delay. **MUST be `false` in production.** Disabling jitter creates a timing side-channel exploitable by traffic analysis. The UI MUST show a red warning and require a second confirmation. |
| 91 | `proxy.relay.max_circuits` | `proxy.relay.max_circuits` | int | **normal** | Concurrent circuit limit (default 1024). Resource tuning. |
| 92 | `proxy.relay.max_queue_depth` | `proxy.relay.max_queue_depth` | int | **normal** | Per-circuit pending chunk limit (default 256). Resource tuning. |

### 2.16 Proxy — Exit Node — `proxy.exit.*`

| # | Field path | YAML key | Go type | Tier | Rationale |
|---|-----------|----------|---------|------|-----------|
| 93 | `proxy.exit.allowed_ports` | `proxy.exit.allowed_ports` | []int | **require-step-up** | **Legal liability.** Destination ports the exit will connect to (default `[80, 443]`). Expanding this list increases the operator's legal exposure. Operators should understand that running an exit node may violate their ISP's terms of service. |
| 94 | `proxy.exit.allow_all_ports` | `proxy.exit.allow_all_ports` | bool | **require-step-up** | **CRITICAL legal exposure.** Removes all port restrictions. When `true`, the exit will connect to any port — including SMTP (25), SSH (22), and others commonly used for abuse. The UI MUST show a prominent legal warning and require TWO confirmations before enabling. |
| 95 | `proxy.exit.destination_filter` | `proxy.exit.destination_filter` | []string | **require-step-up** | CIDR/FQDN patterns the exit is allowed to connect to. Empty = allow all destinations (subject to port restrictions). This is the primary exit security boundary — tightening it reduces abuse risk. |
| 96 | `proxy.exit.audit_log_dir` | `proxy.exit.audit_log_dir` | string | **normal** | Exit audit log directory. Path config. |
| 97 | `proxy.exit.audit_retention_days` | `proxy.exit.audit_retention_days` | int | **normal** | Audit log retention in days (default 7). |

---

## 3. Peer Management — `peers[]`

Peers are managed as a **collection resource** (like web_users), not individual scalar fields.
Each peer entry has 27+ leaf fields. The security tiers for peer fields:

### 3.1 Peer Identity (per-peer)

| Field path | YAML key | Tier | Rationale |
|-----------|----------|------|-----------|
| `peers[].public_key` | `public_key` | **require-step-up** | WireGuard public key. Changing this breaks the peer relationship — the node will reject handshakes from the new key. |
| `peers[].endpoint` | `endpoint` | **require-step-up** | Connection endpoint (`host:port`). Changing routes WG traffic to a different host. |
| `peers[].allowed_ips` | `allowed_ips` | **require-step-up** | Mesh IPs routed to this peer. Changing affects mesh routing topology. |
| `peers[].capabilities` | `capabilities` | **require-step-up** | **Security-critical.** What this peer can do (`ssh_proxy`, `file_transfer`, `monitor_read`, `monitor_write`, `service_manage`, `binary_upgrade`). Granting capabilities to the wrong peer = lateral movement. |
| `peers[].obfuscation` | `obfuscation` | **require-step-up** | Transport obfuscation mode (`none`, `padded`, `websocket`, `reality`). Changing from `reality` to `none` exposes WG handshake to DPI. |
| `peers[].preshared_key` | `preshared_key` | **masked** | **SECRET.** WireGuard PSK. Adds post-quantum resistance to Noise_IKpsk2. Exposure weakens the handshake. |
| `peers[].service_manage` | `service_manage` | **require-step-up** | **Security-relevant.** Which systemd services this peer can manage. |
| `peers[].file_transfer_paths` | `file_transfer_paths` | **require-step-up** | **Security-relevant.** Directory prefixes for file transfers. Empty = unrestricted. |
| `peers[].monitor_scopes` | `monitor_scopes` | **require-step-up** | **Security-relevant.** Metric categories this peer can access. |

### 3.2 Peer Obfuscation Settings (`peers[].obf_config.*`)

| Field path | YAML key | Tier | Rationale |
|-----------|----------|------|-----------|
| `obf_config.h1`–`h4` | `h1`–`h4` | **normal** | WG message type ranges. Obfuscation parameters; not secret but changing them breaks compatibility with the peer's settings. |
| `obf_config.s1`–`s4` | `s1`–`s4` | **normal** | Max random padding bytes per message type. |
| `obf_config.jc`, `jmin`, `jmax` | `jc`, `jmin`, `jmax` | **normal** | Junk train configuration (v2 feature). |
| `obf_config.psk` | `psk` | **masked** | **SECRET.** Hex anti-probe PSK (32 bytes). If set, handshake initiations must include a valid HMAC tag. Exposure allows an attacker to craft valid handshake probes. |
| `obf_config.jitter_max_ms` | `jitter_max_ms` | **normal** | Timing jitter maximum. |
| `obf_config.ws_use_tls` | `ws_use_tls` | **require-step-up** | Enables TLS for WebSocket mode. Changes transport security. |
| `obf_config.tls_sni` | `tls_sni` | **normal** | TLS SNI hostname for websocket mode. |
| `obf_config.tls_fingerprint` | `tls_fingerprint` | **normal** | Browser ClientHello mimic (`chrome`, `firefox`, `safari`, `edge`, `ios`, `android`). |

### 3.3 Peer Reality Client Settings (`peers[].reality.*`)

| Field path | YAML key | Tier | Rationale |
|-----------|----------|------|-----------|
| `reality.server_name` | `server_name` | **normal** | SNI hostname to present. |
| `reality.public_key` | `public_key` | **normal** | Server's X25519 public key. This is a **public** key — meant to be shared. |
| `reality.short_id` | `short_id` | **masked** | **SENSITIVE.** Per-client short ID for REALITY auth. Must match one of the server's `short_ids`. |
| `reality.tls_fingerprint` | `tls_fingerprint` | **normal** | Browser ClientHello to mimic. |

### 3.4 Peer-Lifecycle Operations

| Operation | Tier | Guardrails |
|-----------|------|------------|
| **Create peer** | **require-step-up** | Adding a peer with `ssh_proxy` or `service_manage` capabilities grants the peer access to this node. Show a capability summary before confirming. |
| **Delete peer** | **require-step-up** | Deleting a peer silently drops all WG sessions and removes the peer from the mesh. Confirmation dialog with peer public key displayed. |
| **Edit peer** | **require-step-up** | Any field edit on an existing peer requires step-up. |

---

## 4. Web User Management — `auth.web_users[]`

| Operation | Tier | Guardrails |
|-----------|------|------------|
| **Create user** | **require-step-up** | Creating a new web dashboard user. Requires step-up. |
| **Change password** | **masked** | Password is never displayed. Change flow: enter current password → enter new password (twice) → step-up verify. bcrypt hash generated server-side. |
| **Delete user** | **require-step-up** | Cannot delete the last remaining web user (prevents lockout). Must be at least one active user. |
| **View user list** | **normal** | Usernames are displayed. Password hashes are never sent to the frontend. |

---

## 5. Guardrails Summary

### 5.1 Confirmation Prompts

The following operations require a confirmation dialog BEFORE the step-up challenge:

| Operation | Confirmation text | Special handling |
|-----------|-------------------|------------------|
| `auth.require_2fa` → `true` | "Are you sure you want to mandate 2FA for ALL users? At least 1 user must have completed TOTP enrollment first." | Pre-check: count enrolled users. Block if 0. |
| `auth.totp_store_dir` change | "Changing the TOTP storage directory will lose all currently enrolled TOTP secrets. All users will need to re-enroll. Continue?" | |
| `reality.private_key` change | "Changing the Reality private key will break all existing Reality TLS connections. Connected clients will be disconnected. Continue?" | |
| `proxy.relay.enabled` → `true` | "Enabling relay mode means this node will blindly forward encrypted traffic for other nodes. You may be legally responsible for traffic you cannot inspect. Continue?" | Show legal notice. |
| `proxy.exit.allow_all_ports` → `true` | "⚠️ CRITICAL: Removing all port restrictions exposes this exit node to full legal liability. This includes SMTP (port 25), SSH (port 22), and other ports commonly used for abuse. This is NOT recommended. Are you sure?" | **Double confirmation required.** |
| `proxy.debug_fixed_chunks` → `true` | "⚠️ Enabling fixed-size chunks makes proxy traffic trivially fingerprintable by DPI. This MUST only be used for testing. Are you sure?" | Red warning banner. |
| `proxy.relay.disable_jitter` → `true` | "⚠️ Disabling jitter creates a timing side-channel exploitable by traffic analysis. This MUST only be used for testing. Are you sure?" | Red warning banner. |
| `proxy.entry.socks5.enabled` → true | "Enabling the SOCKS5 proxy entry allows SOCKS5 clients to connect after Reality TLS handshake. Any standard SOCKS5 client can then route traffic through the mesh. Continue?" | |
| Delete last web user | Blocked entirely — "Cannot delete the last web user." | |
| Delete peer | "Delete peer `<public_key_fingerprint>`? All active WireGuard sessions with this peer will be terminated." | Show key fingerprint. |

### 5.2 Write Protection (Runtime vs Restart-Required)

Some field changes cannot take effect without a process restart. The Dashboard MUST indicate this:

**Restart required (full process restart):**

| Field | Why |
|-------|-----|
| `node.identity` | WireGuard keypair is loaded once at startup. (Also read-only via Dashboard.) |
| `node.web` | HTTP listener is bound at startup. Changing port/addr requires restart. |
| `mesh.port` | WireGuard listener bind. |
| `mesh.gossip_port` | Memberlist listener bind. |
| `webssh.port` | SSH server listener bind. |
| `webssh.host_key` | SSH host key loaded at startup. (Also read-only.) |
| `reality.enabled`, `reality.listen_addr`, `reality.listen_port` | Reality listener lifecycle. |

**Subsystem restart required (no full process restart):**

| Field | Why |
|-------|-----|
| `p2p.enabled` | P2P gossip layer start/stop. |
| `proxy.cf_tunnel.enabled` | cloudflared subprocess start/stop. |
| `proxy.relay.enabled` | Relay module lifecycle. |
| `proxy.entry.socks5.enabled` | SOCKS5 proxy entry listener enable/disable. |

**Hot-reloadable (takes effect immediately):**

| Category | Fields |
|----------|--------|
| Tuning parameters | All interval/timeout/size limits (gossip_interval, circuit timeouts, max_peers, max_sessions, etc.) |
| Operational paths | upload_dir, totp_store_dir, audit_log_dir, config_dir |
| Display/identity | hostname, position, totp_issuer |
| Auth config | require_2fa, totp_window, step_up_timeout, alert_webhook_url |
| Capability/security | authorized_keys, capabilities, service_manage, file_transfer_paths, monitor_scopes |

### 5.3 Step-Up Auth Integration

All field edits in the **require-step-up** and **masked** tiers share the existing `OpSettings`
step-up token flow:

```
1. User clicks "Edit" on a step-up-protected field
2. If no valid step-up token for OpSettings:
   a. Frontend redirects to GET /api/stepup/challenge?op=settings
   b. Server renders password re-entry form
   c. User enters password
   d. POST /api/stepup/verify?op=settings
   e. Server validates password, creates stepUpToken with Operations=["settings"], 5-min TTL
3. User edits the field value
4. Frontend sends PUT /api/config/<section> with step-up token validated by requireStepUp middleware
5. Server writes config (config.Save) and, if hot-reloadable, notifies subsystems
```

The existing `OpSettings` constant in `internal/web/stepup.go:18` already exists and is
unused — it was defined for exactly this purpose.

### 5.4 Masked Field Protocol

For fields in the **masked** tier, the GET endpoint returns the value as `"••••••••"` (8 bullets,
fixed length to prevent value-length inference). The user must:

1. Click "Show" → requires step-up auth → server returns cleartext ONCE
2. Click "Edit" → requires step-up auth → show input field → enter new value → confirm → save
3. Cleartext is NEVER cached in `localStorage` or `sessionStorage`

The reveal endpoint: `POST /api/config/reveal?field=<dot.path>` (requires step-up, returns JSON `{"value": "..."}`).

### 5.5 Read-Only Field Handling

Read-only fields are displayed in the UI with a lock icon and a tooltip explaining WHY
they can't be edited:

| Field | Tooltip |
|-------|---------|
| `node.identity` | "WireGuard private key. Auto-generated at node startup. Changing this would break all mesh connectivity. Edit config.yaml directly on the node if you must rotate keys." |
| `webssh.host_key` | "SSH host key. Auto-generated at startup. Changing this would trigger 'REMOTE HOST IDENTIFICATION HAS CHANGED' warnings on all SSH clients. Edit config.yaml directly if you must rotate." |

---

## 6. Implementation Notes

### 6.1 Server-Side Enforcement Pattern

```go
// All config write endpoints use this middleware chain:
mux.HandleFunc("/api/config/{section}", s.requireAuth(
    s.requireStepUp(OpSettings, s.handleConfigWrite),
))
```

Masked fields require an additional check in the handler:
```go
// In handleConfigWrite:
if tier == "masked" && newValue == "••••••••" {
    // User didn't change the masked field — skip this field's update
    continue
}
```

### 6.2 API Response Shape

GET endpoints return field metadata alongside values:
```json
{
  "fields": [
    {
      "path": "node.identity",
      "value": "••••••••",
      "tier": "read-only",
      "default": "<auto-generated>",
      "restart_required": true,
      "description": "WireGuard private key — auto-generated"
    },
    {
      "path": "node.hostname",
      "value": "my-node",
      "tier": "normal",
      "default": "<auto-detected>",
      "restart_required": false,
      "description": "Node display name"
    }
  ]
}
```

### 6.3 Existing Code to Reuse

| Component | Location | Status |
|-----------|----------|--------|
| `OpSettings` constant | `internal/web/stepup.go:18` | Defined, unused — ready. |
| `StepUpStore.Grant/Validate` | `internal/web/stepup.go:43-73` | Fully implemented, tested. |
| `requireStepUp` middleware | `internal/web/server.go:569` | Works for JSON API endpoints. |
| `config.Save()` | `internal/config/config.go:883` | Writes with `0600` perms. Unused — no HTTP caller. |
| `config.Load()` | `internal/config/config.go:703` | Reads, applies defaults, detects legacy TOTP. Ready. |

### 6.4 What Must Be Built

1. **Config GET endpoints** — `GET /api/config/{section}` returns all fields for a section with tier metadata.
2. **Config PUT endpoints** — `PUT /api/config/{section}` accepts a partial field map, validates tiers, and saves.
3. **Reveal endpoint** — `POST /api/config/reveal?field=<path>` returns cleartext for a masked field.
4. **Per-field tier validation** — a server-side function `func FieldTier(path string) Tier` that maps dot-separated paths to tiers (this document is the spec for that function).
5. **Frontend field renderer** — renders fields according to their tier (lock icon, mask, step-up gate, confirmation dialogs).
6. **Restart-required indicator** — after saving a restart-required field, show a banner: "Restart required for changes to take effect."

---

## 7. Tier Distribution Summary

| Tier | Count | Fields |
|------|-------|--------|
| read-only | 2 | `node.identity`, `webssh.host_key` |
| masked | 7 | `reality.private_key`, `reality.short_ids`, `proxy.ss.password`, `peers[].preshared_key`, `peers[].obf_config.psk`, `peers[].reality.short_id`, `auth.web_users[].password_hash` |
| require-step-up | 35 | All security-relevant, disruptive, and legal-exposure fields |
| normal | 53 | All tuning, cosmetic, and operational-path fields |

**Total leaf fields: ~97** (97 individual configurable fields across 11 sections, plus peer and web_user collection resources).

---

## 8. Verification Checklist

To validate this model was correctly applied, verify the following against the source:

- [ ] `node.identity` is **not writable** via any `/api/config` endpoint (read-only)
- [ ] `proxy.ss.password` returns masked value on GET (masked)
- [ ] `proxy.debug_fixed_chunks` → `true` triggers confirmation + step-up (require-step-up)
- [ ] `proxy.exit.allow_all_ports` → `true` triggers **double** confirmation + step-up
- [ ] `auth.require_2fa` → `true` pre-checks enrolled users count (require-step-up + guardrail)
- [ ] All normal fields are writable without step-up after login
- [ ] Masked field reveal requires step-up, returns cleartext once, never cached
- [ ] Step-up token for `OpSettings` is valid for 5 minutes (default) or configured `step_up_timeout`
- [ ] Confirmation dialogs display the correct field-specific warning text
- [ ] Restart-required banner appears after saving restart-required fields
- [ ] Last web user cannot be deleted
- [ ] Peer deletion shows peer public key fingerprint in confirmation

---

*Generated by reviewer (t_49251780). Source: `internal/config/config.go` (923 lines), `internal/web/stepup.go` (88 lines), `internal/web/server.go` (1136 lines).*
