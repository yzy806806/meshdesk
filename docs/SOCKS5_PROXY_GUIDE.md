# MeshDesk SOCKS5 Proxy Setup Guide

**Version:** 1.0
**Status:** Beta
**Last updated:** 2026-08-02

## Overview

MeshDesk provides a SOCKS5 proxy that allows client devices (phones, laptops) to
route internet traffic through the mesh network to exit nodes. The proxy works
with any standard SOCKS5 client — no special software needed.

### How It Works

```
Phone/Laptop          Mesh Node            Mesh Network         Exit Node
┌──────────┐       ┌──────────────┐       ┌────────────┐       ┌─────────┐
│ SOCKS5   │──TLS──│ MuxTransport │──smux─│ Mesh Relay │──smux─│ Exit    │──→ Internet
│ Client   │  1.3  │ :52888       │       │ (encrypted)│       │ Node    │
│ (port    │       │ Reality TLS  │       │            │       │ TCP to  │
│  1080)   │       │ handshake    │       │            │       │ target  │
└──────────┘       └──────────────┘       └────────────┘       └─────────┘
```

1. SOCKS5 client connects to the mesh node's MuxTransport port (default 52888)
2. Reality TLS 1.3 handshake authenticates the connection
3. SOCKS5 CONNECT request is multiplexed via smux virtual port
4. MeshDesk routes the stream through relay peers to a configured exit node
5. Exit node opens a TCP connection to the destination and relays data

## Prerequisites

- A running meshdesk instance with `--web` (Dashboard) on at least one node
- At least one node configured as an **entry node** (where SOCKS5 clients connect)
- At least one node configured as an **exit node** (has internet access)
- The entry node must have Reality TLS configured (the SOCKS5 stream requires
  the Reality handshake for GFW evasion)

## Step 1: Configure the Exit Node

On the node that will serve as the internet exit:

Edit `/etc/meshdesk/config.yaml` or use the Dashboard config page:

```yaml
proxy:
  exit:
    enabled: true
    allowed_ports: [80, 443]      # only HTTP/HTTPS by default
    # allow_all_ports: false      # set true to allow any port (higher risk)
```

Restart the node or use the Dashboard hot-reload to apply changes.

**Security note:** Exit nodes forward traffic to the internet. The operator
should understand the legal implications in their jurisdiction. By default,
only ports 80 and 443 are allowed.

## Step 2: Configure the Entry Node

On the node where SOCKS5 clients will connect:

```yaml
proxy:
  entry:
    socks5:
      enabled: true
      port: 77                    # virtual port (default), multiplexed on 52888
      auth: "none"                # or "password" for client authentication
```

The SOCKS5 port is a virtual port multiplexed on the MuxTransport port (52888).
No additional firewall ports need to be opened.

If using password authentication:

```yaml
proxy:
  entry:
    socks5:
      enabled: true
      port: 77
      auth: "password"
      users:
        - username: "phone1"
          password: "your-strong-password"
```

## Step 3: Configure SOCKS5 Client

### Android

1. Install any SOCKS5-compatible proxy app (e.g., SagerNet, v2rayNG, Clash)
2. Create a new SOCKS5 profile:
   - **Server:** your mesh node's address (e.g., `aliyun.example.com`)
   - **Port:** 52888
   - **TLS/SSL:** Enable (required — Reality TLS handshake)
   - **Authentication:** None or Username/Password (match your config)
3. Connect and verify traffic routes through the mesh

### iOS

1. Use Shadowrocket, Surge, or Quantumult X
2. Add a SOCKS5 proxy:
   - **Server:** mesh node address
   - **Port:** 52888
   - **TLS:** On
   - **Auth:** Match your config

### Desktop (Linux/macOS/Windows)

Browser proxy settings (Firefox):

1. Settings → Network Settings → Manual proxy configuration
2. SOCKS Host: your mesh node address
3. Port: 52888
4. SOCKS v5
5. Check "Proxy DNS when using SOCKS v5"

Command-line with proxychains:

```bash
# /etc/proxychains.conf
[ProxyList]
socks5 <mesh-node-ip> 52888
```

```bash
proxychains curl https://example.com
```

### Direct SOCKS5 (for apps that support it)

Most chat apps with proxy support:

```
Type: SOCKS5
Host: <mesh-node-address>
Port: 52888
```

## Step 4: Verify

1. Connect your SOCKS5 client to the entry node
2. Check the Dashboard → Proxy Status page — you should see the active session
3. Visit an IP check site (e.g., ip.sb) from the client — it should show the
   exit node's IP, not your own

## Troubleshooting

### "Connection refused" on port 52888

The mesh node's MuxTransport is not running or the port is blocked by firewall.
Check: `ss -tlnp | grep 52888` on the mesh node.

### SOCKS5 client connects but no data flows

Verify the exit node configuration:
```bash
grep -A5 "exit:" /etc/meshdesk/config.yaml
```
Ensure `proxy.exit.enabled: true` and the exit node has internet access.

### TLS handshake fails

SOCKS5 via meshdesk requires Reality TLS. Ensure the client has TLS/SSL enabled
in its proxy settings. The handshake is transparent — the client doesn't need
Reality keys; the mesh node handles Reality authentication.

### "No route to exit node"

Check the Dashboard → Nodes page. The exit node must be online and reachable
via the mesh network. If the exit node is behind NAT without a public endpoint,
it must dial out to a seed node first to establish connectivity.

## Dashboard Management

From the Dashboard (`http://<mesh-node>:52888`):

1. Navigate to **Proxy** → **SOCKS5 Configuration**
2. Enable/disable the SOCKS5 entry listener
3. Configure authentication method and users
4. Select which nodes serve as exit nodes
5. View active SOCKS5 sessions and traffic statistics

## Advanced: Direct Mesh-Internal Connection

If the SOCKS5 client is on a mesh node itself (not a phone), you can bypass
Reality TLS and connect directly via the mesh-internal path:

```
SOCKS5 client → localhost:77 (virtual port, smux direct)
```

This skips the TLS handshake and is suitable for:
- Running a local proxy on the same machine as meshdesk
- Chaining proxies within the mesh network
- Testing and debugging

## Limitations

- **Reality TLS overhead:** Each SOCKS5 connection undergoes a Reality TLS
  handshake, adding ~100ms initial latency
- **Single exit path:** All SOCKS5 traffic routes to the configured exit node
  (no per-request exit selection yet)
- **No UDP ASSOCIATE:** Only SOCKS5 CONNECT (TCP) is supported; UDP relay is
  not yet implemented
- **Beta status:** End-to-end testing with real SOCKS5 clients on phones is
  pending
