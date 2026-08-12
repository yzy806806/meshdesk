# Config Inventory

**Version:** 1.0 — matches v1.5.11

Main configuration sections in `/etc/meshdesk/config.yaml`.

## `node`
| Key | Description |
|-----|-------------|
| `identity_file` | Path to the Ed25519 identity PEM |
| `fingerprint` | Hex public key (auto-derived from identity) |
| `hostname` | Display name |
| `web` | Dashboard listen address (e.g. `:8080` or `127.0.0.1:8080`) |

## `mesh`
| Key | Description |
|-----|-------------|
| `port` | Mesh/Reality listen port (default 52888) |
| `gossip_port` | memberlist port |
| `zone` | Free-form zone tag (`cn`/`us`/… — same zone = UDP, cross = Reality) |
| `tun_enabled` / `tun_name` / `tun_mtu` | TUN device settings |
| `mesh_cidr` | Virtual IP subnet (default 10.100.0.0/24) |
| `static_virtual_ip` | Optional fixed VIP |
| `dns_enabled` / `dns_port` | Built-in mesh DNS |

## `peers`
List of static peers: `public_key`, `endpoint`, `zone`, `reality`
(client block: `server_name`, `public_key`, `short_id`, `tls_fingerprint`).

## `p2p`
`enabled`, `seeds`, `nat_traversal`, `stun_servers`, `relay_mode`,
`max_relay_hops` (relay forwarding depth, v1.5.11+), `join_approval`,
`gossip_interval`, `advertise_endpoints`, `peer_cache_path`.

## `proxy.socks5`
| Key | Description |
|-----|-------------|
| `allowed_ports` / `allow_all_ports` | Exit destination ports (default 80/443) |
| `destination_filter` | CIDR allowlist for the exit |
| `require_mesh_peer` / `allowed_peers` | Restrict who can use the exit |
| `entry_listen` | Entry listener address (empty = off) |
| `entry_username` / `entry_password` | RFC 1929 auth (required for non-loopback) |
| `exit_node` | Pin the entry to one fixed exit |
| `exit_nodes` | Exit list — lowest live RTT picked per connection |

## Other sections
`monitoring` (collectors/interval/port), `webssh`, `auth` (web_users,
TOTP), `transfer`, `acl`, `reality` (server: `listen_port`, `dest`,
`server_names`, `private_key`, `short_ids`).
