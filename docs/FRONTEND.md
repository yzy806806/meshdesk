# Frontend (Dashboard)

**Version:** 1.0 — matches v1.5.11

The Dashboard is served by the Go binary (`--web`) — server-rendered
templates + vanilla JS, dark theme (Pico CSS).

## Pages

| Route | Template | Purpose |
|-------|----------|---------|
| `/` | dashboard | Overview + monitoring |
| `/nodes` | nodes | Per-node metrics (CPU/mem/load/traffic) |
| `/peers` | peers | Peer table (routing table + meta-learned peers) |
| `/topology` | topology | **3D topology** (three.js) |
| `/files` | files | File transfer |
| `/update` | update | Binary update / restart |
| `/services` | services | Service management |
| `/config` | config | Config editing + restart |
| `/proxy` | proxy | SOCKS5 entry/exit config (save auto-restarts) |
| `/acl` | acl | Access control |
| `/alerts` | alerts | Security alerts |
| `/join` | join | One-click join (install script) |

## 3D topology (`topology.js`)

- Nodes: ring color = zone (stable hash palette); label shows
  `hostname [zone]`.
- Edges: **full connectivity** — every node pair (v1.5.10). Color =
  transport (Reality green / UDP blue / 0x4D amber / relay grey).
- **Latency-sized layout** (v1.5.10): spring rest length maps live RTT
  (`latencyToSpringLength`) — low latency = short edge.
- Hover: edge shows transport / ping / bandwidth; node shows
  zone/role/status.

## Backend APIs

- `GET /api/topology` — nodes (zone, transport, latency, bandwidth)
- `GET /api/stats` — per-peer sessions/streams
- `GET /api/peers`, `GET /api/monitor`, `GET /api/config` (+PATCH)
- `POST /api/config/restart` — SIGTERM self (supervisor restarts)
- `GET /join?token=...` / `POST /join` (token in body)
