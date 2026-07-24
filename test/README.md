# MeshDesk Test Infrastructure

Real-machine and Docker-based test harness for MeshDesk.

## Quick Start

### Option A: Docker Cluster (recommended for dev/testing)

```bash
# 1. Build the binary
go build -o meshdesk ./cmd/meshdesk/

# 2. Start 3-node cluster
docker compose -f test/docker-compose.yml up --build -d

# 3. Run scenario matrix
./test/scenario-matrix.sh

# 4. Clean up
docker compose -f test/docker-compose.yml down -v
```

### Option B: Real Machines

```bash
# 1. Provision each node
ssh root@test-node1 'bash -s' < test/provision.sh    # public VPS
ssh root@test-node2 'bash -s' < test/provision.sh    # behind NAT
ssh root@test-node3 'bash -s' < test/provision.sh    # cross-region

# 2. Configure test nodes
cp test/config.env test/config.env.local
# Edit config.env.local with your node IPs and SSH keys

# 3. Run scenario matrix
source test/config.env.local
./test/scenario-matrix.sh
```

### Option C: CI Pipeline

```bash
# Full pipeline: lint → unit → build → integration
./ci/test-pipeline.sh

# Skip stages as needed
./ci/test-pipeline.sh --skip-integration
```

## File Layout

```
test/
├── config.env              # Test configuration template
├── docker-compose.yml      # 3-node Docker cluster (public VPS, NAT, cross-region)
├── Dockerfile.test         # Ubuntu 24.04 test container
├── entrypoint.sh           # Container entrypoint (tc netem, GFW sim, config gen)
├── provision.sh            # Real-machine provisioning (Ubuntu 24.04)
├── scenario-matrix.sh      # 23-scenario test runner with JSON reporting
└── README.md               # This file

ci/
└── test-pipeline.sh        # 4-stage CI pipeline (lint → unit → build → integration)
```

## Node Inventory (3 Minimum)

| Node | Profile | Description |
|------|---------|-------------|
| node1 | Public VPS | Collector + Web UI, clean internet, open ports |
| node2 | Behind NAT | Agent only, restrictive firewall, moderate latency |
| node3 | Cross-region | Agent only, 150ms latency, 1% packet loss |

## Scenario Matrix

9 scenario categories covering all 7 stop-condition criteria:

| Category | Scenarios | Stop Condition |
|----------|-----------|----------------|
| mesh | P2P ping, handshake, throughput | VPN performance |
| nat | Reachability, bidirectional, keepalive | NAT traversal |
| resilience | Reconnect, packet loss, partition heal | Network resilience |
| webssh | Connect, multiplex, resize | WebSSH functionality |
| transfer | Upload, download, checksum | File transfer |
| service | List, restart, logs | Service management |
| monitoring | CPU, memory, disk | Monitoring |

## GFW Simulation

Docker containers can simulate GFW-like interference via iptables DPI rules.
Set `SIM_GFW=1` in the docker-compose environment. This is **approximate** —
real GFW testing requires a node physically located in China.

## Results

All results are written as JSON to `test/results/test_report.json`.
CI pipeline results go to `test/results/pipeline.json`.