#!/bin/bash
# MeshDesk Node Provisioning Script
# Provisions real Ubuntu 24.04 machines for MeshDesk testing.
#
# Usage:
#   ssh root@<target> 'bash -s' < test/provision.sh
#   # Or with env vars:
#   MESHDESK_ROLE=public-vps MESHDESK_BRANCH=main ssh root@<target> 'bash -s' < test/provision.sh
#
# Roles:
#   public-vps   — Collector + Web UI (ports 8080, 51820 open)
#   behind-nat   — Agent only, no inbound ports
#   cross-region — Agent only, with tc latency simulation
#   agent        — Generic agent

set -euo pipefail

ROLE="${MESHDESK_ROLE:-agent}"
BRANCH="${MESHDESK_BRANCH:-main}"
REPO="${MESHDESK_REPO:-https://github.com/yzy806806/meshdesk.git}"
INSTALL_DIR="${MESHDESK_INSTALL_DIR:-/opt/meshdesk}"
CONFIG_DIR="/etc/meshdesk"
DATA_DIR="/var/lib/meshdesk"

echo "=== MeshDesk Provisioning ==="
echo "  Role:       $ROLE"
echo "  Branch:     $BRANCH"
echo "  Install:    $INSTALL_DIR"
echo "  Hostname:   $(hostname)"
echo "  OS:         $(lsb_release -ds 2>/dev/null || cat /etc/os-release | head -1)"
echo "  Arch:       $(uname -m)"
echo "============================="

# --- Prerequisites ---
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    golang-go \
    iproute2 \
    iptables \
    jq \
    openssh-server \
    wireguard-tools

# --- Clone and build ---
if [ ! -d "$INSTALL_DIR" ]; then
    git clone --branch "$BRANCH" "$REPO" "$INSTALL_DIR"
else
    cd "$INSTALL_DIR"
    git fetch origin
    git checkout "$BRANCH"
    git pull origin "$BRANCH"
fi

cd "$INSTALL_DIR"
go build -o meshdesk ./cmd/meshdesk/
cp meshdesk /usr/local/bin/

# --- Directory structure ---
mkdir -p "$CONFIG_DIR" "$DATA_DIR"

# --- Generate WireGuard identity ---
if [ ! -f "$CONFIG_DIR/identity" ]; then
    /usr/local/bin/meshdesk --gen-key > "$CONFIG_DIR/identity"
    chmod 600 "$CONFIG_DIR/identity"
fi

IDENTITY=$(grep "private" "$CONFIG_DIR/identity" | awk '{print $NF}' || echo "")
PUBLIC_KEY=$(grep "public" "$CONFIG_DIR/identity" | awk '{print $NF}' || echo "")
echo "  Public Key: $PUBLIC_KEY"

# --- Role-specific configuration ---
case "$ROLE" in
    public-vps)
        WEB_ADDR=":8080"
        MONITOR_COLLECTOR="true"
        # Open firewall ports
        ufw allow 8080/tcp 2>/dev/null || true
        ufw allow 51820/udp 2>/dev/null || true
        ;;
    behind-nat)
        WEB_ADDR=""
        MONITOR_COLLECTOR="false"
        ;;
    cross-region)
        WEB_ADDR=""
        MONITOR_COLLECTOR="false"
        # Apply latency simulation on the egress interface
        IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
        if [ -n "${SIM_LATENCY_MS:-}" ] && [ "$SIM_LATENCY_MS" != "0" ]; then
            echo "  Applying tc netem: latency=${SIM_LATENCY_MS}ms on $IFACE"
            tc qdisc add dev "$IFACE" root netem delay "${SIM_LATENCY_MS}ms" || true
        fi
        ;;
    agent|*)
        WEB_ADDR=""
        MONITOR_COLLECTOR="false"
        ;;
esac

# --- Generate config ---
cat > "$CONFIG_DIR/config.yaml" <<YAML
node:
  identity: "${IDENTITY}"
  hostname: "$(hostname)"
  web: "${WEB_ADDR}"
mesh:
  port: 51820
peers: []
monitoring:
  collectors: []
webssh:
  port: 2222
YAML

# --- Systemd service ---
cat > /etc/systemd/system/meshdesk.service <<UNIT
[Unit]
Description=MeshDesk Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/meshdesk --config $CONFIG_DIR/config.yaml ${WEB_ADDR:+--web}
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable meshdesk
systemctl restart meshdesk || echo "WARNING: meshdesk service failed to start (check config)"

echo "=== Provisioning Complete ==="
echo "  Service: systemctl status meshdesk"
echo "  Logs:    journalctl -u meshdesk -f"
echo "  Config:  $CONFIG_DIR/config.yaml"
echo "  Identity: $CONFIG_DIR/identity"
echo "  Public Key: $PUBLIC_KEY"