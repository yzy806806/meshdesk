#!/bin/bash
# MeshDesk test container entrypoint.
# Configures the node based on MESHDESK_ROLE env var and runs meshdesk.
set -euo pipefail

ROLE="${MESHDESK_ROLE:-agent}"
HOSTNAME="${MESHDESK_HOSTNAME:-$(hostname)}"
IDENTITY="${MESHDESK_IDENTITY:-}"

echo "[meshdesk-entrypoint] Starting node: role=$ROLE hostname=$HOSTNAME"

# --- Apply simulated network conditions ---
# tc netem is used to simulate latency and packet loss between nodes.
# The test harness sets up tc rules via docker-compose's cap_add: NET_ADMIN.
if [ -n "${SIM_LATENCY_MS:-}" ] && [ "${SIM_LATENCY_MS}" != "0" ]; then
    IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
    echo "[meshdesk-entrypoint] Applying tc netem: latency=${SIM_LATENCY_MS}ms loss=${SIM_PACKET_LOSS:-0}% on $IFACE"
    tc qdisc add dev "$IFACE" root netem \
        delay "${SIM_LATENCY_MS}ms" \
        loss "${SIM_PACKET_LOSS:-0}%"
fi

# --- GFW simulation (iptables-based, approximate) ---
if [ "${SIM_GFW:-0}" = "1" ]; then
    echo "[meshdesk-entrypoint] Enabling GFW simulation (iptables DPI drop)"
    # Drop packets containing WireGuard handshake signatures
    iptables -A OUTPUT -p udp --dport 51820 -m string \
        --algo bm --hex-string "|01000000|" -j DROP
    iptables -A INPUT -p udp --sport 51820 -m string \
        --algo bm --hex-string "|01000000|" -j DROP
fi

# --- Generate config ---
CONFIG_FILE="/etc/meshdesk/config.yaml"
cat > "$CONFIG_FILE" <<YAML
node:
  identity: "${IDENTITY}"
  hostname: "${HOSTNAME}"
  web: "${MESHDESK_WEB:-}"
mesh:
  port: ${MESHDESK_PORT:-51820}
peers: []
monitoring:
  collectors: []
webssh:
  port: 2222
YAML

# Append any peers passed via env
if [ -n "${MESHDESK_PEERS:-}" ]; then
    echo "$MESHDESK_PEERS" >> "$CONFIG_FILE"
fi

echo "[meshdesk-entrypoint] Config written to $CONFIG_FILE"
cat "$CONFIG_FILE"

# --- Start meshdesk ---
exec /usr/local/bin/meshdesk --config "$CONFIG_FILE" ${MESHDESK_WEB:+--web}