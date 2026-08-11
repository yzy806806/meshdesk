#!/bin/sh
# MeshDesk one-click install script
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --version v1.1.0
#   curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --join-url https://bootstrap:8443 --join-token <token>
#
# After install, edit /etc/meshdesk/config.yaml and start with:
#   systemctl start meshdesk
#   systemctl enable meshdesk

set -e

# ============================================================================
# Defaults
# ============================================================================
REPO="yzy806806/meshdesk"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/meshdesk"
DATA_DIR="/var/lib/meshdesk"
SERVICE_FILE="/etc/systemd/system/meshdesk.service"
VERSION=""
JOIN_URL=""
JOIN_TOKEN=""
WEB_MODE=false

# ============================================================================
# Helpers
# ============================================================================
info()  { printf "\033[1;32m[INFO]\033[0m  %s\n" "$1"; }
warn()  { printf "\033[1;33m[WARN]\033[0m  %s\n" "$1"; }
error() { printf "\033[1;31m[ERROR]\033[0m %s\n" "$1" >&2; }
fatal() { error "$1"; exit 1; }

# ============================================================================
# Parse args
# ============================================================================
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --join-url)
            JOIN_URL="$2"
            shift 2
            ;;
        --join-token)
            JOIN_TOKEN="$2"
            shift 2
            ;;
        --web)
            WEB_MODE=true
            shift
            ;;
        --help|-h)
            cat <<EOF
MeshDesk installer

Options:
  --version <ver>       Specific version to install (e.g. v1.1.0)
  --join-url <url>      Bootstrap node URL for one-click join
  --join-token <token>  Join token from Dashboard
  --web                 Enable web UI mode in systemd service
  --help                Show this help

Examples:
  curl -fsSL .../install.sh | sh
  curl -fsSL .../install.sh | sh -s -- --version v1.1.0
  curl -fsSL .../install.sh | sh -s -- --join-url https://host:8443 --join-token TOKEN
EOF
            exit 0
            ;;
        *)
            fatal "Unknown option: $1 (use --help)"
            ;;
    esac
done

# ============================================================================
# Detect architecture
# ============================================================================
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ASSET_NAME="meshdesk-linux-amd64"
        ;;
    aarch64|arm64)
        ASSET_NAME="meshdesk-linux-arm64"
        ;;
    *)
        fatal "Unsupported architecture: $ARCH (only linux/amd64 and linux/arm64 are supported)"
        ;;
esac

# Check OS
OS=$(uname -s)
if [ "$OS" != "Linux" ]; then
    fatal "Unsupported OS: $OS (only Linux is supported)"
fi

info "Detected: Linux/$ARCH"

# ============================================================================
# Check root
# ============================================================================
if [ "$(id -u)" -ne 0 ]; then
    fatal "This script must be run as root. Try: sudo sh install.sh"
fi

# ============================================================================
# Check for curl
# ============================================================================
if ! command -v curl >/dev/null 2>&1; then
    fatal "curl is required but not installed. Install it first: apt install curl / yum install curl"
fi

# ============================================================================
# Resolve version
# ============================================================================
if [ -z "$VERSION" ]; then
    info "Fetching latest release version..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        fatal "Failed to determine latest version. Specify with --version <ver>"
    fi
fi
info "Installing MeshDesk $VERSION"

# ============================================================================
# Download binary
# ============================================================================
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
TMP_FILE="/tmp/meshdesk-${VERSION}-${ASSET_NAME}"

info "Downloading: $DOWNLOAD_URL"
if ! curl -fSL -o "$TMP_FILE" "$DOWNLOAD_URL"; then
    fatal "Download failed. Check that version $VERSION exists and has the $ASSET_NAME asset."
fi

# Verify download is not empty
if [ ! -s "$TMP_FILE" ]; then
    fatal "Downloaded file is empty. Something went wrong."
fi

# Verify checksum against the release checksums.txt (when available)
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
EXPECTED_SHA=$(curl -fsSL "$CHECKSUM_URL" 2>/dev/null | grep -F "$ASSET_NAME" | awk '{print $1}')
if [ -n "$EXPECTED_SHA" ]; then
    ACTUAL_SHA=$(sha256sum "$TMP_FILE" | awk '{print $1}')
    if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
        fatal "Checksum mismatch for $ASSET_NAME (got $ACTUAL_SHA, want $EXPECTED_SHA) — aborting"
    fi
    info "Checksum verified ($ASSET_NAME)"
else
    info "Warning: no checksum entry for $ASSET_NAME — skipping verification (supply-chain hardening recommended)"
fi

info "Downloaded $(stat -c %s "$TMP_FILE" 2>/dev/null || stat -f %z "$TMP_FILE") bytes"

# ============================================================================
# Install binary
# ============================================================================
info "Installing binary to $INSTALL_DIR/meshdesk"
install -m 0755 "$TMP_FILE" "$INSTALL_DIR/meshdesk"
rm -f "$TMP_FILE"

# Print version to verify
meshdesk --version || warn "Could not verify binary version"

# ============================================================================
# Create directories
# ============================================================================
mkdir -p "$CONFIG_DIR" "$DATA_DIR"

# ============================================================================
# Generate default config if not exists
# ============================================================================
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    info "Generating default config at $CONFIG_DIR/config.yaml"
    cat > "$CONFIG_DIR/config.yaml" <<'CFGEOF'
# MeshDesk configuration
# See: https://github.com/yzy806806/meshdesk/blob/main/README.md

mesh:
  port: 52888
  # Set to true on shared (public) nodes
  reality:
    enabled: false
    # target: apple.com
    # private_key: ""
    # short_ids: [""]

identity:
  # Auto-generated on first start if empty
  # private_key: ""
  # public_key: ""

# peers:
#   - endpoint: "203.0.113.5:52888"
#     public_key: "peer-public-key-hex"

# collectors:
#   - endpoint: "203.0.113.5:52888"
#     public_key: "collector-public-key-hex"

monitor:
  enabled: true
  interval: 15s

web:
  enabled: false
  listen: ":8080"

tun:
  enabled: false
  cidr: "10.244.0.0/16"

logging:
  level: info
CFGEOF
    info "Default config written. Edit $CONFIG_DIR/config.yaml before starting."
else
    info "Config already exists at $CONFIG_DIR/config.yaml (skipped)"
fi

# ============================================================================
# Download and install systemd unit
# ============================================================================
info "Installing systemd service"
SERVICE_URL="https://raw.githubusercontent.com/${REPO}/${VERSION}/deploy/meshdesk.service"
if curl -fSL -o "$SERVICE_FILE" "$SERVICE_URL" 2>/dev/null; then
    info "Downloaded systemd unit from GitHub"
else
    info "Generating systemd unit inline"
    cat > "$SERVICE_FILE" <<'SVCEOF'
[Unit]
Description=MeshDesk Mesh VPN Node
Documentation=https://github.com/yzy806806/meshdesk
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml
Restart=on-failure
RestartSec=5
StartLimitBurst=10
StartLimitIntervalSec=60
StandardOutput=journal
StandardError=journal
SyslogIdentifier=meshdesk
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
fi

# Patch in --web flag if requested
if [ "$WEB_MODE" = true ]; then
    sed -i 's|ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml$|ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml --web|' "$SERVICE_FILE"
    info "Web UI mode enabled in systemd unit"
fi

chmod 644 "$SERVICE_FILE"
systemctl daemon-reload

# ============================================================================
# Join protocol (optional)
# ============================================================================
if [ -n "$JOIN_URL" ] && [ -n "$JOIN_TOKEN" ]; then
    info "Running join protocol: $JOIN_URL"
    if "$INSTALL_DIR/meshdesk" join --join-url "$JOIN_URL" --join-token "$JOIN_TOKEN"; then
        info "Join successful! Config written to $CONFIG_DIR/config.yaml"
    else
        fatal "Join failed. Check the token and bootstrap node availability."
    fi
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "========================================"
echo " MeshDesk $VERSION installed successfully!"
echo "========================================"
echo ""
echo " Binary:  $INSTALL_DIR/meshdesk"
echo " Config:  $CONFIG_DIR/config.yaml"
echo " Data:    $DATA_DIR/"
echo " Service: $SERVICE_FILE"
echo ""
echo " Next steps:"
echo "   1. Edit config:  nano $CONFIG_DIR/config.yaml"
if [ "$WEB_MODE" = true ]; then
echo "   2. Start:        systemctl start meshdesk"
echo "   3. Enable:       systemctl enable meshdesk"
echo "   4. Check:        systemctl status meshdesk"
echo "   5. Web UI:       http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8080"
else
echo "   2. Start:        systemctl start meshdesk"
echo "   3. Enable:       systemctl enable meshdesk"
echo "   4. Check:        systemctl status meshdesk"
echo "   5. Logs:         journalctl -u meshdesk -f"
fi
echo ""
echo " To join a mesh:  meshdesk join <bootstrap-url> --token <token>"
echo " To generate key: meshdesk --gen-key"
echo ""
