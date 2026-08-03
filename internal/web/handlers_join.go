package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/join"
)

// JoinTokenGenerator abstracts the ability to generate join tokens.
// In production, this is implemented by the main node setup which has
// access to the join secret and server identity.
type JoinTokenGenerator interface {
	// GenerateJoinToken creates a new join token with the given lifetime.
	// Returns the base64-encoded token string.
	GenerateJoinToken(lifetime time.Duration) (string, error)

	// JoinServerURL returns the externally reachable URL of the join server
	// (e.g., "https://bootstrap.example.com:8443"). Returns empty if join
	// server is not enabled.
	JoinServerURL() string

	// BinaryDownloadURL returns the URL from which the meshdesk binary can
	// be downloaded for the given architecture (amd64, arm64). Returns
	// empty if not configured.
	BinaryDownloadURL(arch string) string

	// JoinEnabled reports whether the join server is running on this node.
	JoinEnabled() bool
}

// defaultJoinTokenGenerator is the default implementation used when the
// web server has access to the node's config and identity but no explicit
// JoinTokenGenerator was injected. It can generate tokens from the config's
// join secret, but cannot serve binary downloads (BinaryDownloadURL returns "").
type defaultJoinTokenGenerator struct {
	cfg     *config.Config
	identity *identity.Identity
}

func (d *defaultJoinTokenGenerator) GenerateJoinToken(lifetime time.Duration) (string, error) {
	if d.cfg == nil || d.cfg.Join.Secret == "" {
		return "", fmt.Errorf("join secret not configured")
	}
	if d.identity == nil {
		return "", fmt.Errorf("node identity not available")
	}
	serverFP := ""
	if d.identity != nil {
		serverFP = d.identity.PublicKey
	}
	return join.GenerateToken([]byte(d.cfg.Join.Secret), serverFP, lifetime)
}

func (d *defaultJoinTokenGenerator) JoinServerURL() string {
	if d.cfg == nil || !d.cfg.Join.Enabled {
		return ""
	}
	// Build the join server URL from the node's hostname and join listen addr.
	host := d.cfg.Node.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	addr := d.cfg.Join.ListenAddr
	if addr == "" {
		addr = ":8443"
	}
	// Parse the port from the listen address.
	port := strings.TrimPrefix(addr, ":")
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		port = addr[idx+1:]
	}
	// Determine scheme.
	scheme := "https"
	if d.cfg.Join.TLSCertFile == "" || d.cfg.Join.TLSKeyFile == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

func (d *defaultJoinTokenGenerator) BinaryDownloadURL(arch string) string {
	// Not available in the default implementation.
	return ""
}

func (d *defaultJoinTokenGenerator) JoinEnabled() bool {
	return d.cfg != nil && d.cfg.Join.Enabled && d.cfg.Reality.Enabled
}

// handleJoinPage renders the one-click join page.
func (s *Server) handleJoinPage(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:      "Join",
		ActivePage: "join",
	}
	s.renderPage(w, "join.html", data)
}

// handleJoinRoute is the dispatcher for /join. When the "token" query
// parameter is present, it serves the install shell script (public, no auth).
// Otherwise it renders the Dashboard join page (auth required).
func (s *Server) handleJoinRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Query().Get("token") != "" {
		s.handleJoinScript(w, r)
		return
	}
	// No token → render the Dashboard join page (requires auth).
	s.requireAuth(s.handleJoinPage)(w, r)
}

// handleJoinScript validates a join token from the query parameter and,
// if valid, returns the install shell script. This endpoint is public
// (no session auth) so that `curl -sSL http://<dashboard>:8080/join?token=xxx | sh`
// works on a fresh node that has no browser session.
//
// The token is validated using the node's join secret (HMAC signature +
// expiration). The install script embeds the token, join server URL, and
// binary download URL. The actual mesh join (challenge-response protocol)
// happens when the script runs `meshdesk join --join-url ... --join-token ...`.
func (s *Server) handleJoinScript(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}

	// Get the join token generator (injected or default).
	gen := s.joinTokenGen
	if gen == nil {
		gen = &defaultJoinTokenGenerator{cfg: s.cfg, identity: s.nodeIdentity()}
	}

	// Validate the token using the join secret.
	secret := ""
	if s.cfg != nil {
		secret = s.cfg.Join.Secret
	}
	if secret == "" {
		writeInstallScriptError(w, "join server is not configured on this node (join.secret is empty)")
		return
	}

	token, err := join.ParseToken(tokenStr, []byte(secret))
	if err != nil {
		log.Printf("[join] install script token validation failed from %s: %v", r.RemoteAddr, err)
		writeInstallScriptError(w, fmt.Sprintf("invalid or expired token: %v", err))
		return
	}

	// Optionally verify the server fingerprint matches this node.
	// This prevents a token issued by node A from being used to fetch
	// an install script from node B (which would embed the wrong join URL).
	nodeID := s.nodeIdentity()
	if nodeID != nil && token.ServerFP != "" && token.ServerFP != nodeID.PublicKey {
		log.Printf("[join] install script token server fingerprint mismatch from %s", r.RemoteAddr)
		writeInstallScriptError(w, "token was not issued for this server")
		return
	}

	// Derive the join server URL and binary download URL.
	joinURL := gen.JoinServerURL()
	if joinURL == "" {
		writeInstallScriptError(w, "join server is not enabled on this node")
		return
	}

	// Pass empty arch — the install script auto-detects via uname.
	binaryURL := gen.BinaryDownloadURL("")

	script := buildInstallScript(joinURL, tokenStr, binaryURL)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="meshdesk-install.sh"`)
	w.Write([]byte(script))
}

// writeInstallScriptError writes an error as a shell script that echoes
// the error message and exits with code 1. This ensures that when piped
// to `sh`, the user sees a clear error message instead of HTML or JSON.
func writeInstallScriptError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, "#!/bin/sh\necho 'Error: %s' >&2\nexit 1\n", escapeShellSingle(msg))
}

// joinTokenRequest is the JSON body for POST /api/join/token.
type joinTokenRequest struct {
	// Lifetime is the token validity duration in minutes. Default: 30.
	Lifetime int `json:"lifetime"`

	// Arch is the target architecture for binary download URL selection
	// (amd64, arm64). If empty, the install script auto-detects.
	Arch string `json:"arch"`
}

// joinTokenResponse is the JSON response for POST /api/join/token.
type joinTokenResponse struct {
	Success        bool   `json:"success"`
	Error          string `json:"error,omitempty"`
	Token          string `json:"token,omitempty"`
	JoinURL        string `json:"join_url,omitempty"`
	InstallCommand string `json:"install_command,omitempty"`
	ExpiresIn      int    `json:"expires_in_seconds,omitempty"`
}

// handleJoinToken generates a join token and builds the one-line install command.
//
// POST /api/join/token
// Body: {"lifetime": 30, "arch": "amd64"}
// Response: {"success": true, "token": "...", "join_url": "...", "install_command": "curl ... | sh"}
func (s *Server) handleJoinToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	gen := s.joinTokenGen
	if gen == nil {
		gen = &defaultJoinTokenGenerator{cfg: s.cfg, identity: s.nodeIdentity()}
	}

	if !gen.JoinEnabled() {
		writeJSON(w, http.StatusBadRequest, joinTokenResponse{
			Success: false,
			Error:   "join server is not enabled on this node (requires join.enabled: true and reality.enabled: true)",
		})
		return
	}

	var req joinTokenRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	lifetime := time.Duration(req.Lifetime) * time.Minute
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	if lifetime > 24*time.Hour {
		lifetime = 24 * time.Hour
	}

	token, err := gen.GenerateJoinToken(lifetime)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, joinTokenResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to generate token: %v", err),
		})
		return
	}

	joinURL := gen.JoinServerURL()
	if joinURL == "" {
		writeJSON(w, http.StatusBadRequest, joinTokenResponse{
			Success: false,
			Error:   "join server URL not available",
		})
		return
	}

	binaryURL := gen.BinaryDownloadURL(req.Arch)

	// Build the install command: curl -fsSL <install_script_url> | sh
	// The install script URL is served by this web server at /api/join/install.sh.
	// We pass the token, join URL, and optional binary URL as query params.
	installScriptURL := s.installScriptURL(joinURL, token, binaryURL)

	installCmd := fmt.Sprintf("curl -fsSL '%s' | sh", installScriptURL)

	writeJSON(w, http.StatusOK, joinTokenResponse{
		Success:        true,
		Token:          token,
		JoinURL:        joinURL,
		InstallCommand: installCmd,
		ExpiresIn:      int(lifetime.Seconds()),
	})
}

// installScriptURL builds the URL to the install script endpoint with
// embedded query parameters (token, join_url, binary_url).
func (s *Server) installScriptURL(joinURL, token, binaryURL string) string {
	// The install script is served at /api/join/install.sh on this web server.
	// We embed the join URL, token, and binary URL as query params so the
	// script is self-contained when piped to sh.
	base := s.webBaseURL()
	params := fmt.Sprintf("?join_url=%s&token=%s", urlEncode(joinURL), urlEncode(token))
	if binaryURL != "" {
		params += fmt.Sprintf("&binary_url=%s", urlEncode(binaryURL))
	}
	return base + "/api/join/install.sh" + params
}

// webBaseURL returns the base URL of the web server (scheme://host:port).
// It derives this from the request host header or the config.
func (s *Server) webBaseURL() string {
	if s.cfg != nil && s.cfg.Node.WebAddr != "" {
		addr := s.cfg.Node.WebAddr
		host := s.cfg.Node.Hostname
		if host == "" {
			host, _ = os.Hostname()
		}
		port := addr
		if strings.HasPrefix(addr, ":") {
			port = addr
		}
		// If addr is just a port like ":8080", prepend hostname.
		if strings.HasPrefix(addr, ":") {
			return fmt.Sprintf("http://%s%s", host, addr)
		}
		_ = port
		return fmt.Sprintf("http://%s", addr)
	}
	// Fallback: use localhost:8080
	return "http://localhost:8080"
}

// handleJoinInstallScript serves the install shell script.
// The script is generated dynamically with embedded token, join URL,
// and optional binary URL from query parameters.
func (s *Server) handleJoinInstallScript(w http.ResponseWriter, r *http.Request) {
	joinURL := r.URL.Query().Get("join_url")
	token := r.URL.Query().Get("token")
	binaryURL := r.URL.Query().Get("binary_url")

	if joinURL == "" || token == "" {
		http.Error(w, "missing join_url or token parameter", http.StatusBadRequest)
		return
	}

	script := buildInstallScript(joinURL, token, binaryURL)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\"meshdesk-install.sh\"")
	w.Write([]byte(script))
}

// buildInstallScript generates the shell script that a new node executes
// via `curl ... | sh`. The script:
//  1. Detects OS and architecture
//  2. Downloads the meshdesk binary (from binary_url if provided, or from
//     GitHub releases as fallback)
//  3. Creates config directory and writes minimal config
//  4. Runs `meshdesk join --join-url <url> --join-token <token>` which
//     contacts the join server, gets the config bundle (identity, REALITY
//     keys, collector list), and joins the mesh
//  5. Sets up a systemd service so meshdesk auto-starts on boot
func buildInstallScript(joinURL, token, binaryURL string) string {
	var b strings.Builder

	// Detect whether the join URL uses HTTPS or HTTP.
	// If HTTP, we need to pass --insecure-tls to the join command.
	joinFlags := "--join-url \"$JOIN_URL\" --join-token \"$JOIN_TOKEN\""
	if len(joinURL) >= 8 && joinURL[:8] != "https://" {
		joinFlags += " --insecure-tls"
	}

	b.WriteString("#!/bin/sh\n")
	b.WriteString("# MeshDesk auto-install script — generated by Dashboard\n")
	b.WriteString("# This script downloads the meshdesk binary and joins the mesh cluster.\n")
	b.WriteString("# Usage: curl -fsSL '<url>' | sh\n")
	b.WriteString("set -e\n\n")

	// --- Detect OS and architecture ---
	b.WriteString("# Detect OS and architecture\n")
	b.WriteString("OS=$(uname -s | tr '[:upper:]' '[:lower:]')\n")
	b.WriteString("ARCH=$(uname -m)\n")
	b.WriteString("case \"$ARCH\" in\n")
	b.WriteString("  x86_64|amd64) ARCH=amd64 ;;\n")
	b.WriteString("  aarch64|arm64) ARCH=arm64 ;;\n")
	b.WriteString("  *) echo \"Unsupported architecture: $ARCH\"; exit 1 ;;\n")
	b.WriteString("esac\n")
	b.WriteString("case \"$OS\" in\n")
	b.WriteString("  linux) OS=linux ;;\n")
	b.WriteString("  darwin) OS=darwin ;;\n")
	b.WriteString("  *) echo \"Unsupported OS: $OS\"; exit 1 ;;\n")
	b.WriteString("esac\n\n")

	// --- Set up directories ---
	b.WriteString("# Create meshdesk directories\n")
	b.WriteString("INSTALL_DIR=\"/usr/local/bin\"\n")
	b.WriteString("CONFIG_DIR=\"/etc/meshdesk\"\n")
	b.WriteString("DATA_DIR=\"/var/lib/meshdesk\"\n")
	b.WriteString("mkdir -p \"$CONFIG_DIR\" \"$DATA_DIR\" 2>/dev/null || sudo mkdir -p \"$CONFIG_DIR\" \"$DATA_DIR\"\n\n")

	// --- Download binary ---
	b.WriteString("# Download meshdesk binary\n")
	b.WriteString("BINARY_URL=''\n")
	if binaryURL != "" {
		b.WriteString(fmt.Sprintf("BINARY_URL='%s'\n", escapeShellSingle(binaryURL)))
	}
	b.WriteString(`
# If no explicit binary URL, try GitHub releases
if [ -z "$BINARY_URL" ]; then
  BINARY_URL="https://github.com/yzy806806/meshdesk/releases/latest/download/meshdesk-${OS}-${ARCH}"
fi
echo "Downloading meshdesk binary from $BINARY_URL ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o /tmp/meshdesk "$BINARY_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -qO /tmp/meshdesk "$BINARY_URL"
else
  echo "Error: neither curl nor wget found"; exit 1
fi
chmod +x /tmp/meshdesk
mv /tmp/meshdesk "$INSTALL_DIR/meshdesk" 2>/dev/null || sudo mv /tmp/meshdesk "$INSTALL_DIR/meshdesk"
echo "Binary installed to $INSTALL_DIR/meshdesk"

`)

	// --- Write minimal config ---
	b.WriteString("# Write minimal config (join server fills in the rest)\n")
	b.WriteString(fmt.Sprintf("cat > \"$CONFIG_DIR/config.yaml\" <<'CFGEOF'\n"))
	b.WriteString("node:\n")
	b.WriteString("  hostname: \"\"\n")
	b.WriteString("  web: \":8080\"\n")
	b.WriteString("mesh:\n")
	b.WriteString("  gossip_port: 7946\n")
	b.WriteString("monitoring:\n")
	b.WriteString("  collectors: []\n")
	b.WriteString("  interval: 30\n")
	b.WriteString("  port: 4191\n")
	b.WriteString("CFGEOF\n")
	b.WriteString("chmod 600 \"$CONFIG_DIR/config.yaml\" 2>/dev/null || sudo chmod 600 \"$CONFIG_DIR/config.yaml\"\n\n")

	// --- Systemd service setup (Linux only, BEFORE join) ---
	// We set up the systemd unit before the join command because `exec`
	// replaces the shell process. The unit file runs meshdesk in normal
	// node mode (not join mode) — it will be used after the initial join
	// completes and the node is restarted.
	b.WriteString(`
# --- Set up systemd service for auto-restart on boot (Linux only) ---
if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
  # Write systemd unit file (runs meshdesk in normal node mode after join)
  cat > /tmp/meshdesk.service <<'SVCEOF'
[Unit]
Description=MeshDesk Mesh Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
  sudo mv /tmp/meshdesk.service /etc/systemd/system/meshdesk.service 2>/dev/null || \
    mv /tmp/meshdesk.service /etc/systemd/system/meshdesk.service
  sudo systemctl daemon-reload 2>/dev/null || systemctl daemon-reload
  sudo systemctl enable meshdesk 2>/dev/null || systemctl enable meshdesk
  echo "Systemd service installed. After join completes, run: sudo systemctl start meshdesk"
fi

`)

	// --- Join the mesh ---
	b.WriteString("# Join the mesh cluster via auto-join protocol\n")
	b.WriteString(fmt.Sprintf("JOIN_URL='%s'\n", escapeShellSingle(joinURL)))
	b.WriteString(fmt.Sprintf("JOIN_TOKEN='%s'\n", escapeShellSingle(token)))
	b.WriteString(fmt.Sprintf(`echo "Joining mesh cluster at $JOIN_URL ..."
exec "$INSTALL_DIR/meshdesk" join %s --config "$CONFIG_DIR/config.yaml"
`, joinFlags))

	return b.String()
}

// escapeShellSingle escapes a string for use inside single quotes in shell.
// Since single-quoted strings in shell can't contain single quotes, we
// close the quote, add an escaped quote, and reopen.
func escapeShellSingle(s string) string {
	return strings.ReplaceAll(s, "'", `'\''`)
}

// urlEncode does a minimal URL query encoding.
func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteRune(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

// nodeIdentity returns the node's Ed25519 identity, or nil if not available.
func (s *Server) nodeIdentity() *identity.Identity {
	if s.node == nil {
		return nil
	}
	return s.node.Identity()
}


