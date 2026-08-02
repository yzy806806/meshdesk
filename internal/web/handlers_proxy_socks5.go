package web

import (
	"encoding/json"
	"net/http"
)

// SOCKS5ProxyStatus is the JSON response for GET /api/proxy/socks5/status.
// It aggregates the local node's SOCKS5 configuration, runtime state,
// and mesh topology information relevant to proxy management.
type SOCKS5ProxyStatus struct {
	// LocalNode is the node viewing this page.
	LocalNode LocalNodeInfo `json:"local_node"`

	// SOCKS5Enabled indicates whether the SOCKS5 handler (virtual port
	// 0x5350) is currently running on this node (direct-dial exit mode).
	SOCKS5Enabled bool `json:"socks5_enabled"`

	// SOCKS5ExitEnabled indicates whether the SOCKS5 exit handler
	// (virtual port 0x4558) is running on this node.
	SOCKS5ExitEnabled bool `json:"socks5_exit_enabled"`

	// ActiveConnections is the number of currently active SOCKS5
	// connections on this node (forward + exit handlers combined).
	ActiveConnections int64 `json:"active_connections"`

	// ProxyPort is the Reality TLS listener port that phone clients
	// connect to. Phone clients use SOCKS5 over Reality TLS on this
	// port. Derived from reality.listen_port (default 52888 if not
	// configured).
	ProxyPort int `json:"proxy_port"`

	// SOCKS5Config holds the current SOCKS5 configuration from config.yaml.
	SOCKS5Config socks5ConfigJSON `json:"socks5_config"`

	// ExitConfig holds the current exit-node configuration from config.yaml.
	ExitConfig exitConfigJSON `json:"exit_config"`

	// RealityEnabled indicates whether the Reality TLS listener is active
	// on this node (required for phone client connections).
	RealityEnabled bool `json:"reality_enabled"`

	// RealityListenAddr is the address the Reality TLS listener binds to.
	RealityListenAddr string `json:"reality_listen_addr"`

	// ExitNodes lists mesh peers that have advertised exit capability
	// (CapExit=true in NodeMeta). Each entry includes hostname, ID,
	// endpoint, and status.
	ExitNodes []proxyNodeInfo `json:"exit_nodes"`

	// EntryNodes lists mesh peers that have advertised proxy entry
	// capability (CapProxyEntry=true in NodeMeta).
	EntryNodes []proxyNodeInfo `json:"entry_nodes"`

	// PathMode is the current path selection mode ("manual" or "auto").
	PathMode string `json:"path_mode"`

	// ConfiguredPaths holds manually configured relay paths (when
	// PathMode is "manual"). Each path is a list of relay node IDs.
	ConfiguredPaths [][]string `json:"configured_paths,omitempty"`

	// ExitAddr is the configured exit node address (if any).
	ExitAddr string `json:"exit_addr,omitempty"`
}

// LocalNodeInfo describes the node viewing the proxy management page.
type LocalNodeInfo struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	ShortID  string `json:"short_id"`
	Role     string `json:"role"`
}

// socks5ConfigJSON is the JSON representation of the SOCKS5 config section.
type socks5ConfigJSON struct {
	Enabled           bool     `json:"enabled"`
	AllowedPorts      []int    `json:"allowed_ports,omitempty"`
	AllowAllPorts     bool     `json:"allow_all_ports"`
	DestinationFilter []string `json:"destination_filter,omitempty"`
	DialTimeoutSec    int      `json:"dial_timeout_sec"`
	IdleTimeoutSec    int      `json:"idle_timeout_sec"`
	MaxConnections    int      `json:"max_connections"`
	RequireMeshPeer   bool     `json:"require_mesh_peer"`
}

// exitConfigJSON is the JSON representation of the exit-node config section.
type exitConfigJSON struct {
	AllowedPorts       []int    `json:"allowed_ports,omitempty"`
	AllowAllPorts      bool     `json:"allow_all_ports"`
	DestinationFilter  []string `json:"destination_filter,omitempty"`
	AuditLogDir        string   `json:"audit_log_dir,omitempty"`
	AuditRetentionDays int      `json:"audit_retention_days"`
}

// proxyNodeInfo describes a mesh peer relevant to proxy routing.
type proxyNodeInfo struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	ShortID  string `json:"short_id"`
	Endpoint string `json:"endpoint,omitempty"`
	Status   string `json:"status"`
}

// SOCKS5StatusProvider is an interface that supplies runtime SOCKS5
// handler state (active connections, enabled flags). In production it
// is backed by *mesh.MeshNode; in tests it can be replaced with a mock.
type SOCKS5StatusProvider interface {
	// SOCKS5HandlerActive returns true if the SOCKS5 direct-dial handler
	// (virtual port 0x5350) is registered and running.
	SOCKS5HandlerActive() bool

	// SOCKS5ExitHandlerActive returns true if the SOCKS5 exit handler
	// (virtual port 0x4558) is registered and running.
	SOCKS5ExitHandlerActive() bool

	// SOCKS5ActiveConnections returns the total number of active SOCKS5
	// connections across all handlers on this node.
	SOCKS5ActiveConnections() int64
}

// handleProxySocks5Status handles GET /api/proxy/socks5/status.
//
// This endpoint returns the local node's SOCKS5 proxy configuration,
// runtime handler state, and mesh topology information about exit/entry
// nodes — everything the proxy management Dashboard page needs to render.
//
// Auth: Session cookie (requireAuth). Exempt from 2FA enforcement so
// the dashboard can query proxy status during monitoring.
func (s *Server) handleProxySocks5Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	resp := SOCKS5ProxyStatus{}

	// --- Local node info ---
	if s.node != nil && s.node.Identity() != nil {
		pk := s.node.Identity().PublicKey
		hostname := ""
		role := "agent"
		if s.cfg != nil {
			hostname = s.cfg.Node.Hostname
		}
		resp.LocalNode = LocalNodeInfo{
			ID:       pk,
			Hostname: hostname,
			ShortID:  shortID(pk),
			Role:     role,
		}
	}

	// --- SOCKS5 runtime state (from injected provider or node) ---
	if s.socks5StatusProvider != nil {
		resp.SOCKS5Enabled = s.socks5StatusProvider.SOCKS5HandlerActive()
		resp.SOCKS5ExitEnabled = s.socks5StatusProvider.SOCKS5ExitHandlerActive()
		resp.ActiveConnections = s.socks5StatusProvider.SOCKS5ActiveConnections()
	}

	// --- Config-derived info ---
	if s.cfg != nil {
		// SOCKS5 config
		s5 := s.cfg.Proxy.SOCKS5
		resp.SOCKS5Config = socks5ConfigJSON{
			Enabled:           s5.Enabled,
			AllowedPorts:      s5.AllowedPorts,
			AllowAllPorts:     s5.AllowAllPorts,
			DestinationFilter: s5.DestinationFilter,
			DialTimeoutSec:    s5.DialTimeoutSec,
			IdleTimeoutSec:    s5.IdleTimeoutSec,
			MaxConnections:    s5.MaxConnections,
			RequireMeshPeer:   s5.RequireMeshPeer,
		}

		// Exit config
		ec := s.cfg.Proxy.Exit
		resp.ExitConfig = exitConfigJSON{
			AllowedPorts:       ec.AllowedPorts,
			AllowAllPorts:      ec.AllowAllPorts,
			DestinationFilter:  ec.DestinationFilter,
			AuditLogDir:        ec.AuditLogDir,
			AuditRetentionDays: ec.AuditRetentionDays,
		}

		// Reality listener info
		resp.RealityEnabled = s.cfg.Reality.Enabled
		resp.RealityListenAddr = s.cfg.Reality.ListenAddr
		if s.cfg.Reality.ListenPort > 0 {
			resp.ProxyPort = s.cfg.Reality.ListenPort
		} else {
			// Default port for Reality TLS (phone client connection point).
			// The mesh desk project uses port 52888 as the standard
			// Reality TLS listener port for proxy entry.
			resp.ProxyPort = 52888
		}

		// Path selection info
		resp.PathMode = s.cfg.Proxy.PathSelection.Mode
		resp.ConfiguredPaths = s.cfg.Proxy.Paths
		resp.ExitAddr = s.cfg.Proxy.ExitAddr
	}

	// --- Mesh topology: find exit and entry nodes from gossip ---
	if s.node != nil {
		snapshot := s.getTopologySnapshot()
		// Build a set of known peers for endpoint lookup.
		rt := s.node.RoutingTable()
		for _, tn := range snapshot.Nodes {
			ni := proxyNodeInfo{
				ID:       tn.ID,
				Hostname: tn.Hostname,
				ShortID:  shortID(tn.ID),
				Status:   tn.Status,
			}
			// Look up endpoint from routing table.
			if rt != nil {
				if pe, ok := rt.GetPeer(tn.ID); ok {
					ni.Endpoint = pe.Endpoint
				}
			}
			// Classify by role.
			switch tn.Role {
			case "exit":
				resp.ExitNodes = append(resp.ExitNodes, ni)
			case "entry":
				resp.EntryNodes = append(resp.EntryNodes, ni)
			}
			// Also include nodes that have role "relay" but with CapExit
			// in their NodeMeta — but since TopologyNode doesn't carry
			// capabilities, we rely on the Role field set by the topology
			// builder, which already maps CapExit→"exit".
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// shortID returns the first 8 characters of a hex node ID for display.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
