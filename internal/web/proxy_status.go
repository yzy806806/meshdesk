package web

import (
	"encoding/json"
	"net/http"
)

// ProxyStatusProvider is an interface that supplies proxy subsystem
// status information for the dashboard. In production it is backed by
// *proxy.EntryNode; in tests it can be replaced with a mock.
//
// The dashboard calls ProxyStatus() on every hit to /api/proxy/status
// and renders the result as JSON. This endpoint is exempt from 2FA
// enforcement (see require2FAEnforcement) so that monitoring tools
// and the dashboard itself can query proxy health even when the admin
// has not completed TOTP verification.
type ProxyStatusProvider interface {
	// ProxyStatus returns a JSON-serializable status snapshot.
	// Implementations should be safe for concurrent access.
	ProxyStatus() any
}

// proxyStatusResponse is the JSON envelope returned by /api/proxy/status.
type proxyStatusResponse struct {
	Running       bool     `json:"running"`
	SessionCount  int      `json:"session_count"`
	CFTunnelReady bool     `json:"cf_tunnel_ready"`
	Path1Relays   []string `json:"path1_relays,omitempty"`
	Path2Relays   []string `json:"path2_relays,omitempty"`
	ExitAddr      string   `json:"exit_addr,omitempty"`
}

// handleProxyStatus handles GET /api/proxy/status.
//
// This endpoint is registered with requireAuth (session-based auth)
// but is EXEMPT from 2FA enforcement. When no proxy status provider is
// configured, it returns a "proxy not configured" stub.
func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := proxyStatusResponse{}

	if s.proxyStatusProvider != nil {
		raw := s.proxyStatusProvider.ProxyStatus()
		// If the provider returns something we can extract fields from,
		// try to populate our response struct. Otherwise, just pass
		// through the raw value.
		if data, ok := raw.(proxyStatusData); ok {
			resp = proxyStatusResponse(data)
		} else {
			// Fallback: serialize whatever the provider gives us.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(raw)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// proxyStatusData is an intermediate struct used to convert between
// the proxy package's status type and our JSON response. The web
// package cannot import internal/proxy (would create import cycles
// since proxy already imports web for alerting adapters), so the
// provider adapter converts to this struct.
type proxyStatusData struct {
	Running       bool
	SessionCount  int
	CFTunnelReady bool
	Path1Relays   []string
	Path2Relays   []string
	ExitAddr      string
}
