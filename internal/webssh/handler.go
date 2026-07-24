package webssh

import (
	"net/http"
	"strconv"
)

// AuthChecker is the interface for capability-based authorization of
// incoming WebSocket terminal sessions. In production this is implemented
// by wrapping *auth.CapabilityEngine. The handler calls AuthorizeSSH
// before accepting a WebSocket upgrade, enforcing Decision E (zero-trust).
//
// If the checker is nil, all peers are allowed (for testing only).
// In production, always set an auth checker.
type AuthChecker interface {
	// AuthorizeSSH checks whether peerID is authorized to open an SSH
	// terminal session. Returns true if allowed, false otherwise.
	// Every call should produce an audit log entry.
	AuthorizeSSH(peerID string) bool
}

// Handler is the HTTP handler for the /ws/terminal WebSocket endpoint.
// It upgrades the connection and delegates to the Hub.
//
// Query parameters:
//
//	node: target peer ID (hex WireGuard public key)
//	cols: initial terminal columns (default 80)
//	rows: initial terminal rows (default 24)
type Handler struct {
	hub         *Hub
	authChecker AuthChecker
}

// NewHandler creates an HTTP handler for WebSocket terminal connections.
// No auth checker is set; use NewHandlerWithAuth for production.
func NewHandler(hub *Hub) *Handler {
	return &Handler{hub: hub}
}

// NewHandlerWithAuth creates an HTTP handler with capability enforcement.
// The authChecker is called for every incoming WebSocket connection to
// verify the requesting peer has the ssh_proxy capability (Decision E
// compliance). If authChecker is nil, all peers are allowed (testing mode).
func NewHandlerWithAuth(hub *Hub, authChecker AuthChecker) *Handler {
	return &Handler{hub: hub, authChecker: authChecker}
}

// ServeHTTP handles the WebSocket upgrade and delegates to the Hub.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Query().Get("node")
	if peerID == "" {
		http.Error(w, "missing 'node' query parameter", http.StatusBadRequest)
		return
	}

	// Capability check: verify the requesting peer is authorized to
	// open an SSH terminal session (Decision E — zero-trust).
	// This runs before the WebSocket upgrade, so unauthorized peers
	// get a clean HTTP 403 instead of a WebSocket connection.
	if h.authChecker != nil {
		if !h.authChecker.AuthorizeSSH(peerID) {
			http.Error(w, "forbidden: ssh_proxy capability denied", http.StatusForbidden)
			return
		}
	}

	cols := 80
	rows := 24

	if c := r.URL.Query().Get("cols"); c != "" {
		if v, err := strconv.Atoi(c); err == nil && v > 0 {
			cols = v
		}
	}

	if rr := r.URL.Query().Get("rows"); rr != "" {
		if v, err := strconv.Atoi(rr); err == nil && v > 0 {
			rows = v
		}
	}

	ws, err := h.hub.Upgrader().Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote an error response
		return
	}

	h.hub.HandleWebSocket(r.Context(), ws, peerID, cols, rows)
}
