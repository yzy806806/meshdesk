package webssh

import (
	"net/http"
	"strconv"
)

// Handler is the HTTP handler for the /ws/terminal WebSocket endpoint.
// It upgrades the connection and delegates to the Hub.
//
// Query parameters:
//
//	node: target peer ID (hex WireGuard public key)
//	cols: initial terminal columns (default 80)
//	rows: initial terminal rows (default 24)
type Handler struct {
	hub *Hub
}

// NewHandler creates an HTTP handler for WebSocket terminal connections.
func NewHandler(hub *Hub) *Handler {
	return &Handler{hub: hub}
}

// ServeHTTP handles the WebSocket upgrade and delegates to the Hub.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Query().Get("node")
	if peerID == "" {
		http.Error(w, "missing 'node' query parameter", http.StatusBadRequest)
		return
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
