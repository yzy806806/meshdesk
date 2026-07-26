package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/yzy806806/meshdesk/internal/xray"
)

// --- x-ui Panel Page Handler ---

// xuiData holds template data for the x-ui panel page.
type xuiData struct {
	PageData
	XrayAvailable bool
	BinaryHint    string
}

// handleXuiPage renders the x-ui panel page — the integrated proxy
// management UI with traffic stats, client management, and share link
// generation. This is the MeshDesk-native equivalent of the x-ui panel,
// built on top of the existing xray-core managed subprocess layer.
func (s *Server) handleXuiPage(w http.ResponseWriter, r *http.Request) {
	xrayAvailable := s.xrayManager != nil
	binaryHint := "not configured"
	if xrayAvailable {
		binaryHint = s.xrayManager.BinaryPath()
	}

	data := xuiData{
		PageData:      PageData{Title: "x-ui Panel", ActivePage: "xui"},
		XrayAvailable: xrayAvailable,
		BinaryHint:    binaryHint,
	}
	s.renderPage(w, "xui.html", data)
}

// --- Stats Handlers ---

// handleXrayStats handles GET /api/xray/stats.
// Returns traffic statistics for all inbounds and clients,
// queried from xray-core's StatsService via the gRPC API.
//
// Optional query params:
//   - ?tag=<inbound_tag> — get stats for a single inbound only
func (s *Server) handleXrayStats(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "xray manager not configured")
		return
	}

	status := s.xrayManager.Status()
	if !status.Running {
		writeJSONError(w, http.StatusServiceUnavailable, "xray is not running")
		return
	}

	apiAddr := s.xrayManager.APIAddr()
	binaryPath := s.xrayManager.BinaryPath()

	ctx, cancel := context.WithTimeout(r.Context(), xray.StatsQueryTimeout)
	defer cancel()

	tag := r.URL.Query().Get("tag")
	if tag != "" {
		stats, err := xray.QueryInboundStats(ctx, binaryPath, apiAddr, tag)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("query stats: %v", err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}

	allStats, err := xray.QueryAllStats(ctx, binaryPath, apiAddr)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("query stats: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allStats)
}

// --- Client Management Handlers ---

// addClientRequest is the JSON body for POST /api/xray/inbound/client.
type addClientRequest struct {
	InboundTag string `json:"inbound_tag"`
	UUID       string `json:"uuid"`
	Flow       string `json:"flow,omitempty"`
	Email      string `json:"email,omitempty"`
	AutoReload bool   `json:"auto_reload,omitempty"`
}

// clientResponse is the JSON response for a client operation.
type clientResponse struct {
	InboundTag   string `json:"inbound_tag"`
	UUID         string `json:"uuid"`
	Flow         string `json:"flow,omitempty"`
	Email        string `json:"email,omitempty"`
	ReloadStatus string `json:"reload_status,omitempty"`
}

// handleXrayClient handles POST/GET/DELETE /api/xray/inbound/client.
//
// POST:   Add a VLESS client to an existing inbound.
// GET:    List clients on an inbound (?tag=<inbound_tag>).
// DELETE: Remove a client (?tag=<inbound_tag>&uuid=<client_uuid>).
func (s *Server) handleXrayClient(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "xray manager not configured")
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handleAddClient(w, r)
	case http.MethodGet:
		s.handleListClients(w, r)
	case http.MethodDelete:
		s.handleRemoveClient(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAddClient handles POST /api/xray/inbound/client.
func (s *Server) handleAddClient(w http.ResponseWriter, r *http.Request) {
	var req addClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.InboundTag == "" {
		writeJSONError(w, http.StatusBadRequest, "inbound_tag is required")
		return
	}

	if req.UUID == "" {
		// Auto-generate a UUID if not provided
		req.UUID = xray.GenerateVLESSUUID()
	}

	if req.Flow == "" {
		req.Flow = "xtls-rprx-vision"
	}

	client := xray.VLESSClient{
		ID:    req.UUID,
		Flow:  req.Flow,
		Email: req.Email,
	}

	if err := s.xrayManager.AddClient(req.InboundTag, client); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	reloadStatus := ""
	if req.AutoReload {
		status := s.xrayManager.Status()
		if status.Running {
			if err := s.xrayManager.Reload(); err != nil {
				reloadStatus = fmt.Sprintf("client added but reload failed: %v", err)
			} else {
				reloadStatus = "xray hot-reloaded"
			}
		}
	}

	resp := clientResponse{
		InboundTag:   req.InboundTag,
		UUID:         req.UUID,
		Flow:         req.Flow,
		Email:        req.Email,
		ReloadStatus: reloadStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// handleListClients handles GET /api/xray/inbound/client?tag=<inbound_tag>.
func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		writeJSONError(w, http.StatusBadRequest, "tag query parameter is required")
		return
	}

	clients, ok := s.xrayManager.GetClients(tag)
	if !ok {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("inbound %q not found", tag))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"inbound_tag": tag,
		"clients":     clients,
		"count":       len(clients),
	})
}

// handleRemoveClient handles DELETE /api/xray/inbound/client?tag=<inbound_tag>&uuid=<uuid>.
func (s *Server) handleRemoveClient(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	uuid := r.URL.Query().Get("uuid")

	if tag == "" {
		writeJSONError(w, http.StatusBadRequest, "tag query parameter is required")
		return
	}
	if uuid == "" {
		writeJSONError(w, http.StatusBadRequest, "uuid query parameter is required")
		return
	}

	if err := s.xrayManager.RemoveClient(tag, uuid); err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}

	autoReload := r.URL.Query().Get("reload") == "true"
	reloadStatus := ""
	if autoReload {
		status := s.xrayManager.Status()
		if status.Running {
			if err := s.xrayManager.Reload(); err != nil {
				reloadStatus = fmt.Sprintf("client removed but reload failed: %v", err)
			} else {
				reloadStatus = "xray hot-reloaded"
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted":       uuid,
		"inbound_tag":   tag,
		"reload_status": reloadStatus,
	})
}

// --- Share Link Handlers ---

// shareLinkRequest is the JSON body for POST /api/xray/share.
type shareLinkRequest struct {
	InboundTag    string `json:"inbound_tag"`
	ClientUUID    string `json:"client_uuid"`
	ServerAddress string `json:"server_address"` // public IP/hostname clients connect to
}

// shareLinkResponse is the JSON response for share link generation.
type shareLinkResponse struct {
	Link   string            `json:"link"`
	Client xray.VLESSClient  `json:"client"`
	Info   *xray.VLESSLinkInfo `json:"info"`
}

// handleXrayShare handles POST /api/xray/share.
// Generates a VLESS+REALITY share link for a specific client on an inbound.
//
// The server_address field is the public IP or hostname that clients
// will connect to (may differ from the listen address if behind NAT).
func (s *Server) handleXrayShare(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "xray manager not configured")
		return
	}

	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req shareLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.InboundTag == "" {
		writeJSONError(w, http.StatusBadRequest, "inbound_tag is required")
		return
	}
	if req.ClientUUID == "" {
		writeJSONError(w, http.StatusBadRequest, "client_uuid is required")
		return
	}
	if req.ServerAddress == "" {
		writeJSONError(w, http.StatusBadRequest, "server_address is required")
		return
	}

	ic, ok := s.xrayManager.GetInbound(req.InboundTag)
	if !ok {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("inbound %q not found", req.InboundTag))
		return
	}

	// Find the client
	var client *xray.VLESSClient
	for i := range ic.VLESSClients {
		if ic.VLESSClients[i].ID == req.ClientUUID {
			client = &ic.VLESSClients[i]
			break
		}
	}
	if client == nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("client %q not found in inbound %q", req.ClientUUID, req.InboundTag))
		return
	}

	link, err := xray.GenerateShareLinkForInbound(ic, *client, req.ServerAddress)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("generate share link: %v", err))
		return
	}

	info, err := xray.ParseVLESSLink(link)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("parse share link: %v", err))
		return
	}

	resp := shareLinkResponse{
		Link:   link,
		Client: *client,
		Info:   info,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
