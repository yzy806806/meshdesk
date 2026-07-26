package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yzy806806/meshdesk/internal/xray"
)

// XrayManager is the interface the web server uses to interact with
// the xray-core config layer. In production this is backed by
// *xray.XrayConfigManager; in tests it can be replaced with a mock.
type XrayManager interface {
	AddInbound(cfg *xray.InboundConfig) error
	RemoveInbound(tag string) error
	GetInbound(tag string) (*xray.InboundConfig, bool)
	ListInbounds() []*xray.InboundConfig
	GenerateConfig() (*xray.XrayConfig, error)
	WriteConfig() error
	Reload() error
	Start() error
	Stop() error
	ForceStop() error
	Status() xray.ProcessStatus
	Logs() []xray.LogEntry
	TailLogs(n int) []xray.LogEntry
	ConfigPath() string
	BinaryPath() string

	// Health / readiness
	IsReady() bool
	HealthStatus() xray.HealthStatus
	CheckHealthNow() error

	// Self-test
	SelfTest() *xray.SelfTestResult

	// Client management (x-ui panel features)
	AddClient(inboundTag string, client xray.VLESSClient) error
	RemoveClient(inboundTag, clientUUID string) error
	GetClients(inboundTag string) ([]xray.VLESSClient, bool)

	// API address for stats queries (gRPC API inbound)
	APIAddr() string
}

// --- Request/Response types ---

// createInboundRequest is the JSON body for POST /api/xray/inbound.
type createInboundRequest struct {
	Tag               string             `json:"tag"`
	Protocol          string             `json:"protocol,omitempty"` // default "vless-reality"
	Port              int                `json:"port"`
	Listen            string             `json:"listen,omitempty"`       // default "0.0.0.0"
	Network           string             `json:"network,omitempty"`      // default "tcp"
	Security          string             `json:"security,omitempty"`     // default "reality"
	Dest              string             `json:"dest,omitempty"`         // camouflage target
	ServerNames       []string           `json:"server_names,omitempty"` // SNI list
	PrivateKey        string             `json:"private_key,omitempty"`  // X25519 private key
	ShortIds          []string           `json:"short_ids,omitempty"`    // per-client hex IDs
	CertFile          string             `json:"cert_file,omitempty"`    // for TLS security
	KeyFile           string             `json:"key_file,omitempty"`     // for TLS security
	VLESSClients      []xray.VLESSClient `json:"vless_clients,omitempty"`
	SniffEnabled      bool               `json:"sniff_enabled,omitempty"`
	SniffDestOverride []string           `json:"sniff_dest_override,omitempty"`
	AutoStart         bool               `json:"auto_start,omitempty"` // reload xray after adding
}

// inboundResponse is the JSON response for a single inbound.
type inboundResponse struct {
	Tag          string             `json:"tag"`
	Protocol     string             `json:"protocol"`
	Port         int                `json:"port"`
	Listen       string             `json:"listen"`
	Network      string             `json:"network"`
	Security     string             `json:"security"`
	Dest         string             `json:"dest,omitempty"`
	ServerNames  []string           `json:"server_names,omitempty"`
	ShortIds     []string           `json:"short_ids,omitempty"`
	VLESSClients []xray.VLESSClient `json:"vless_clients,omitempty"`
	SniffEnabled bool               `json:"sniff_enabled"`
}

// statusResponse is the JSON response for GET /api/xray/status.
type statusResponse struct {
	Running      bool   `json:"running"`
	Ready        bool   `json:"ready"`
	HealthState  string `json:"health_state"`
	PID          int    `json:"pid,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
	RestartCount int    `json:"restart_count"`
	ConfigPath   string `json:"config_path"`
	BinaryPath   string `json:"binary_path"`
	InboundCount int    `json:"inbound_count"`

	// Health details
	LastHealthy  string `json:"last_healthy,omitempty"`
	LastFailure  string `json:"last_failure,omitempty"`
	CheckCount   int64  `json:"check_count"`
	FailureCount int64  `json:"failure_count"`
}

// logsResponse is the JSON response for GET /api/xray/logs.
type logsResponse struct {
	Entries []xray.LogEntry `json:"entries"`
	Count   int             `json:"count"`
}

// --- Handlers ---

// handleXrayInbound handles POST/GET/DELETE /api/xray/inbound.
//
// POST:   Create or replace an inbound. Optionally auto-reloads xray.
// GET:    List all inbounds (or get a specific one via ?tag=).
// DELETE: Remove an inbound by ?tag=. Optionally auto-reloads xray.
func (s *Server) handleXrayInbound(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handleCreateInbound(w, r)
	case http.MethodGet:
		s.handleListInbounds(w, r)
	case http.MethodDelete:
		s.handleDeleteInbound(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleCreateInbound handles POST /api/xray/inbound.
func (s *Server) handleCreateInbound(w http.ResponseWriter, r *http.Request) {
	var req createInboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.Tag == "" {
		writeJSONError(w, http.StatusBadRequest, "tag is required")
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "valid port (1-65535) is required")
		return
	}

	// Build the InboundConfig from the request
	ic := &xray.InboundConfig{
		Tag:               req.Tag,
		Protocol:          req.Protocol,
		Port:              req.Port,
		Listen:            req.Listen,
		Network:           req.Network,
		Security:          req.Security,
		Dest:              req.Dest,
		ServerNames:       req.ServerNames,
		PrivateKey:        req.PrivateKey,
		ShortIds:          req.ShortIds,
		CertFile:          req.CertFile,
		KeyFile:           req.KeyFile,
		VLESSClients:      req.VLESSClients,
		SniffEnabled:      req.SniffEnabled,
		SniffDestOverride: req.SniffDestOverride,
	}

	// If no VLESS clients and this is a VLESS protocol, auto-generate one
	if (req.Protocol == "" || strings.HasPrefix(req.Protocol, "vless")) && len(ic.VLESSClients) == 0 {
		ic.VLESSClients = []xray.VLESSClient{
			{ID: xray.GenerateVLESSUUID(), Flow: "xtls-rprx-vision"},
		}
	}

	// If security is reality and no private key, auto-generate one
	if (req.Security == "" || req.Security == "reality") && ic.PrivateKey == "" {
		priv, _, err := xray.GenerateX25519Key()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("generate X25519 key: %v", err))
			return
		}
		ic.PrivateKey = priv
	}

	// If no short IDs, auto-generate one
	if (req.Security == "" || req.Security == "reality") && len(ic.ShortIds) == 0 {
		ic.ShortIds = []string{xray.GenerateShortID()}
	}

	// Add the inbound
	if err := s.xrayManager.AddInbound(ic); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Optionally reload xray if it's running
	reloadStatus := ""
	if req.AutoStart {
		status := s.xrayManager.Status()
		if status.Running {
			if err := s.xrayManager.Reload(); err != nil {
				reloadStatus = fmt.Sprintf("inbound added but reload failed: %v", err)
			} else {
				reloadStatus = "xray hot-reloaded"
			}
		} else {
			if err := s.xrayManager.Start(); err != nil {
				reloadStatus = fmt.Sprintf("inbound added but start failed: %v", err)
			} else {
				reloadStatus = "xray started"
			}
		}
	}

	// Build response
	resp := inboundResponse{
		Tag:          ic.Tag,
		Protocol:     ic.Protocol,
		Port:         ic.Port,
		Listen:       ic.Listen,
		Network:      ic.Network,
		Security:     ic.Security,
		Dest:         ic.Dest,
		ServerNames:  ic.ServerNames,
		ShortIds:     ic.ShortIds,
		VLESSClients: ic.VLESSClients,
		SniffEnabled: ic.SniffEnabled,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"inbound":       resp,
		"reload_status": reloadStatus,
	})
}

// handleListInbounds handles GET /api/xray/inbound (or ?tag= for single).
func (s *Server) handleListInbounds(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	if tag != "" {
		ic, ok := s.xrayManager.GetInbound(tag)
		if !ok {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("inbound %q not found", tag))
			return
		}
		resp := inboundResponse{
			Tag:          ic.Tag,
			Protocol:     ic.Protocol,
			Port:         ic.Port,
			Listen:       ic.Listen,
			Network:      ic.Network,
			Security:     ic.Security,
			Dest:         ic.Dest,
			ServerNames:  ic.ServerNames,
			ShortIds:     ic.ShortIds,
			VLESSClients: ic.VLESSClients,
			SniffEnabled: ic.SniffEnabled,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	inbounds := s.xrayManager.ListInbounds()
	resp := make([]inboundResponse, 0, len(inbounds))
	for _, ic := range inbounds {
		resp = append(resp, inboundResponse{
			Tag:          ic.Tag,
			Protocol:     ic.Protocol,
			Port:         ic.Port,
			Listen:       ic.Listen,
			Network:      ic.Network,
			Security:     ic.Security,
			Dest:         ic.Dest,
			ServerNames:  ic.ServerNames,
			ShortIds:     ic.ShortIds,
			VLESSClients: ic.VLESSClients,
			SniffEnabled: ic.SniffEnabled,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"inbounds": resp,
		"count":    len(resp),
	})
}

// handleDeleteInbound handles DELETE /api/xray/inbound?tag=...
func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		writeJSONError(w, http.StatusBadRequest, "tag query parameter is required")
		return
	}

	if err := s.xrayManager.RemoveInbound(tag); err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("inbound %q not found", tag))
		return
	}

	// Optionally reload
	autoReload := r.URL.Query().Get("reload") == "true"
	reloadStatus := ""
	if autoReload {
		status := s.xrayManager.Status()
		if status.Running {
			if err := s.xrayManager.Reload(); err != nil {
				reloadStatus = fmt.Sprintf("inbound removed but reload failed: %v", err)
			} else {
				reloadStatus = "xray hot-reloaded"
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted":       tag,
		"reload_status": reloadStatus,
	})
}

// handleXrayStatus handles GET /api/xray/status.
func (s *Server) handleXrayStatus(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	status := s.xrayManager.Status()
	health := s.xrayManager.HealthStatus()
	resp := statusResponse{
		Running:      status.Running,
		Ready:        s.xrayManager.IsReady(),
		HealthState:  health.State.String(),
		PID:          status.PID,
		StartedAt:    "",
		RestartCount: status.RestartCount,
		ConfigPath:   status.ConfigPath,
		BinaryPath:   status.BinaryPath,
		InboundCount: len(s.xrayManager.ListInbounds()),
		CheckCount:   health.CheckCount,
		FailureCount: health.FailureCount,
	}
	if !status.StartedAt.IsZero() {
		resp.StartedAt = status.StartedAt.Format("2006-01-02T15:04:05Z")
	}
	if !health.LastHealthy.IsZero() {
		resp.LastHealthy = health.LastHealthy.Format("2006-01-02T15:04:05Z")
	}
	if health.LastFailure != "" {
		resp.LastFailure = health.LastFailure
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleXrayLogs handles GET /api/xray/logs.
// Optional ?n= parameter limits the number of log entries returned.
func (s *Server) handleXrayLogs(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	var logs []xray.LogEntry
	nStr := r.URL.Query().Get("n")
	if nStr != "" {
		var n int
		if _, err := fmt.Sscanf(nStr, "%d", &n); err == nil && n > 0 {
			logs = s.xrayManager.TailLogs(n)
		} else {
			logs = s.xrayManager.Logs()
		}
	} else {
		logs = s.xrayManager.Logs()
	}

	resp := logsResponse{
		Entries: logs,
		Count:   len(logs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleXrayStart handles POST /api/xray/start.
func (s *Server) handleXrayStart(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	if err := s.xrayManager.Start(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"started": true,
		"status":  s.xrayManager.Status(),
	})
}

// handleXrayStop handles POST /api/xray/stop.
// With ?force=true it calls ForceStop (skip drain, immediate SIGTERM).
func (s *Server) handleXrayStop(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	force := r.URL.Query().Has("force") || r.URL.Query().Get("force") == "true"

	var err error
	if force {
		err = s.xrayManager.ForceStop()
	} else {
		err = s.xrayManager.Stop()
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stopped": true,
		"force":   force,
	})
}

// handleXrayReload handles POST /api/xray/reload.
func (s *Server) handleXrayReload(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	if err := s.xrayManager.Reload(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reloaded": true,
	})
}

// handleXrayHealth handles POST /api/xray/health.
// Triggers an immediate health check and returns the result.
func (s *Server) handleXrayHealth(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	err := s.xrayManager.CheckHealthNow()
	health := s.xrayManager.HealthStatus()

	resp := map[string]interface{}{
		"state":         health.State.String(),
		"ready":         s.xrayManager.IsReady(),
		"last_checked":  "",
		"check_count":   health.CheckCount,
		"failure_count": health.FailureCount,
	}
	if !health.LastChecked.IsZero() {
		resp["last_checked"] = health.LastChecked.Format("2006-01-02T15:04:05Z")
	}
	if !health.LastHealthy.IsZero() {
		resp["last_healthy"] = health.LastHealthy.Format("2006-01-02T15:04:05Z")
	}
	if health.LastFailure != "" {
		resp["last_failure"] = health.LastFailure
	}
	if err != nil {
		resp["error"] = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(resp)
}

// handleXraySelfTest handles GET /api/xray/selftest.
//
// Runs a comprehensive diagnostic of the xray-core subsystem and
// returns a structured result with an overall status (healthy /
// degraded / unhealthy) and individual check results. Designed
// for monitoring and alerting systems.
//
// HTTP status codes:
//   - 200 OK: overall status is healthy or degraded
//   - 503 Service Unavailable: overall status is unhealthy
//   - 503: xray manager not configured
func (s *Server) handleXraySelfTest(w http.ResponseWriter, r *http.Request) {
	if s.xrayManager == nil {
		http.Error(w, `{"error":"xray manager not configured"}`, http.StatusServiceUnavailable)
		return
	}

	result := s.xrayManager.SelfTest()

	w.Header().Set("Content-Type", "application/json")
	if result.Overall == xray.OverallUnhealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(result)
}

// writeJSONError writes a JSON error response with the given status code.
func writeJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
