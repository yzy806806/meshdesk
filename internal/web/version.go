package web

import (
	"encoding/json"
	"net/http"
)

// normalizeVersionInfo fills in default values for any zero-valued fields.
func normalizeVersionInfo(v VersionInfo) VersionInfo {
	if v.Version == "" {
		v.Version = "dev"
	}
	if v.Commit == "" {
		v.Commit = "unknown"
	}
	if v.BuildTime == "" {
		v.BuildTime = "unknown"
	}
	return v
}

// handleVersion returns build-time version metadata as JSON.
// This endpoint is public (no auth) so that join clients and monitoring
// tools can check the node version without authenticating.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.versionInfo)
}
