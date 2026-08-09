package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/update"
)

// ──────────────────────────────────────────────────────────────────────────
// One-click update API (T2.3):
//   GET  /api/update/plan?nodes=a,b&binary=...  → version matrix / check
//   POST /api/update/start (multipart file + nodes) → run coordinator
//   GET  /api/update/status → last run results
// ──────────────────────────────────────────────────────────────────────────

// meshUpdateDialer adapts MeshDialer to the update.FileSvc/CommandSvc
// interfaces (dial the FileServer / CommandServer virtual ports).
type meshUpdateDialer struct {
	d MeshDialer
}

func (m meshUpdateDialer) DialFile(ctx context.Context, nodeID string) (io.ReadWriteCloser, error) {
	return m.d.DialMesh(ctx, nodeID, mesh.FileVirtualPort)
}

func (m meshUpdateDialer) DialCommand(ctx context.Context, nodeID string) (io.ReadWriteCloser, error) {
	return m.d.DialMesh(ctx, nodeID, mesh.CommandVirtualPort)
}

// updateRunner holds the last coordinator run state.
type updateRunner struct {
	mu      sync.Mutex
	results []update.NodeResult
	lastErr string
	running bool
}

var globalUpdateRunner = &updateRunner{}

// handleUpdatePlan checks nodes and returns their current version info.
func (s *Server) handleUpdatePlan(w http.ResponseWriter, r *http.Request) {
	nodesParam := r.URL.Query().Get("nodes")
	if nodesParam == "" {
		writeJSONError(w, http.StatusBadRequest, "nodes required")
		return
	}
	plan := make([]map[string]any, 0)
	for _, nid := range splitComma(nodesParam) {
		if nid == "" {
			continue
		}
		info := s.queryNodeVersion(r.Context(), nid)
		plan = append(plan, info)
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan})
}

// queryNodeVersion asks a node for its meshdesk version.
func (s *Server) queryNodeVersion(ctx context.Context, nodeID string) map[string]any {
	out := map[string]any{"node": nodeID}
	if s.meshDialer == nil {
		out["error"] = "no mesh dialer"
		return out
	}
	conn, err := s.meshDialer.DialMesh(ctx, nodeID, mesh.CommandVirtualPort)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(map[string]any{"cmd": "meshdesk version 2>/dev/null || /usr/local/bin/meshdesk version 2>/dev/null || echo UNKNOWN", "timeout": 15}); err != nil {
		out["error"] = err.Error()
		return out
	}
	var resp struct {
		OK     bool   `json:"ok"`
		Stdout string `json:"stdout"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		out["error"] = err.Error()
		return out
	}
	if resp.OK {
		out["version"] = firstLine(resp.Stdout)
	} else {
		out["error"] = resp.Error
	}
	return out
}

// handleUpdateStart runs the coordinator with an uploaded binary.
func (s *Server) handleUpdateStart(w http.ResponseWriter, r *http.Request) {
	globalUpdateRunner.mu.Lock()
	if globalUpdateRunner.running {
		globalUpdateRunner.mu.Unlock()
		writeJSONError(w, http.StatusConflict, "update already running")
		return
	}
	globalUpdateRunner.running = true
	globalUpdateRunner.mu.Unlock()

	defer func() {
		globalUpdateRunner.mu.Lock()
		globalUpdateRunner.running = false
		globalUpdateRunner.mu.Unlock()
	}()

	if err := r.ParseMultipartForm(128 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse multipart: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "file required")
		return
	}
	nodesParam := r.FormValue("nodes")
	if nodesParam == "" {
		writeJSONError(w, http.StatusBadRequest, "nodes required")
		return
	}
	installPath := r.FormValue("install_path")
	if installPath == "" {
		installPath = "/usr/local/bin/meshdesk"
	}

	// Save the uploaded binary locally.
	tmp, err := os.CreateTemp("", "meshdesk-update-*")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "temp: "+err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, file); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	tmp.Close()

	coord := update.NewCoordinator(
		meshUpdateDialer{d: s.meshDialer},
		meshUpdateDialer{d: s.meshDialer},
		update.Options{
			Nodes:       splitComma(nodesParam),
			BinaryPath:  tmp.Name(),
			InstallPath: installPath,
			Service:     r.FormValue("service"),
		},
	)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	results := coord.Run(ctx)
	globalUpdateRunner.mu.Lock()
	globalUpdateRunner.results = results
	globalUpdateRunner.lastErr = ""
	globalUpdateRunner.mu.Unlock()

	ok := 0
	for _, res := range results {
		if res.OK {
			ok++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      ok == len(results) && len(results) > 0,
		"total":   len(results),
		"succeed": ok,
		"results": results,
		"file":    header.Filename,
	})
}

// handleUpdateStatus returns the last run's results.
func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	globalUpdateRunner.mu.Lock()
	defer globalUpdateRunner.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"running": globalUpdateRunner.running,
		"results": globalUpdateRunner.results,
		"error":   globalUpdateRunner.lastErr,
	})
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if seg := trimSpace(s[start:i]); seg != "" {
				out = append(out, seg)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

var _ = fmt.Sprintf
