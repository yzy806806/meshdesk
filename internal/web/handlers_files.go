package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yzy806806/meshdesk/internal/mesh"
)

// ──────────────────────────────────────────────────────────────────────────
// Cluster file API (T1.2) — proxies the FileServer virtual port on any
// node over the mesh channel:
//   GET  /api/files/browse?node=<peer>&path=/etc        → directory listing
//   GET  /api/files/read?node=<peer>&path=/etc/hosts    → file download
//   POST /api/files/copy?src_node&src_path&dst_node&dst_path → cross-node copy
//   POST /api/files/distribute?nodes=a,b&path=...       → multi-node write
// ──────────────────────────────────────────────────────────────────────────

// fileServerConn dials a node's FileServer virtual port over the mesh.
func (s *Server) fileServerConn(ctx context.Context, nodeID string) (io.ReadWriteCloser, error) {
	if s.meshDialer == nil {
		return nil, fmt.Errorf("mesh dialer not configured")
	}
	return s.meshDialer.DialMesh(ctx, nodeID, mesh.FileVirtualPort)
}

// handleFileBrowse lists a directory on a remote node.
func (s *Server) handleFileBrowse(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node")
	path := r.URL.Query().Get("path")
	if nodeID == "" {
		writeJSONError(w, http.StatusBadRequest, "node required")
		return
	}
	if path == "" {
		path = "/"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	conn, err := s.fileServerConn(ctx, nodeID)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("dial %s: %v", shortIDDisplay(nodeID), err))
		return
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(mesh.FileRequest{Op: "list", Path: path}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var resp mesh.FileResponse
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !resp.OK {
		writeJSONError(w, http.StatusBadRequest, resp.Error)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":    path,
		"entries": resp.Entries,
	})
}

// handleFileRead streams a file from a remote node.
func (s *Server) handleFileRead(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node")
	path := r.URL.Query().Get("path")
	if nodeID == "" || path == "" {
		writeJSONError(w, http.StatusBadRequest, "node and path required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	conn, err := s.fileServerConn(ctx, nodeID)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("dial %s: %v", shortIDDisplay(nodeID), err))
		return
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(mesh.FileRequest{Op: "read", Path: path}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var resp mesh.FileResponse
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !resp.OK {
		writeJSONError(w, http.StatusBadRequest, resp.Error)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(resp.Size, 10))
	name := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		name = path[i+1:]
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	io.Copy(w, conn)
}

// handleFileCopy copies a file between nodes (streamed through this
// Dashboard node).
func (s *Server) handleFileCopy(w http.ResponseWriter, r *http.Request) {
	srcNode := r.URL.Query().Get("src_node")
	srcPath := r.URL.Query().Get("src_path")
	dstNode := r.URL.Query().Get("dst_node")
	dstPath := r.URL.Query().Get("dst_path")
	if srcNode == "" || srcPath == "" || dstNode == "" || dstPath == "" {
		writeJSONError(w, http.StatusBadRequest, "src_node/src_path/dst_node/dst_path required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	// Read from source.
	srcConn, err := s.fileServerConn(ctx, srcNode)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("dial src: %v", err))
		return
	}
	defer srcConn.Close()
	if err := json.NewEncoder(srcConn).Encode(mesh.FileRequest{Op: "read", Path: srcPath}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var srcResp mesh.FileResponse
	if err := json.NewDecoder(io.LimitReader(srcConn, 64<<10)).Decode(&srcResp); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !srcResp.OK {
		writeJSONError(w, http.StatusBadRequest, "src: "+srcResp.Error)
		return
	}

	// Write to destination.
	dstConn, err := s.fileServerConn(ctx, dstNode)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("dial dst: %v", err))
		return
	}
	defer dstConn.Close()
	if err := json.NewEncoder(dstConn).Encode(mesh.FileRequest{Op: "write", Path: dstPath, Size: srcResp.Size}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Stream source payload → destination.
	if _, err := io.CopyN(dstConn, srcConn, srcResp.Size); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "copy stream: "+err.Error())
		return
	}
	var dstResp mesh.FileResponse
	if err := json.NewDecoder(io.LimitReader(dstConn, 64<<10)).Decode(&dstResp); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !dstResp.OK {
		writeJSONError(w, http.StatusBadRequest, "dst: "+dstResp.Error)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"src_node":  srcNode[:min(len(srcNode), 16)],
		"src_path":  srcPath,
		"dst_node":  dstNode[:min(len(dstNode), 16)],
		"dst_path":  dstPath,
		"size":      srcResp.Size,
		"copied_at": time.Now().Format(time.RFC3339),
	})
}

// handleFileDistribute writes one file to multiple nodes from an
// uploaded stream (multipart "file").
func (s *Server) handleFileDistribute(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse multipart: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "file required")
		return
	}
	defer file.Close()
	dstPath := r.FormValue("path")
	if dstPath == "" {
		dstPath = "/tmp/" + header.Filename
	}
	nodesParam := r.FormValue("nodes")
	if nodesParam == "" {
		writeJSONError(w, http.StatusBadRequest, "nodes (comma-separated peer IDs) required")
		return
	}
	nodeIDs := strings.Split(nodesParam, ",")

	results := make([]map[string]any, 0, len(nodeIDs))
	for _, nid := range nodeIDs {
		nid = strings.TrimSpace(nid)
		if nid == "" {
			continue
		}
		// Rewind the uploaded file for each node.
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			results = append(results, map[string]any{"node": nid, "ok": false, "error": "seek: " + err.Error()})
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		conn, derr := s.fileServerConn(ctx, nid)
		if derr != nil {
			cancel()
			results = append(results, map[string]any{"node": nid, "ok": false, "error": derr.Error()})
			continue
		}
		encErr := json.NewEncoder(conn).Encode(mesh.FileRequest{Op: "write", Path: dstPath, Size: header.Size})
		if encErr == nil {
			_, encErr = io.CopyN(conn, file, header.Size)
		}
		var resp mesh.FileResponse
		if encErr == nil {
			encErr = json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp)
		}
		conn.Close()
		cancel()

		if encErr != nil {
			results = append(results, map[string]any{"node": nid, "ok": false, "error": encErr.Error()})
			continue
		}
		results = append(results, map[string]any{"node": nid, "ok": resp.OK, "written": resp.Written, "error": resp.Error})
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
