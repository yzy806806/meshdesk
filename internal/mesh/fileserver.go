package mesh

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// FileVirtualPort is the mesh virtual port for the cluster file
// server (T1.1). Dashboard reaches it via DialVirtualPort to browse /
// transfer files on any node over the encrypted mesh channel.
const FileVirtualPort = 0x1F4 // 500

// ──────────────────────────────────────────────────────────────────────────
// FileServer protocol (JSON request/response frames over a mesh stream):
//
//   Request:  {"op":"list","path":"/etc"} | {"op":"read","path":"/x"}
//             {"op":"write","path":"/x","size":1234}
//             {"op":"stat","path":"/x"} | {"op":"delete","path":"/x"}
//
//   Response (list): {"ok":true,"entries":[{"name":"..","size":N,"dir":bool,"mtime":N},...]}
//   Response (read): {"ok":true,"size":N} followed by raw bytes (N total)
//   Response (write): {"ok":true,"written":N}
//   Response (stat):  {"ok":true,"name":"..","size":N,"dir":bool,"mtime":N}
//   Response (error): {"ok":false,"error":"..."}
// ──────────────────────────────────────────────────────────────────────────

// FileEntry describes one directory entry or file.
type FileEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Dir   bool   `json:"dir"`
	Mtime int64  `json:"mtime"`
}

// FileRequest is a single file-server operation.
type FileRequest struct {
	Op   string `json:"op"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// fileResponse is the JSON envelope sent before any raw payload.
type fileResponse struct {
	OK      bool        `json:"ok"`
	Error   string      `json:"error,omitempty"`
	Entries []FileEntry `json:"entries,omitempty"`
	Size    int64       `json:"size,omitempty"`
	Written int64       `json:"written,omitempty"`
	Name    string      `json:"name,omitempty"`
	Dir     bool        `json:"dir,omitempty"`
	Mtime   int64       `json:"mtime,omitempty"`
}

// FileServerConfig configures the cluster file server.
type FileServerConfig struct {
	// AllowedPaths restricts serving to these directory prefixes.
	// Empty = serve any path (not recommended).
	AllowedPaths []string
	// MaxWriteSize caps a single write operation in bytes (0 = 64MB).
	MaxWriteSize int64
}

// FileServer serves files over the mesh virtual port.
type FileServer struct {
	cfg      FileServerConfig
	listener net.Listener
	done     chan struct{}
}

// RegisterFileServer registers the cluster file server on the mesh
// virtual port and starts its accept loop.
func (n *MeshNode) RegisterFileServer(cfg FileServerConfig) (*FileServer, error) {
	if cfg.MaxWriteSize == 0 {
		cfg.MaxWriteSize = 64 << 20 // 64MB default
	}
	ln, err := n.ListenVirtualPort(FileVirtualPort)
	if err != nil {
		return nil, fmt.Errorf("fileserver: register port 0x%x: %w", FileVirtualPort, err)
	}
	fs := &FileServer{
		cfg:      cfg,
		listener: ln,
		done:     make(chan struct{}),
	}
	go fs.serve()
	log.Printf("[fileserver] listening on virtual port 0x%x (allowed=%v)", FileVirtualPort, cfg.AllowedPaths)
	return fs, nil
}

// Close stops the file server.
func (fs *FileServer) Close() error {
	select {
	case <-fs.done:
		return nil
	default:
		close(fs.done)
	}
	return fs.listener.Close()
}

func (fs *FileServer) serve() {
	for {
		conn, err := fs.listener.Accept()
		if err != nil {
			select {
			case <-fs.done:
				return
			default:
			}
			continue
		}
		go fs.handle(conn)
	}
}

func (fs *FileServer) handle(conn net.Conn) {
	defer conn.Close()

	// Read one JSON request frame (bounded). Use a bufio.Reader so any
	// bytes the JSON decoder buffers beyond the request (e.g. the write
	// payload) stay available for the payload copy below.
	br := bufio.NewReader(conn)
	dec := json.NewDecoder(io.LimitReader(br, 64<<10))
	var req FileRequest
	if err := dec.Decode(&req); err != nil {
		writeFileResp(conn, fileResponse{OK: false, Error: "bad request: " + err.Error()})
		return
	}

	resolved, err := fs.resolvePath(req.Path)
	if err != nil {
		writeFileResp(conn, fileResponse{OK: false, Error: err.Error()})
		return
	}

	switch req.Op {
	case "list":
		entries, err := listDir(resolved)
		if err != nil {
			writeFileResp(conn, fileResponse{OK: false, Error: err.Error()})
			return
		}
		writeFileResp(conn, fileResponse{OK: true, Entries: entries})

	case "stat":
		info, err := os.Stat(resolved)
		if err != nil {
			writeFileResp(conn, fileResponse{OK: false, Error: err.Error()})
			return
		}
		writeFileResp(conn, fileResponse{
			OK:    true,
			Name:  info.Name(),
			Size:  info.Size(),
			Dir:   info.IsDir(),
			Mtime: info.ModTime().Unix(),
		})

	case "read":
		if err := fs.serveRead(conn, resolved); err != nil {
			log.Printf("[fileserver] read %s: %v", resolved, err)
		}

	case "write":
		log.Printf("[FSDBG] write op path=%s size=%d", resolved, req.Size)
		written, werr := fs.serveWrite(br, resolved, req.Size)
		log.Printf("[FSDBG] write result written=%d err=%v", written, werr)
		if werr != nil {
			writeFileResp(conn, fileResponse{OK: false, Error: werr.Error()})
		} else {
			writeFileResp(conn, fileResponse{OK: true, Written: written})
		}

	case "delete":
		if err := os.RemoveAll(resolved); err != nil {
			writeFileResp(conn, fileResponse{OK: false, Error: err.Error()})
			return
		}
		writeFileResp(conn, fileResponse{OK: true})

	default:
		writeFileResp(conn, fileResponse{OK: false, Error: "unknown op: " + req.Op})
	}
}

func (fs *FileServer) serveRead(conn net.Conn, path string) error {
	f, err := os.Open(path)
	if err != nil {
		writeFileResp(conn, fileResponse{OK: false, Error: err.Error()})
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		writeFileResp(conn, fileResponse{OK: false, Error: err.Error()})
		return err
	}
	if info.IsDir() {
		writeFileResp(conn, fileResponse{OK: false, Error: "is a directory"})
		return fmt.Errorf("read: %s is a directory", path)
	}

	writeFileResp(conn, fileResponse{OK: true, Size: info.Size()})
	_, err = io.Copy(conn, f)
	return err
}

func (fs *FileServer) serveWrite(r io.Reader, path string, size int64) (int64, error) {
	max := fs.cfg.MaxWriteSize
	if max == 0 {
		max = 64 << 20 // default when constructed directly (tests)
	}
	if size < 0 || size > max {
		return 0, fmt.Errorf("write: size %d exceeds limit %d", size, max)
	}
	// Ensure parent dir exists.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	written, err := io.CopyN(f, r, size)
	if err != nil && err != io.EOF {
		return 0, err
	}
	return written, nil
}

// resolvePath cleans the requested path, rejects traversal, and checks
// the allowed-prefix whitelist.
func (fs *FileServer) resolvePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	clean := filepath.Clean(p)
	// Reject traversal attempts.
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal rejected")
	}
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("abs: %w", err)
	}
	if len(fs.cfg.AllowedPaths) > 0 {
		allowed := false
		for _, ap := range fs.cfg.AllowedPaths {
			aap, err := filepath.Abs(ap)
			if err != nil {
				continue
			}
			if abs == aap || strings.HasPrefix(abs, aap+string(filepath.Separator)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("path %s outside allowed roots", abs)
		}
	}
	return abs, nil
}

func listDir(dir string) ([]FileEntry, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, FileEntry{
			Name:  e.Name(),
			Size:  info.Size(),
			Dir:   e.IsDir(),
			Mtime: info.ModTime().Unix(),
		})
	}
	return out, nil
}

func writeFileResp(w io.Writer, resp fileResponse) {
	json.NewEncoder(w).Encode(resp)
}
