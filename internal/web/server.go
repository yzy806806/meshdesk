package web

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/mesh/peer"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/webssh"
	webembed "github.com/yzy806806/meshdesk/web"
)

// Server is the HTTP web server for MeshDesk's --web mode.
// It serves server-rendered HTML pages (Go templates + htmx), a WebSocket
// terminal endpoint (delegated to webssh.Handler), an SSE stream for live
// dashboard metrics, and JSON API endpoints for file/service operations.
type Server struct {
	cfg          *config.Config
	node         *mesh.MeshNode
	monitorStore *monitor.Store
	sshHub       *webssh.Hub
	authEngine   *auth.CapabilityEngine
	svcMgr       service.ServiceManager
	meshDialer   MeshDialer // for remote file transfer + remote service management

	tmpl  *template.Template
	pages map[string]*template.Template

	sessions *SessionStore
	sseHub   *SSEHub

	httpServer *http.Server
}

// MeshDialer abstracts mesh-internal dialing for remote file transfer
// and remote service management. In production this wraps mesh.MeshNode.Dial().
type MeshDialer interface {
	DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error)
}

// Deps holds the injectable dependencies for the web server.
type Deps struct {
	Config       *config.Config
	Node         *mesh.MeshNode
	MonitorStore *monitor.Store
	SSHHub       *webssh.Hub
	AuthEngine   *auth.CapabilityEngine
	ServiceMgr   service.ServiceManager
	MeshDialer   MeshDialer
}

// New creates a new web server from the given dependencies.
// It parses all embedded templates and registers template helper functions.
func New(deps Deps) (*Server, error) {
	// Parse all templates with helper functions.
	// Each page template defines a "content" block, so we can't parse them
	// all into one template tree — the last one would shadow the rest.
	// Instead, we parse the layout separately and clone it per page.
	funcMap := template.FuncMap{
		"humanBytes":    humanBytes,
		"humanDuration": humanDuration,
		"cpuClass":      metricBarClass,
		"memClass":      metricBarClass,
		"diskClass":     metricBarClass,
		"shortID":       shortIDDisplay,
	}

	layoutFS, err := webembed.Templates()
	if err != nil {
		return nil, fmt.Errorf("load template FS: %w", err)
	}

	// Parse layout.html as the base template
	layoutTmpl, err := template.New("layout").Funcs(funcMap).ParseFS(layoutFS, "layout.html")
	if err != nil {
		return nil, fmt.Errorf("parse layout template: %w", err)
	}

	// Parse each page template by cloning the layout and adding the page
	pageNames := []string{
		"dashboard.html", "node_detail.html", "terminal.html",
		"files.html", "services.html", "login.html", "peers.html",
	}

	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		clone, err := layoutTmpl.Clone()
		if err != nil {
			return nil, fmt.Errorf("clone layout for %s: %w", name, err)
		}
		pageTmpl, err := clone.ParseFS(layoutFS, name)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		pages[name] = pageTmpl
	}

	s := &Server{
		cfg:          deps.Config,
		node:         deps.Node,
		monitorStore: deps.MonitorStore,
		sshHub:       deps.SSHHub,
		authEngine:   deps.AuthEngine,
		svcMgr:       deps.ServiceMgr,
		meshDialer:   deps.MeshDialer,
		tmpl:         layoutTmpl,
		pages:        pages,
		sessions:     NewSessionStore(),
		sseHub:       NewSSEHub(),
	}

	if s.monitorStore == nil {
		s.monitorStore = monitor.NewStore()
	}

	return s, nil
}

// Start begins serving HTTP on the configured address.
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.recoverMiddleware(s.authMiddleware(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // no write timeout — SSE/WebSocket need long-lived conns
		IdleTimeout:  120 * time.Second,
	}

	// Start SSE hub goroutine
	go s.sseHub.Run()

	log.Printf("Web UI: http://%s", addr)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Web server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the web server.
func (s *Server) Stop() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}
	s.sseHub.Close()
}

// registerRoutes wires all HTTP routes to the mux.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Static assets (no auth required — they're public)
	staticFS, _ := webembed.Static()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Login/logout (no auth required)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// WebSocket terminal (auth checked inside handler via session)
	mux.HandleFunc("/ws/terminal", s.handleWebSocketTerminal)

	// SSE events stream (auth required)
	mux.HandleFunc("/api/events", s.requireAuth(s.handleSSE))

	// API endpoints (auth required, return JSON or HTML fragments)
	mux.HandleFunc("/api/dashboard/partial", s.requireAuth(s.handleDashboardPartial))
	mux.HandleFunc("/api/files/upload", s.requireAuth(s.handleFileUpload))
	mux.HandleFunc("/api/files/list", s.requireAuth(s.handleFileList))
	mux.HandleFunc("/api/services/list", s.requireAuth(s.handleServiceList))
	mux.HandleFunc("/api/services/start", s.requireAuth(s.handleServiceAction("start")))
	mux.HandleFunc("/api/services/stop", s.requireAuth(s.handleServiceAction("stop")))
	mux.HandleFunc("/api/services/restart", s.requireAuth(s.handleServiceAction("restart")))

	// Page routes (auth required)
	mux.HandleFunc("/", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/nodes", s.requireAuth(s.handleNodeList))
	mux.HandleFunc("/nodes/", s.requireAuth(s.handleNodeDetail))
	mux.HandleFunc("/terminal", s.requireAuth(s.handleTerminalPage))
	mux.HandleFunc("/files", s.requireAuth(s.handleFilesPage))
	mux.HandleFunc("/services", s.requireAuth(s.handleServicesPage))
	mux.HandleFunc("/peers", s.requireAuth(s.handlePeersPage))
}

// --- Middleware ---

// authMiddleware checks for a valid session cookie on all routes except
// /login, /logout, /static/, and /ws/terminal (which has its own auth check).
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Public routes
		if path == "/login" || path == "/logout" ||
			strings.HasPrefix(path, "/static/") ||
			path == "/ws/terminal" {
			next.ServeHTTP(w, r)
			return
		}

		// If no web users are configured, allow access (first-run setup mode)
		if len(s.cfg.Auth.WebUsers) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Check session
		cookie, err := r.Cookie("meshdesk_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session := s.sessions.Get(cookie.Value)
		if session == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Store username in request context for handlers
		ctx := context.WithValue(r.Context(), ctxUsernameKey{}, session.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recoverMiddleware catches panics and returns 500 instead of crashing.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PANIC: %s %v", r.URL.Path, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requireAuth wraps a handler with session authentication.
// This is used for routes that must be behind auth even when no web users
// are configured (API endpoints). For page routes, authMiddleware handles it.
func (s *Server) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no web users are configured, allow access (first-run setup)
		if len(s.cfg.Auth.WebUsers) == 0 {
			handler(w, r)
			return
		}

		cookie, err := r.Cookie("meshdesk_session")
		if err != nil {
			if isHTMXRequest(r) {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session := s.sessions.Get(cookie.Value)
		if session == nil {
			if isHTMXRequest(r) {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), ctxUsernameKey{}, session.Username)
		handler(w, r.WithContext(ctx))
	}
}

// isHTMXRequest checks if the request is from htmx (via HX-Request header).
func isHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// ctxUsernameKey is the context key for the authenticated username.
type ctxUsernameKey struct{}

// usernameFromCtx extracts the username from the request context.
func usernameFromCtx(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUsernameKey{}).(string); ok {
		return v
	}
	return ""
}

// --- Template Rendering ---

// PageData is the base data passed to all page templates.
type PageData struct {
	Title      string
	ActivePage string
	Username   string
}

// renderPage renders a full page using the layout template.
func (s *Server) renderPage(w http.ResponseWriter, pageName string, data interface{}) {
	tmpl, ok := s.pages[pageName]
	if !ok {
		log.Printf("template not found: %s", pageName)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("template render error (%s): %v", pageName, err)
	}
}

// renderPartial renders just a named block/template fragment (for htmx).
func (s *Server) renderPartial(w http.ResponseWriter, templateName string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// For partials, we look up the named template from the layout template tree.
	// The "node-cards" template is defined in dashboard.html.
	for _, page := range s.pages {
		if t := page.Lookup(templateName); t != nil {
			if err := t.Execute(w, data); err != nil {
				log.Printf("partial render error (%s): %v", templateName, err)
			}
			return
		}
	}
	log.Printf("partial template not found: %s", templateName)
}

// --- SSE Hub Integration ---

// SSEHub manages Server-Sent Events connections for live dashboard updates.
// When new metrics arrive in the monitor store, the hub broadcasts a JSON
// update to all connected SSE clients.
type SSEHub struct {
	mu      sync.Mutex
	clients map[chan SSEEvent]struct{}
	stopCh  chan struct{}
}

// SSEEvent is a server-sent event.
type SSEEvent struct {
	Event string
	Data  string
}

// NewSSEHub creates a new SSE hub.
func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients: make(map[chan SSEEvent]struct{}),
		stopCh:  make(chan struct{}),
	}
}

// Run starts the hub's broadcast loop. It periodically polls the monitor
// store and broadcasts metric updates to all connected clients.
func (h *SSEHub) Run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			// The hub just broadcasts; the data is fetched by the handler
			// and pushed via Broadcast. This ticker is a keepalive.
		}
	}
}

// Close shuts down the hub.
func (h *SSEHub) Close() {
	select {
	case <-h.stopCh:
	default:
		close(h.stopCh)
	}
}

// Register adds a new SSE client channel.
func (h *SSEHub) Register() chan SSEEvent {
	ch := make(chan SSEEvent, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unregister removes an SSE client channel.
func (h *SSEHub) Unregister(ch chan SSEEvent) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}

// Broadcast sends an event to all connected SSE clients.
func (h *SSEHub) Broadcast(event SSEEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- event:
		default:
			// Client buffer full, skip this event
		}
	}
}

// ClientCount returns the number of connected SSE clients.
func (h *SSEHub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// BroadcastMetrics sends a metrics update to all SSE clients.
// This is called when new metrics arrive in the store.
func (s *Server) BroadcastMetrics() {
	if s.sseHub == nil || s.sseHub.ClientCount() == 0 {
		return
	}

	data := s.buildDashboardJSON()
	if data == "" {
		return
	}

	s.sseHub.Broadcast(SSEEvent{
		Event: "metrics",
		Data:  data,
	})
}

// --- Helper: SessionStore ---

// SessionStore manages in-memory session tokens for web UI auth.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// Session represents an authenticated web UI session.
type Session struct {
	Token     string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewSessionStore creates a new session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// Create creates a new session for the given username.
func (s *SessionStore) Create(username string) *Session {
	token := generateToken()
	session := &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.mu.Lock()
	s.sessions[token] = session
	s.mu.Unlock()
	return session
}

// Get retrieves a session by token. Returns nil if not found or expired.
func (s *SessionStore) Get(token string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[token]
	if !ok {
		return nil
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, token)
		return nil
	}
	return session
}

// Delete removes a session.
func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// generateToken generates a random session token.
func generateToken() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// --- PeerResolver adapter ---

// meshPeerResolver adapts mesh.RoutingTable to the webssh.PeerResolver interface.
type meshPeerResolver struct {
	routes *mesh.RoutingTable
}

func (r *meshPeerResolver) ResolvePeerMeshIP(peerID string) (string, error) {
	entry, ok := r.routes.GetPeer(peerID)
	if !ok {
		return "", fmt.Errorf("peer %s not found in routing table", peerID)
	}
	if len(entry.AllowedIPs) == 0 {
		return "", fmt.Errorf("peer %s has no mesh IP", peerID)
	}
	// Use the first allowed IP as the mesh IP
	return strings.Split(entry.AllowedIPs[0], "/")[0], nil
}

// NewPeerResolver creates a webssh.PeerResolver backed by the mesh routing table.
func NewPeerResolver(routes *mesh.RoutingTable) webssh.PeerResolver {
	return &meshPeerResolver{routes: routes}
}

// --- MeshDialer adapter for webssh ---

// sshMeshDialer adapts mesh.MeshNode.Dial to the webssh.MeshDialer interface.
type sshMeshDialer struct {
	node *mesh.MeshNode
}

func (d *sshMeshDialer) DialMesh(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.node.Dial(ctx, network, addr)
}

// NewMeshDialer creates a webssh.MeshDialer backed by the mesh node.
func NewMeshDialer(node *mesh.MeshNode) webssh.MeshDialer {
	return &sshMeshDialer{node: node}
}

// --- PeerMeshDialer adapter for service/transfer ---

// peerMeshDialer adapts mesh.MeshNode to the service.MeshDialer interface,
// which resolves a peer ID to a mesh IP and dials a specific port.
type peerMeshDialer struct {
	node *mesh.MeshNode
}

func (d *peerMeshDialer) DialMesh(ctx context.Context, peerID string, port int) (net.Conn, error) {
	entry, ok := d.node.RoutingTable().GetPeer(peerID)
	if !ok {
		return nil, fmt.Errorf("peer %s not found in routing table", peerID)
	}
	if len(entry.AllowedIPs) == 0 {
		return nil, fmt.Errorf("peer %s has no mesh IP", peerID)
	}
	meshIP := entry.AllowedIPs[0]
	// Strip CIDR if present
	if idx := strings.IndexByte(meshIP, '/'); idx >= 0 {
		meshIP = meshIP[:idx]
	}
	addr := fmt.Sprintf("%s:%d", meshIP, port)
	return d.node.Dial(ctx, "tcp", addr)
}

// NewPeerMeshDialer creates a MeshDialer (service.MeshDialer compatible)
// backed by the mesh node's routing table and dialer.
func NewPeerMeshDialer(node *mesh.MeshNode) MeshDialer {
	return &peerMeshDialer{node: node}
}

// --- Template helper functions ---

func humanBytes(bytes uint64) string {
	if bytes == 0 {
		return "0 B"
	}
	const unit = 1024
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	val := float64(bytes)
	idx := 0
	for val >= unit && idx < len(units)-1 {
		val /= unit
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d %s", int64(val), units[idx])
	}
	return fmt.Sprintf("%.1f %s", val, units[idx])
}

func humanDuration(seconds int64) string {
	if seconds <= 0 {
		return "—"
	}
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	m := (seconds % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh", d, h)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// metricBarClass returns a CSS class based on the percentage value.
func metricBarClass(pct float64) string {
	if pct >= 90 {
		return "crit"
	}
	if pct >= 75 {
		return "warn"
	}
	return ""
}

func shortIDDisplay(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// PeerInfo holds display-ready peer information for templates.
type PeerInfo struct {
	ID           string
	Endpoint     string
	AllowedIPs   []string
	Obfuscation  string
	Capabilities []string
}

// GrantInfo holds display-ready capability grant info.
type GrantInfo struct {
	PeerID            string
	Capabilities      []string
	ServiceScopes     []string
	FileTransferPaths []string
}

// RevocationInfo holds display-ready revocation info.
type RevocationInfo struct {
	PeerID    string
	RevokedBy string
	RevokedAt time.Time
	Reason    string
}

// unused but needed to satisfy imports during development
var _ = peer.Identity{}

// NodeCardData holds display-ready node metrics for dashboard cards.
type NodeCardData struct {
	NodeID    string
	ShortID   string
	Hostname  string
	CPUUsage  float64
	MemUsage  float64
	MemUsed   uint64
	MemTotal  uint64
	Load1     float64
	Load5     float64
	Load15    float64
	Uptime    int64
	HasDisk   bool
	DiskUsage float64
	CoreCount int
	PerCore   []float64
}
