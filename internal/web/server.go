package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	totpStore   *TOTPStore
	totpKM      *TOTPKeyManager
	stepUpStore *StepUpStore
	alertStore  *AlertStore

	proxyStatusProvider ProxyStatusProvider

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

	// 2FA / security stores. When nil, fresh stores are created.
	TOTPStore   *TOTPStore
	StepUpStore *StepUpStore
	AlertStore  *AlertStore

	// TOTPKeyManager handles encryption of per-user TOTP secrets.
	// When nil, a new one is created from the node-local master secret
	// at /var/lib/meshdesk/totp/master.key (or a test path if configured).
	TOTPKeyManager *TOTPKeyManager

	// ProxyStatusProvider supplies proxy subsystem status for the
	// /api/proxy/status dashboard endpoint. May be nil when the node
	// is not running as a proxy entry point.
	ProxyStatusProvider ProxyStatusProvider
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
		"files.html", "services.html", "login.html", "login_2fa.html",
		"peers.html", "error.html",
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
		totpStore:    deps.TOTPStore,
		totpKM:       deps.TOTPKeyManager,
		stepUpStore:   deps.StepUpStore,
		alertStore:    deps.AlertStore,
		proxyStatusProvider: deps.ProxyStatusProvider,
	}

	if s.monitorStore == nil {
		s.monitorStore = monitor.NewStore()
	}
	if s.totpKM == nil && s.totpStore == nil {
		// Create key manager from node-local master secret.
		// In production, this reads/generates /var/lib/meshdesk/totp/master.key.
		// If the config has a legacy totp_secret, it's used for one-time migration.
		legacySecret := ""
		if deps.Config != nil {
			legacySecret = deps.Config.Auth.LegacyTOTPSecret()
		}
		km, err := NewTOTPKeyManager(DefaultMasterSecretPath, legacySecret)
		if err != nil {
			log.Printf("[WARNING] failed to create TOTP key manager: %v — TOTP secrets will be stored unencrypted", err)
		} else {
			s.totpKM = km
		}
	}
	if s.totpStore == nil {
		// Use persistent encrypted store when TOTPStoreDir is configured,
		// otherwise fall back to in-memory (lost on restart).
		storeDir := ""
		if deps.Config != nil {
			storeDir = deps.Config.Auth.TOTPStoreDir
		}
		if s.totpKM != nil && storeDir != "" {
			store, err := NewPersistentTOTPStore(s.totpKM, storeDir)
			if err != nil {
				log.Printf("[WARNING] failed to create persistent TOTP store: %v — falling back to in-memory", err)
				s.totpStore = NewTOTPStore(s.totpKM)
			} else {
				s.totpStore = store
			}
		} else {
			// No key manager or no store dir — in-memory only
			s.totpStore = NewTOTPStore(s.totpKM)
		}
	}
	if s.stepUpStore == nil {
		s.stepUpStore = NewStepUpStore()
	}
	if s.alertStore == nil {
		s.alertStore = NewAlertStore()
	}

	return s, nil
}

// Start begins serving HTTP on the configured address.
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.recoverMiddleware(s.authMiddleware(s.require2FAEnforcement(mux))),
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

	// 2FA endpoints (no session required — /api/2fa/verify uses 2fa_pending cookie)
	mux.HandleFunc("/api/2fa/verify", s.handle2FAVerify)
	mux.HandleFunc("/api/2fa/enroll", s.requireAuth(s.handle2FAEnroll))
	mux.HandleFunc("/api/2fa/disable", s.requireAuth(s.handle2FADisable))
	mux.HandleFunc("/api/2fa/status", s.requireAuth(s.handle2FAStatus))

	// Step-up auth endpoints (session required)
	mux.HandleFunc("/api/stepup/challenge", s.requireAuth(s.handleStepUpChallenge))
	mux.HandleFunc("/api/stepup/verify", s.requireAuth(s.handleStepUpVerify))

	// Security alerts (session required)
	mux.HandleFunc("/api/alerts", s.requireAuth(s.handleAlertsList))
	mux.HandleFunc("/api/alerts/dismiss", s.requireAuth(s.handleAlertsDismiss))

	// Proxy status (session required, but EXEMPT from 2FA enforcement
	// even when Auth.Require2FA is true — see require2FAEnforcement).
	// This endpoint shares the same HTTP router as all other dashboard
	// routes, but must remain accessible to monitoring tools and the
	// dashboard itself even when the admin has not completed TOTP.
	mux.HandleFunc("/api/proxy/status", s.requireAuth(s.handleProxyStatus))

	// WebSocket terminal — middleware chain enforces:
	//   sessionAuthMiddleware  → valid web session (if web users configured)
	//   stepUpMiddleware       → valid step-up token for "terminal" operation
	//   peerIDFromQueryMiddleware → extracts peer ID from ?node= query param
	//   auth.RequireCapability  → ssh_proxy capability check (Decision E)
	// The webssh handler itself no longer contains auth logic.
	sshHandler := webssh.NewHandler(s.sshHub)
	var terminalChain http.Handler
	if s.authEngine != nil {
		terminalChain = s.sessionAuthMiddleware(
			s.stepUpMiddleware(OpTerminal,
				s.peerIDFromQueryMiddleware(
					auth.RequireCapability(s.authEngine, auth.CapSSHProxy)(sshHandler),
				),
			),
		)
	} else {
		// No auth engine (testing mode) — still enforce session auth + step-up,
		// but skip capability check.
		terminalChain = s.sessionAuthMiddleware(
			s.stepUpMiddleware(OpTerminal,
				s.peerIDFromQueryMiddleware(sshHandler),
			),
		)
	}
	mux.Handle("/ws/terminal", terminalChain)

	// SSE events stream (auth required)
	mux.HandleFunc("/api/events", s.requireAuth(s.handleSSE))

	// API endpoints (auth required, return JSON or HTML fragments)
	mux.HandleFunc("/api/dashboard/partial", s.requireAuth(s.handleDashboardPartial))
	mux.HandleFunc("/api/files/upload", s.requireAuth(s.requireStepUp(OpFileUpload, s.handleFileUpload)))
	mux.HandleFunc("/api/files/list", s.requireAuth(s.handleFileList))
	mux.HandleFunc("/api/services/list", s.requireAuth(s.handleServiceList))
	mux.HandleFunc("/api/services/start", s.requireAuth(s.requireStepUp(OpServiceManage, s.handleServiceAction("start"))))
	mux.HandleFunc("/api/services/stop", s.requireAuth(s.requireStepUp(OpServiceManage, s.handleServiceAction("stop"))))
	mux.HandleFunc("/api/services/restart", s.requireAuth(s.requireStepUp(OpServiceManage, s.handleServiceAction("restart"))))

	// Page routes (auth required)
	mux.HandleFunc("/", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/nodes", s.requireAuth(s.handleNodeList))
	mux.HandleFunc("/nodes/", s.requireAuth(s.handleNodeDetail))
	mux.HandleFunc("/terminal", s.requireAuth(s.requireStepUpPage(OpTerminal, s.handleTerminalPage)))
	mux.HandleFunc("/files", s.requireAuth(s.handleFilesPage))
	mux.HandleFunc("/services", s.requireAuth(s.handleServicesPage))
	mux.HandleFunc("/peers", s.requireAuth(s.handlePeersPage))
}

// --- Middleware ---

// authMiddleware checks for a valid session cookie on all routes except
// /login, /logout, /static/, and /ws/terminal. The /ws/terminal route
// is excluded because it runs its own sessionAuthMiddleware in the
// middleware chain assembled in registerRoutes.
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

// peerIDFromQueryMiddleware extracts the peer ID from the "node" query
// parameter and injects it into the request context via auth.WithPeerID.
// This is the bridge between the web UI's query-string-based peer selection
// and the auth.RequireCapability middleware, which expects the peer ID in
// the context. If the "node" parameter is missing, the request is rejected
// with 400 Bad Request.
func (s *Server) peerIDFromQueryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerID := r.URL.Query().Get("node")
		if peerID == "" {
			http.Error(w, "missing 'node' query parameter", http.StatusBadRequest)
			return
		}
		ctx := auth.WithPeerID(r.Context(), peerID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sessionAuthMiddleware enforces session-based authentication for routes
// that are not covered by authMiddleware (e.g. /ws/terminal was previously
// exempted from authMiddleware and did its own session check inline). This
// middleware centralizes that check. If no web users are configured, all
// requests pass through (first-run setup mode).
func (s *Server) sessionAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.Auth.WebUsers) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("meshdesk_session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		session := s.sessions.Get(cookie.Value)
		if session == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ctxUsernameKey{}, session.Username)
		ctx = context.WithValue(ctx, ctxSessionTokenKey{}, session.Token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireStepUp wraps a handler with step-up authentication for the given
// operation. If the session does not have a valid step-up token for the
// operation, the request is rejected with 403 (JSON) or a redirect to the
// step-up challenge page (browser). If no web users are configured, the
// check is bypassed (first-run setup mode).
func (s *Server) requireStepUp(operation string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		if !s.stepUpStore.Validate(session.Token, operation) {
			if isHTMXRequest(r) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("HX-Redirect", "/api/stepup/challenge?op="+operation)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			http.Redirect(w, r, "/api/stepup/challenge?op="+operation, http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), ctxUsernameKey{}, session.Username)
		ctx = context.WithValue(ctx, ctxSessionTokenKey{}, session.Token)
		handler(w, r.WithContext(ctx))
	}
}

// requireStepUpPage is like requireStepUp but for page routes — it always
// redirects to the step-up challenge page on failure (no JSON response).
func (s *Server) requireStepUpPage(operation string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.Auth.WebUsers) == 0 {
			handler(w, r)
			return
		}

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

		if !s.stepUpStore.Validate(session.Token, operation) {
			http.Redirect(w, r, "/api/stepup/challenge?op="+operation, http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), ctxUsernameKey{}, session.Username)
		ctx = context.WithValue(ctx, ctxSessionTokenKey{}, session.Token)
		handler(w, r.WithContext(ctx))
	}
}

// stepUpMiddleware is the http.Handler variant of requireStepUp, used in
// the WebSocket terminal middleware chain. On failure it returns 403
// (WebSocket clients don't follow redirects).
func (s *Server) stepUpMiddleware(operation string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.Auth.WebUsers) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("meshdesk_session")
		if err != nil {
			http.Error(w, "Step-up authentication required", http.StatusForbidden)
			return
		}

		session := s.sessions.Get(cookie.Value)
		if session == nil {
			http.Error(w, "Step-up authentication required", http.StatusForbidden)
			return
		}

		if !s.stepUpStore.Validate(session.Token, operation) {
			http.Error(w, "Step-up authentication required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ctxSessionTokenKey is the context key for the session token string.
type ctxSessionTokenKey struct{}

// --- Template Rendering ---

// PageData is the base data passed to all page templates.
type PageData struct {
	Title      string
	ActivePage string
	Username   string
}

// renderPage renders a full page using the layout template.
func (s *Server) renderPage(w http.ResponseWriter, pageName string, data any) {
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
func (s *Server) renderPartial(w http.ResponseWriter, templateName string, data any) {
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

// errorData holds the context for the error page template.
type errorData struct {
	PageData
	StatusCode int
	StatusText string
	Message    string
}

// renderError renders a styled error page using the error.html template.
func (s *Server) renderError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	data := errorData{
		PageData:   PageData{Title: "Error", ActivePage: ""},
		StatusCode: statusCode,
		StatusText: http.StatusText(statusCode),
		Message:    message,
	}
	s.renderPage(w, "error.html", data)
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
	// pending holds 2FA-pending tokens: users who passed password auth
	// but still need to provide a TOTP code before receiving a full session.
	pending map[string]*pendingSession
}

// pendingSession holds a user who passed password auth but hasn't
// completed TOTP verification yet.
type pendingSession struct {
	Username  string
	ExpiresAt time.Time
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
		pending:  make(map[string]*pendingSession),
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

// SetPending creates a 2FA-pending session for the given username.
// This is used when password auth succeeds but TOTP is still required.
func (s *SessionStore) SetPending(token, username string) {
	s.mu.Lock()
	s.pending[token] = &pendingSession{
		Username:  username,
		ExpiresAt: time.Now().Add(twoFactorPendingTTL),
	}
	s.mu.Unlock()
}

// GetPending retrieves a 2FA-pending session by token.
// Returns nil if not found or expired.
func (s *SessionStore) GetPending(token string) *pendingSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, ok := s.pending[token]
	if !ok {
		return nil
	}
	if time.Now().After(ps.ExpiresAt) {
		delete(s.pending, token)
		return nil
	}
	return ps
}

// ClearPending removes a 2FA-pending session.
func (s *SessionStore) ClearPending(token string) {
	s.mu.Lock()
	delete(s.pending, token)
	s.mu.Unlock()
}

// generateToken generates a cryptographically secure random session token.
// It returns 32 bytes encoded as a 64-character lowercase hex string.
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// AlertStore returns the server's security alert store. This is used by
// main.go to wire external subsystem callbacks (auth deny, mesh peer join,
// proxy security events) into the dashboard alerting system.
func (s *Server) AlertStore() *AlertStore {
	return s.alertStore
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
