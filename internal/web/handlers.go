package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/transfer"
	"golang.org/x/crypto/bcrypt"
)

// TransferPort is the mesh-internal port for the file transfer server.
// This must match the listener on the target node.
const TransferPort = 4193

// --- Login / Logout ---

// twoFactorPendingCookie is the cookie name for the intermediate 2FA-pending
// state. When a user with TOTP enrollment provides correct password+username,
// instead of creating a full session immediately, the server issues this
// short-lived cookie. The user must then POST a valid TOTP code (or recovery
// code) to /api/2fa/verify to receive a full session cookie.
const twoFactorPendingCookie = "meshdesk_2fa_pending"

// twoFactorPendingTTL is the lifetime of the 2FA-pending cookie.
const twoFactorPendingTTL = 5 * time.Minute

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// If ?2fa=1 is present, render the 2FA code entry page
		if r.URL.Query().Get("2fa") == "1" {
			data := struct {
				Title      string
				ActivePage string
				Error      string
			}{
				Title:      "Two-Factor Authentication",
				ActivePage: "login",
			}
			s.renderPage(w, "login_2fa.html", data)
			return
		}
		data := struct {
			Title      string
			ActivePage string
			Error      string
		}{
			Title:      "Login",
			ActivePage: "login",
		}
		s.renderPage(w, "login.html", data)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if s.authenticate(username, password) {
			// Check if the user has TOTP enrolled
			if s.totpStore.IsEnrolled(username) {
				// Password is correct, but TOTP is required.
				// Set a 2FA-pending cookie (short-lived) and redirect to the challenge page.
				pendingToken := generateToken()
				s.sessions.SetPending(pendingToken, username)
				http.SetCookie(w, &http.Cookie{
					Name:     twoFactorPendingCookie,
					Value:    pendingToken,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   int(twoFactorPendingTTL.Seconds()),
					SameSite: http.SameSiteStrictMode,
				})
				http.Redirect(w, r, "/login?2fa=1", http.StatusSeeOther)
				return
			}

			// No TOTP — proceed with normal session
			session := s.sessions.Create(username)
			http.SetCookie(w, &http.Cookie{
				Name:     "meshdesk_session",
				Value:    session.Token,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   86400,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Log failed login attempt for alerting
		s.alertStore.Add(SecurityAlert{
			Type:        "login_failure",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: "failed login attempt",
			Severity:    AlertWarning,
		})

		data := struct {
			Title      string
			ActivePage string
			Error      string
		}{
			Title:      "Login",
			ActivePage: "login",
			Error:      "Invalid username or password",
		}
		s.renderPage(w, "login.html", data)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("meshdesk_session")
	if err == nil {
		// Revoke any step-up tokens for this session
		s.stepUpStore.Revoke(cookie.Value)
		s.sessions.Delete(cookie.Value)
	}
	// Also clear 2FA pending cookie if present
	pending, err := r.Cookie(twoFactorPendingCookie)
	if err == nil {
		s.sessions.ClearPending(pending.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "meshdesk_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     twoFactorPendingCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// authenticate checks credentials against the config's web_users list.
// Passwords must be bcrypt-hashed ($2a$, $2b$, or $2y$ prefix).
// Non-bcrypt stored values (including plaintext) are rejected.
func (s *Server) authenticate(username, password string) bool {
	for _, user := range s.cfg.Auth.WebUsers {
		if user.Username == username {
			// Reject any stored value that isn't a bcrypt hash.
			// Accept $2a$, $2b$, and $2y$ prefixes (bcrypt variants).
			if !isBcryptHash(user.PasswordHash) {
				return false
			}
			return bcryptCompare(user.PasswordHash, password)
		}
	}
	return false
}

// isBcryptHash reports whether s looks like a bcrypt hash.
// Bcrypt hashes start with $2a$, $2b$, or $2y$ followed by a cost and 53-char
// salt+hash (total 60 chars).
func isBcryptHash(s string) bool {
	return len(s) == 60 &&
		(strings.HasPrefix(s, "$2a$") ||
			strings.HasPrefix(s, "$2b$") ||
			strings.HasPrefix(s, "$2y$"))
}

// --- Dashboard ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	nodes := s.buildNodeCards()
	data := struct {
		PageData
		Nodes          []NodeCardData
		NodeCount      int
		ActiveSessions int
		Collecting     bool
	}{
		PageData:       PageData{Title: "Dashboard", ActivePage: "dashboard"},
		Nodes:          nodes,
		NodeCount:      len(nodes),
		ActiveSessions: s.activeSessionCount(),
		Collecting:     s.monitorStore != nil && s.monitorStore.NodeCount() > 0,
	}

	if isHTMXRequest(r) {
		s.renderPartial(w, "node-cards", data)
		return
	}
	s.renderPage(w, "dashboard.html", data)
}

func (s *Server) handleDashboardPartial(w http.ResponseWriter, r *http.Request) {
	nodes := s.buildNodeCards()
	data := struct {
		Nodes          []NodeCardData
		NodeCount      int
		ActiveSessions int
		Collecting     bool
	}{
		Nodes:          nodes,
		NodeCount:      len(nodes),
		ActiveSessions: s.activeSessionCount(),
		Collecting:     s.monitorStore != nil && s.monitorStore.NodeCount() > 0,
	}
	s.renderPartial(w, "node-cards", data)
}

// --- Nodes ---

func (s *Server) handleNodeList(w http.ResponseWriter, r *http.Request) {
	nodes := s.buildNodeCards()
	data := struct {
		PageData
		Nodes          []NodeCardData
		NodeCount      int
		ActiveSessions int
		Collecting     bool
	}{
		PageData:       PageData{Title: "Nodes", ActivePage: "nodes"},
		Nodes:          nodes,
		NodeCount:      len(nodes),
		ActiveSessions: s.activeSessionCount(),
		Collecting:     s.monitorStore != nil && s.monitorStore.NodeCount() > 0,
	}
	s.renderPage(w, "dashboard.html", data)
}

func (s *Server) handleNodeDetail(w http.ResponseWriter, r *http.Request) {
	// Extract node ID from path /nodes/<id>
	nodeID := strings.TrimPrefix(r.URL.Path, "/nodes/")
	if nodeID == "" {
		http.Redirect(w, r, "/nodes", http.StatusSeeOther)
		return
	}

	metrics := s.monitorStore.Latest(nodeID)
	if metrics == nil {
		s.renderError(w, http.StatusNotFound, "Node not found or no metrics available for: "+nodeID)
		return
	}

	nd := buildNodeDetail(metrics)
	data := struct {
		PageData
		Node NodeDetailData
	}{
		PageData: PageData{Title: "Node " + nd.Hostname, ActivePage: "nodes"},
		Node:     nd,
	}
	s.renderPage(w, "node_detail.html", data)
}

// --- Terminal ---

func (s *Server) handleTerminalPage(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Query().Get("node")
	if peerID == "" {
		http.Error(w, "Missing 'node' parameter", http.StatusBadRequest)
		return
	}

	data := struct {
		PageData
		PeerID      string
		PeerShortID string
	}{
		PageData:    PageData{Title: "Terminal", ActivePage: ""},
		PeerID:      peerID,
		PeerShortID: shortIDDisplay(peerID),
	}
	s.renderPage(w, "terminal.html", data)
}

// --- Files ---

func (s *Server) handleFilesPage(w http.ResponseWriter, r *http.Request) {
	nodes := s.buildNodeCards()
	data := struct {
		PageData
		Nodes []NodeCardData
	}{
		PageData: PageData{Title: "Files", ActivePage: "files"},
		Nodes:    nodes,
	}
	s.renderPage(w, "files.html", data)
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (10 MB max)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	targetNode := r.FormValue("target_node")
	destPath := r.FormValue("dest_path")
	if destPath == "" {
		destPath = "/tmp/"
	}

	// If a target node is specified and is not "local", transfer over the mesh.
	if targetNode != "" && targetNode != "local" {
		if s.meshDialer == nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<p class='error'>Mesh dialer not configured — cannot transfer to remote node.</p>")
			return
		}

		// Dial the target node's transfer port on the mesh.
		ctx, cancel := context.WithTimeout(r.Context(), transfer.DefaultTimeout)
		defer cancel()

		conn, err := s.meshDialer.DialMesh(ctx, targetNode, TransferPort)
		if err != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<p class='error'>Failed to connect to node %s: %v</p>", shortIDDisplay(targetNode), err)
			return
		}
		defer conn.Close()

		// Create a file header from the uploaded file info.
		fileHeader := &transfer.FileHeader{
			Version:   transfer.ProtocolVersion,
			Filename:  header.Filename,
			Size:      header.Size,
			Mode:      0644,
			FileType:  transfer.FileTypeRegular,
			ModTime:   time.Now().Format(time.RFC3339),
			SrcPeerID: "local",
		}

		// Send the file over the mesh.
		result, err := transfer.SendWithContext(ctx, conn, file, fileHeader)
		if err != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<p class='error'>Transfer to %s failed: %v</p>", shortIDDisplay(targetNode), err)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		if result.OK {
			fmt.Fprintf(w, "<p>Transferred: <code>%s</code> (%d bytes) → node %s:%s</p>",
				header.Filename, header.Size, shortIDDisplay(targetNode), destPath)
		} else {
			fmt.Fprintf(w, "<p class='error'>Remote node rejected transfer: %s</p>", result.Message)
		}
		return
	}

	// Local upload: save to destPath on this node
	uploadDir := destPath
	savedPath, err := saveUploadedFile(file, header.Filename, uploadDir)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<p class='error'>Upload failed: %s</p>", err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Uploaded: <code>%s</code> (%d bytes) → %s</p>",
		header.Filename, header.Size, savedPath)
}

func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	// List files in the upload directory
	entries := listUploadFiles()

	w.Header().Set("Content-Type", "text/html")
	if len(entries) == 0 {
		fmt.Fprint(w, "<p class='placeholder'>No uploaded files.</p>")
		return
	}

	fmt.Fprint(w, "<table><thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead><tbody>")
	for _, e := range entries {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
			e.Name, humanBytes(uint64(e.Size)), e.ModTime.Format("2006-01-02 15:04"))
	}
	fmt.Fprint(w, "</tbody></table>")
}

// --- Services ---

func (s *Server) handleServicesPage(w http.ResponseWriter, r *http.Request) {
	nodes := s.buildNodeCards()

	var services []serviceStatusDisplay
	if s.svcMgr != nil {
		if list, err := s.svcMgr.List(); err == nil {
			for _, svc := range list {
				services = append(services, serviceStatusDisplay{
					Name:        svc.Name,
					ActiveState: svc.ActiveState,
					SubState:    svc.SubState,
					Description: svc.Description,
				})
			}
		}
	}

	data := struct {
		PageData
		Nodes    []NodeCardData
		Services []serviceStatusDisplay
	}{
		PageData: PageData{Title: "Services", ActivePage: "services"},
		Nodes:    nodes,
		Services: services,
	}
	s.renderPage(w, "services.html", data)
}

func (s *Server) handleServiceList(w http.ResponseWriter, r *http.Request) {
	if s.svcMgr == nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<p class='placeholder'>Service manager not available on this node.</p>")
		return
	}

	services, err := s.svcMgr.List()
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<p class='error'>Error listing services: %s</p>", err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if len(services) == 0 {
		fmt.Fprint(w, "<p class='placeholder'>No services found.</p>")
		return
	}

	fmt.Fprint(w, "<table><thead><tr><th>Name</th><th>State</th><th>Sub</th><th>Description</th></tr></thead><tbody>")
	for _, svc := range services {
		stateClass := "badge"
		if svc.ActiveState == "active" {
			stateClass = "badge"
		}
		fmt.Fprintf(w, "<tr><td><code>%s</code></td><td><span class='%s'>%s</span></td><td>%s</td><td>%s</td></tr>",
			svc.Name, stateClass, svc.ActiveState, svc.SubState, svc.Description)
	}
	fmt.Fprint(w, "</tbody></table>")
}

func (s *Server) handleServiceAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		node := r.FormValue("node")
		serviceName := r.FormValue("service")

		if serviceName == "" {
			http.Error(w, "Missing service name", http.StatusBadRequest)
			return
		}

		// For local services:
		if node == "" || node == "local" {
			if s.svcMgr == nil {
				http.Error(w, "Service manager not available", http.StatusServiceUnavailable)
				return
			}

			// For local services, use the plain ServiceManager directly.
			// The web UI user has already passed session-based authentication,
			// so capability checks here would only break local operations
			// (no grant exists for a fabricated "local" peerID).
			// Remote service operations still go through AuthorizedServiceManager
			// via the mesh request path.
			var err error
			switch action {
			case "start":
				err = s.svcMgr.Start(serviceName)
			case "stop":
				err = s.svcMgr.Stop(serviceName)
			case "restart":
				err = s.svcMgr.Restart(serviceName)
			}

			if err != nil {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Failed to %s %s: %v", action, serviceName, err)
				return
			}

			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Service %s %sed successfully", serviceName, action)
			return
		}

		// Remote node service management: dial the mesh, send command, receive response.
		if s.meshDialer == nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "Mesh dialer not configured — cannot manage remote services")
			return
		}

		client := service.NewRemoteClient(s.meshDialer, 0, 30*time.Second)
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Populate PeerID with the local node's identity so the remote
		// server can enforce per-peer capability checks.
		localPeerID := ""
		if s.node != nil {
			localPeerID = s.node.Identity().PublicKey
		}

		resp, err := client.Call(ctx, node, &service.ServiceRequest{
			PeerID:  localPeerID,
			Action:  action,
			Service: serviceName,
		})
		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "Failed to reach node %s: %v", shortIDDisplay(node), err)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		if resp.OK {
			fmt.Fprintf(w, "Service %s %sed successfully on node %s", serviceName, action, shortIDDisplay(node))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Remote node error: %s", resp.Message)
		}
	}
}

// --- Peers ---

func (s *Server) handlePeersPage(w http.ResponseWriter, r *http.Request) {
	var peers []PeerInfo
	var grants []GrantInfo
	var revocations []RevocationInfo

	if s.node != nil {
		rt := s.node.RoutingTable()
		for _, p := range rt.AllPeers() {
			peers = append(peers, PeerInfo{
				ID:           p.ID,
				Endpoint:     p.Endpoint,
				AllowedIPs:   p.AllowedIPs,
				Transport:    "reality", // v2: only Reality TLS transport
				Capabilities: s.getPeerCapabilities(p.ID),
			})
		}
	}

	if s.authEngine != nil {
		for _, g := range s.authEngine.AllGrants() {
			caps := make([]string, 0, len(g.Capabilities))
			for cap := range g.Capabilities {
				caps = append(caps, cap)
			}
			scopes := make([]string, 0, len(g.ServiceScopes))
			for sc := range g.ServiceScopes {
				scopes = append(scopes, sc)
			}
			grants = append(grants, GrantInfo{
				PeerID:            g.PeerID,
				Capabilities:      caps,
				ServiceScopes:     scopes,
				FileTransferPaths: g.FileTransferPaths,
			})
		}

		for _, rev := range s.authEngine.AllRevocations() {
			revocations = append(revocations, RevocationInfo{
				PeerID:    rev.PeerID,
				RevokedBy: rev.RevokedBy,
				RevokedAt: rev.RevokedAt,
				Reason:    rev.Reason,
			})
		}
	}

	localKey := ""
	localMeshIP := ""
	localHostname := ""
	meshPort := s.cfg.Mesh.Port
	if s.node != nil && s.node.Identity() != nil {
		localKey = s.node.Identity().PublicKey
		localHostname = s.cfg.Node.Hostname
		if localHostname == "" {
			localHostname, _ = getHostname()
		}
	}

	data := struct {
		PageData
		Peers         []PeerInfo
		Grants        []GrantInfo
		Revocations   []RevocationInfo
		LocalKey      string
		LocalMeshIP   string
		LocalHostname string
		MeshPort      int
		PeerCount     int
	}{
		PageData:      PageData{Title: "Peers", ActivePage: "peers"},
		Peers:         peers,
		Grants:        grants,
		Revocations:   revocations,
		LocalKey:      localKey,
		LocalMeshIP:   localMeshIP,
		LocalHostname: localHostname,
		MeshPort:      meshPort,
		PeerCount:     len(peers),
	}
	s.renderPage(w, "peers.html", data)
}

// --- 3D Topology ---

func (s *Server) handleTopologyPage(w http.ResponseWriter, r *http.Request) {
	data := struct {
		PageData
	}{
		PageData: PageData{Title: "3D Topology", ActivePage: "topology"},
	}
	s.renderPage(w, "topology.html", data)
}

func (s *Server) getPeerCapabilities(peerID string) []string {
	if s.authEngine == nil {
		return nil
	}
	g := s.authEngine.GetGrant(peerID)
	if g == nil {
		return nil
	}
	caps := make([]string, 0, len(g.Capabilities))
	for cap := range g.Capabilities {
		caps = append(caps, cap)
	}
	return caps
}

// --- SSE Handler ---

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Register with SSE hub
	ch := s.sseHub.Register()
	defer s.sseHub.Unregister(ch)

	// Send initial data
	initialData := s.buildDashboardJSON()
	if initialData != "" {
		fmt.Fprintf(w, "event: metrics\ndata: %s\n\n", initialData)
		flusher.Flush()
	}

	// Keepalive ticker
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Event, event.Data)
			flusher.Flush()
		case <-ticker.C:
			// Send keepalive comment
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// --- Data building helpers ---

// buildNodeCards converts monitor store metrics into display-ready card data.
func (s *Server) buildNodeCards() []NodeCardData {
	if s.monitorStore == nil {
		return nil
	}

	allLatest := s.monitorStore.AllLatest()
	cards := make([]NodeCardData, 0, len(allLatest))

	for nodeID, m := range allLatest {
		card := NodeCardData{
			NodeID:    nodeID,
			ShortID:   shortIDDisplay(nodeID),
			Hostname:  m.Hostname,
			CPUUsage:  m.CPU.UsagePercent,
			CoreCount: m.CPU.CoreCount,
			PerCore:   m.CPU.PerCore,
			Load1:     m.LoadAvg.Load1,
			Load5:     m.LoadAvg.Load5,
			Load15:    m.LoadAvg.Load15,
			Uptime:    m.Uptime,
		}

		if m.Memory.Total > 0 {
			card.MemTotal = m.Memory.Total
			card.MemUsed = m.Memory.Used
			card.MemUsage = float64(m.Memory.Used) / float64(m.Memory.Total) * 100
		}

		if len(m.Disk) > 0 {
			card.HasDisk = true
			// Use root partition if available, else first
			for _, d := range m.Disk {
				if d.MountPoint == "/" || card.DiskUsage == 0 {
					if d.Total > 0 {
						card.DiskUsage = float64(d.Used) / float64(d.Total) * 100
						if d.MountPoint == "/" {
							break
						}
					}
				}
			}
		}

		cards = append(cards, card)
	}

	return cards
}

// buildDashboardJSON creates the JSON payload for SSE metric updates.
func (s *Server) buildDashboardJSON() string {
	cards := s.buildNodeCards()
	if len(cards) == 0 {
		return ""
	}

	type jsonNode struct {
		NodeID    string  `json:"node_id"`
		Hostname  string  `json:"hostname"`
		CPUUsage  float64 `json:"cpu_usage"`
		MemUsed   uint64  `json:"mem_used"`
		MemTotal  uint64  `json:"mem_total"`
		Load1     float64 `json:"load1"`
		Load5     float64 `json:"load5"`
		Load15    float64 `json:"load15"`
		Uptime    int64   `json:"uptime_seconds"`
		CoreCount int     `json:"core_count"`
	}

	type dashboardData struct {
		Nodes          []jsonNode `json:"nodes"`
		NodeCount      int        `json:"node_count"`
		ActiveSessions int        `json:"active_sessions"`
	}

	data := dashboardData{
		Nodes:          make([]jsonNode, len(cards)),
		NodeCount:      len(cards),
		ActiveSessions: s.activeSessionCount(),
	}

	for i, c := range cards {
		data.Nodes[i] = jsonNode{
			NodeID:    c.NodeID,
			Hostname:  c.Hostname,
			CPUUsage:  c.CPUUsage,
			MemUsed:   c.MemUsed,
			MemTotal:  c.MemTotal,
			Load1:     c.Load1,
			Load5:     c.Load5,
			Load15:    c.Load15,
			Uptime:    c.Uptime,
			CoreCount: c.CoreCount,
		}
	}

	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(b)
}

// NodeDetailData holds display-ready metrics for the node detail page.
type NodeDetailData struct {
	NodeID    string
	ShortID   string
	Hostname  string
	CPUUsage  float64
	CoreCount int
	PerCore   []float64
	MemUsage  float64
	MemUsed   uint64
	MemTotal  uint64
	SwapTotal uint64
	SwapUsed  uint64
	Load1     float64
	Load5     float64
	Load15    float64
	Uptime    int64
	BootTime  string
	Disks     []diskDetail
	Networks  []networkDetail
}

type diskDetail struct {
	Device       string
	MountPoint   string
	FSType       string
	Total        uint64
	Used         uint64
	Free         uint64
	UsagePercent float64
}

type networkDetail struct {
	Name      string
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	RxErrors  uint64
	TxErrors  uint64
	SpeedMbps int
}

// buildNodeDetail converts monitor.Metrics into display-ready detail data.
func buildNodeDetail(m *monitor.Metrics) NodeDetailData {
	d := NodeDetailData{
		NodeID:    m.NodeID,
		ShortID:   shortIDDisplay(m.NodeID),
		Hostname:  m.Hostname,
		CPUUsage:  m.CPU.UsagePercent,
		CoreCount: m.CPU.CoreCount,
		PerCore:   m.CPU.PerCore,
		Load1:     m.LoadAvg.Load1,
		Load5:     m.LoadAvg.Load5,
		Load15:    m.LoadAvg.Load15,
		Uptime:    m.Uptime,
		BootTime:  m.Timestamp.Add(-time.Duration(m.Uptime) * time.Second).Format("2006-01-02 15:04"),
	}

	if m.Memory.Total > 0 {
		d.MemTotal = m.Memory.Total
		d.MemUsed = m.Memory.Used
		d.MemUsage = float64(m.Memory.Used) / float64(m.Memory.Total) * 100
		d.SwapTotal = m.Memory.SwapTotal
		d.SwapUsed = m.Memory.SwapUsed
	}

	for _, disk := range m.Disk {
		dd := diskDetail{
			Device:     disk.Device,
			MountPoint: disk.MountPoint,
			FSType:     disk.FSType,
			Total:      disk.Total,
			Used:       disk.Used,
			Free:       disk.Free,
		}
		if disk.Total > 0 {
			dd.UsagePercent = float64(disk.Used) / float64(disk.Total) * 100
		}
		d.Disks = append(d.Disks, dd)
	}

	for _, net := range m.Network {
		d.Networks = append(d.Networks, networkDetail{
			Name:      net.Name,
			RxBytes:   net.RxBytes,
			TxBytes:   net.TxBytes,
			RxPackets: net.RxPackets,
			TxPackets: net.TxPackets,
			RxErrors:  net.RxErrors,
			TxErrors:  net.TxErrors,
			SpeedMbps: net.SpeedMbps,
		})
	}

	return d
}

// activeSessionCount returns the number of active WebSSH sessions.
func (s *Server) activeSessionCount() int {
	if s.sshHub != nil {
		return s.sshHub.SessionCount()
	}
	return 0
}

// serviceStatusDisplay is a display-ready service status.
type serviceStatusDisplay struct {
	Name        string
	ActiveState string
	SubState    string
	Description string
}

// --- File helpers ---

type fileEntry struct {
	Name    string
	Size    int64
	ModTime time.Time
}

func saveUploadedFile(src interface{ Read([]byte) (int, error) }, filename, dir string) (string, error) {
	// Sanitize filename
	safeName := sanitizeFilename(filename)
	if safeName == "" {
		return "", fmt.Errorf("invalid filename")
	}

	// Ensure dir exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create dir: %w", err)
	}

	path := filepath.Join(dir, safeName)
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, 64*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return "", fmt.Errorf("write file: %w", werr)
			}
		}
		if err != nil {
			break
		}
	}
	return path, nil
}

func listUploadFiles() []fileEntry {
	dir := "/tmp/meshdesk-uploads/"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var result []fileEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, fileEntry{
			Name:    entry.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	return result
}

// --- Proxy Nodes ---

// proxyNodesData holds the template data for the proxy nodes page.
type proxyNodesData struct {
	PageData
	XrayAvailable bool
	BinaryHint    string
}

// handleProxyNodesPage renders the proxy node management page.
// It shows the xray-core status bar, deployed inbound list, and the
// create-new-inbound form when xray is configured. When xrayManager
// is nil, it renders an informational "not configured" panel.
func (s *Server) handleProxyNodesPage(w http.ResponseWriter, r *http.Request) {
	xrayAvailable := s.xrayManager != nil
	binaryHint := "not configured"
	if xrayAvailable {
		binaryHint = s.xrayManager.BinaryPath()
	}

	data := proxyNodesData{
		PageData:      PageData{Title: "Proxy Nodes", ActivePage: "proxy_nodes"},
		XrayAvailable: xrayAvailable,
		BinaryHint:    binaryHint,
	}
	s.renderPage(w, "proxy_nodes.html", data)
}

// --- Configuration Management Page ---

// handleConfigPage renders the full configuration management page.
// This page uses client-side JS (config.js) to fetch config data from
// /api/config and render all 11 config sections with tiered field display:
// read-only fields shown greyed, masked fields shown as dots, step-up fields
// behind re-auth, and normal fields editable. Live validation and hot-reload
// feedback indicators are handled via PATCH /api/config and POST /api/config/reload.
func (s *Server) handleConfigPage(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:      "Configuration",
		ActivePage: "config",
	}
	s.renderPage(w, "config.html", data)
}

// --- Misc helpers ---

func getHostname() (string, error) {
	return os.Hostname()
}

func sanitizeFilename(name string) string {
	// Strip path separators
	for _, c := range []string{"/", "\\", ".."} {
		name = strings.ReplaceAll(name, c, "_")
	}
	return name
}

// bcryptCompare checks a bcrypt hash against a plaintext password.
func bcryptCompare(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
