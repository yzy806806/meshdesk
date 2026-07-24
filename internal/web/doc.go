// Package web is the HTTP server integration layer for MeshDesk.
//
// It wires together the mesh, monitor, webssh, transfer, service, and auth
// subsystems into an HTTP server with Go templates + htmx + embedded assets
// (ARCHITECTURE.md Decision D). The server provides:
//
//   - Server-rendered dashboard with live metric updates via SSE
//   - WebSSH terminal via WebSocket (delegated to webssh.Handler)
//   - File transfer UI
//   - Service management UI
//   - Peer/capability management view
//   - Session-based auth middleware (bcrypt credentials from config)
package web
