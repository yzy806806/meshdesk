package web

import (
	"net/http"
	"strings"
)

// require2FAEnforcement is a middleware that enforces mandatory TOTP 2FA
// enrollment when cfg.Auth.Require2FA is true.
//
// When Require2FA is false (the default), this middleware is a no-op pass-through.
//
// When Require2FA is true, it checks whether the authenticated user has completed
// TOTP enrollment. If not, the request is rejected with 403 Forbidden and a JSON
// error indicating the user must enroll in 2FA. The only exceptions are:
//
//   - /api/proxy/status — proxy health monitoring must remain accessible even
//     when the admin hasn't completed 2FA enrollment, because monitoring tools
//     and the dashboard itself query this endpoint for health checks.
//   - /api/2fa/enroll — the user must be able to enroll in 2FA to satisfy the
//     requirement.
//   - /api/2fa/status — the user must be able to check their 2FA enrollment
//     status to know whether they need to enroll.
//   - /api/alerts — security alerts must remain visible so the admin can see
//     that 2FA enforcement is blocking access.
//
// This middleware runs AFTER authMiddleware (which validates the session),
// so the username is already in the request context when this runs.
//
// This middleware must NOT be applied to /login, /logout, /static/, or
// /ws/terminal — those are handled by authMiddleware's public route exemption
// or by their own middleware chains. The 2FA-pending cookie flow at
// /api/2fa/verify is also exempt because it runs before a full session exists.
func (s *Server) require2FAEnforcement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If Require2FA is not enabled, pass through.
		if !s.cfg.Auth.Require2FA {
			next.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path

		// Endpoints exempt from 2FA enforcement:
		// - /api/proxy/status: proxy health monitoring must remain accessible
		// - /api/2fa/enroll: user must be able to enroll
		// - /api/2fa/status: user must be able to check status
		// - /api/2fa/verify: runs before full session (2FA-pending cookie flow)
		// - /api/alerts: security alerts should remain visible
		// - /api/alerts/dismiss: managing alerts is still needed
		if path == "/api/proxy/status" ||
			path == "/api/2fa/enroll" ||
			path == "/api/2fa/status" ||
			path == "/api/2fa/verify" ||
			path == "/api/alerts" ||
			path == "/api/alerts/dismiss" {
			next.ServeHTTP(w, r)
			return
		}

		// Get the authenticated username from context (set by authMiddleware
		// or requireAuth).
		username, ok := r.Context().Value(ctxUsernameKey{}).(string)
		if !ok || username == "" {
			// No username in context — this can happen for public routes
			// (static assets, login page) that bypass authMiddleware.
			// Let them through; they don't expose sensitive data.
			next.ServeHTTP(w, r)
			return
		}

		// Check if the user has completed TOTP enrollment.
		if !s.totpStore.IsEnrolled(username) {
			// User has not enrolled in 2FA. Reject the request.
			// Generate a security alert for this enforcement action.
			s.alertStore.Add(SecurityAlert{
				Type:        "2fa_enforcement_block",
				Username:    username,
				SourceIP:    r.RemoteAddr,
				Description: "access blocked: 2FA enrollment required (Require2FA=true) for path: " + path,
				Severity:    AlertWarning,
			})

			if isHTMXRequest(r) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("HX-Redirect", "/api/2fa/enroll")
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// For API requests, return JSON error.
			if strings.HasPrefix(path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"2FA enrollment required. Please complete TOTP enrollment at /api/2fa/enroll."}`))
				return
			}

			// For page requests, redirect to the enrollment page.
			http.Redirect(w, r, "/api/2fa/enroll", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
