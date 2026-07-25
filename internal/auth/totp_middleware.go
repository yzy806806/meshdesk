// Package auth — TOTP 2FA middleware interface.
//
// This file defines the TOTPVerifier contract and an HTTP middleware
// factory so that packages outside of internal/web (e.g., proxy
// management, future gRPC handlers) can depend on auth without
// coupling to the web package's full TOTP implementation.
//
// The internal/web package's TOTPStore satisfies TOTPVerifier
// implicitly (it already implements IsEnrolled, ValidateCode, and
// IsLocked). No changes to the web package are required — the
// caller wires the verifier and username extractor at construction
// time.
package auth

import (
	"encoding/json"
	"net/http"
)

// TOTPVerifier is the contract for TOTP 2FA state queries.
//
// Implementations manage enrollment lifecycle, code validation, and
// lockout internally. Callers (HTTP middleware, gRPC interceptors,
// proxy management endpoints) depend on this interface rather than
// a concrete store so the auth package stays free of the web layer.
//
// The web package's *TOTPStore implicitly satisfies this interface.
type TOTPVerifier interface {
	// IsEnrolled reports whether the user has completed TOTP
	// enrollment and is subject to 2FA at login.
	IsEnrolled(username string) bool

	// ValidateCode checks a TOTP code against the user's secret
	// with ±skew tolerance. On success for PENDING users, the
	// implementation completes enrollment (PENDING → VERIFIED).
	ValidateCode(username, code string) bool

	// IsLocked reports whether the user's account is temporarily
	// locked due to too many failed TOTP attempts.
	IsLocked(username string) bool
}

// TOTPAlertFunc is invoked when 2FA enforcement blocks a request.
// The caller wires this to their alert system (e.g., the web
// dashboard's AlertStore). It is called synchronously within the
// middleware, so implementations must be fast and MUST NOT call
// back into the verifier (deadlock risk).
type TOTPAlertFunc func(username, sourceIP, path string)

// UserExtractor pulls the authenticated username from an HTTP
// request. The caller wires this to their session mechanism (cookie,
// bearer token, context value). Returns (username, true) when the
// user is known; ("", false) when the request is unauthenticated
// and should pass through (public assets, login page).
type UserExtractor func(r *http.Request) (username string, ok bool)

// NewTOTPMiddleware returns an HTTP middleware that enforces TOTP
// 2FA enrollment.
//
// When require2FA is false the middleware is a no-op pass-through.
// When require2FA is true it checks every request:
//
//  1. If the path is in exemptPaths, the request passes through
//     without a 2FA check (e.g. /api/2fa/enroll, /login).
//  2. If getUser returns ("", false) the request passes through
//     (unauthenticated / public route).
//  3. If the user is not enrolled in 2FA, the middleware blocks
//     with HTTP 403 and calls onDeny (if non-nil).
//  4. Otherwise the request proceeds to the next handler.
//
// The returned function has signature func(http.Handler) http.Handler
// so it can be used directly with mux.Use() or wrapped around a handler.
func NewTOTPMiddleware(
	verifier TOTPVerifier,
	require2FA bool,
	exemptPaths []string,
	getUser UserExtractor,
	onDeny TOTPAlertFunc,
) func(http.Handler) http.Handler {
	// Build a fast lookup set for exempt paths.
	exempt := make(map[string]struct{}, len(exemptPaths))
	for _, p := range exemptPaths {
		exempt[p] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fast path: 2FA not required.
			if !require2FA {
				next.ServeHTTP(w, r)
				return
			}

			path := r.URL.Path

			if _, skip := exempt[path]; skip {
				next.ServeHTTP(w, r)
				return
			}

			username, ok := getUser(r)
			if !ok || username == "" {
				// Unauthenticated — pass through (public route).
				next.ServeHTTP(w, r)
				return
			}

			if !verifier.IsEnrolled(username) {
				if onDeny != nil {
					onDeny(username, r.RemoteAddr, path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "2FA enrollment required. Please complete TOTP enrollment.",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
