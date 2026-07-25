package auth

import (
	"context"
	"net/http"
)

// ctxPeerIDKey is the context key for the authenticated peer ID (hex
// WireGuard public key). It is set by upstream middleware (e.g. an
// mTLS / mesh-identity middleware) and read by RequireCapability.
//
// We use an unexported struct type as the key to avoid key collisions
// with other packages, following the pattern established by
// web.ctxUsernameKey.
type ctxPeerIDKey struct{}

// PeerIDFromContext extracts the authenticated peer ID from the request
// context. Returns the peer ID and true if present, or "" and false if
// the request was not authenticated as a mesh peer.
//
// This is the canonical way for downstream handlers and middleware to
// retrieve the calling peer's identity. When the request originates from
// the local web UI (session-based auth) rather than a mesh peer, the
// peer ID will be absent — callers should handle that case explicitly.
func PeerIDFromContext(ctx context.Context) (string, bool) {
	peerID, ok := ctx.Value(ctxPeerIDKey{}).(string)
	if !ok || peerID == "" {
		return "", false
	}
	return peerID, true
}

// WithPeerID returns a new context with the given peer ID stored under
// ctxPeerIDKey. It is intended to be called by upstream authentication
// middleware (the layer that authenticates mesh peers) before the
// request reaches capability-gated routes.
//
// Example:
//
//	ctx = auth.WithPeerID(ctx, peerID)
//	r = r.WithContext(ctx)
//	mux.ServeHTTP(w, r)
func WithPeerID(ctx context.Context, peerID string) context.Context {
	return context.WithValue(ctx, ctxPeerIDKey{}, peerID)
}

// Auther is the minimal interface that RequireCapability needs from the
// capability engine. *CapabilityEngine satisfies this implicitly.
// Defining a narrow interface here keeps the middleware testable with a
// stub and decoupled from the full engine type.
type Auther interface {
	// Authorize checks whether sourcePeer is authorized for the given
	// capability. The resource parameter is empty for capabilities that
	// don't have a resource scope (the common case for HTTP middleware).
	Authorize(sourcePeer, capability, resource string) AuthResult
}

// RequireCapability returns an HTTP middleware that enforces a capability
// check on every incoming request. It extracts the authenticated peer ID
// from the request context (set by upstream mesh-auth middleware via
// WithPeerID) and delegates to the provided Auther.
//
// If the peer ID is not in the context (unauthenticated request, or a
// local web-UI session without mesh identity), the middleware returns
// 401 Unauthorized.
//
// If the peer is authenticated but lacks the requested capability, the
// middleware returns 403 Forbidden.
//
// If the Auther is nil, the middleware returns 500 Internal Server Error
// on every request — this is a misconfiguration (production code should
// always wire the capability engine). Use a test double if you need to
// test routes without auth.
//
// Usage:
//
//	mux.Handle("/api/ssh/proxy",
//	    auth.RequireCapability(engine, auth.CapSSHProxy)(sshHandler))
//
// The resource parameter is left empty — this middleware is for coarse
// capability gating. Fine-grained resource scoping (e.g. specific service
// names or file paths) should be checked in the handler itself via
// engine.Authorize.
func RequireCapability(engine Auther, cap string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if engine == nil {
				http.Error(w, "auth engine not configured", http.StatusInternalServerError)
				return
			}

			peerID, ok := PeerIDFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized: peer identity not found", http.StatusUnauthorized)
				return
			}

			result := engine.Authorize(peerID, cap, "")
			if !result.Allowed {
				http.Error(w, "forbidden: "+cap+" capability denied ("+result.Reason+")", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
