package web

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// =============================================================================
// TOTP 2FA Handlers
// =============================================================================

// totpEnrollResponse is the JSON response from the enrollment endpoint.
type totpEnrollResponse struct {
	Secret    string   `json:"secret"`
	QRURL     string   `json:"qr_url"`
	Algorithm string   `json:"algorithm"`
	Digits    int      `json:"digits"`
	Period    int      `json:"period"`
	Recovery  []string `json:"recovery"`
}

// handle2FAEnroll handles POST /api/2fa/enroll.
// Requires a valid session. The user must not already be enrolled.
// Returns the TOTP secret, QR provisioning URI, and recovery codes.
func (s *Server) handle2FAEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, ok := r.Context().Value(ctxUsernameKey{}).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check for existing enrollment
	if s.totpStore.IsEnrolled(username) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, `{"error":"TOTP already enrolled. Disable first to re-enroll."}`)
		return
	}

	state, err := s.totpStore.Enroll(username)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}

	issuer := s.cfg.Auth.TOTPIssuer
	if issuer == "" {
		issuer = "MeshDesk"
	}

	resp := totpEnrollResponse{
		Secret:    state.Secret,
		QRURL:     QRURL(issuer, username, state.Secret),
		Algorithm: "SHA256",
		Digits:    totpDigits,
		Period:    totpPeriod,
		Recovery:  state.RecoveryCodes,
	}

	// Generate security alert
	s.alertStore.Add(SecurityAlert{
		Type:        "totp_enrollment",
		Username:    username,
		SourceIP:    r.RemoteAddr,
		Description: "TOTP 2FA enrollment completed",
		Severity:    AlertInfo,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handle2FAVerify handles POST /api/2fa/verify.
// This endpoint consumes the 2FA-pending cookie (set during login when
// the user has TOTP enrolled) and verifies the submitted TOTP code.
// On success, it promotes the pending session to a full session.
func (s *Server) handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Look up the 2FA-pending cookie
	pendingCookie, err := r.Cookie(twoFactorPendingCookie)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"No 2FA pending session. Please log in again."}`)
		return
	}

	pending := s.sessions.GetPending(pendingCookie.Value)
	if pending == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"2FA session expired. Please log in again."}`)
		return
	}

	username := pending.Username
	code := r.FormValue("code")
	recovery := r.FormValue("recovery")

	// Check lockout
	if s.totpStore.IsLocked(username) {
		s.alertStore.Add(SecurityAlert{
			Type:        "totp_locked",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: "TOTP attempt while account locked",
			Severity:    AlertCritical,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"error":"Account locked. Try again in 30 seconds."}`)
		return
	}

	// Try TOTP code first
	if code != "" {
		if s.totpStore.ValidateCode(username, code) {
			// Success — promote to full session
			s.sessions.ClearPending(pendingCookie.Value)
			s.totpStore.ClearFailedAttempts(username)
			session := s.sessions.Create(username)

			http.SetCookie(w, &http.Cookie{
				Name:     "meshdesk_session",
				Value:    session.Token,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   86400,
				SameSite: http.SameSiteStrictMode,
			})
			// Clear the 2FA pending cookie
			http.SetCookie(w, &http.Cookie{
				Name:     twoFactorPendingCookie,
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				MaxAge:   -1,
			})

			if isHTMXRequest(r) {
				w.Header().Set("HX-Redirect", "/")
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Failed TOTP attempt
		locked := s.totpStore.RecordFailedAttempt(username)
		s.alertStore.Add(SecurityAlert{
			Type:        "totp_failure",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: "failed TOTP verification attempt",
			Severity:    AlertWarning,
		})

		if locked {
			s.alertStore.Add(SecurityAlert{
				Type:        "totp_lockout",
				Username:    username,
				SourceIP:    r.RemoteAddr,
				Description: "account locked after 5 failed TOTP attempts",
				Severity:    AlertCritical,
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"error":"Account locked after 5 failed attempts. Try again in 30 seconds."}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"Invalid TOTP code."}`)
		return
	}

	// Try recovery code
	if recovery != "" {
		if s.totpStore.ConsumeRecoveryCode(username, recovery) {
			// Recovery code accepted — promote to full session
			s.sessions.ClearPending(pendingCookie.Value)
			s.totpStore.ClearFailedAttempts(username)
			session := s.sessions.Create(username)

			s.alertStore.Add(SecurityAlert{
				Type:        "recovery_code_used",
				Username:    username,
				SourceIP:    r.RemoteAddr,
				Description: "recovery code used to bypass TOTP",
				Severity:    AlertInfo,
			})

			http.SetCookie(w, &http.Cookie{
				Name:     "meshdesk_session",
				Value:    session.Token,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   86400,
				SameSite: http.SameSiteStrictMode,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     twoFactorPendingCookie,
				Value:    "",
				Path:     "/",
				HttpOnly: true,
				MaxAge:   -1,
			})

			if isHTMXRequest(r) {
				w.Header().Set("HX-Redirect", "/")
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Failed recovery code
		s.alertStore.Add(SecurityAlert{
			Type:        "recovery_failure",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: "invalid recovery code attempt",
			Severity:    AlertWarning,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"Invalid recovery code."}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `{"error":"Provide either 'code' or 'recovery' field."}`)
}

// handle2FADisable handles POST /api/2fa/disable.
// Removes TOTP enrollment for the current user.
func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, ok := r.Context().Value(ctxUsernameKey{}).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !s.totpStore.Exists(username) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"TOTP is not enrolled."}`)
		return
	}

	s.totpStore.Disable(username)

	// Revoke all step-up tokens for this user's session
	if token, ok := r.Context().Value(ctxSessionTokenKey{}).(string); ok && token != "" {
		s.stepUpStore.Revoke(token)
	}

	s.alertStore.Add(SecurityAlert{
		Type:        "totp_disabled",
		Username:    username,
		SourceIP:    r.RemoteAddr,
		Description: "TOTP 2FA disabled",
		Severity:    AlertWarning,
	})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"disabled"}`)
}

// handle2FAStatus handles GET /api/2fa/status.
// Returns whether TOTP is enrolled for the current user.
func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, ok := r.Context().Value(ctxUsernameKey{}).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	enrolled := s.totpStore.IsEnrolled(username)
	locked := s.totpStore.IsLocked(username)

	resp := map[string]interface{}{
		"enrolled": enrolled,
		"locked":   locked,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// TOTP Key Rotation Handlers
// =============================================================================

// handle2FARotate handles POST /api/2fa/rotate.
// Initiates TOTP key rotation: generates a new secret (old remains valid
// until confirm/cancel), returns the new QR provisioning URL, secret, and
// fresh recovery codes for the user to enroll in their authenticator app.
func (s *Server) handle2FARotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, ok := r.Context().Value(ctxUsernameKey{}).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	result, err := s.totpStore.InitiateRotation(username)
	if err != nil {
		s.alertStore.Add(SecurityAlert{
			Type:        "totp_rotation_initiated",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: fmt.Sprintf("TOTP rotation initiation failed: %s", err.Error()),
			Severity:    AlertWarning,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}

	issuer := s.cfg.Auth.TOTPIssuer
	if issuer == "" {
		issuer = "MeshDesk"
	}

	resp := totpEnrollResponse{
		Secret:    result.Secret,
		QRURL:     QRURL(issuer, username, result.Secret),
		Algorithm: "SHA256",
		Digits:    totpDigits,
		Period:    totpPeriod,
		Recovery:  result.RecoveryCodes,
	}

	s.alertStore.Add(SecurityAlert{
		Type:        "totp_rotation_initiated",
		Username:    username,
		SourceIP:    r.RemoteAddr,
		Description: "TOTP key rotation initiated — new secret generated, awaiting confirmation",
		Severity:    AlertWarning,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handle2FARotateConfirm handles POST /api/2fa/rotate/confirm.
// Reads `code` from the form body and calls ConfirmRotation. On success,
// the old secret is discarded and the new secret becomes primary.
func (s *Server) handle2FARotateConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, ok := r.Context().Value(ctxUsernameKey{}).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"Missing 'code' field."}`)
		return
	}

	if err := s.totpStore.ConfirmRotation(username, code); err != nil {
		s.alertStore.Add(SecurityAlert{
			Type:        "totp_rotation_confirmed",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: fmt.Sprintf("TOTP rotation confirmation failed: %s", err.Error()),
			Severity:    AlertWarning,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}

	s.alertStore.Add(SecurityAlert{
		Type:        "totp_rotation_confirmed",
		Username:    username,
		SourceIP:    r.RemoteAddr,
		Description: "TOTP key rotation confirmed — new secret activated, old secret discarded",
		Severity:    AlertInfo,
	})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"rotated"}`)
}

// handle2FARotateCancel handles POST /api/2fa/rotate/cancel.
// Cancels an in-progress rotation, restoring the old secret as primary.
func (s *Server) handle2FARotateCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, ok := r.Context().Value(ctxUsernameKey{}).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := s.totpStore.CancelRotation(username); err != nil {
		s.alertStore.Add(SecurityAlert{
			Type:        "totp_rotation_cancelled",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: fmt.Sprintf("TOTP rotation cancel failed: %s", err.Error()),
			Severity:    AlertWarning,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}

	s.alertStore.Add(SecurityAlert{
		Type:        "totp_rotation_cancelled",
		Username:    username,
		SourceIP:    r.RemoteAddr,
		Description: "TOTP key rotation cancelled — old secret restored",
		Severity:    AlertInfo,
	})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"cancelled"}`)
}

// =============================================================================
// Step-Up Auth Handlers
// =============================================================================

// handleStepUpChallenge handles GET /api/stepup/challenge?op=<operation>.
// Renders the step-up challenge page (password re-entry form).
func (s *Server) handleStepUpChallenge(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Query().Get("op")
	if op == "" {
		op = "unknown"
	}

	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><head><title>Step-Up Authentication</title>
<link rel="stylesheet" href="/static/css/pico.min.css">
<link rel="stylesheet" href="/static/css/app.css">
</head><body><main class="container">
<h2>Step-Up Authentication Required</h2>
<p>You are about to perform a sensitive operation: <strong>%s</strong>.</p>
<p>Please re-enter your password to continue.</p>
<form method="POST" action="/api/stepup/verify?op=%s">
<input type="hidden" name="op" value="%s">
<label>Password<input type="password" name="password" required autofocus></label>
<button type="submit">Verify</button>
</form>
<p><a href="/">Cancel</a></p>
</main></body></html>`, op, op, op)
		return
	}
}

// handleStepUpVerify handles POST /api/stepup/verify?op=<operation>.
// Validates the password and grants a step-up token scoped to the operation.
func (s *Server) handleStepUpVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	op := r.URL.Query().Get("op")
	if op == "" {
		op = r.FormValue("op")
	}
	if op == "" {
		http.Error(w, "Missing 'op' parameter", http.StatusBadRequest)
		return
	}

	username, ok := r.Context().Value(ctxUsernameKey{}).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	password := r.FormValue("password")

	if !s.authenticate(username, password) {
		s.alertStore.Add(SecurityAlert{
			Type:        "stepup_failure",
			Username:    username,
			SourceIP:    r.RemoteAddr,
			Description: fmt.Sprintf("failed step-up auth for operation: %s", op),
			Severity:    AlertWarning,
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `<!doctype html><html><head><title>Step-Up Failed</title>
<link rel="stylesheet" href="/static/css/pico.min.css">
<link rel="stylesheet" href="/static/css/app.css">
</head><body><main class="container">
<h2>Step-Up Authentication Failed</h2>
<p>Incorrect password. Please try again.</p>
<form method="POST" action="/api/stepup/verify?op=%s">
<input type="hidden" name="op" value="%s">
<label>Password<input type="password" name="password" required autofocus></label>
<button type="submit">Retry</button>
</form>
<p><a href="/">Cancel</a></p>
</main></body></html>`, op, op)
		return
	}

	// Password verified — grant step-up token
	sessionToken, _ := r.Context().Value(ctxSessionTokenKey{}).(string)
	if sessionToken == "" {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	s.stepUpStore.Grant(sessionToken, []string{op})

	if isHTMXRequest(r) {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// =============================================================================
// Security Alerts Handlers
// =============================================================================

// handleAlertsList handles GET /api/alerts.
// Returns all security alerts as JSON.
func (s *Server) handleAlertsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	alerts := s.alertStore.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

// handleAlertsDismiss handles POST /api/alerts/dismiss.
// Marks all alerts as dismissed (bulk acknowledge).
func (s *Server) handleAlertsDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.alertStore.DismissAll()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"dismissed"}`)
}
