package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// testVerifier is a minimal TOTPVerifier stub for testing the middleware.
type testVerifier struct {
	enrolled map[string]bool
	locked   map[string]bool
}

func (v *testVerifier) IsEnrolled(username string) bool {
	return v.enrolled[username]
}

func (v *testVerifier) ValidateCode(username, code string) bool {
	return code == "123456"
}

func (v *testVerifier) IsLocked(username string) bool {
	return v.locked[username]
}

// staticUserExtractor returns a fixed username for every request.
func staticUserExtractor(username string) UserExtractor {
	return func(r *http.Request) (string, bool) {
		if username == "" {
			return "", false
		}
		return username, true
	}
}

func TestTOTPMiddleware_Require2FAFalse_PassThrough(t *testing.T) {
	v := &testVerifier{enrolled: map[string]bool{}}
	mw := NewTOTPMiddleware(v, false, nil, staticUserExtractor("admin"), nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestTOTPMiddleware_ExemptPath_PassThrough(t *testing.T) {
	v := &testVerifier{enrolled: map[string]bool{}}
	exemptPaths := []string{"/api/2fa/enroll", "/api/proxy/status"}
	mw := NewTOTPMiddleware(v, true, exemptPaths, staticUserExtractor("admin"), nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/proxy/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("exempt path should pass through: got %d", rec.Code)
	}
}

func TestTOTPMiddleware_EnrolledUser_PassThrough(t *testing.T) {
	v := &testVerifier{enrolled: map[string]bool{"admin": true}}
	mw := NewTOTPMiddleware(v, true, nil, staticUserExtractor("admin"), nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/proxy/manage", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("enrolled user should pass through: got %d", rec.Code)
	}
}

func TestTOTPMiddleware_UnenrolledUser_Blocked(t *testing.T) {
	v := &testVerifier{enrolled: map[string]bool{"admin": false}}
	var denied bool
	onDeny := func(username, sourceIP, path string) {
		denied = true
		if username != "admin" {
			t.Errorf("expected username 'admin', got '%s'", username)
		}
		if path != "/api/proxy/manage" {
			t.Errorf("expected path '/api/proxy/manage', got '%s'", path)
		}
	}
	mw := NewTOTPMiddleware(v, true, nil, staticUserExtractor("admin"), onDeny)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/proxy/manage", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("unenrolled user should get 403: got %d", rec.Code)
	}
	if !denied {
		t.Error("onDeny callback should have been invoked")
	}
	body := rec.Body.String()
	if body == "" {
		t.Error("response body should not be empty")
	}
}

func TestTOTPMiddleware_UnauthenticatedUser_PassThrough(t *testing.T) {
	v := &testVerifier{enrolled: map[string]bool{}}
	mw := NewTOTPMiddleware(v, true, nil, staticUserExtractor(""), nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("unauthenticated should pass through: got %d", rec.Code)
	}
}

func TestTOTPMiddleware_NilOnDeny_NoPanic(t *testing.T) {
	v := &testVerifier{enrolled: map[string]bool{"admin": false}}
	// nil onDeny callback — should not panic
	mw := NewTOTPMiddleware(v, true, nil, staticUserExtractor("admin"), nil)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/proxy/manage", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
