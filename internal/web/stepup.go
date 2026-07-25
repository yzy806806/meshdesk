package web

import (
	"sync"
	"time"
)

// Step-up auth constants.
const (
	defaultStepUpTimeout = 5 * time.Minute
)

// Sensitive operations that require step-up authentication.
const (
	OpTerminal       = "terminal"
	OpServiceManage  = "service_manage"
	OpFileUpload     = "file_upload"
	OpSettings       = "settings"
)

// stepUpToken represents a per-session elevated-privilege token.
type stepUpToken struct {
	GrantedAt  time.Time
	ExpiresAt  time.Time
	Operations []string
}

// StepUpStore manages step-up authentication tokens keyed by session token.
// Tokens are per-session, expire after 5 minutes of inactivity, and are
// scoped to specific operations.
type StepUpStore struct {
	mu     sync.Mutex
	tokens map[string]*stepUpToken
}

// NewStepUpStore creates a new step-up auth token store.
func NewStepUpStore() *StepUpStore {
	return &StepUpStore{tokens: make(map[string]*stepUpToken)}
}

// Grant creates a step-up token for the given session, scoped to the
// specified operations. The token expires after defaultStepUpTimeout.
func (s *StepUpStore) Grant(sessionToken string, operations []string) *stepUpToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := &stepUpToken{
		GrantedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(defaultStepUpTimeout),
		Operations: operations,
	}
	s.tokens[sessionToken] = tok
	return tok
}

// Validate checks whether a valid step-up token exists for the session
// and is scoped to the requested operation. Expired tokens are purged.
func (s *StepUpStore) Validate(sessionToken, operation string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[sessionToken]
	if !ok {
		return false
	}
	if time.Now().After(tok.ExpiresAt) {
		delete(s.tokens, sessionToken)
		return false
	}
	for _, op := range tok.Operations {
		if op == operation {
			return true
		}
	}
	return false
}

// Revoke removes a step-up token (e.g., on logout or password change).
func (s *StepUpStore) Revoke(sessionToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, sessionToken)
}

// RevokeAll clears all step-up tokens (e.g., on server reset).
func (s *StepUpStore) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]*stepUpToken)
}
