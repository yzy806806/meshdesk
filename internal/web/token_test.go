package web

import (
	"regexp"
	"testing"
)

func TestGenerateToken_Format(t *testing.T) {
	token := generateToken()

	// Token must be 64 hex characters from crypto/rand
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64", len(token))
	}

	matched, err := regexp.MatchString("^[0-9a-f]{64}$", token)
	if err != nil {
		t.Fatalf("regexp error: %v", err)
	}
	if !matched {
		t.Errorf("token %q is not 64 lowercase hex chars", token)
	}
}

func TestGenerateToken_Uniqueness(t *testing.T) {
	// Generate multiple tokens and ensure they are all unique
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token := generateToken()
		if seen[token] {
			t.Fatalf("duplicate token generated at iteration %d: %s", i, token)
		}
		seen[token] = true
	}
}
