package webssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/ssh"
)

// generateTestHostKey generates an RSA key pair and returns the ssh.PublicKey.
func generateTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("new SSH public key: %v", err)
	}
	return pub
}

func TestKnownHostsStore_TOFU(t *testing.T) {
	store := NewKnownHostsStore()
	cb := store.HostKeyCallback()

	key1 := generateTestHostKey(t)
	key2 := generateTestHostKey(t) // different key

	// First connection — key is pinned, should succeed.
	err := cb("10.0.0.1:22", nil, key1)
	if err != nil {
		t.Fatalf("first connection should succeed: %v", err)
	}

	// Second connection with same key — should succeed.
	err = cb("10.0.0.1:22", nil, key1)
	if err != nil {
		t.Fatalf("second connection with same key should succeed: %v", err)
	}

	// Third connection with different key — should fail (MITM detected).
	err = cb("10.0.0.1:22", nil, key2)
	if err == nil {
		t.Fatal("connection with different key should fail")
	}
}

func TestKnownHostsStore_PinExplicitly(t *testing.T) {
	store := NewKnownHostsStore()
	key := generateTestHostKey(t)
	keyB64 := base64.StdEncoding.EncodeToString(key.Marshal())

	store.Pin("192.168.1.1", keyB64)

	if !store.IsPinned("192.168.1.1") {
		t.Fatal("key should be pinned after Pin()")
	}

	cb := store.HostKeyCallback()

	// Connection with the pinned key should succeed.
	err := cb("192.168.1.1:22", nil, key)
	if err != nil {
		t.Fatalf("connection with pinned key should succeed: %v", err)
	}

	// Connection with a different key should fail.
	key2 := generateTestHostKey(t)
	err = cb("192.168.1.1:22", nil, key2)
	if err == nil {
		t.Fatal("connection with different key should fail")
	}
}

func TestKnownHostsStore_DifferentHosts(t *testing.T) {
	store := NewKnownHostsStore()
	_ = store
}

// Helper to avoid unused linter — tests that different hosts are independent.
func TestKnownHostsStore_DifferentHostsIndependent(t *testing.T) {
	store := NewKnownHostsStore()
	cb := store.HostKeyCallback()

	key1 := generateTestHostKey(t)
	key2 := generateTestHostKey(t) // different key

	// First host — pin key1.
	err := cb("10.0.0.1:22", nil, key1)
	if err != nil {
		t.Fatalf("first host connection should succeed: %v", err)
	}

	// Second host — pin key2 (different key, different host — should be fine).
	err = cb("10.0.0.2:22", nil, key2)
	if err != nil {
		t.Fatalf("second host connection should succeed: %v", err)
	}
}

func TestKnownHostsStore_NormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"10.0.0.1:22", "10.0.0.1"},
		{"example.com:22", "example.com"},
		{"[::1]:22", "[::1]"},
		{"noport", "noport"},
	}

	for _, tt := range tests {
		got := normalizeHost(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNewSSHClient_DefaultUsesKnownHosts(t *testing.T) {
	// When hostKeyCallback is nil, the client should use a KnownHostsStore
	// (not InsecureIgnoreHostKey). We verify this by checking that the
	// callback is not the insecure one.
	client := NewSSHClient(&NetDialer{}, 0, nil)
	if client.hostKeyCallback == nil {
		t.Fatal("hostKeyCallback should not be nil")
	}
	// The callback should not be ssh.InsecureIgnoreHostKey — we can verify
	// by checking that it rejects a nil key (InsecureIgnoreHostKey never errors).
	// Generate a key and see if the callback accepts it on first connect.
	key := generateTestHostKey(t)
	err := client.hostKeyCallback("testhost:22", nil, key)
	if err != nil {
		t.Fatalf("first connection with TOFU should succeed: %v", err)
	}
	// A different key should be rejected.
	key2 := generateTestHostKey(t)
	err = client.hostKeyCallback("testhost:22", nil, key2)
	if err == nil {
		t.Fatal("TOFU should reject different key on second connection")
	}
}

// Ensure x509 import is used (for encoding purposes in future extensions).
var _ = x509.NewCertPool
