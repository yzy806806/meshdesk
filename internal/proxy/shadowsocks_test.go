package proxy

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

// TestDeriveSSKey verifies key derivation produces a 32-byte key.
func TestDeriveSSKey(t *testing.T) {
	key := deriveSSKey("test-password")
	if len(key) != chacha20poly1305.KeySize {
		t.Errorf("key length = %d, want %d", len(key), chacha20poly1305.KeySize)
	}

	// Same password should produce same key.
	key2 := deriveSSKey("test-password")
	if string(key) != string(key2) {
		t.Error("same password produced different keys")
	}

	// Different password should produce different key.
	key3 := deriveSSKey("different-password")
	if string(key) == string(key3) {
		t.Error("different passwords produced same key")
	}
}

// TestSSSessionHandshake verifies the SS AEAD handshake and data
// transfer works correctly between a client and server.
func TestSSSessionHandshake(t *testing.T) {
	password := "test-secret-password"
	masterKey := deriveSSKey(password)

	// Create a pipe to simulate the TCP connection.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Client side: send salt + encrypted target address + data.
	go func() {
		// Generate salt.
		salt := make([]byte, SaltSize)
		rand.Read(salt)
		clientConn.Write(salt)

		// Derive session subkey (same as server).
		subkey := make([]byte, chacha20poly1305.KeySize)
		hkdf.New(sha256.New, masterKey, salt, []byte("ss-session-v1")).Read(subkey)
		aead, _ := chacha20poly1305.New(subkey)

		// Build target address: domain "example.com:443"
		target := buildSSTarget("example.com", 443)
		testData := []byte("Hello, SS proxy!")

		// Encrypt and send: [AEAD(len(target+data))][AEAD(target+data)]
		// Actually SS sends target and data together in the first chunk.
		plaintext := append(target, testData...)
		writeSSFrame(clientConn, aead, plaintext)
	}()

	// Server side: read salt, create session, read target.
	serverConn.SetDeadline(time.Now().Add(5 * time.Second))
	session, err := newSSSession(serverConn, masterKey)
	if err != nil {
		t.Fatalf("newSSSession failed: %v", err)
	}
	defer session.Close()

	target, err := session.ReadTarget()
	if err != nil {
		t.Fatalf("ReadTarget failed: %v", err)
	}

	if target != "example.com:443" {
		t.Errorf("target = %q, want %q", target, "example.com:443")
	}

	// Read the remaining data.
	buf := make([]byte, 1024)
	n, err := session.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != "Hello, SS proxy!" {
		t.Errorf("data = %q, want %q", string(buf[:n]), "Hello, SS proxy!")
	}
}

// TestSSSessionIPv4Target verifies IPv4 address parsing.
func TestSSSessionIPv4Target(t *testing.T) {
	password := "test-ipv4"
	masterKey := deriveSSKey(password)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		salt := make([]byte, SaltSize)
		rand.Read(salt)
		clientConn.Write(salt)

		subkey := make([]byte, chacha20poly1305.KeySize)
		hkdf.New(sha256.New, masterKey, salt, []byte("ss-session-v1")).Read(subkey)
		aead, _ := chacha20poly1305.New(subkey)

		// IPv4 address: type 0x01 + 4 bytes IP + 2 bytes port.
		target := make([]byte, 1+4+2)
		target[0] = 0x01
		copy(target[1:5], net.ParseIP("93.184.216.34").To4())
		binary.BigEndian.PutUint16(target[5:7], 80)

		writeSSFrame(clientConn, aead, target)
	}()

	serverConn.SetDeadline(time.Now().Add(5 * time.Second))
	session, err := newSSSession(serverConn, masterKey)
	if err != nil {
		t.Fatalf("newSSSession failed: %v", err)
	}
	defer session.Close()

	target, err := session.ReadTarget()
	if err != nil {
		t.Fatalf("ReadTarget failed: %v", err)
	}

	if target != "93.184.216.34:80" {
		t.Errorf("target = %q, want %q", target, "93.184.216.34:80")
	}
}

// TestSSListenerCreate verifies that a listener can be created.
func TestSSListenerCreate(t *testing.T) {
	cfg := SSConfig{
		Password:  "test-password",
		Cipher:    CipherChaCha20IETFPoly1305,
		ListenAddr: "127.0.0.1:0", // random port
	}

	ln, err := NewSSListener(cfg)
	if err != nil {
		t.Fatalf("NewSSListener failed: %v", err)
	}
	defer ln.Close()

	if ln.Addr() == nil {
		t.Error("listener Addr is nil")
	}
}

// TestSSListenerRejectsEmptyPassword verifies validation.
func TestSSListenerRejectsEmptyPassword(t *testing.T) {
	cfg := SSConfig{
		Password:  "",
		ListenAddr: "127.0.0.1:0",
	}

	_, err := NewSSListener(cfg)
	if err == nil {
		t.Error("expected error for empty password")
	}
}

// TestSSListenerRejectsUnsupportedCipher verifies cipher validation.
func TestSSListenerRejectsUnsupportedCipher(t *testing.T) {
	cfg := SSConfig{
		Password:  "test",
		Cipher:    "aes-256-gcm",
		ListenAddr: "127.0.0.1:0",
	}

	_, err := NewSSListener(cfg)
	if err == nil {
		t.Error("expected error for unsupported cipher")
	}
}

// buildSSTarget builds a SS SOCKS5 target address for a domain.
// Format: [0x03] [1-byte domain length] [domain bytes] [2-byte port]
func buildSSTarget(domain string, port uint16) []byte {
	buf := make([]byte, 1+1+len(domain)+2)
	buf[0] = 0x03
	buf[1] = byte(len(domain))
	copy(buf[2:], []byte(domain))
	binary.BigEndian.PutUint16(buf[2+len(domain):], port)
	return buf
}

// writeSSFrame writes one SS AEAD frame to the connection.
// Frame format: [AEAD(2-byte length)][AEAD(payload)]
func writeSSFrame(w io.Writer, aead cipher.AEAD, plaintext []byte) error {
	// Nonce starts at 0, increments per AEAD operation.
	nonce := make([]byte, chacha20poly1305.NonceSize)

	// Encrypt length.
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(plaintext)))
	lenCipher := aead.Seal(nil, nonce, lenBytes, nil)
	w.Write(lenCipher)

	// Increment nonce.
	nonce[11]++

	// Encrypt payload.
	payloadCipher := aead.Seal(nil, nonce, plaintext, nil)
	w.Write(payloadCipher)
	return nil
}
