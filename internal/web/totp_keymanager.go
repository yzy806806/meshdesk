package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

// Domain separation constants for HKDF key derivation (spec §2.2).
const (
	hkdfSalt     = "meshdesk-totp-encryption-v1"
	hkdfInfo     = "per-user-key"
	masterSecretSize = 32 // 256-bit
	gcmNonceSize     = 12 // standard GCM nonce size
)

// DefaultMasterSecretPath is the conventional location for the node-local
// TOTP master secret. The file is created with mode 0600 on first boot.
const DefaultMasterSecretPath = "/var/lib/meshdesk/totp.ms"

// TOTPKeyManager manages the encryption of per-user TOTP secrets.
// It is created once at server startup and injected into TOTPStore.
//
// The master secret is a 32-byte cryptographically random value generated
// at first boot and stored at a node-local path (default: /var/lib/meshdesk/totp.ms)
// with mode 0600. It is NEVER written to config.yaml.
//
// The encryption key is derived from the master secret via HKDF-SHA256
// with domain separation, and is held in-memory only — never persisted.
//
// Per-user TOTP secrets are encrypted with AES-256-GCM using the username
// as Additional Authenticated Data (AAD), binding ciphertext to the user
// to prevent cross-user ciphertext substitution.
type TOTPKeyManager struct {
	encKey []byte // derived at startup from master secret, never persisted
	path   string // master secret file path (for reference)
}

// NewTOTPKeyManager creates a TOTPKeyManager from a master secret file.
// If the file does not exist, a new 32-byte random master secret is generated
// and written with mode 0600. If masterSecretPath is empty, DefaultMasterSecretPath
// is used.
//
// If a legacy totp_secret value is provided (from config.yaml migration),
// it is used as the initial master secret when the file does not exist,
// and a deprecation warning is logged.
func NewTOTPKeyManager(masterSecretPath, legacyTOTPSecret string) (*TOTPKeyManager, error) {
	if masterSecretPath == "" {
		masterSecretPath = DefaultMasterSecretPath
	}

	var masterSecret []byte
	var migrated bool

	if _, err := os.Stat(masterSecretPath); err == nil {
		// File exists — load it.
		masterSecret, err = os.ReadFile(masterSecretPath)
		if err != nil {
			return nil, fmt.Errorf("read master secret: %w", err)
		}
		if len(masterSecret) != masterSecretSize {
			return nil, fmt.Errorf("master secret file %s: expected %d bytes, got %d",
				masterSecretPath, masterSecretSize, len(masterSecret))
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// File does not exist — generate a new master secret.
		masterSecret = make([]byte, masterSecretSize)
		if _, err := rand.Read(masterSecret); err != nil {
			return nil, fmt.Errorf("generate master secret: %w", err)
		}

		// If a legacy totp_secret is present in config, use it as the
		// initial master secret (one-time migration shim, spec §6.2).
		if legacyTOTPSecret != "" {
			decoded, err := decodeBase32(legacyTOTPSecret)
			if err == nil && len(decoded) >= masterSecretSize {
				copy(masterSecret, decoded[:masterSecretSize])
				migrated = true
			} else {
				// If the legacy secret isn't valid base32 or too short,
				// hash it to derive a stable 32-byte secret.
				h := sha256.Sum256([]byte(legacyTOTPSecret))
				copy(masterSecret, h[:])
				migrated = true
			}
		}

		// Write the master secret file with restrictive permissions.
		if err := os.MkdirAll(filepath.Dir(masterSecretPath), 0700); err != nil {
			return nil, fmt.Errorf("create master secret directory: %w", err)
		}
		if err := os.WriteFile(masterSecretPath, masterSecret, 0600); err != nil {
			return nil, fmt.Errorf("write master secret: %w", err)
		}
	} else {
		return nil, fmt.Errorf("stat master secret: %w", err)
	}

	if migrated {
		log.Printf("[WARNING] totp_secret in config.yaml is deprecated. "+
			"Migrated to node-local %s. Remove totp_secret from config.yaml "+
			"to silence this warning.", masterSecretPath)
	}

	// Derive the encryption key via HKDF-SHA256 with domain separation.
	encKey := make([]byte, 32) // AES-256 key size
	hkdfReader := hkdf.New(sha256.New, masterSecret, []byte(hkdfSalt), []byte(hkdfInfo))
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}

	// Zero the master secret from memory — only the derived key is needed.
	for i := range masterSecret {
		masterSecret[i] = 0
	}

	return &TOTPKeyManager{
		encKey: encKey,
		path:   masterSecretPath,
	}, nil
}

// NewTOTPKeyManagerFromBytes creates a TOTPKeyManager directly from a
// master secret byte slice. This is intended for testing — production
// code should use NewTOTPKeyManager which handles file I/O.
func NewTOTPKeyManagerFromBytes(masterSecret []byte) (*TOTPKeyManager, error) {
	if len(masterSecret) < masterSecretSize {
		return nil, fmt.Errorf("master secret too short: %d bytes, need %d",
			len(masterSecret), masterSecretSize)
	}

	encKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, masterSecret[:masterSecretSize],
		[]byte(hkdfSalt), []byte(hkdfInfo))
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}

	return &TOTPKeyManager{encKey: encKey}, nil
}

// Seal encrypts a base32 TOTP secret bound to a specific username.
// Returns the AEAD ciphertext as (nonce || data) suitable for storage.
// The username is used as Additional Authenticated Data (AAD) — it is not
// included in the ciphertext but is required for decryption.
func (km *TOTPKeyManager) Seal(username, plaintextSecret string) ([]byte, error) {
	block, err := aes.NewCipher(km.encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the ciphertext to the nonce: nonce || ciphertext || tag
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintextSecret), []byte(username))
	return ciphertext, nil
}

// Open decrypts a per-user TOTP secret.
// The aad (username) must match the value used during Seal.
// Returns the plaintext base32-encoded secret.
func (km *TOTPKeyManager) Open(username string, ciphertext []byte) (string, error) {
	if len(ciphertext) < gcmNonceSize {
		return "", fmt.Errorf("ciphertext too short: %d bytes", len(ciphertext))
	}

	block, err := aes.NewCipher(km.encKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := ciphertext[:gcmNonceSize]
	encrypted := ciphertext[gcmNonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encrypted, []byte(username))
	if err != nil {
		return "", fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	return string(plaintext), nil
}

// MasterSecretPath returns the filesystem path where the master secret
// is stored. Returns empty for key managers created from bytes (testing).
func (km *TOTPKeyManager) MasterSecretPath() string {
	return km.path
}

// decodeBase32 decodes a base32-encoded string (no padding) to bytes.
func decodeBase32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
