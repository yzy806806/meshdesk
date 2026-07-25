package web

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// persistedState is the JSON-serializable representation of totpState
// that gets encrypted and written to disk. It mirrors totpState but
// uses pointer types for optional time fields so zero values are
// omitted from JSON (smaller blobs, cleaner output).
type persistedState struct {
	Version            int    `json:"version"`
	EncryptedSecret    []byte `json:"encrypted_secret"`
	OldEncryptedSecret []byte `json:"old_encrypted_secret,omitempty"`
	RecoveryCodes      []string `json:"recovery_codes,omitempty"`
	State              int    `json:"state"`
	PendingSince       *time.Time `json:"pending_since,omitempty"`
	FailedAttempts     int    `json:"failed_attempts"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
}

const persistedStateVersion = 1

// encFileExtension is the file extension for encrypted TOTP state files.
const encFileExtension = ".enc"

// tmpFileExtension is used for atomic writes (write tmp, then rename).
const tmpFileExtension = ".tmp"

// usersSubDir is the subdirectory under storeDir for per-user encrypted blobs.
const usersSubDir = "users"

// persist writes the user's totpState to disk as an encrypted blob.
// The state is serialized to JSON, encrypted via the key manager, and
// written atomically (tmp file + rename). If storeDir is empty or the
// key manager is nil, this is a no-op (in-memory mode).
func (s *TOTPStore) persist(username string) error {
	if s.storeDir == "" || s.km == nil {
		return nil // in-memory mode — no persistence
	}

	st, ok := s.users[username]
	if !ok {
		// State was deleted — remove from disk
		return s.removeFromDisk(username)
	}

	// Convert totpState to persistedState
	ps := toPersistedState(st)

	// Serialize to JSON
	plaintext, err := json.Marshal(ps)
	if err != nil {
		return fmt.Errorf("marshal TOTP state for %s: %w", username, err)
	}

	// Encrypt the JSON blob (username as AAD binds ciphertext to user)
	blob, err := s.km.Seal(username, string(plaintext))
	if err != nil {
		return fmt.Errorf("encrypt TOTP state for %s: %w", username, err)
	}

	// Write atomically
	usersDir := filepath.Join(s.storeDir, usersSubDir)
	if err := os.MkdirAll(usersDir, 0700); err != nil {
		return fmt.Errorf("create users directory: %w", err)
	}

	return writeBlobAtomic(usersDir, username, blob)
}

// loadFromDisk reads all encrypted user state files from disk and
// populates the in-memory cache. Called on startup. If storeDir is
// empty or km is nil, this is a no-op.
func (s *TOTPStore) loadFromDisk() error {
	if s.storeDir == "" || s.km == nil {
		return nil
	}

	usersDir := filepath.Join(s.storeDir, usersSubDir)
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no users directory yet — clean start
		}
		return fmt.Errorf("read users directory: %w", err)
	}

	loaded := 0
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != encFileExtension {
			continue
		}

		username := name[:len(name)-len(encFileExtension)]

		blob, err := os.ReadFile(filepath.Join(usersDir, name))
		if err != nil {
			log.Printf("[WARNING] TOTP: failed to read %s: %v", name, err)
			continue
		}

		plaintext, err := s.km.Open(username, blob)
		if err != nil {
			log.Printf("[WARNING] TOTP: failed to decrypt %s: %v", name, err)
			continue
		}

		var ps persistedState
		if err := json.Unmarshal([]byte(plaintext), &ps); err != nil {
			log.Printf("[WARNING] TOTP: failed to parse %s: %v", name, err)
			continue
		}

		st := fromPersistedState(&ps)
		s.users[username] = st
		loaded++
	}

	if loaded > 0 {
		log.Printf("[INFO] TOTP: loaded %d user states from disk", loaded)
	}
	return nil
}

// removeFromDisk deletes the encrypted blob for a user.
// If the file doesn't exist, this is a no-op.
func (s *TOTPStore) removeFromDisk(username string) error {
	if s.storeDir == "" {
		return nil
	}

	path := encFilePath(s.storeDir, username)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove TOTP file for %s: %w", username, err)
	}
	return nil
}

// encFilePath returns the full path to a user's encrypted TOTP blob.
func encFilePath(storeDir, username string) string {
	return filepath.Join(storeDir, usersSubDir, username+encFileExtension)
}

// writeBlobAtomic writes data to <dir>/<username>.enc using a tmp file
// and atomic rename. This prevents partial writes from corrupting the
// store on crash or power loss (spec §4.5, AC-ATOMIC-01).
func writeBlobAtomic(dir, username string, data []byte) error {
	finalPath := filepath.Join(dir, username+encFileExtension)
	tmpPath := filepath.Join(dir, username+tmpFileExtension)

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write tmp file: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath) // clean up on failure
		return fmt.Errorf("rename tmp to final: %w", err)
	}

	return nil
}

// toPersistedState converts an in-memory totpState to a serializable
// persistedState for disk storage.
func toPersistedState(st *totpState) *persistedState {
	ps := &persistedState{
		Version:            persistedStateVersion,
		EncryptedSecret:    st.EncryptedSecret,
		OldEncryptedSecret: st.OldEncryptedSecret,
		RecoveryCodes:      st.RecoveryCodes,
		State:              int(st.State),
		FailedAttempts:     st.FailedAttempts,
	}

	if !st.PendingSince.IsZero() {
		t := st.PendingSince
		ps.PendingSince = &t
	}

	if !st.LockedUntil.IsZero() {
		t := st.LockedUntil
		ps.LockedUntil = &t
	}

	return ps
}

// fromPersistedState converts a deserialized persistedState back to an
// in-memory totpState.
func fromPersistedState(ps *persistedState) *totpState {
	st := &totpState{
		EncryptedSecret:    ps.EncryptedSecret,
		OldEncryptedSecret: ps.OldEncryptedSecret,
		RecoveryCodes:      ps.RecoveryCodes,
		State:              EnrollmentState(ps.State),
		FailedAttempts:     ps.FailedAttempts,
	}

	if ps.PendingSince != nil {
		st.PendingSince = *ps.PendingSince
	}

	if ps.LockedUntil != nil {
		st.LockedUntil = *ps.LockedUntil
	}

	return st
}
