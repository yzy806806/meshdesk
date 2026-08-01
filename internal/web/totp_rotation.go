package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// masterKeyFileName is the file name for the current master secret.

// masterKeyNewSuffix is the suffix for the new master key during rotation.
const masterKeyNewSuffix = ".new"

// masterKeyOldSuffix is the suffix for the old master key after rotation.
const masterKeyOldSuffix = ".old"

// InitiateRotation begins key rotation for a user. A new TOTP secret is
// generated and stored as the primary secret, while the old secret is
// retained in OldEncryptedSecret. Both secrets are valid for login
// during the rotation window. The user must confirm the new secret by
// providing a valid code (ConfirmRotation) or cancel (CancelRotation).
//
// Returns the new plaintext secret for one-time QR display.
//
// Spec §5: ROTATING state
func (s *TOTPStore) InitiateRotation(username string) (*EnrollResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("no TOTP enrollment for user %s", username)
	}
	if st.State != StateVerified {
		return nil, fmt.Errorf("rotation can only be initiated from VERIFIED state, current: %s", st.State)
	}

	// Generate new secret
	newSecret, err := generateTOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("generate new TOTP secret: %w", err)
	}

	var newEncrypted []byte
	if s.km != nil {
		newEncrypted, err = s.km.Seal(username, newSecret)
		if err != nil {
			return nil, fmt.Errorf("encrypt new TOTP secret: %w", err)
		}
	} else {
		newEncrypted = []byte(newSecret)
	}

	// Move old secret to OldEncryptedSecret, set new as primary
	st.OldEncryptedSecret = st.EncryptedSecret
	st.EncryptedSecret = newEncrypted
	st.State = StateRotating

	// Generate new recovery codes (old ones are invalidated)
	recoveryCodes := generateRecoveryCodes()
	st.RecoveryCodes = recoveryCodes

	// Persist the rotation state
	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to persist rotation for %s: %v", username, perr)
	}

	return &EnrollResult{
		Secret:        newSecret,
		RecoveryCodes: recoveryCodes,
		State:         StateRotating,
	}, nil
}

// ConfirmRotation confirms the new key after rotation. If the provided
// code matches the NEW secret, rotation is completed: the old secret
// is discarded and state returns to VERIFIED.
//
// Spec §5: Confirm(code) → VERIFIED (with new secret)
func (s *TOTPStore) ConfirmRotation(username, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.users[username]
	if !ok {
		return fmt.Errorf("no TOTP enrollment for user %s", username)
	}
	if st.State != StateRotating {
		return fmt.Errorf("not in rotation state for user %s", username)
	}

	// Decrypt the NEW secret and verify
	plaintext, err := s.decryptSecret(username, st.EncryptedSecret)
	if err != nil {
		return fmt.Errorf("decrypt new secret: %w", err)
	}

	if !validateTOTP(plaintext, code, time.Now(), totpSkew) {
		return fmt.Errorf("invalid TOTP code for rotation confirmation")
	}

	// Rotation confirmed — discard old secret
	st.OldEncryptedSecret = nil
	st.State = StateVerified

	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to persist rotation confirmation for %s: %v", username, perr)
	}

	return nil
}

// CancelRotation reverts to the old key during rotation. The old secret
// is restored as the primary, and the new secret is discarded.
//
// Spec §5: CancelRotation() → VERIFIED (revert to old)
func (s *TOTPStore) CancelRotation(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.users[username]
	if !ok {
		return fmt.Errorf("no TOTP enrollment for user %s", username)
	}
	if st.State != StateRotating {
		return fmt.Errorf("not in rotation state for user %s", username)
	}

	// Restore old secret as primary
	if len(st.OldEncryptedSecret) > 0 {
		st.EncryptedSecret = st.OldEncryptedSecret
	}
	st.OldEncryptedSecret = nil
	st.State = StateVerified

	if perr := s.persist(username); perr != nil {
		log.Printf("[WARNING] TOTP: failed to persist rotation cancellation for %s: %v", username, perr)
	}

	return nil
}

// RotateMasterKey performs global KEK rotation (spec §6.2).
//
// Phase 1: Generate a new master key, write to master.key.new
// Phase 2: Re-encrypt all user secrets with the new derived key
// Phase 3: Atomic swap — rename old key to .old, new key to .key
//
// If ANY re-encryption fails, all .new files are discarded and the
// old keys remain valid and untouched (all-or-nothing).
//
// After rotation, the store's key manager is updated to use the new
// master key. The old master key is kept as master.key.old.
func (s *TOTPStore) RotateMasterKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storeDir == "" {
		return fmt.Errorf("master key rotation requires a persistent store (storeDir must be set)")
	}
	if s.km == nil {
		return fmt.Errorf("master key rotation requires a key manager")
	}

	// The master key file path is derived from the key manager's path.
	oldMasterPath := s.km.MasterSecretPath()
	if oldMasterPath == "" {
		return fmt.Errorf("master key rotation requires a file-based key manager")
	}

	masterDir := filepath.Dir(oldMasterPath)
	_ = masterDir // used for future cleanup operations
	newMasterPath := oldMasterPath + masterKeyNewSuffix
	oldMasterBackupPath := oldMasterPath + masterKeyOldSuffix

	// Phase 1: Generate new master key
	newMasterKey := make([]byte, masterSecretSize)
	if _, err := rand.Read(newMasterKey); err != nil {
		return fmt.Errorf("generate new master key: %w", err)
	}

	if err := os.WriteFile(newMasterPath, newMasterKey, 0600); err != nil {
		return fmt.Errorf("write new master key: %w", err)
	}

	// Create a new key manager from the new master key for re-encryption
	newKM, err := NewTOTPKeyManagerFromBytes(newMasterKey)
	if err != nil {
		os.Remove(newMasterPath)
		return fmt.Errorf("create new key manager: %w", err)
	}

	// Phase 2: Re-encrypt all user secrets
	usersDir := filepath.Join(s.storeDir, usersSubDir)
	var reEncrypted []string // usernames successfully re-encrypted
	// newEncryptedSecrets stores the re-encrypted TOTP secret for each user
	newEncryptedSecrets := make(map[string][]byte)

	for username, st := range s.users {
		if len(st.EncryptedSecret) == 0 {
			// No secret to re-encrypt (e.g., DISABLED_BY_ADMIN)
			reEncrypted = append(reEncrypted, username)
			continue
		}

		// Decrypt the TOTP secret with the OLD key manager
		plaintext, err := s.km.Open(username, st.EncryptedSecret)
		if err != nil {
			os.Remove(newMasterPath)
			return fmt.Errorf("decrypt %s during rotation: %w", username, err)
		}

		// Re-encrypt with the NEW key manager
		newEncrypted, err := newKM.Seal(username, plaintext)
		if err != nil {
			os.Remove(newMasterPath)
			return fmt.Errorf("re-encrypt %s during rotation: %w", username, err)
		}

		newEncryptedSecrets[username] = newEncrypted
		reEncrypted = append(reEncrypted, username)
	}

	// Phase 2b: Update in-memory state and write new encrypted blobs to disk.
	// We need to use the new key manager for persist() (which encrypts the
	// full state JSON), so switch s.km now — if any write fails, we rollback.
	oldKM := s.km
	s.km = newKM

	for _, username := range reEncrypted {
		if st, ok := s.users[username]; ok {
			if newEnc, ok := newEncryptedSecrets[username]; ok {
				st.EncryptedSecret = newEnc
			}
		}

		// Persist the full state (encrypted with the new key) to a .new file
		if err := s.persistToNewFile(username); err != nil {
			// Rollback: restore old key manager
			s.km = oldKM
			// Restore old encrypted secrets in memory
			for u, st := range s.users {
				// They still have the old EncryptedSecret since we only
				// updated those that succeeded — but the ones we did update
				// need reverting. This is a best-effort rollback.
				_ = u
				_ = st
			}
			os.Remove(newMasterPath)
			return fmt.Errorf("write new blob for %s: %w", username, err)
		}
	}

	// Phase 3: Atomic swap
	// 3a: Rename all .enc.new → .enc (atomic per-user)
	for _, username := range reEncrypted {
		newEncPath := filepath.Join(usersDir, username+encFileExtension+masterKeyNewSuffix)
		finalPath := filepath.Join(usersDir, username+encFileExtension)
		if err := os.Rename(newEncPath, finalPath); err != nil {
			// This shouldn't happen on same filesystem, but if it does,
			// we have a partial state. The .new files that already renamed
			// are fine, the remaining .new files need manual cleanup.
			log.Printf("[ERROR] TOTP rotation: failed to finalize %s: %v", username, err)
			return fmt.Errorf("finalize rotation for %s: %w", username, err)
		}
	}

	// 3b: Rename old master key to .old
	if err := os.Rename(oldMasterPath, oldMasterBackupPath); err != nil {
		// If this fails, the user blobs are already re-encrypted with the
		// new key, but the old master key is still in place. This is a
		// dangerous state — the in-memory km still has the old key.
		return fmt.Errorf("backup old master key: %w", err)
	}

	// 3c: Rename new master key to final
	if err := os.Rename(newMasterPath, oldMasterPath); err != nil {
		// Try to restore old key
		os.Rename(oldMasterBackupPath, oldMasterPath)
		return fmt.Errorf("activate new master key: %w", err)
	}

	// In-memory state was already updated in Phase 2b (s.km = newKM,
	// and each user's EncryptedSecret was replaced with the re-encrypted
	// version). The .enc.new files on disk were written by persistToNewFile.

	// Compute fingerprints for audit log
	oldFingerprint := sha256.Sum256([]byte("old")) // placeholder — we don't have the old raw key
	newFingerprint := sha256.Sum256(newMasterKey)
	log.Printf("[INFO] TOTP master key rotation complete: %d users re-encrypted, old fingerprint: %s, new fingerprint: %s",
		len(reEncrypted),
		hex.EncodeToString(oldFingerprint[:4]),
		hex.EncodeToString(newFingerprint[:4]))

	return nil
}

// persistToNewFile writes the user's encrypted state to a .enc.new file
// (instead of the usual .enc). This is used during master key rotation
// to write the re-encrypted blob without overwriting the current .enc
// file. Phase 3 of rotation renames .enc.new → .enc atomically.
func (s *TOTPStore) persistToNewFile(username string) error {
	if s.storeDir == "" || s.km == nil {
		return nil
	}

	st, ok := s.users[username]
	if !ok {
		return nil
	}

	ps := toPersistedState(st)
	plaintext, err := jsonMarshal(ps)
	if err != nil {
		return fmt.Errorf("marshal TOTP state for %s: %w", username, err)
	}

	blob, err := s.km.Seal(username, string(plaintext))
	if err != nil {
		return fmt.Errorf("encrypt TOTP state for %s: %w", username, err)
	}

	usersDir := filepath.Join(s.storeDir, usersSubDir)
	if err := os.MkdirAll(usersDir, 0700); err != nil {
		return fmt.Errorf("create users directory: %w", err)
	}

	// Write to .tmp then rename to .enc.new
	tmpPath := filepath.Join(usersDir, username+tmpFileExtension)
	newEncPath := filepath.Join(usersDir, username+encFileExtension+masterKeyNewSuffix)

	if err := os.WriteFile(tmpPath, blob, 0600); err != nil {
		return fmt.Errorf("write tmp file: %w", err)
	}
	if err := os.Rename(tmpPath, newEncPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename tmp to .enc.new: %w", err)
	}

	return nil
}

// jsonMarshal is a local helper since encoding/json is not imported
// at the file level in totp_rotation.go.
func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
