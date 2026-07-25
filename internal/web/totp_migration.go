package web

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// jsonFileExtension is the file extension for legacy plaintext TOTP state.
const jsonFileExtension = ".json"

// migratePlaintext scans the users/ directory for legacy plaintext .json
// files, encrypts them with the current master key, and deletes the
// plaintext originals. This is called on startup by NewPersistentTOTPStore.
//
// If no .json files exist, this is a no-op. If a .json file cannot be
// read, parsed, or encrypted, the migration aborts with an error (the
// plaintext file is left intact for manual inspection).
//
// Spec §7: Migration Path — Plaintext → Encrypted
func (s *TOTPStore) migratePlaintext() error {
	if s.storeDir == "" || s.km == nil {
		return nil
	}

	usersDir := filepath.Join(s.storeDir, usersSubDir)
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read users directory for migration: %w", err)
	}

	migrated := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, jsonFileExtension) {
			continue // skip non-plaintext files
		}

		username := strings.TrimSuffix(name, jsonFileExtension)

		// Read plaintext JSON
		plaintextPath := filepath.Join(usersDir, name)
		plaintext, err := os.ReadFile(plaintextPath)
		if err != nil {
			return fmt.Errorf("migrate %s: read plaintext: %w", username, err)
		}

		// Parse the legacy state
		var ps persistedState
		if err := json.Unmarshal(plaintext, &ps); err != nil {
			return fmt.Errorf("migrate %s: parse JSON: %w", username, err)
		}

		// If the state contains a plaintext secret (not yet encrypted),
		// encrypt it now. The persistedState format stores EncryptedSecret
		// which may contain plaintext in legacy files.
		// We re-encrypt the entire state blob via the key manager.

		// Serialize and encrypt
		blobJSON, err := json.Marshal(ps)
		if err != nil {
			return fmt.Errorf("migrate %s: marshal state: %w", username, err)
		}

		blob, err := s.km.Seal(username, string(blobJSON))
		if err != nil {
			return fmt.Errorf("migrate %s: encrypt: %w", username, err)
		}

		// Write encrypted blob
		if err := writeBlobAtomic(usersDir, username, blob); err != nil {
			return fmt.Errorf("migrate %s: write encrypted: %w", username, err)
		}

		// Remove plaintext file ONLY after successful encrypted write
		if err := os.Remove(plaintextPath); err != nil {
			log.Printf("[WARNING] TOTP migration: encrypted %s but failed to remove plaintext: %v", username, err)
		}

		migrated++
	}

	if migrated > 0 {
		log.Printf("[INFO] TOTP migration: encrypted %d user secrets", migrated)
	}
	return nil
}

// cleanupStaleTmpFiles removes any .tmp files left behind by a crash
// during writeBlobAtomic. Called on startup to ensure clean state.
func (s *TOTPStore) cleanupStaleTmpFiles() error {
	if s.storeDir == "" {
		return nil
	}

	usersDir := filepath.Join(s.storeDir, usersSubDir)
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, tmpFileExtension) {
			tmpPath := filepath.Join(usersDir, name)
			if err := os.Remove(tmpPath); err != nil {
				log.Printf("[WARNING] TOTP: failed to remove stale tmp file %s: %v", name, err)
			} else {
				log.Printf("[INFO] TOTP: removed stale tmp file %s", name)
			}
		}
	}
	return nil
}
