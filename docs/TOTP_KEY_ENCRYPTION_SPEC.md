# TOTP Key Encryption-at-Rest Specification

**Version:** 1.0
**Status:** Proposed (action item 4/6 from motion-ab7dcffe52e8)
**Package:** `internal/web/totp.go` (to be refactored)
**Dependencies:** `golang.org/x/crypto` (already in go.mod)
**Parent spec:** None (supersedes the preliminary outline in t_4155ba9c)

---

## 1. Threat Model

### 1.1 What We're Protecting Against

| Threat | Severity | Mitigation |
|--------|----------|------------|
| **Disk theft / server compromise** — attacker gains read access to the filesystem and exfiltrates the TOTP secret store | CRITICAL | AES-256-GCM encryption with node-local master secret |
| **Backup exfiltration** — operator backs up the data directory without realizing it contains plaintext TOTP secrets | HIGH | Secrets are encrypted on disk; backups contain only ciphertext |
| **Config file leak** — config.yaml with `totp_secret` field committed to version control or shared | HIGH | Remove `totp_secret` from config; master key is node-local file, never in config |
| **Memory dump** — attacker obtains a memory dump of the running process | MEDIUM | Out of scope for this spec. Accept that live secrets exist in memory during TOTP code validation (~microseconds). GCM key material is zeroed after use via `clear(derivedKey)`. |
| **Insider with shell access** — legitimate user reads `/var/lib/meshdesk/totp/master.key` | MEDIUM | 0600 file permissions + audit log event on master key access. Root bypass is inherent; this is a defense-in-depth measure. |

### 1.2 What We're NOT Protecting Against

- **Live memory inspection** during TOTP validation (the secret must be decrypted into memory briefly; an attacker with ptrace access wins).
- **Root user on the host** (they can read the master key file and decrypt everything).
- **Side-channel attacks** (timing, power analysis) — out of scope for a Go userspace daemon.

---

## 2. Architecture Overview

```
                    ┌──────────────────────────────┐
                    │ /var/lib/meshdesk/totp/       │
                    │   master.key (0600, 32 bytes) │  ← node-local, auto-generated
                    └──────────────┬───────────────┘
                                   │
                          HKDF-SHA256(salt=username)
                                   │
                    ┌──────────────▼───────────────┐
                    │ Per-user AES-256-GCM key     │  ← 32 bytes, never stored
                    └──────────────┬───────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
   ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
   │ users/alice.enc  │ │ users/bob.enc    │ │ users/carol.enc  │
   │ [12B nonce]      │ │ [12B nonce]      │ │ [12B nonce]      │
   │ [GCM ciphertext] │ │ [GCM ciphertext] │ │ [GCM ciphertext] │
   │ [16B tag]        │ │ [16B tag]        │ │ [16B tag]        │
   └──────────────────┘ └──────────────────┘ └──────────────────┘
```

**Design principle:** The master secret is a key-encrypting-key (KEK). Each user's TOTP secret is encrypted with a per-user key derived from the KEK via HKDF, using the username as salt. This means:

1. Re-keying all users requires only replacing `master.key` and re-encrypting user blobs.
2. A single user's compromise (e.g., known plaintext of one TOTP secret) does not help decrypt other users' secrets.
3. The KEK never leaves the node. It is NEVER in config.yaml.

---

## 3. Key Derivation

### 3.1 Master Secret (KEK)

The master secret is the root of trust for all TOTP encryption on a node.

**Generation (first boot):**
```go
masterKey := make([]byte, 32) // 256 bits
if _, err := rand.Read(masterKey); err != nil {
    return fmt.Errorf("generate master key: %w", err)
}
```

**Storage:**
- Path: `/var/lib/meshdesk/totp/master.key`
- Permissions: `0600` (owner read/write only)
- Format: raw 32 bytes (not hex-encoded, not base64 — raw binary)
- Parent directory: `0700`, created by the process on startup if missing

**Loading (subsequent boots):**
```go
masterKey, err := os.ReadFile("/var/lib/meshdesk/totp/master.key")
if err != nil {
    if os.IsNotExist(err) {
        // First boot: generate and store
        masterKey = generateMasterKey()
        os.MkdirAll("/var/lib/meshdesk/totp/users", 0700)
        os.WriteFile("/var/lib/meshdesk/totp/master.key", masterKey, 0600)
        log.Printf("Generated TOTP master key at /var/lib/meshdesk/totp/master.key")
    } else {
        return fmt.Errorf("read master key: %w", err)
    }
}
```

### 3.2 Per-User Encryption Key

Derived from the master secret using HKDF-SHA256:

```go
func deriveUserKey(masterKey []byte, username string) []byte {
    key := make([]byte, 32)
    r := hkdf.New(sha256.New, masterKey, []byte(username), []byte("meshdesk-totp-user-v1"))
    io.ReadFull(r, key)
    return key
}
```

**Salt:** The username string (UTF-8 encoded). Rationale: usernames are unique within a MeshDesk node and stable — the same username always derives the same key on the same node, which is the desired property for deterministic encryption/decryption.

**Info string:** `"meshdesk-totp-user-v1"` provides domain separation so the same master key used in other contexts (future extensions) won't produce colliding derived keys.

### 3.3 Why HKDF, Not scrypt/argon2

scrypt and argon2 are **password-based KDFs** designed to stretch low-entropy inputs (human-chosen passwords) by consuming CPU/memory. Our master secret is a **full-entropy 256-bit random key** from `crypto/rand` — it needs no stretching. HKDF is the correct primitive for expanding a high-entropy key into multiple domain-separated sub-keys.

Using scrypt/argon2 here would:
- Waste CPU/memory at every encryption/decryption with zero security benefit
- Introduce tuneable parameters (N, r, p for scrypt; time, memory, threads for argon2) that operators would need to configure
- Mislead future readers into thinking the master key is low-entropy

**The one valid use of scrypt/argon2** in this system would be if we supported an operator-provided passphrase instead of auto-generated master key. This spec does NOT support that mode for v1 — it adds key-management complexity (passphrase recovery, rotation coordination) with no practical security improvement when the master key is already locked behind filesystem permissions.

---

## 4. Encryption Scheme

### 4.1 Cipher: AES-256-GCM

- **Algorithm:** AES-256 in Galois/Counter Mode (GCM)
- **Key:** 32 bytes, derived via HKDF-SHA256 (§3.2)
- **Nonce:** 12 bytes, randomly generated per encryption via `crypto/rand.Read`
- **Tag:** 16 bytes, appended to ciphertext by GCM
- **AEAD interface:** `crypto/cipher.NewGCM(aesBlock)` (Go stdlib)

### 4.2 Encrypted Blob Format

```
Offset  Size    Field
------  ----    -----
0       12      Nonce (random, per-encryption)
12      N       Ciphertext (AES-256-GCM encrypted)
12+N    16      Authentication tag (appended by GCM)
```

Total file size: `12 + plaintextLen + 16`

### 4.3 Plaintext Schema (before encryption)

The plaintext is a JSON object containing the user's TOTP state:

```json
{
  "version": 1,
  "totp_secret": "JBSWY3DPEHPK3PXP",   // base32, no padding
  "recovery_codes": ["ABCDEFGH", ...],  // remaining unused codes
  "enrollment_state": "verified",       // §5 enrollment model
  "created_at": "2026-07-25T22:00:00Z", // RFC 3339
  "rotated_at": null,                   // last key rotation, if any
  "failed_attempts": 0,
  "locked_until": null                  // RFC 3339 or null
}
```

### 4.4 Encryption / Decryption Pseudocode

```go
func encryptUserSecret(userKey []byte, state *totpState) ([]byte, error) {
    plaintext, _ := json.Marshal(state)

    block, _ := aes.NewCipher(userKey)
    gcm, _ := cipher.NewGCM(block)

    nonce := make([]byte, gcm.NonceSize()) // 12 bytes
    rand.Read(nonce)

    // Seal appends the ciphertext to nonce, then appends the tag.
    // Result: nonce (12) + ciphertext (len(plaintext)) + tag (16)
    blob := gcm.Seal(nonce, nonce, plaintext, nil)
    return blob, nil
}

func decryptUserSecret(userKey []byte, blob []byte) (*totpState, error) {
    block, _ := aes.NewCipher(userKey)
    gcm, _ := cipher.NewGCM(block)

    nonceSize := gcm.NonceSize()
    if len(blob) < nonceSize {
        return nil, ErrMalformedBlob
    }
    nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]

    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("decrypt: %w", err) // GCM tag verification failed
    }

    var state totpState
    json.Unmarshal(plaintext, &state)
    return &state, nil
}
```

### 4.5 Atomic Writes

All file writes to `users/<username>.enc` MUST use atomic rename:

```go
func writeBlob(dir, username string, blob []byte) error {
    tmpPath := filepath.Join(dir, username+".tmp")
    finalPath := filepath.Join(dir, username+".enc")

    if err := os.WriteFile(tmpPath, blob, 0600); err != nil {
        return err
    }
    if err := os.Rename(tmpPath, finalPath); err != nil {
        os.Remove(tmpPath)
        return err
    }
    return nil
}
```

This prevents partial writes from corrupting the store on crash/power-loss.

---

## 5. Enrollment State Machine

Replaces the current binary `enrolled bool` with a 5-state model:

```
                    ┌──────────┐
          ┌────────>│ DISABLED │<─────────┐
          │         └────┬─────┘          │
          │              │ Enroll()       │
          │         ┌────▼─────┐          │
          │         │ PENDING  │          │ Disable() or
          │         └────┬─────┘          │ admin override
          │              │ Verify(code)   │
          │         ┌────▼─────┐          │
          │         │ VERIFIED │──────────┘
          │         └────┬─────┘
          │              │ InitiateRotation()
          │         ┌────▼─────┐
          │         │ ROTATING │
          │         └────┬─────┘
          │              │ Confirm(code)   or
          │              │ (new code works)   │ CancelRotation()
          │         ┌────▼─────┐          │
          │         │ VERIFIED │<─────────┘
          │         └──────────┘
          │
          └──── DISABLED_BY_ADMIN (terminal; requires admin to re-enable)
```

**States:**

| State | Meaning | Allowed Actions |
|-------|---------|-----------------|
| `DISABLED` | User has never enrolled or has been disabled by themselves | Enroll() → PENDING |
| `PENDING` | Enrollment initiated, secret generated, not yet verified | Verify(code) → VERIFIED; timeout → DISABLED (24h TTL) |
| `VERIFIED` | 2FA active, codes validated against stored secret | Disable() → DISABLED; InitiateRotation() → ROTATING |
| `ROTATING` | New secret generated, awaiting confirmation of new code | Confirm(code) → VERIFIED (with new secret); CancelRotation() → VERIFIED (revert to old) |
| `DISABLED_BY_ADMIN` | Administrator forcibly disabled 2FA for this user | Only admin re-enable → DISABLED |

**PENDING timeout:** If a user enrolls but never completes verification, the PENDING state expires after 24 hours and the secret is deleted. This prevents abandoned enrollment secrets from accumulating.

**ROTATING window:** During rotation, the old secret remains valid for verification alongside the new one. This allows a grace period where either code works. Confirming the new code (or timing out after 5 minutes) finalizes the transition.

---

## 6. Key Management & Rotation

### 6.1 Rotation Triggers

Key rotation is an infrequent operator-initiated event, not automatic. Triggers include:
- Suspected key compromise
- Regular security maintenance (e.g., quarterly)
- Pre-decommission (rotate before retiring a node)

### 6.2 Rotation Procedure

```
Phase 1: Generate new master key
  ─────────────────────────────────
  1. Generate newMasterKey (32 bytes from crypto/rand)
  2. Write to /var/lib/meshdesk/totp/master.key.new (0600)

Phase 2: Re-encrypt all user secrets
  ───────────────────────────────────
  3. Read all users/<username>.enc files
  4. For each user:
     a. Decrypt with OLD derived key: oldKey = HKDF(oldMaster, username)
     b. Encrypt with NEW derived key: newKey = HKDF(newMaster, username)
     c. Write to users/<username>.enc.new (atomic rename)
  5. If ALL re-encryptions succeed:
     a. For each user, rename users/<username>.enc.new → users/<username>.enc
     b. Rename master.key → master.key.old
     c. Rename master.key.new → master.key
  6. If ANY re-encryption fails:
     a. Discard all .new files
     b. Remove master.key.new
     c. Return error; old keys remain valid and untouched

Phase 3: Log and audit
  ──────────────────────
  7. Log rotation event with:
     - Timestamp
     - Number of users re-encrypted
     - Old master key SHA-256 fingerprint (first 8 hex chars)
     - New master key SHA-256 fingerprint (first 8 hex chars)
  8. Emit security alert via AlertStore
```

### 6.3 Recovery from Failed Rotation

If the process crashes during Phase 2:
- `users/<username>.enc` files are unchanged (atomic rename protects them)
- `master.key.new` exists alongside `master.key` — on next startup, check for `.new` and either resume or clean up
- `master.key.old` is kept for one rotation cycle; operator can manually roll back by renaming `.old` → `.key`

### 6.4 Operator CLI

```bash
# Initiate rotation
meshdesk totp rotate

# Check rotation status
meshdesk totp status

# Roll back to previous key (if master.key.old exists)
meshdesk totp rotate --rollback
```

---

## 7. Migration Path: Plaintext → Encrypted

### 7.1 Current State (HEAD a9b1ab5)

- `TOTPStore` is pure in-memory (`map[string]*totpState`).
- `totpState.Secret` is a plaintext base32 string.
- No persistence at all — secrets are lost on restart.
- Config field `TOTPSecret` (string in config.yaml) exists but is unused by the store.

### 7.2 Migration Strategy

Since the current store is **in-memory only** with zero persistence, there are NO existing plaintext files to migrate. The migration is effectively a greenfield deployment of encrypted persistence.

However, this spec defines a forward-compatible migration path for the hypothetical case where an operator has manually serialized TOTP state:

**Automatic migration on startup (future-proof):**
```go
func migrateIfNeeded(storeDir string, masterKey []byte) error {
    oldDir := filepath.Join(storeDir, "users")
    entries, err := os.ReadDir(oldDir)
    if err != nil {
        return nil // directory doesn't exist or is empty — nothing to migrate
    }

    migrated := 0
    for _, entry := range entries {
        if !strings.HasSuffix(entry.Name(), ".json") {
            continue // skip non-plaintext files
        }
        username := strings.TrimSuffix(entry.Name(), ".json")

        // Read plaintext
        plaintext, err := os.ReadFile(filepath.Join(oldDir, entry.Name()))
        if err != nil {
            return fmt.Errorf("migrate %s: read: %w", username, err)
        }

        var state totpState
        if err := json.Unmarshal(plaintext, &state); err != nil {
            return fmt.Errorf("migrate %s: parse: %w", username, err)
        }

        // Encrypt and write
        userKey := deriveUserKey(masterKey, username)
        blob, err := encryptUserSecret(userKey, &state)
        if err != nil {
            return fmt.Errorf("migrate %s: encrypt: %w", username, err)
        }

        encPath := filepath.Join(oldDir, username+".enc")
        if err := writeBlob(oldDir, username, blob); err != nil {
            return fmt.Errorf("migrate %s: write: %w", username, err)
        }

        // Remove plaintext file ONLY after successful encrypted write
        os.Remove(filepath.Join(oldDir, entry.Name()))
        migrated++
    }

    if migrated > 0 {
        log.Printf("TOTP migration: encrypted %d user secrets", migrated)
    }
    return nil
}
```

### 7.3 Config Cleanup

The `AuthConfig.TOTPSecret` field (§363 of config.go, the `totp_secret` YAML key) MUST be removed. It is a security anti-pattern: placing secret key material in a configuration file that operators routinely check into version control or share.

**Migration for operators who have set `totp_secret`:**
- On startup, if `totp_secret` is present in config, log a warning: `config.yaml contains deprecated field 'totp_secret' — TOTP encryption now uses node-local /var/lib/meshdesk/totp/master.key. The config field is ignored.`
- Do NOT attempt to migrate the config value into master.key — it may have been shared across nodes.

---

## 8. EncryptedTOTPStore API

### 8.1 Interface (supersedes current TOTPStore)

```go
type EncryptedTOTPStore struct {
    mu        sync.RWMutex
    masterKey []byte          // loaded once at startup, never leaves memory
    storeDir  string          // /var/lib/meshdesk/totp/users/
    cache     map[string]*totpState // in-memory cache, encrypted on flush
}

func NewEncryptedTOTPStore(storeDir string) (*EncryptedTOTPStore, error)
```

### 8.2 Public Methods

```go
// Enroll generates a new TOTP secret, stores it encrypted on disk,
// and returns the state (in PENDING state). Returns error if already enrolled.
func (s *EncryptedTOTPStore) Enroll(username string) (*totpState, error)

// Verify checks the provided TOTP code. If the state is PENDING and the
// code is correct, transitions to VERIFIED and persists. If VERIFIED,
// performs the normal validation. Returns (valid bool, err error).
func (s *EncryptedTOTPStore) Verify(username, code string) (bool, error)

// Disable removes TOTP enrollment, deleting the encrypted blob from disk.
func (s *EncryptedTOTPStore) Disable(username string) error

// AdminDisable force-disables TOTP for a user (sets DISABLED_BY_ADMIN).
func (s *EncryptedTOTPStore) AdminDisable(username string) error

// IsEnrolled reports whether the user is in VERIFIED or ROTATING state.
func (s *EncryptedTOTPStore) IsEnrolled(username string) bool

// IsLocked reports whether the user is currently locked out.
func (s *EncryptedTOTPStore) IsLocked(username string) bool

// RecordFailedAttempt increments failure counter; returns true if now locked.
func (s *EncryptedTOTPStore) RecordFailedAttempt(username string) (bool, error)

// ClearFailedAttempts resets the failure counter.
func (s *EncryptedTOTPStore) ClearFailedAttempts(username string) error

// ConsumeRecoveryCode attempts to use a one-time recovery code.
func (s *EncryptedTOTPStore) ConsumeRecoveryCode(username, code string) (bool, error)

// InitiateRotation begins key rotation for a user.
func (s *EncryptedTOTPStore) InitiateRotation(username string) (*totpState, error)

// ConfirmRotation confirms the new key after rotation.
func (s *EncryptedTOTPStore) ConfirmRotation(username, code string) error

// CancelRotation reverts to the old key during rotation.
func (s *EncryptedTOTPStore) CancelRotation(username string) error

// RotateMasterKey performs global KEK rotation (§6.2).
func (s *EncryptedTOTPStore) RotateMasterKey() error

// Status returns enrollment state for a user.
func (s *EncryptedTOTPStore) Status(username string) (EnrollmentState, error)
```

### 8.3 In-Memory Cache Strategy

For performance (avoiding disk reads on every code validation), the store maintains an in-memory cache of decrypted TOTP state. Cache behavior:

- **On read:** Check cache first; if miss, read from disk, decrypt, populate cache.
- **On write:** Update cache immediately, then write encrypted to disk asynchronously (or synchronously, but don't block the caller).
- **Cache invalidation:** Only on explicit Disable() or AdminDisable().
- **Memory pressure:** Cache is bounded (no eviction needed — number of users is small in MeshDesk deployments).

### 8.4 Concurrency

- All reads acquire `RLock`, all writes acquire `Lock`.
- The EncryptedTOTPStore replaces the current `sync.Mutex` with `sync.RWMutex` to allow concurrent reads (multiple simultaneous TOTP validations from different users).
- Disk I/O during writes is serialized (single writer at a time).

---

## 9. Acceptance Criteria

### 9.1 Cryptographic Correctness

- [ ] **AC-CRYPTO-01:** Given a generated master key, encrypting a known TOTP secret and decrypting with `EncryptedTOTPStore` returns the original secret (round-trip test).
- [ ] **AC-CRYPTO-02:** GCM tag verification fails (decrypt returns error) when ciphertext is modified by 1 bit.
- [ ] **AC-CRYPTO-03:** Two different usernames with the same TOTP secret produce different ciphertexts (HKDF salt isolation).
- [ ] **AC-CRYPTO-04:** Encrypting the same secret twice for the same user produces different ciphertexts (random nonce per encryption).
- [ ] **AC-CRYPTO-05:** `deriveUserKey` with the same (masterKey, username) produces the same key deterministically.

### 9.2 Persistence

- [ ] **AC-PERSIST-01:** After `Enroll("alice")` and process restart, `IsEnrolled("alice")` returns true.
- [ ] **AC-PERSIST-02:** After `Enroll("alice")` and `Verify("alice", correctCode)`, the enrollment state is VERIFIED across restarts.
- [ ] **AC-PERSIST-03:** After `Disable("alice")`, the file `users/alice.enc` does not exist on disk.
- [ ] **AC-PERSIST-04:** `RecoveryCodes` consumed during one process lifetime are not available after restart (consumed codes are persisted).

### 9.3 Enrollment State Machine

- [ ] **AC-STATE-01:** `Enroll()` transitions DISABLED → PENDING. Calling `Enroll()` again in PENDING returns an error.
- [ ] **AC-STATE-02:** `Verify(wrongCode)` in PENDING increments `FailedAttempts` but stays PENDING. After `maxFailedTOTP` (5) attempts, account is locked.
- [ ] **AC-STATE-03:** `Verify(correctCode)` in PENDING transitions to VERIFIED. Subsequent `IsEnrolled()` returns true.
- [ ] **AC-STATE-04:** `Disable()` in VERIFIED transitions to DISABLED.
- [ ] **AC-STATE-05:** `InitiateRotation()` in VERIFIED transitions to ROTATING. Old secret still validates.
- [ ] **AC-STATE-06:** `ConfirmRotation(correctNewCode)` in ROTATING transitions to VERIFIED with new secret.
- [ ] **AC-STATE-07:** `CancelRotation()` in ROTATING reverts to VERIFIED with old secret.
- [ ] **AC-STATE-08:** `AdminDisable()` from any state transitions to DISABLED_BY_ADMIN. Only admin re-enable works.
- [ ] **AC-STATE-09:** PENDING state expires after 24 hours (secret deleted, back to DISABLED).

### 9.4 Key Rotation

- [ ] **AC-ROTATE-01:** `RotateMasterKey()` with N users succeeds — all N user secrets are re-encrypted with the new master key.
- [ ] **AC-ROTATE-02:** After rotation, user secrets decrypt correctly with the new master key.
- [ ] **AC-ROTATE-03:** After rotation, user secrets do NOT decrypt with the old master key.
- [ ] **AC-ROTATE-04:** If re-encryption of user 3/N fails, users 0–2 remain encrypted with old key (no partial migration).
- [ ] **AC-ROTATE-05:** `master.key.old` exists after successful rotation.
- [ ] **AC-ROTATE-06:** Process crash mid-rotation leaves consistent state: either old keys work (rollback) or new keys work (completed). No split-brain.

### 9.5 Master Key Management

- [ ] **AC-MASTER-01:** First startup generates `master.key` if it doesn't exist.
- [ ] **AC-MASTER-02:** `master.key` permissions are 0600.
- [ ] **AC-MASTER-03:** `users/` directory permissions are 0700.
- [ ] **AC-MASTER-04:** Encrypted user blob permissions are 0600.
- [ ] **AC-MASTER-05:** Startup fails with a clear error if `master.key` exists but is unreadable (wrong permissions/corruption).
- [ ] **AC-MASTER-06:** The `totp_secret` field in config.yaml is ignored with a log warning (config cleanup).

### 9.6 Atomicity

- [ ] **AC-ATOMIC-01:** Process crash during `writeBlob()` leaves either the old `.enc` file intact or the new `.enc` file intact. No partial `.enc` file exists.
- [ ] **AC-ATOMIC-02:** After a crash during rotation, no `.new` or `.tmp` files remain that would block the next startup.

### 9.7 Backward Compatibility

- [ ] **AC-COMPAT-01:** All existing `handlers_2fa.go` callers of `TOTPStore` methods continue to work with the new `EncryptedTOTPStore` (same public method signatures where possible).
- [ ] **AC-COMPAT-02:** `Server.New()` in server.go wires `EncryptedTOTPStore` via the same `Deps.TOTPStore` field (interface extraction).

---

## 10. File Manifest

| File | Purpose |
|------|---------|
| `internal/web/encrypted_totp_store.go` | New: EncryptedTOTPStore implementation (replace TOTPStore) |
| `internal/web/encrypted_totp_store_test.go` | New: test suite covering all acceptance criteria |
| `internal/web/totp.go` | Modify: remove TOTPStore, keep crypto helpers (validateTOTP, computeTOTPCode, etc.) |
| `internal/web/totp_state.go` | New: totpState, EnrollmentState, JSON serialization |
| `internal/web/totp_rotation.go` | New: RotateMasterKey logic |
| `internal/web/totp_migration.go` | New: startup migration from plaintext (if any) |
| `internal/web/server.go` | Modify: wire EncryptedTOTPStore via Deps (line 132) |
| `internal/config/config.go` | Modify: deprecate TOTPSecret field (lines 358-363) |
| `docs/TOTP_KEY_ENCRYPTION_SPEC.md` | This document |

---

## 11. Design Decisions & Trade-offs

### 11.1 In-Memory Cache vs. Always Decrypt

**Chosen:** In-memory cache with encrypted disk backing.

**Reasoning:** TOTP code validation happens on every dashboard page load and API call. Decrypting from disk for every validation would add ~100µs disk + ~5µs AES-GCM per request. For a low-traffic admin dashboard this is acceptable, but the cache eliminates the disk I/O entirely. Cache invalidation is trivial because the store is single-writer (the web server process).

### 11.2 Per-User Files vs. Single Encrypted Database

**Chosen:** Per-user files (`users/<username>.enc`).

| Aspect | Per-User Files | Single DB |
|--------|---------------|-----------|
| Atomicity | Per-user atomic rename | Whole-DB write on any change |
| Rotation | Re-encrypt one file at a time | Decrypt/re-encrypt entire DB |
| Concurrency | Multiple readers, single writer per file | Single writer for entire DB |
| Backup | rsync individual files | Single file |
| Complexity | Simple (os.ReadFile/WriteFile) | Requires DB library or custom format |

**Decision:** Per-user files. MeshDesk deployments typically have 1–10 dashboard users. The "database" is trivial enough that per-file simplicity wins over single-file efficiency.

### 11.3 Remove `totp_secret` from Config vs. Keep as Override

**Chosen:** Remove entirely with deprecation warning.

**Reasoning:** Config files are shared, backed up, and version-controlled. Placing secret key material in them defeats the purpose of encryption-at-rest. The `master.key` file is local to each node — even if config.yaml leaks, the TOTP secrets remain encrypted. A config-based override would create a false sense of security and an easy operator mistake.

### 11.4 Go stdlib crypto vs. External Library

**Chosen:** Go stdlib `crypto/aes` + `crypto/cipher` + `golang.org/x/crypto/hkdf`.

**Reasoning:** All primitives are already in the project's dependency tree. No new imports required. `golang.org/x/crypto` is maintained by the Go team and has a stable API. No additional audit burden.

---

## 12. Next Steps

1. **Implement EncryptedTOTPStore** (developer task t_4bfd784b): Core encryption, persistence, state machine.
2. **Implement rotation logic** (developer task t_4bfd784b extension or new task): `RotateMasterKey()`.
3. **Wire into server.go**: Replace `TOTPStore` with `EncryptedTOTPStore` in `Deps` and `New()`.
4. **Config cleanup**: Deprecate `TOTPSecret` field.
5. **Acceptance test suite**: Run all 9.1–9.7 acceptance criteria as automated tests.