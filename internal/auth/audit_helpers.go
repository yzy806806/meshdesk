package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// hashEntry computes the SHA-256 hex digest of a JSON-encoded
// audit entry (the raw bytes, without the trailing newline).
// This is used to build the tamper-evident hash chain: each
// entry's prev_hash is the hash of the previous entry.
func hashEntry(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// splitLines splits a byte slice into lines by '\n'. The final
// line is included even if it doesn't end with a newline.
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	// Trim a single trailing newline so we don't get an empty final line
	data = bytes.TrimSuffix(data, []byte{'\n'})
	return bytes.Split(data, []byte{'\n'})
}

// trimSpace trims leading and trailing whitespace from a byte slice.
func trimSpace(data []byte) []byte {
	return bytes.TrimSpace(data)
}
