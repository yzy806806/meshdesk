// Wire format test generator for AC-L2.I3.
//
// This program writes a single encrypted frame to a binary file using the
// same wire format as SecureConn. The output can be decrypted by the
// accompanying Python validator (tests/wire_format_validator.py).
//
// Usage: go run tests/wire_format_gen.go <output_file> <message> <hex_key>
// Example: go run tests/wire_format_gen.go wire.bin "hello world" 00...00

//go:build ignore

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <output_file> <message> <hex_key>\n", os.Args[0])
		os.Exit(1)
	}

	outputFile := os.Args[1]
	message := []byte(os.Args[2])
	hexKey := os.Args[3]

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hex key: %v\n", err)
		os.Exit(1)
	}
	if len(key) != 32 {
		fmt.Fprintf(os.Stderr, "key must be 32 bytes, got %d\n", len(key))
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create cipher: %v\n", err)
		os.Exit(1)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create GCM: %v\n", err)
		os.Exit(1)
	}

	// Nonce = 12 bytes, counter = 0 (all zeros).
	nonce := make([]byte, 12)

	// Encrypt: Seal appends ciphertext + 16-byte tag.
	ciphertext := aead.Seal(nil, nonce, message, nil)

	// Wire format: [len:2][nonce:12][ciphertext]
	frame := make([]byte, 2+12+len(ciphertext))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(ciphertext)))
	copy(frame[2:14], nonce)
	copy(frame[14:], ciphertext)

	if err := os.WriteFile(outputFile, frame, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %d bytes to %s\n", len(frame), outputFile)
	fmt.Printf("  Message: %q (%d bytes)\n", message, len(message))
	fmt.Printf("  Ciphertext: %d bytes (incl. 16-byte tag)\n", len(ciphertext))
	fmt.Printf("  Key: %s\n", hexKey)
}
