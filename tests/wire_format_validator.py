#!/usr/bin/env python3
"""
Wire format validator for MeshDesk v2 Layer 2b (AES-256-GCM Encryption).

AC-L2.I3: Wire format compliance — external validator.

This script demonstrates that the wire format produced by Go's SecureConn
can be parsed and decrypted by a non-Go implementation using standard
AES-256-GCM.

Wire format (per message):
    [2 bytes: length (uint16 big-endian)] [12 bytes: nonce] [length bytes: ciphertext]

The ciphertext includes the 16-byte GCM authentication tag appended by Seal.

Usage:
    python3 wire_format_validator.py <wire_file> <hex_key>

    wire_file: binary file containing the raw wire bytes from a SecureConn.Write
    hex_key:   32-byte AES-256 key in hex (64 hex chars)

Example:
    # In Go, write encrypted data to a file:
    #   sc.Write([]byte("hello world"))
    #   // capture the raw bytes written to the underlying conn

    # Then decrypt with this script:
    python3 wire_format_validator.py wire.bin 0000000000000000000000000000000000000000000000000000000000000000
"""

import sys
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def parse_and_decrypt(wire_data: bytes, key: bytes) -> bytes:
    """
    Parse the wire format and decrypt the message.

    Returns the plaintext.
    """
    offset = 0

    # 1. Read 2-byte length prefix (uint16 big-endian).
    if len(wire_data) < 2:
        raise ValueError("wire data too short for length prefix")
    ct_len = struct.unpack(">H", wire_data[offset:offset+2])[0]
    offset += 2

    # 2. Read 12-byte nonce.
    if len(wire_data) < offset + 12:
        raise ValueError("wire data too short for nonce")
    nonce = wire_data[offset:offset+12]
    offset += 12

    # 3. Read ciphertext (including 16-byte GCM tag).
    if len(wire_data) < offset + ct_len:
        raise ValueError(f"wire data too short for ciphertext: expected {ct_len} bytes, got {len(wire_data) - offset}")
    ciphertext = wire_data[offset:offset+ct_len]
    offset += ct_len

    # 4. Decrypt with AES-256-GCM.
    aead = AESGCM(key)
    plaintext = aead.decrypt(nonce, ciphertext, None)

    return plaintext


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <wire_file> <hex_key>")
        print(f"  wire_file: binary file containing raw wire bytes from SecureConn.Write")
        print(f"  hex_key:   32-byte AES-256 key in hex (64 hex chars)")
        sys.exit(1)

    wire_file = sys.argv[1]
    hex_key = sys.argv[2]

    key = bytes.fromhex(hex_key)
    if len(key) != 32:
        print(f"Error: key must be 32 bytes (64 hex chars), got {len(key)} bytes")
        sys.exit(1)

    with open(wire_file, "rb") as f:
        wire_data = f.read()

    try:
        plaintext = parse_and_decrypt(wire_data, key)
        print(f"Decryption successful!")
        print(f"  Plaintext ({len(plaintext)} bytes): {plaintext}")
        if len(plaintext) <= 100:
            try:
                print(f"  As string: {plaintext.decode('utf-8')}")
            except UnicodeDecodeError:
                pass
    except Exception as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
