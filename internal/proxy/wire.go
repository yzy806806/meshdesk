// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file implements the wire-level serialization for WireChunk:
// converting between the in-memory WireChunk struct and the byte
// sequence sent over TCP between relay nodes.
//
// Wire format (all integers big-endian):
//
//	[HeaderLen  (2 bytes)]  — always ForwardingHeaderSize (64)
//	[Header     (64 bytes)] — onion-encrypted forwarding header
//	[NonceLen   (2 bytes)]  — always NonceSize (12)
//	[Nonce      (12 bytes)] — AEAD nonce
//	[CipherLen  (4 bytes)]  — length of AEAD ciphertext
//	[Ciphertext (variable)] — AEAD-encrypted payload
//
// The length prefixes allow a relay to read a complete chunk without
// any framing protocol — it reads the fixed fields, then reads
// CipherLen bytes. The relay never decrypts the ciphertext; it only
// reads the header to determine the next hop.
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxWireCiphertextSize is the maximum allowed AEAD ciphertext size
// on the wire. This is MaxChunkPayloadSize + metadata overhead +
// Poly1305 tag. We allow some headroom to accommodate padding.
const MaxWireCiphertextSize = MaxChunkPayloadSize + 256 + 16 // ~65.8KB

// SerializeWireChunk serializes a WireChunk into a byte slice
// suitable for sending over a TCP connection.
func SerializeWireChunk(wc *WireChunk) ([]byte, error) {
	if len(wc.Header) != ForwardingHeaderSize {
		return nil, fmt.Errorf("header must be %d bytes, got %d", ForwardingHeaderSize, len(wc.Header))
	}
	if len(wc.Nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(wc.Nonce))
	}
	if len(wc.Ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}
	if len(wc.Ciphertext) > MaxWireCiphertextSize {
		return nil, fmt.Errorf("ciphertext too large: %d bytes (max %d)", len(wc.Ciphertext), MaxWireCiphertextSize)
	}

	// Total size: 2 + 64 + 2 + 12 + 4 + len(ciphertext)
	total := 2 + ForwardingHeaderSize + 2 + NonceSize + 4 + len(wc.Ciphertext)
	buf := make([]byte, 0, total)

	// Header length (2 bytes) + header
	hdrLen := make([]byte, 2)
	binary.BigEndian.PutUint16(hdrLen, uint16(ForwardingHeaderSize))
	buf = append(buf, hdrLen...)
	buf = append(buf, wc.Header...)

	// Nonce length (2 bytes) + nonce
	nonceLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nonceLen, uint16(NonceSize))
	buf = append(buf, nonceLen...)
	buf = append(buf, wc.Nonce...)

	// Ciphertext length (4 bytes) + ciphertext
	cipherLen := make([]byte, 4)
	binary.BigEndian.PutUint32(cipherLen, uint32(len(wc.Ciphertext)))
	buf = append(buf, cipherLen...)
	buf = append(buf, wc.Ciphertext...)

	return buf, nil
}

// DeserializeWireChunk parses a byte slice into a WireChunk.
// The input must be a complete serialized chunk (as produced by
// SerializeWireChunk). Returns the number of bytes consumed.
func DeserializeWireChunk(data []byte) (*WireChunk, int, error) {
	minSize := 2 + ForwardingHeaderSize + 2 + NonceSize + 4
	if len(data) < minSize {
		return nil, 0, fmt.Errorf("data too short: %d bytes (min %d)", len(data), minSize)
	}

	offset := 0

	// Read header length.
	hdrLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(hdrLen) != ForwardingHeaderSize {
		return nil, 0, fmt.Errorf("header length = %d, expected %d", hdrLen, ForwardingHeaderSize)
	}
	if offset+int(hdrLen) > len(data) {
		return nil, 0, fmt.Errorf("header overflows data")
	}
	header := make([]byte, hdrLen)
	copy(header, data[offset:offset+int(hdrLen)])
	offset += int(hdrLen)

	// Read nonce length.
	nonceLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(nonceLen) != NonceSize {
		return nil, 0, fmt.Errorf("nonce length = %d, expected %d", nonceLen, NonceSize)
	}
	if offset+int(nonceLen) > len(data) {
		return nil, 0, fmt.Errorf("nonce overflows data")
	}
	nonce := make([]byte, nonceLen)
	copy(nonce, data[offset:offset+int(nonceLen)])
	offset += int(nonceLen)

	// Read ciphertext length.
	cipherLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if cipherLen == 0 {
		return nil, 0, fmt.Errorf("ciphertext length is 0")
	}
	if cipherLen > MaxWireCiphertextSize {
		return nil, 0, fmt.Errorf("ciphertext too large: %d bytes (max %d)", cipherLen, MaxWireCiphertextSize)
	}
	if offset+int(cipherLen) > len(data) {
		return nil, 0, fmt.Errorf("ciphertext overflows data: need %d more bytes, have %d",
			cipherLen, len(data)-offset)
	}
	ciphertext := make([]byte, cipherLen)
	copy(ciphertext, data[offset:offset+int(cipherLen)])
	offset += int(cipherLen)

	return &WireChunk{
		Header:     header,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, offset, nil
}

// WriteWireChunk writes a WireChunk to an io.Writer. This is the
// streaming version of SerializeWireChunk, suitable for writing
// directly to a TCP connection.
func WriteWireChunk(w io.Writer, wc *WireChunk) error {
	data, err := SerializeWireChunk(wc)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ReadWireChunk reads a WireChunk from an io.Reader. This reads
// the framing fields in order, then reads the variable-length
// ciphertext. It uses io.ReadFull to ensure complete reads.
func ReadWireChunk(r io.Reader) (*WireChunk, error) {
	// Read header length (2 bytes).
	hdrLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, hdrLenBuf); err != nil {
		return nil, fmt.Errorf("read header length: %w", err)
	}
	hdrLen := binary.BigEndian.Uint16(hdrLenBuf)
	if int(hdrLen) != ForwardingHeaderSize {
		return nil, fmt.Errorf("header length = %d, expected %d", hdrLen, ForwardingHeaderSize)
	}

	// Read header.
	header := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Read nonce length (2 bytes).
	nonceLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, nonceLenBuf); err != nil {
		return nil, fmt.Errorf("read nonce length: %w", err)
	}
	nonceLen := binary.BigEndian.Uint16(nonceLenBuf)
	if int(nonceLen) != NonceSize {
		return nil, fmt.Errorf("nonce length = %d, expected %d", nonceLen, NonceSize)
	}

	// Read nonce.
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	// Read ciphertext length (4 bytes).
	cipherLenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, cipherLenBuf); err != nil {
		return nil, fmt.Errorf("read ciphertext length: %w", err)
	}
	cipherLen := binary.BigEndian.Uint32(cipherLenBuf)
	if cipherLen == 0 {
		return nil, fmt.Errorf("ciphertext length is 0")
	}
	if cipherLen > MaxWireCiphertextSize {
		return nil, fmt.Errorf("ciphertext too large: %d bytes (max %d)", cipherLen, MaxWireCiphertextSize)
	}

	// Read ciphertext.
	ciphertext := make([]byte, cipherLen)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, fmt.Errorf("read ciphertext: %w", err)
	}

	return &WireChunk{
		Header:     header,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}
