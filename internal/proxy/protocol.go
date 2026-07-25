// Package proxy implements the MeshDesk anonymous proxy system.
//
// This file defines the circuit protocol: wire-level structures for
// the multi-path dispersed transport. It implements:
//
//   - ForwardingHeader: fixed 64-byte onion-encrypted per-hop header
//   - WireChunk: on-wire chunk format (header + AEAD-encrypted payload)
//   - ECDH key agreement for entry↔exit end-to-end encryption
//   - ChaCha20-Poly1305 AEAD encryption for per-chunk payload
//   - Circuit setup/teardown/keepalive control messages
//
// See docs/PROXY_DESIGN.md §1.2 (Chunk Format), §1.4 (ECDH Key Agreement),
// §1.7 (Identity Trust Boundary), §1.8 (Circuit Lifecycle), §1.9
// (Forwarding Header Obfuscation).
package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Wire constants for the circuit protocol.
const (
	// ForwardingHeaderSize is the fixed size of the onion-encrypted
	// per-hop forwarding header. Each relay decrypts this header with
	// its own key, reads the next-hop address, and re-encrypts with
	// the next relay's key. The header is fixed-size to prevent
	// length-based fingerprinting (PROXY_DESIGN.md §1.9).
	ForwardingHeaderSize = 64

	// NonceSize is the size of the AEAD nonce (ChaCha20-Poly1305 uses 12 bytes).
	NonceSize = chacha20poly1305.NonceSize

	// KeySize is the size of the ChaCha20-Poly1305 key (32 bytes).
	KeySize = chacha20poly1305.KeySize

	// SaltSize is the size of the ECDH-derived key salt.
	SaltSize = 16

	// CircuitIDSize is the size of a circuit identifier.
	CircuitIDSize = 16

	// MaxChunkPayloadSize is the maximum payload size (64KB).
	MaxChunkPayloadSize = 64 * 1024

	// MinChunkPayloadSize is the minimum payload size (4KB for bounded mode).
	MinChunkPayloadSize = 4 * 1024
)

// CircuitState represents the lifecycle state of a circuit.
type CircuitState byte

const (
	// CircuitCreating: setup in progress, ECDH handshake not yet complete.
	CircuitCreating CircuitState = 0x01

	// CircuitActive: ECDH complete, data flowing on both paths.
	CircuitActive CircuitState = 0x02

	// CircuitTeardown: teardown initiated, flushing remaining data.
	CircuitTeardown CircuitState = 0x03

	// CircuitClosed: circuit fully closed, resources freed.
	CircuitClosed CircuitState = 0x04
)

// MessageType classifies a control or data message on a circuit.
type MessageType byte

const (
	// MsgCircuitSetup: entry → exit, carries ECDH pubkey + target addr.
	MsgCircuitSetup MessageType = 0x01

	// MsgCircuitAck: exit → entry, carries ECDH pubkey + accept/reject.
	MsgCircuitAck MessageType = 0x02

	// MsgCircuitTeardown: either side, signals circuit closure.
	MsgCircuitTeardown MessageType = 0x03

	// MsgKeepalive: entry → exit, prevents idle timeout + measures RTT.
	MsgKeepalive MessageType = 0x04

	// MsgNACK: exit → entry, requests retransmission of missing chunk(s).
	MsgNACK MessageType = 0x05

	// MsgData: carries a chunk payload.
	MsgData MessageType = 0x06

	// MsgACK: exit → entry, window-based acknowledgment for received chunks.
	MsgACK MessageType = 0x07
)

// ForwardingHeader is the 64-byte onion-encrypted per-hop header.
// Each relay in the path decrypts this with its own key to learn
// the next-hop address, then re-encrypts for the next relay.
//
// Layout (before encryption):
//   bytes 0-1:  next-hop address length (uint16, max 62)
//   bytes 2-N:  next-hop address (mesh IP or relay ID)
//   bytes N+1:  remaining bytes are random padding to fill 64 bytes
//
// After encryption, the entire 64 bytes appear as random ciphertext.
// No relay can reconstruct the full path.
type ForwardingHeader struct {
	// NextHop is the mesh address of the next relay or exit node.
	NextHop string
}

// Encode encrypts the forwarding header for a specific relay using
// onion-style encryption. The relayKey is the symmetric key shared
// with this relay (derived from the relay's ECDH key exchange).
//
// The encrypted header is exactly ForwardingHeaderSize (64) bytes.
func (h *ForwardingHeader) Encode(relayKey []byte) ([]byte, error) {
	if len(relayKey) != KeySize {
		return nil, fmt.Errorf("relay key must be %d bytes, got %d", KeySize, len(relayKey))
	}

	// Build the plaintext header.
	plaintext := make([]byte, ForwardingHeaderSize)
	addrLen := len(h.NextHop)
	if addrLen > ForwardingHeaderSize-3 { // 2 bytes for length + 1 byte min padding
		return nil, fmt.Errorf("next-hop address too long: %d bytes (max %d)",
			addrLen, ForwardingHeaderSize-3)
	}

	binary.BigEndian.PutUint16(plaintext[0:2], uint16(addrLen))
	copy(plaintext[2:], []byte(h.NextHop))

	// Fill remaining bytes with random padding.
	if ForwardingHeaderSize-2-addrLen > 0 {
		if _, err := rand.Read(plaintext[2+addrLen:]); err != nil {
			return nil, fmt.Errorf("generate header padding: %w", err)
		}
	}

	// Encrypt with AES-CTR (no authentication needed for the header —
	// the payload has AEAD, and the header is per-hop ephemeral).
	// Using AES-CTR for simplicity; the header is short-lived.
	block, err := aes.NewCipher(relayKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Use a zero IV for the header — the relayKey is unique per relay
	// per circuit, so IV reuse across circuits is not a concern.
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, ForwardingHeaderSize)
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

// DecodeForwardingHeader decrypts a 64-byte forwarding header using
// the relay's key and extracts the next-hop address.
func DecodeForwardingHeader(encrypted []byte, relayKey []byte) (*ForwardingHeader, error) {
	if len(encrypted) != ForwardingHeaderSize {
		return nil, fmt.Errorf("header must be %d bytes, got %d", ForwardingHeaderSize, len(encrypted))
	}
	if len(relayKey) != KeySize {
		return nil, fmt.Errorf("relay key must be %d bytes, got %d", KeySize, len(relayKey))
	}

	block, err := aes.NewCipher(relayKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, ForwardingHeaderSize)
	stream.XORKeyStream(plaintext, encrypted)

	addrLen := binary.BigEndian.Uint16(plaintext[0:2])
	if int(addrLen) > ForwardingHeaderSize-2 {
		return nil, fmt.Errorf("invalid next-hop address length: %d", addrLen)
	}

	return &ForwardingHeader{
		NextHop: string(plaintext[2 : 2+addrLen]),
	}, nil
}

// WireChunk is the on-wire representation of a chunk: forwarding header
// + AEAD-encrypted payload. The payload includes the Chunk metadata
// (StreamID, Sequence, Total, Type) and the application data.
//
// Wire layout:
//   [ForwardingHeader (64 bytes)]
//   [Nonce (12 bytes)]
//   [AEAD Ciphertext (chunk metadata + payload + 16-byte auth tag)]
type WireChunk struct {
	Header  []byte // 64-byte onion-encrypted forwarding header
	Nonce   []byte // 12-byte AEAD nonce
	Ciphertext []byte // AEAD-encrypted payload
}

// EncodeChunk encrypts a Chunk for end-to-end transport (entry → exit).
// The e2eKey is the shared ChaCha20-Poly1305 key derived from ECDH.
// The relayKey is used for the per-hop forwarding header.
//
// The encrypted payload format:
//   [StreamID (4)] [Sequence (4)] [Total (4)] [Type (1)] [PaddingLen (2)]
//   [PayloadLen (4)] [Payload (variable)]
//   + 16-byte Poly1305 auth tag (added by AEAD)
func EncodeChunk(chunk Chunk, e2eKey []byte, relayKey []byte, nextHop string) (*WireChunk, error) {
	if len(e2eKey) != KeySize {
		return nil, fmt.Errorf("e2e key must be %d bytes, got %d", KeySize, len(e2eKey))
	}

	// Build the plaintext (metadata + payload).
	payloadLen := len(chunk.Payload)
	// Metadata: StreamID(4) + Sequence(4) + Total(4) + Type(1) + PaddingLen(2) + PayloadLen(4) = 19 bytes
	metaSize := 19
	plaintext := make([]byte, metaSize+payloadLen)

	binary.BigEndian.PutUint32(plaintext[0:4], chunk.StreamID)
	binary.BigEndian.PutUint32(plaintext[4:8], chunk.Sequence)
	binary.BigEndian.PutUint32(plaintext[8:12], chunk.Total)
	plaintext[12] = byte(chunk.Type)
	binary.BigEndian.PutUint16(plaintext[13:15], chunk.PaddingLen)
	binary.BigEndian.PutUint32(plaintext[15:19], uint32(payloadLen))
	copy(plaintext[19:], chunk.Payload)

	// Generate a random nonce.
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt with ChaCha20-Poly1305 AEAD.
	aead, err := chacha20poly1305.New(e2eKey)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	// Associated data: the forwarding header binds the ciphertext to
	// its routing context, preventing header swapping attacks.
	header, err := (&ForwardingHeader{NextHop: nextHop}).Encode(relayKey)
	if err != nil {
		return nil, fmt.Errorf("encode forwarding header: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, header)

	return &WireChunk{
		Header:     header,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// DecodeChunk decrypts a WireChunk back into a Chunk using the E2E key.
// This is called by the exit node after receiving the chunk.
func DecodeChunk(wc *WireChunk, e2eKey []byte) (Chunk, error) {
	if len(e2eKey) != KeySize {
		return Chunk{}, fmt.Errorf("e2e key must be %d bytes, got %d", KeySize, len(e2eKey))
	}
	if len(wc.Nonce) != NonceSize {
		return Chunk{}, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(wc.Nonce))
	}
	if len(wc.Header) != ForwardingHeaderSize {
		return Chunk{}, fmt.Errorf("header must be %d bytes, got %d", ForwardingHeaderSize, len(wc.Header))
	}

	aead, err := chacha20poly1305.New(e2eKey)
	if err != nil {
		return Chunk{}, fmt.Errorf("create AEAD: %w", err)
	}

	// Decrypt with the forwarding header as associated data.
	plaintext, err := aead.Open(nil, wc.Nonce, wc.Ciphertext, wc.Header)
	if err != nil {
		return Chunk{}, fmt.Errorf("AEAD decrypt failed: %w", err)
	}

	// Parse metadata.
	if len(plaintext) < 19 {
		return Chunk{}, fmt.Errorf("plaintext too short: %d bytes (min 19)", len(plaintext))
	}

	chunk := Chunk{
		StreamID:   binary.BigEndian.Uint32(plaintext[0:4]),
		Sequence:   binary.BigEndian.Uint32(plaintext[4:8]),
		Total:      binary.BigEndian.Uint32(plaintext[8:12]),
		Type:       ChunkType(plaintext[12]),
		PaddingLen: binary.BigEndian.Uint16(plaintext[13:15]),
	}

	payloadLen := binary.BigEndian.Uint32(plaintext[15:19])
	if int(payloadLen) != len(plaintext)-19 {
		return Chunk{}, fmt.Errorf("payload length mismatch: declared %d, actual %d",
			payloadLen, len(plaintext)-19)
	}

	chunk.Payload = make([]byte, payloadLen)
	copy(chunk.Payload, plaintext[19:])

	return chunk, nil
}

// ECDHKeyPair holds an X25519 key pair for circuit ECDH key agreement.
type ECDHKeyPair struct {
	Private []byte // 32 bytes
	Public  []byte // 32 bytes
}

// GenerateECDHKeyPair generates a new X25519 key pair for circuit setup.
func GenerateECDHKeyPair() (*ECDHKeyPair, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	// Clamp per Curve25519 spec.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	return &ECDHKeyPair{Private: priv, Public: pub}, nil
}

// DeriveSharedKey performs X25519 ECDH and derives a ChaCha20-Poly1305
// key from the shared secret using HKDF-like derivation.
//
// This is called by both entry and exit nodes after exchanging ECDH
// public keys. The resulting key is used for all AEAD encryption on
// the circuit.
func DeriveSharedKey(privKey []byte, peerPubKey []byte) ([]byte, error) {
	if len(privKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privKey))
	}
	if len(peerPubKey) != 32 {
		return nil, fmt.Errorf("peer public key must be 32 bytes, got %d", len(peerPubKey))
	}

	shared, err := curve25519.X25519(privKey, peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("X25519: %w", err)
	}

	// Derive a 32-byte key from the shared secret using a simple
	// HKDF-like construction (extract-then-expand). We use HMAC-SHA256
	// for the extract step and a single-block expand.
	//
	// For simplicity, we hash the shared secret with a domain separator.
	// In production, use crypto/hkdf from the standard library (Go 1.24+)
	// or golang.org/x/crypto/hkdf.
	return deriveKey(shared, []byte("meshdesk-circuit-e2e-v1")), nil
}

// deriveKey derives a 32-byte key from a secret using HMAC-SHA256.
// This is a minimal HKDF-Extract-then-Expand.
func deriveKey(secret, info []byte) []byte {
	// Extract: PRK = HMAC(salt, IKM)
	// We use a zero salt (the shared secret already has high entropy).
	h := newHMACSHA256(append([]byte("meshdesk-prk:"), secret...))
	prk := h

	// Expand: OKM = HMAC(PRK, info || 0x01)
	expandInput := append(append([]byte{}, info...), 0x01)
	okm := newHMACSHA256WithKey(prk, expandInput)

	// Truncate to 32 bytes (HMAC-SHA256 output is already 32 bytes).
	return okm[:KeySize]
}

// newHMACSHA256 computes HMAC-SHA256(key, data) using a zero key.
func newHMACSHA256(data []byte) []byte {
	return newHMACSHA256WithKey(make([]byte, 32), data)
}

// newHMACSHA256WithKey computes HMAC-SHA256(key, data).
func newHMACSHA256WithKey(key, data []byte) []byte {
	// Inline HMAC-SHA256 to avoid importing crypto/hmac separately.
	// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
	// where K' is K padded to block size (64 bytes for SHA-256).
	const blockSize = 64

	// Pad key to block size.
	k := make([]byte, blockSize)
	copy(k, key)

	// Create ipad and opad.
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}

	// Inner hash: H(ipad || data)
	inner := sha256Hash(append(ipad, data...))
	// Outer hash: H(opad || inner)
	return sha256Hash(append(opad, inner...))
}

// sha256Hash computes SHA-256 using the standard library.
func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// CircuitSetup is the control message sent from entry to exit during
// circuit creation. It carries the entry's ECDH public key and the
// target address (CONNECT-style for port validation).
type CircuitSetup struct {
	CircuitID  []byte // 16-byte unique circuit identifier
	ECDHPubKey []byte // 32-byte X25519 public key
	TargetAddr string // host:port (CONNECT-style for exit port validation)
}

// Encode serializes the CircuitSetup message to bytes.
func (cs *CircuitSetup) Encode() ([]byte, error) {
	if len(cs.CircuitID) != CircuitIDSize {
		return nil, fmt.Errorf("circuit ID must be %d bytes", CircuitIDSize)
	}
	if len(cs.ECDHPubKey) != 32 {
		return nil, fmt.Errorf("ECDH public key must be 32 bytes")
	}

	// Format: [CircuitID (16)] [ECDHPubKey (32)] [TargetLen (2)] [TargetAddr]
	targetLen := len(cs.TargetAddr)
	if targetLen > 65535 {
		return nil, fmt.Errorf("target address too long: %d", targetLen)
	}

	buf := make([]byte, 0, CircuitIDSize+32+2+targetLen)
	buf = append(buf, cs.CircuitID...)
	buf = append(buf, cs.ECDHPubKey...)
	tlen := make([]byte, 2)
	binary.BigEndian.PutUint16(tlen, uint16(targetLen))
	buf = append(buf, tlen...)
	buf = append(buf, []byte(cs.TargetAddr)...)
	return buf, nil
}

// DecodeCircuitSetup deserializes a CircuitSetup message from bytes.
func DecodeCircuitSetup(data []byte) (*CircuitSetup, error) {
	if len(data) < CircuitIDSize+32+2 {
		return nil, fmt.Errorf("data too short: %d bytes (min %d)",
			len(data), CircuitIDSize+32+2)
	}

	cs := &CircuitSetup{
		CircuitID:  data[:CircuitIDSize],
		ECDHPubKey: data[CircuitIDSize : CircuitIDSize+32],
	}

	targetLen := binary.BigEndian.Uint16(data[CircuitIDSize+32:])
	targetStart := CircuitIDSize + 32 + 2
	if int(targetLen) != len(data)-targetStart {
		return nil, fmt.Errorf("target length mismatch: declared %d, actual %d",
			targetLen, len(data)-targetStart)
	}
	cs.TargetAddr = string(data[targetStart:])
	return cs, nil
}

// CircuitAck is the response from exit to entry during circuit creation.
type CircuitAck struct {
	CircuitID  []byte // matches the setup CircuitID
	ECDHPubKey []byte // exit's X25519 public key
	Accepted   bool   // true if exit accepts the circuit
	Reason     string // rejection reason if Accepted=false
}

// Encode serializes the CircuitAck message.
func (ca *CircuitAck) Encode() ([]byte, error) {
	if len(ca.CircuitID) != CircuitIDSize {
		return nil, fmt.Errorf("circuit ID must be %d bytes", CircuitIDSize)
	}
	if len(ca.ECDHPubKey) != 32 {
		return nil, fmt.Errorf("ECDH public key must be 32 bytes")
	}

	reasonLen := len(ca.Reason)
	buf := make([]byte, 0, CircuitIDSize+32+1+2+reasonLen)
	buf = append(buf, ca.CircuitID...)
	buf = append(buf, ca.ECDHPubKey...)

	if ca.Accepted {
		buf = append(buf, 0x01)
	} else {
		buf = append(buf, 0x00)
	}

	rlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rlen, uint16(reasonLen))
	buf = append(buf, rlen...)
	buf = append(buf, []byte(ca.Reason)...)
	return buf, nil
}

// DecodeCircuitAck deserializes a CircuitAck message.
func DecodeCircuitAck(data []byte) (*CircuitAck, error) {
	if len(data) < CircuitIDSize+32+1+2 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	ca := &CircuitAck{
		CircuitID:  data[:CircuitIDSize],
		ECDHPubKey: data[CircuitIDSize : CircuitIDSize+32],
	}

	ca.Accepted = data[CircuitIDSize+32] == 0x01

	reasonLen := binary.BigEndian.Uint16(data[CircuitIDSize+33:])
	reasonStart := CircuitIDSize + 33 + 2
	if int(reasonLen) > len(data)-reasonStart {
		return nil, fmt.Errorf("reason length overflows data")
	}
	ca.Reason = string(data[reasonStart : reasonStart+int(reasonLen)])
	return ca, nil
}

// TeardownMsg is the control message to close a circuit.
type TeardownMsg struct {
	CircuitID []byte
	Reason    string
}

// Encode serializes the TeardownMsg message.
func (ct *TeardownMsg) Encode() ([]byte, error) {
	if len(ct.CircuitID) != CircuitIDSize {
		return nil, fmt.Errorf("circuit ID must be %d bytes", CircuitIDSize)
	}

	reasonLen := len(ct.Reason)
	buf := make([]byte, 0, CircuitIDSize+2+reasonLen)
	buf = append(buf, ct.CircuitID...)
	rlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rlen, uint16(reasonLen))
	buf = append(buf, rlen...)
	buf = append(buf, []byte(ct.Reason)...)
	return buf, nil
}

// DecodeTeardown deserializes a TeardownMsg message.
func DecodeTeardown(data []byte) (*TeardownMsg, error) {
	if len(data) < CircuitIDSize+2 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	ct := &TeardownMsg{
		CircuitID: data[:CircuitIDSize],
	}

	reasonLen := binary.BigEndian.Uint16(data[CircuitIDSize:])
	reasonStart := CircuitIDSize + 2
	if int(reasonLen) > len(data)-reasonStart {
		return nil, fmt.Errorf("reason length overflows data")
	}
	ct.Reason = string(data[reasonStart : reasonStart+int(reasonLen)])
	return ct, nil
}

// KeepaliveMsg is a periodic ping to prevent idle timeout and measure RTT.
type KeepaliveMsg struct {
	CircuitID []byte
	Timestamp int64 // unix nanoseconds for RTT measurement
}

// Encode serializes a KeepaliveMsg.
func (k *KeepaliveMsg) Encode() ([]byte, error) {
	if len(k.CircuitID) != CircuitIDSize {
		return nil, fmt.Errorf("circuit ID must be %d bytes", CircuitIDSize)
	}
	buf := make([]byte, CircuitIDSize+8)
	copy(buf[:CircuitIDSize], k.CircuitID)
	binary.BigEndian.PutUint64(buf[CircuitIDSize:], uint64(k.Timestamp))
	return buf, nil
}

// DecodeKeepalive deserializes a KeepaliveMsg.
func DecodeKeepalive(data []byte) (*KeepaliveMsg, error) {
	if len(data) < CircuitIDSize+8 {
		return nil, fmt.Errorf("data too short: %d bytes (need %d)", len(data), CircuitIDSize+8)
	}
	return &KeepaliveMsg{
		CircuitID: data[:CircuitIDSize],
		Timestamp: int64(binary.BigEndian.Uint64(data[CircuitIDSize:])),
	}, nil
}

// NACKMsg is the exit→entry retransmission request for missing chunks.
type NACKMsg struct {
	CircuitID []byte
	StreamID  uint32
	// MissingSeqs is the list of missing sequence numbers.
	MissingSeqs []uint32
}

// Encode serializes a NACKMsg.
func (n *NACKMsg) Encode() ([]byte, error) {
	if len(n.CircuitID) != CircuitIDSize {
		return nil, fmt.Errorf("circuit ID must be %d bytes", CircuitIDSize)
	}

	// Format: [CircuitID (16)] [StreamID (4)] [Count (2)] [Seqs (4*Count)]
	count := len(n.MissingSeqs)
	buf := make([]byte, CircuitIDSize+4+2+4*count)
	copy(buf[:CircuitIDSize], n.CircuitID)
	binary.BigEndian.PutUint32(buf[CircuitIDSize:], n.StreamID)
	binary.BigEndian.PutUint16(buf[CircuitIDSize+4:], uint16(count))

	offset := CircuitIDSize + 6
	for _, seq := range n.MissingSeqs {
		binary.BigEndian.PutUint32(buf[offset:], seq)
		offset += 4
	}
	return buf, nil
}

// DecodeNACK deserializes a NACKMsg.
func DecodeNACK(data []byte) (*NACKMsg, error) {
	if len(data) < CircuitIDSize+6 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	n := &NACKMsg{
		CircuitID: data[:CircuitIDSize],
		StreamID:  binary.BigEndian.Uint32(data[CircuitIDSize:]),
	}

	count := binary.BigEndian.Uint16(data[CircuitIDSize+4:])
	n.MissingSeqs = make([]uint32, count)

	offset := CircuitIDSize + 6
	for i := 0; i < int(count); i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("NACK seq %d overflows data", i)
		}
		n.MissingSeqs[i] = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}
	return n, nil
}

// GenerateCircuitID generates a random 16-byte circuit identifier.
func GenerateCircuitID() ([]byte, error) {
	id := make([]byte, CircuitIDSize)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generate circuit ID: %w", err)
	}
	return id, nil
}

// CircuitConfig holds configuration for circuit management.
type CircuitConfig struct {
	// IdleTimeout is how long a circuit stays active without data
	// before automatic teardown. Default: 5 minutes.
	IdleTimeout time.Duration

	// KeepaliveInterval is how often the entry sends keepalive pings.
	// Default: 30 seconds.
	KeepaliveInterval time.Duration

	// NACKTimeout is how long the exit waits for a missing chunk
	// before sending a NACK. Default: 5 seconds.
	NACKTimeout time.Duration

	// OrphanTimeout is how long the exit keeps an incomplete reassembly
	// buffer before cleaning it up. Default: 30 seconds.
	OrphanTimeout time.Duration

	// MaxReassemblyWindow is the hard limit on reassembly window size
	// (chunks ahead of the highest contiguous byte). Default: 256.
	MaxReassemblyWindow int
}

// DefaultCircuitConfig returns sensible defaults for circuit management.
func DefaultCircuitConfig() CircuitConfig {
	return CircuitConfig{
		IdleTimeout:         5 * time.Minute,
		KeepaliveInterval:   30 * time.Second,
		NACKTimeout:         5 * time.Second,
		OrphanTimeout:       30 * time.Second,
		MaxReassemblyWindow: 256,
	}
}

// Common errors.
var (
	ErrCircuitNotFound    = errors.New("circuit not found")
	ErrCircuitClosed      = errors.New("circuit is closed")
	ErrInvalidCircuitState = errors.New("invalid circuit state transition")
	ErrAEADDecryptFailed   = errors.New("AEAD decryption failed")
)
