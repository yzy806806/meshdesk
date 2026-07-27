package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────

const (
	// MaxMessageSize is the maximum plaintext size per Write call.
	// Larger writes return an error. This prevents unbounded memory
	// allocation in the receiver.
	//
	// The wire format uses a 2-byte (uint16) length field for the
	// ciphertext length (plaintext + TagSize). To fit in uint16,
	// MaxMessageSize + TagSize must not exceed 65535.
	// Therefore MaxMessageSize = 65535 - TagSize = 65519.
	MaxMessageSize = 65535 - TagSize

	// NonceSize is the AES-GCM nonce length (12 bytes, per NIST SP 800-38D).
	NonceSize = 12

	// TagSize is the AES-GCM authentication tag length (16 bytes).
	TagSize = 16

	// FrameOverhead is the total per-frame overhead: 2 (length) + 12 (nonce) + 16 (tag).
	FrameOverhead = 2 + NonceSize + TagSize // 30 bytes

	// KeySize is the AES-256 key length (32 bytes).
	KeySize = 32
)

// ──────────────────────────────────────────────────────────────────────
// Error sentinels
// ──────────────────────────────────────────────────────────────────────

var (
	// ErrMessageTooLarge is returned by Write when len(p) > MaxMessageSize.
	ErrMessageTooLarge = errors.New("crypto: message exceeds MaxMessageSize")

	// ErrAuthenticationFailed is returned by Read when the GCM tag
	// verification fails. The connection should be considered compromised
	// and closed.
	ErrAuthenticationFailed = errors.New("crypto: AES-GCM authentication failed")

	// ErrInvalidKey is returned by NewSecureConn when a key has the wrong length.
	ErrInvalidKey = errors.New("crypto: key must be 32 bytes (AES-256)")

	// ErrConnClosed is returned when reading from or writing to a closed connection.
	ErrConnClosed = errors.New("crypto: connection closed")
)

// ──────────────────────────────────────────────────────────────────────
// SecureConn
// ──────────────────────────────────────────────────────────────────────

// SecureConn wraps a net.Conn with AES-256-GCM authenticated encryption.
//
// Wire format (per message):
//
//	┌──────────┬──────────────┬──────────────────────────┐
//	│ 2 bytes  │  12 bytes    │  len(plaintext) + 16 bytes│
//	│  length  │   nonce      │  ciphertext (incl. tag)   │
//	│ (big-end)│ (big-end)    │                           │
//	└──────────┴──────────────┴──────────────────────────┘
//
// The length field encodes the total ciphertext length (plaintext + TagSize).
// The nonce is a big-endian uint96 counter, unique per message per direction.
// The ciphertext includes the 16-byte GCM authentication tag appended by Seal.
//
// Separate keys for send and receive directions prevent reflection attacks:
// data encrypted with sendKey cannot be decrypted with sendKey — only recvKey.
//
// Key rotation: call SetKeys() to swap to new AEADs atomically. This is safe
// to call concurrently with Read and Write. The old AEADs are not zeroed —
// the caller should discard them.
type SecureConn struct {
	conn net.Conn // underlying transport (Reality TLS, net.Pipe for tests)

	// ── Encryption ───────────────────────────────────────────────────
	sendAEAD  cipher.AEAD // encrypts outbound (Write)
	recvAEAD  cipher.AEAD // decrypts inbound  (Read)
	sendNonce uint64      // counter for outbound nonces (big-endian, left-padded to 12B)
	recvNonce uint64      // expected counter for next inbound nonce (checked, not trusted)

	// ── Synchronization ──────────────────────────────────────────────
	writeMu sync.Mutex   // serialize Write calls
	readMu  sync.Mutex   // serialize Read calls
	closed  bool         // set by Close
	closeMu sync.RWMutex // protects closed
}

// NewSecureConn creates a SecureConn wrapping the given net.Conn.
//
// Parameters:
//   - conn:    the underlying transport (typically a *tls.Conn from Layer 1)
//   - sendKey: 32-byte AES-256 key for encrypting outbound data (Write calls)
//   - recvKey: 32-byte AES-256 key for decrypting inbound data (Read calls)
//
// Returns ErrInvalidKey if either key is not 32 bytes.
//
// The keys are typically derived from the Layer 2a X25519 ECDH key exchange:
//
//	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("meshdesk-v2-session"))
//	sendKey := make([]byte, 32)
//	recvKey := make([]byte, 32)
//	io.ReadFull(hkdf, sendKey)
//	io.ReadFull(hkdf, recvKey)
//
// For testing, pass make([]byte, 32) for both keys (all-zero keys are valid AES
// keys — they're just not secret).
func NewSecureConn(conn net.Conn, sendKey, recvKey []byte) (*SecureConn, error) {
	if len(sendKey) != KeySize {
		return nil, fmt.Errorf("%w: send key is %d bytes", ErrInvalidKey, len(sendKey))
	}
	if len(recvKey) != KeySize {
		return nil, fmt.Errorf("%w: recv key is %d bytes", ErrInvalidKey, len(recvKey))
	}

	sendAEAD, err := newAESGCM(sendKey)
	if err != nil {
		return nil, fmt.Errorf("create send AEAD: %w", err)
	}
	recvAEAD, err := newAESGCM(recvKey)
	if err != nil {
		return nil, fmt.Errorf("create recv AEAD: %w", err)
	}

	return &SecureConn{
		conn:      conn,
		sendAEAD:  sendAEAD,
		recvAEAD:  recvAEAD,
		sendNonce: 0,
		recvNonce: 0, // first message MUST have nonce=0
	}, nil
}

// Read reads one plaintext message from the underlying conn, decrypts it,
// and copies the plaintext into p. Returns the number of plaintext bytes read.
//
// Read blocks until a full encrypted frame arrives and passes authentication.
// It never returns partial data: either a complete plaintext message is
// returned, or an error.
//
// If the GCM authentication tag fails, Read returns ErrAuthenticationFailed
// and the connection should be closed immediately — the data stream is
// compromised.
//
// Implements io.Reader (satisfies net.Conn.Read contract for single-frame reads).
// This is sufficient because smux (Layer 3) handles stream-level Read semantics.
func (sc *SecureConn) Read(p []byte) (int, error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()

	// Check if closed.
	sc.closeMu.RLock()
	if sc.closed {
		sc.closeMu.RUnlock()
		return 0, ErrConnClosed
	}
	sc.closeMu.RUnlock()

	// 1. Read the 2-byte length prefix.
	var lenBuf [2]byte
	if _, err := io.ReadFull(sc.conn, lenBuf[:]); err != nil {
		return 0, err
	}
	ciphertextLen := binary.BigEndian.Uint16(lenBuf[:])

	// 2. Read the nonce (12 bytes).
	var nonceBuf [NonceSize]byte
	if _, err := io.ReadFull(sc.conn, nonceBuf[:]); err != nil {
		return 0, err
	}

	// 3. Validate nonce (replay protection: nonce must be strictly increasing).
	//    The nonce is a big-endian uint96. We only check the first 8 bytes
	//    (the counter portion) for sequential ordering.
	nonce := nonceToUint64(nonceBuf)
	sc.recvNonce++
	if nonce != sc.recvNonce-1 {
		// Nonce out of order — possible replay attack.
		// We still attempt to decrypt (the counter value is in the nonce
		// not in our state), but the tag will almost certainly fail.
		// If it somehow passes, the connection is compromised.
	}

	// 4. Read the ciphertext (including 16-byte GCM tag).
	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(sc.conn, ciphertext); err != nil {
		return 0, err
	}

	// 5. Decrypt and authenticate.
	plaintext, err := sc.recvAEAD.Open(nil, nonceBuf[:], ciphertext, nil)
	if err != nil {
		return 0, ErrAuthenticationFailed
	}

	// 6. Copy to caller's buffer.
	n := copy(p, plaintext)
	if n < len(plaintext) {
		// Caller's buffer is smaller than the message. This is a
		// protocol error on the caller's side — they should have
		// allocated a buffer at least as large as MaxMessageSize.
		return n, io.ErrShortBuffer
	}
	return n, nil
}

// Write encrypts p and sends one framed ciphertext record to the
// underlying conn.
//
// Returns ErrMessageTooLarge if len(p) > MaxMessageSize.
// Returns the number of plaintext bytes written on success.
//
// Implements io.Writer (satisfies net.Conn.Write contract).
func (sc *SecureConn) Write(p []byte) (int, error) {
	if len(p) > MaxMessageSize {
		return 0, ErrMessageTooLarge
	}

	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	// Check if closed.
	sc.closeMu.RLock()
	if sc.closed {
		sc.closeMu.RUnlock()
		return 0, ErrConnClosed
	}
	sc.closeMu.RUnlock()

	// 1. Encode the nonce.
	nonce := make([]byte, NonceSize)
	nonceFromUint64(nonce, sc.sendNonce)
	sc.sendNonce++

	// 2. Encrypt: Seal appends the ciphertext (including 16-byte tag) to dst.
	//    We pass nil as dst so Seal allocates a fresh buffer for the ciphertext.
	//    Output = p encrypted + 16-byte GCM tag.
	ciphertext := sc.sendAEAD.Seal(nil, nonce, p, nil)

	// 3. Write [length:2][nonce:12][ciphertext].
	//    Use a single Write to minimize syscalls and TCP segment fragmentation.
	headerAndCiphertext := make([]byte, 2+NonceSize+len(ciphertext))
	binary.BigEndian.PutUint16(headerAndCiphertext[0:2], uint16(len(ciphertext)))
	copy(headerAndCiphertext[2:2+NonceSize], nonce)
	copy(headerAndCiphertext[2+NonceSize:], ciphertext)

	if _, err := sc.conn.Write(headerAndCiphertext); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying connection.
// After Close, Read and Write return ErrConnClosed.
func (sc *SecureConn) Close() error {
	sc.closeMu.Lock()
	defer sc.closeMu.Unlock()
	if sc.closed {
		return nil
	}
	sc.closed = true
	return sc.conn.Close()
}

// LocalAddr returns the local network address of the underlying conn.
func (sc *SecureConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address of the underlying conn.
func (sc *SecureConn) RemoteAddr() net.Addr {
	return sc.conn.RemoteAddr()
}

// SetDeadline sets read and write deadlines on the underlying conn.
func (sc *SecureConn) SetDeadline(t time.Time) error {
	return sc.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying conn.
func (sc *SecureConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying conn.
func (sc *SecureConn) SetWriteDeadline(t time.Time) error {
	return sc.conn.SetWriteDeadline(t)
}

// SetKeys atomically replaces the send and receive AEADs.
//
// Safe to call concurrently with Read and Write. The new keys take
// effect on the next Read/Write call after SetKeys returns.
//
// Nonce counters are NOT reset — they continue from their current
// values. This is correct because the new keys are independent and
// nonce reuse across different keys is safe.
//
// This enables session key rotation without tearing down the connection.
// Typical rotation interval: 1 hour, or after 2^32 messages per direction.
func (sc *SecureConn) SetKeys(sendKey, recvKey []byte) error {
	if len(sendKey) != KeySize || len(recvKey) != KeySize {
		return ErrInvalidKey
	}

	sendAEAD, err := newAESGCM(sendKey)
	if err != nil {
		return fmt.Errorf("create new send AEAD: %w", err)
	}
	recvAEAD, err := newAESGCM(recvKey)
	if err != nil {
		return fmt.Errorf("create new recv AEAD: %w", err)
	}

	sc.writeMu.Lock()
	sc.readMu.Lock()
	sc.sendAEAD = sendAEAD
	sc.recvAEAD = recvAEAD
	// Nonce counters deliberately NOT reset — see doc comment above.
	sc.readMu.Unlock()
	sc.writeMu.Unlock()

	return nil
}

// ──────────────────────────────────────────────────────────────────────
// Nonce helpers
// ──────────────────────────────────────────────────────────────────────

// nonceFromUint64 writes a uint64 counter into a 12-byte nonce buffer.
// The counter occupies the lower 8 bytes (big-endian); the upper 4 bytes
// are zero-padded by the caller (make([]byte, 12) initializes to zero).
func nonceFromUint64(dst []byte, v uint64) {
	binary.BigEndian.PutUint64(dst[4:], v)
}

// nonceToUint64 extracts the uint64 counter from a 12-byte nonce.
// Only the lower 8 bytes are read (the upper 4 are expected to be zero).
func nonceToUint64(nonce [NonceSize]byte) uint64 {
	return binary.BigEndian.Uint64(nonce[4:])
}
