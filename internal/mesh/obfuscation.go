// Package mesh provides the WireGuard mesh VPN core: device management,
// gVisor netstack integration, routing, and the pluggable obfuscation shim.
package mesh

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/conn"
)

// WireGuard message type constants (from wireguard.com/protocol).
// These are the first 4 bytes of every WireGuard packet.
const (
	wgMsgInitiation  uint32 = 0x01
	wgMsgResponse     uint32 = 0x02
	wgMsgCookie       uint32 = 0x03
	wgMsgTransport   uint32 = 0x04
	wgInitiationSize        = 148 // 4 type + 32 sender + 32 ephemeral + 16 + 16 + 12 + 16 + 16 + 4 = 148
	wgResponseSize          = 92
	wgCookieSize            = 64
)

// ObfuscationMode selects the obfuscation strategy for a peer.
type ObfuscationMode int

const (
	ObfuscationNone       ObfuscationMode = iota // pass-through, no transformation
	ObfuscationPadded                            // AmneziaWG-style header randomization + padding + anti-probe
	ObfuscationWebSocket                         // wrap in WebSocket frames over TCP+TLS
)

// ParseObfuscationMode converts a string to an ObfuscationMode.
// Default is ObfuscationPadded for unknown strings (fail-safe for GFW resistance).
func ParseObfuscationMode(s string) ObfuscationMode {
	switch s {
	case "none":
		return ObfuscationNone
	case "padded", "":
		return ObfuscationPadded
	case "websocket":
		return ObfuscationWebSocket
	default:
		return ObfuscationPadded
	}
}

// String returns the mode as a config string.
func (m ObfuscationMode) String() string {
	switch m {
	case ObfuscationNone:
		return "none"
	case ObfuscationPadded:
		return "padded"
	case ObfuscationWebSocket:
		return "websocket"
	default:
		return "padded"
	}
}

// --- ObfuscationConfig ---

// ObfuscationConfig holds per-peer obfuscation parameters.
// Based on AmneziaWG 2.0 design (H1-H4, S1-S4, Jc, Jmin, Jmax).
type ObfuscationConfig struct {
	// H1-H4: non-overlapping ranges for the 4 WireGuard message type fields.
	// On send: a random value is drawn from [Min, Max].
	// On receive: any value in [Min, Max] is accepted.
	// If zero-valued, the original WireGuard type field is kept (no header randomization).
	H1 [2]uint32 // [min, max] for Initiation
	H2 [2]uint32 // [min, max] for Response
	H3 [2]uint32 // [min, max] for Cookie
	H4 [2]uint32 // [min, max] for Transport

	// S1-S4: maximum random padding bytes added to each message type.
	// Actual padding is random(0, Sn). If zero, no padding is added.
	S1 int // max padding for Initiation
	S2 int // max padding for Response
	S3 int // max padding for Cookie
	S4 int // max padding for Transport

	// Jc: junk train count — number of junk packets sent before handshake initiation.
	Jc   int
	Jmin int // minimum junk packet size
	Jmax int // maximum junk packet size

	// PSK: pre-shared key for anti-probe challenge (hex-encoded 32 bytes).
	// If set, the server drops any initiation that doesn't include a valid HMAC tag.
	PSK string

	// JitterMaxMs: maximum timing jitter in milliseconds before sending packets.
	// 0 means no jitter.
	JitterMaxMs int
}

// DefaultObfuscationConfig returns a config with AmneziaWG-style defaults
// suitable for basic GFW resistance (v1 level).
func DefaultObfuscationConfig() ObfuscationConfig {
	return ObfuscationConfig{
		H1: [2]uint32{0x10000000, 0x1FFFFFFF},
		H2: [2]uint32{0x20000000, 0x2FFFFFFF},
		H3: [2]uint32{0x30000000, 0x3FFFFFFF},
		H4: [2]uint32{0x40000000, 0x4FFFFFFF},
		S1: 64,
		S2: 64,
		S3: 32,
		S4: 16,
		Jc:   0,   // disabled by default (v2 feature)
		Jmin: 64,
		Jmax: 256,
		PSK:  "",
		JitterMaxMs: 20,
	}
}

// hasHeaderRandomization returns true if H1-H4 ranges are configured.
func (c *ObfuscationConfig) hasHeaderRandomization() bool {
	return c.H1[0] != 0 || c.H1[1] != 0
}

// --- Obfuscator interface ---

// Obfuscator transforms WireGuard packets before network I/O and reverses
// the transform on received packets. Each mode implements this interface.
type Obfuscator interface {
	// WrapOutbound transforms a WireGuard packet before it goes on the wire.
	WrapOutbound(packet []byte) ([]byte, error)
	// UnwrapInbound reverses the transform on a received packet.
	UnwrapInbound(data []byte) ([]byte, error)
	// Mode returns the obfuscation mode.
	Mode() ObfuscationMode
}

// --- none mode ---

// noneObfuscator passes packets through unchanged.
type noneObfuscator struct{}

func (noneObfuscator) WrapOutbound(packet []byte) ([]byte, error)  { return packet, nil }
func (noneObfuscator) UnwrapInbound(data []byte) ([]byte, error)    { return data, nil }
func (noneObfuscator) Mode() ObfuscationMode                          { return ObfuscationNone }

// --- padded mode (AmneziaWG-style) ---

// paddedObfuscator implements AmneziaWG 2.0-style obfuscation:
//   - H1-H4: Replace the fixed 4-byte WireGuard message type with random
//     values drawn from non-overlapping ranges, defeating DPI fingerprinting.
//   - S1-S4: Add per-message-type random padding to break fixed packet sizes.
//   - Jc: Junk train — send random junk packets before handshake initiation.
//   - Anti-probe: PSK challenge — drop packets that fail HMAC verification.
//   - Timing jitter: random delay before sending to disrupt timing analysis.
//
// The frame format on the wire is:
//   [4-byte obfuscated type][original packet minus type field][S_n random padding]
//
// For anti-probe: the first 32 bytes of the original packet (after the type
// field) are the sender ephemeral. We append a 16-byte HMAC tag derived
// from the PSK so the receiver can verify the sender knows the PSK before
// processing the handshake. The HMAC is computed over the packet's
// ephemeral + timestamp using HKDF-derived key from PSK.
type paddedObfuscator struct {
	cfg ObfuscationConfig
	mu  sync.Mutex
	rng *mrand.Rand
}

func newPaddedObfuscator(cfg ObfuscationConfig) *paddedObfuscator {
	if !cfg.hasHeaderRandomization() && cfg.S1 == 0 && cfg.S2 == 0 && cfg.S3 == 0 && cfg.S4 == 0 && cfg.PSK == "" {
		cfg = DefaultObfuscationConfig()
	}
	return &paddedObfuscator{
		cfg: cfg,
		rng: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}
}

// classifyMessage returns the WireGuard message type from the packet's
// first 4 bytes, or 0 if unrecognized.
func classifyMessage(packet []byte) uint32 {
	if len(packet) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(packet[:4])
}

// obfuscateType maps a WireGuard message type to a random value in the
// configured H-range. Returns the original type if no range is configured.
func (p *paddedObfuscator) obfuscateType(wgType uint32) uint32 {
	cfg := p.cfg
	var r [2]uint32
	switch wgType {
	case wgMsgInitiation:
		r = cfg.H1
	case wgMsgResponse:
		r = cfg.H2
	case wgMsgCookie:
		r = cfg.H3
	case wgMsgTransport:
		r = cfg.H4
	default:
		return wgType // unknown type, leave as-is
	}
	if r[0] == 0 && r[1] == 0 {
		return wgType // no range configured for this type
	}
	// Draw a random value from [r.Min, r.Max]
	p.mu.Lock()
	defer p.mu.Unlock()
	return r[0] + uint32(p.rng.Int63n(int64(r[1]-r[0]+1)))
}

// deobfuscateType maps a received obfuscated type back to the WireGuard type.
// It checks each H-range and returns the matching WireGuard type.
func (p *paddedObfuscator) deobfuscateType(obsType uint32) (uint32, bool) {
	cfg := p.cfg
	if obsType >= cfg.H1[0] && obsType <= cfg.H1[1] && cfg.H1[0] != 0 {
		return wgMsgInitiation, true
	}
	if obsType >= cfg.H2[0] && obsType <= cfg.H2[1] && cfg.H2[0] != 0 {
		return wgMsgResponse, true
	}
	if obsType >= cfg.H3[0] && obsType <= cfg.H3[1] && cfg.H3[0] != 0 {
		return wgMsgCookie, true
	}
	if obsType >= cfg.H4[0] && obsType <= cfg.H4[1] && cfg.H4[0] != 0 {
		return wgMsgTransport, true
	}
	// Also accept original WireGuard types (for interoperability with
	// peers that may not have header randomization configured).
	if obsType == wgMsgInitiation || obsType == wgMsgResponse || obsType == wgMsgCookie || obsType == wgMsgTransport {
		return obsType, true
	}
	return 0, false
}

// maxPaddingFor returns the configured max padding for a message type.
func (p *paddedObfuscator) maxPaddingFor(wgType uint32) int {
	switch wgType {
	case wgMsgInitiation:
		return p.cfg.S1
	case wgMsgResponse:
		return p.cfg.S2
	case wgMsgCookie:
		return p.cfg.S3
	case wgMsgTransport:
		return p.cfg.S4
	default:
		return 0
	}
}

// WrapOutbound transforms a WireGuard packet for the wire.
// Frame format: [4-byte obfuscated type][packet body (minus original type)][padding][optional 16-byte PSK tag]
func (p *paddedObfuscator) WrapOutbound(packet []byte) ([]byte, error) {
	if len(packet) < 4 {
		return nil, fmt.Errorf("padded: packet too short (%d bytes)", len(packet))
	}

	wgType := classifyMessage(packet)
	obsType := p.obfuscateType(wgType)

	// Body = everything after the 4-byte type field.
	body := packet[4:]

	// Determine padding.
	padMax := p.maxPaddingFor(wgType)
	padLen := 0
	if padMax > 0 {
		p.mu.Lock()
		padLen = p.rng.Intn(padMax + 1)
		p.mu.Unlock()
	}

	// Build the frame: [obfuscated type (4)][body][padding][PSK tag?]
	pskTag := p.computePSKTag(packet, wgType)
	tagLen := 0
	if pskTag != nil {
		tagLen = len(pskTag)
	}

	frame := make([]byte, 4+len(body)+padLen+tagLen)
	binary.LittleEndian.PutUint32(frame[:4], obsType)
	copy(frame[4:4+len(body)], body)

	// Fill padding with random bytes.
	if padLen > 0 {
		p.mu.Lock()
		_, _ = rand.Read(frame[4+len(body) : 4+len(body)+padLen])
		p.mu.Unlock()
	}

	// Append PSK tag if present.
	if tagLen > 0 {
		copy(frame[4+len(body)+padLen:], pskTag)
	}

	// Timing jitter — disrupts timing analysis. Applied as a non-blocking
	// delay (the jitter is small enough to not block the receive path).
	if p.cfg.JitterMaxMs > 0 {
		p.mu.Lock()
		jitter := time.Duration(p.rng.Intn(p.cfg.JitterMaxMs)) * time.Millisecond
		p.mu.Unlock()
		time.Sleep(jitter)
	}

	return frame, nil
}

// UnwrapInbound reverses the padded obfuscation.
// It reads the obfuscated type, maps it back, reconstructs the original
// WireGuard packet, strips padding, and verifies the PSK tag if configured.
func (p *paddedObfuscator) UnwrapInbound(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("padded unwrap: frame too short (%d bytes)", len(data))
	}

	obsType := binary.LittleEndian.Uint32(data[:4])
	wgType, ok := p.deobfuscateType(obsType)
	if !ok {
		return nil, fmt.Errorf("padded unwrap: unrecognized type 0x%08x", obsType)
	}

	body := data[4:]

	// Expected body length for known message types.
	expectedBody := 0
	switch wgType {
	case wgMsgInitiation:
		expectedBody = wgInitiationSize - 4
	case wgMsgResponse:
		expectedBody = wgResponseSize - 4
	case wgMsgCookie:
		expectedBody = wgCookieSize - 4
	case wgMsgTransport:
		expectedBody = -1 // variable length
	}

	// If PSK is configured, verify the HMAC tag — but only for initiation
	// messages (only initiation packets carry the anti-probe tag).
	if p.cfg.PSK != "" && wgType == wgMsgInitiation {
		// The tag is the last 16 bytes of the body.
		if len(body) < 16 {
			return nil, fmt.Errorf("padded unwrap: body too short for PSK tag")
		}
		tag := body[len(body)-16:]
		bodyWithoutTag := body[:len(body)-16]

		// Reconstruct the original packet (with original WG type) for tag verification.
		pkt := make([]byte, 4+len(bodyWithoutTag))
		binary.LittleEndian.PutUint32(pkt[:4], wgType)
		copy(pkt[4:], bodyWithoutTag)

		expectedTag := p.computePSKTag(pkt, wgType)
		if !hmac.Equal(expectedTag, tag) {
			return nil, fmt.Errorf("padded unwrap: PSK tag verification failed")
		}
		body = bodyWithoutTag
	}

	// For fixed-size messages, strip trailing padding.
	if expectedBody > 0 && expectedBody <= len(body) {
		body = body[:expectedBody]
	}

	// Reconstruct the original WireGuard packet.
	packet := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(packet[:4], wgType)
	copy(packet[4:], body)

	return packet, nil
}

// computePSKTag computes a 16-byte HMAC tag for anti-probe verification.
// The tag is HMAC-SHA256(key, packet[:32+4]) truncated to 16 bytes, where
// the key is derived from the PSK via HKDF. For non-initiation messages,
// no tag is needed (only initiation is probed).
func (p *paddedObfuscator) computePSKTag(packet []byte, wgType uint32) []byte {
	if p.cfg.PSK == "" {
		return nil
	}
	// Only handshake initiation needs the anti-probe tag.
	if wgType != wgMsgInitiation {
		return nil
	}

	// Derive a key from the PSK using HKDF-SHA256.
	pskBytes, err := hex.DecodeString(p.cfg.PSK)
	if err != nil || len(pskBytes) == 0 {
		return nil
	}
	key := make([]byte, 32)
	hkdf_sha256(pskBytes, []byte("meshdesk-obfuscation-v1"), key)

	// HMAC over the first 36 bytes of the packet (4 type + 32 sender ephemeral).
	n := 36
	if len(packet) < n {
		n = len(packet)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(packet[:n])
	fullTag := mac.Sum(nil)
	return fullTag[:16] // truncate to 128 bits
}

// hkdf_sha256 derives a 32-byte key from secret, salt, and writes to out.
func hkdf_sha256(secret, salt []byte, out []byte) {
	r := hkdf.New(sha256.New, secret, salt, []byte("meshdesk"))
	_, _ = io.ReadFull(r, out)
}

func (p *paddedObfuscator) Mode() ObfuscationMode { return ObfuscationPadded }

// --- junk train ---

// JunkPacket represents a single junk packet in the junk train.
type JunkPacket struct {
	Data []byte
}

// GenerateJunkTrain generates a slice of random junk packets for the
// junk train (Jc). These are sent before the handshake initiation to
// blur the timing and size profile of the handshake start.
func GenerateJunkTrain(cfg ObfuscationConfig, rng *mrand.Rand) []JunkPacket {
	if cfg.Jc == 0 {
		return nil
	}
	jmin := cfg.Jmin
	if jmin <= 0 {
		jmin = 64
	}
	jmax := cfg.Jmax
	if jmax <= jmin {
		jmax = jmin + 192
	}

	packets := make([]JunkPacket, cfg.Jc)
	for i := 0; i < cfg.Jc; i++ {
		size := jmin + rng.Intn(jmax-jmin+1)
		data := make([]byte, size)
		_, _ = rand.Read(data)
		packets[i] = JunkPacket{Data: data}
	}
	return packets
}

// --- websocket mode ---

// wsFrameType is the WebSocket binary frame opcode (FIN + binary).
const wsFrameType = 0x82

// websocketObfuscator wraps WireGuard packets in WebSocket binary frames
// over TCP. In production, the connection is wrapped in TLS (wss://) for
// entropy camouflage and active-probe resistance. This implementation handles
// the WebSocket framing layer; the TCP/TLS transport is managed by the
// websocketTransport (below) which handles the actual connection lifecycle.
type websocketObfuscator struct {
	// isClient: true if this is the client side (frames must be masked per RFC 6455).
	isClient bool
}

func newWebsocketObfuscator(isClient bool) *websocketObfuscator {
	return &websocketObfuscator{isClient: isClient}
}

// WrapOutbound wraps a WireGuard packet in a WebSocket binary frame.
func (w *websocketObfuscator) WrapOutbound(packet []byte) ([]byte, error) {
	plen := len(packet)
	var buf []byte

	if plen <= 125 {
		buf = make([]byte, 2+plen)
		buf[0] = wsFrameType
		if w.isClient {
			buf[1] = 0x80 | byte(plen) // masked
		} else {
			buf[1] = byte(plen) // unmasked
		}
	} else if plen <= 65535 {
		buf = make([]byte, 4+plen)
		buf[0] = wsFrameType
		if w.isClient {
			buf[1] = 0x80 | 126
		} else {
			buf[1] = 126
		}
		binary.BigEndian.PutUint16(buf[2:4], uint16(plen))
	} else {
		buf = make([]byte, 10+plen)
		buf[0] = wsFrameType
		if w.isClient {
			buf[1] = 0x80 | 127
		} else {
			buf[1] = 127
		}
		binary.BigEndian.PutUint64(buf[2:10], uint64(plen))
	}

	// Write masking key + masked payload (client side only).
	if w.isClient {
		maskKey := make([]byte, 4)
		_, _ = rand.Read(maskKey)
		offset := len(buf) - plen
		// Append mask key before payload.
		maskedBuf := make([]byte, len(buf)+4)
		copy(maskedBuf[:offset], buf[:offset])
		copy(maskedBuf[offset:offset+4], maskKey)
		copy(maskedBuf[offset+4:], packet)
		for i := 0; i < plen; i++ {
			maskedBuf[offset+4+i] ^= maskKey[i%4]
		}
		buf = maskedBuf
	} else {
		copy(buf[len(buf)-plen:], packet)
	}

	return buf, nil
}

// UnwrapInbound extracts a WireGuard packet from a WebSocket binary frame.
func (w *websocketObfuscator) UnwrapInbound(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("websocket unwrap: frame too short")
	}
	if data[0] != wsFrameType {
		return nil, fmt.Errorf("websocket unwrap: unexpected opcode 0x%02x", data[0])
	}
	masked := data[1]&0x80 != 0
	payloadLen := int(data[1] & 0x7F)
	offset := 2

	switch payloadLen {
	case 126:
		if len(data) < 4 {
			return nil, fmt.Errorf("websocket unwrap: extended length truncated")
		}
		payloadLen = int(binary.BigEndian.Uint16(data[2:4]))
		offset = 4
	case 127:
		if len(data) < 10 {
			return nil, fmt.Errorf("websocket unwrap: extended length truncated")
		}
		payloadLen = int(binary.BigEndian.Uint64(data[2:10]))
		offset = 10
	}

	if masked {
		if len(data) < offset+4 {
			return nil, fmt.Errorf("websocket unwrap: masking key truncated")
		}
		maskKey := data[offset : offset+4]
		offset += 4
		if offset+payloadLen > len(data) {
			return nil, fmt.Errorf("websocket unwrap: payload %d exceeds data %d", payloadLen, len(data)-offset)
		}
		packet := make([]byte, payloadLen)
		copy(packet, data[offset:offset+payloadLen])
		for i := range packet {
			packet[i] ^= maskKey[i%4]
		}
		return packet, nil
	}

	if offset+payloadLen > len(data) {
		return nil, fmt.Errorf("websocket unwrap: payload %d exceeds data %d", payloadLen, len(data)-offset)
	}
	packet := make([]byte, payloadLen)
	copy(packet, data[offset:offset+payloadLen])
	return packet, nil
}

func (w *websocketObfuscator) Mode() ObfuscationMode { return ObfuscationWebSocket }

// --- Obfuscator factory ---

// NewObfuscator creates an Obfuscator for the given mode with default config.
func NewObfuscator(mode ObfuscationMode) Obfuscator {
	switch mode {
	case ObfuscationNone:
		return noneObfuscator{}
	case ObfuscationPadded:
		return newPaddedObfuscator(DefaultObfuscationConfig())
	case ObfuscationWebSocket:
		return newWebsocketObfuscator(true)
	default:
		return newPaddedObfuscator(DefaultObfuscationConfig())
	}
}

// NewObfuscatorWithConfig creates an Obfuscator with a specific config.
// For padded mode, the config controls H1-H4/S1-S4/Jc/PSK/jitter.
// For websocket mode, isClient controls frame masking.
func NewObfuscatorWithConfig(mode ObfuscationMode, cfg ObfuscationConfig, isClient bool) Obfuscator {
	switch mode {
	case ObfuscationNone:
		return noneObfuscator{}
	case ObfuscationPadded:
		return newPaddedObfuscator(cfg)
	case ObfuscationWebSocket:
		return newWebsocketObfuscator(isClient)
	default:
		return newPaddedObfuscator(cfg)
	}
}

// --- Obfuscating Bind (conn.Bind wrapper) ---

// obfuscatingBind wraps a conn.Bind to apply per-peer obfuscation transforms
// on all outbound and inbound packets. This is the integration point between
// the obfuscation shim and wireguard-go's networking layer.
type obfuscatingBind struct {
	inner       conn.Bind
	obfuscators map[string]Obfuscator // keyed by hex public key
	configs     map[string]ObfuscationConfig
	mu          sync.RWMutex
}

// NewObfuscatingBind wraps an inner conn.Bind with per-peer obfuscation.
func NewObfuscatingBind(inner conn.Bind) *obfuscatingBind {
	return &obfuscatingBind{
		inner:       inner,
		obfuscators: make(map[string]Obfuscator),
		configs:     make(map[string]ObfuscationConfig),
	}
}

// SetObfuscator associates an obfuscator with a peer (by hex public key).
func (b *obfuscatingBind) SetObfuscator(peerKey string, mode ObfuscationMode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.obfuscators[peerKey] = NewObfuscator(mode)
	b.configs[peerKey] = DefaultObfuscationConfig()
}

// SetObfuscatorWithConfig associates a configured obfuscator with a peer.
func (b *obfuscatingBind) SetObfuscatorWithConfig(peerKey string, mode ObfuscationMode, cfg ObfuscationConfig, isClient bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.obfuscators[peerKey] = NewObfuscatorWithConfig(mode, cfg, isClient)
	b.configs[peerKey] = cfg
}

// GetObfuscator returns the obfuscator for a peer, defaulting to padded mode.
func (b *obfuscatingBind) GetObfuscator(peerKey string) Obfuscator {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if o, ok := b.obfuscators[peerKey]; ok {
		return o
	}
	return NewObfuscator(ObfuscationPadded)
}

// Open delegates to the inner bind.
func (b *obfuscatingBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, port, err := b.inner.Open(uport)
	if err != nil {
		return nil, 0, err
	}
	// Wrap each receive function to de-obfuscate inbound packets.
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.wrapReceiveFunc(fn)
	}
	return wrapped, port, nil
}

// Close delegates to the inner bind.
func (b *obfuscatingBind) Close() error {
	return b.inner.Close()
}

// SetMark delegates to the inner bind.
func (b *obfuscatingBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

// Send applies the peer's obfuscation transform before delegating to inner Send.
func (b *obfuscatingBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	peerKey := endpoint.DstToString()
	o := b.GetObfuscator(peerKey)

	transformed := make([][]byte, len(bufs))
	for i, buf := range bufs {
		data, err := o.WrapOutbound(buf)
		if err != nil {
			return fmt.Errorf("obfuscate outbound: %w", err)
		}
		transformed[i] = data
	}
	return b.inner.Send(transformed, endpoint)
}

// ParseEndpoint delegates to the inner bind.
func (b *obfuscatingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

// BatchSize delegates to the inner bind.
func (b *obfuscatingBind) BatchSize() int {
	return b.inner.BatchSize()
}

// wrapReceiveFunc wraps a ReceiveFunc to de-obfuscate inbound packets.
func (b *obfuscatingBind) wrapReceiveFunc(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		if err != nil {
			return n, err
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			peerKey := ""
			if eps[i] != nil {
				peerKey = eps[i].DstToString()
			}
			o := b.GetObfuscator(peerKey)
			data, err := o.UnwrapInbound(packets[i][:sizes[i]])
			if err != nil {
				sizes[i] = 0
				continue
			}
			copy(packets[i], data)
			sizes[i] = len(data)
		}
		return n, nil
	}
}

// --- TCP transport for websocket mode ---

// wsConn wraps a net.Conn to implement the streaming frame reader
// needed for WebSocket obfuscation mode (which operates over TCP, not UDP).
type wsConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

// newWSConn wraps a TCP connection for WebSocket-frame streaming.
func newWSConn(c net.Conn) *wsConn {
	return &wsConn{
		conn:   c,
		reader: bufio.NewReader(c),
	}
}

// ReadFrame reads a single WebSocket binary frame from the stream.
func (w *wsConn) ReadFrame() ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(w.reader, header); err != nil {
		return nil, fmt.Errorf("ws read header: %w", err)
	}
	if header[0] != wsFrameType {
		return nil, fmt.Errorf("ws unexpected opcode 0x%02x", header[0])
	}
	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7F)
	offset := 0

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(w.reader, ext); err != nil {
			return nil, fmt.Errorf("ws read ext length: %w", err)
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
		offset = 2
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(w.reader, ext); err != nil {
			return nil, fmt.Errorf("ws read ext length: %w", err)
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
		offset = 8
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(w.reader, maskKey); err != nil {
			return nil, fmt.Errorf("ws read mask: %w", err)
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(w.reader, payload); err != nil {
		return nil, fmt.Errorf("ws read payload: %w", err)
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	_ = offset
	return payload, nil
}

// WriteFrame writes a single WebSocket binary frame to the connection.
func (w *wsConn) WriteFrame(data []byte) error {
	frame, err := newWebsocketObfuscator(true).WrapOutbound(data)
	if err != nil {
		return err
	}
	_, err = w.conn.Write(frame)
	return err
}

// Close closes the underlying connection.
func (w *wsConn) Close() error {
	return w.conn.Close()
}

// --- WebSocket transport with HTTP upgrade handshake ---

// wsUpgradePath is the URL path for WebSocket upgrade requests.
const wsUpgradePath = "/meshdesk"

// websocketTransport manages the TCP+TLS connection for WebSocket obfuscation mode.
// It handles the HTTP upgrade handshake (RFC 6455) and provides a stream-oriented
// interface for sending/receiving WebSocket-framed WireGuard packets.
type websocketTransport struct {
	conn   net.Conn
	wsConn *wsConn
}

// DialWebSocket performs an HTTP upgrade handshake and returns a websocketTransport
// for sending/receiving WebSocket-framed data over a (optionally TLS) TCP connection.
// If tlsConfig is non-nil, the connection is wrapped in TLS.
func DialWebSocket(addr string, useTLS bool) (*websocketTransport, error) {
	var conn net.Conn
	var err error

	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}

	// Perform HTTP upgrade handshake.
	req, _ := http.NewRequest("GET", "http://"+addr+wsUpgradePath, nil)
	key := generateWSKey()
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws write upgrade: %w", err)
	}

	// Read the server's response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("ws upgrade failed: %d %s", resp.StatusCode, resp.Status)
	}
	resp.Body.Close()

	return &websocketTransport{
		conn:   conn,
		wsConn: &wsConn{conn: conn, reader: br},
	}, nil
}

// ListenWebSocket starts a TCP listener (optionally with TLS) that accepts
// WebSocket upgrade requests and returns websocketTransport connections.
type wsListener struct {
	listener net.Listener
	useTLS   bool
}

// ListenWebSocket creates a listener for WebSocket transport connections.
func ListenWebSocket(addr string, useTLS bool, certFile, keyFile string) (*wsListener, error) {
	var listener net.Listener
	var err error

	if useTLS {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("TLS listener requires cert and key files")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("ws load TLS cert: %w", err)
		}
		listener, err = tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	} else {
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("ws listen: %w", err)
	}

	return &wsListener{listener: listener, useTLS: useTLS}, nil
}

// Accept waits for and returns the next WebSocket transport connection.
func (l *wsListener) Accept() (*websocketTransport, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)

	// Read the HTTP upgrade request.
	req, err := http.ReadRequest(br)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws read upgrade request: %w", err)
	}

	// Verify it's a WebSocket upgrade.
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		conn.Close()
		return nil, fmt.Errorf("ws not an upgrade request: Upgrade=%q", req.Header.Get("Upgrade"))
	}

	// Send 101 Switching Protocols response.
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Upgrade":    []string{"websocket"},
			"Connection": []string{"Upgrade"},
		},
	}
	if err := resp.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws write upgrade response: %w", err)
	}

	return &websocketTransport{
		conn:   conn,
		wsConn: &wsConn{conn: conn, reader: br},
	}, nil
}

// Close closes the listener.
func (l *wsListener) Close() error {
	return l.listener.Close()
}

// generateWSKey generates a random 16-byte base64-encoded WebSocket key.
func generateWSKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// hexEncode is a helper for encoding raw bytes to hex.
func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}
