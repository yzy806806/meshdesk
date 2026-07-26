// Package mesh provides the WireGuard mesh VPN core: device management,
// gVisor netstack integration, routing, and the pluggable obfuscation shim.
package mesh

import (
	"bufio"
	"context"
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
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/conn"

	utls "github.com/refraction-networking/utls"
)

// WireGuard message type constants (from wireguard.com/protocol).
// These are the first 4 bytes of every WireGuard packet.
const (
	wgMsgInitiation  uint32 = 0x01
	wgMsgResponse    uint32 = 0x02
	wgMsgCookie      uint32 = 0x03
	wgMsgTransport   uint32 = 0x04
	wgInitiationSize        = 148 // 4 type + 32 sender + 32 ephemeral + 16 + 16 + 12 + 16 + 16 + 4 = 148
	wgResponseSize          = 92
	wgCookieSize            = 64
)

// ObfuscationMode selects the obfuscation strategy for a peer.
type ObfuscationMode int

const (
	ObfuscationNone      ObfuscationMode = iota // pass-through, no transformation
	ObfuscationPadded                           // AmneziaWG-style header randomization + padding + anti-probe
	ObfuscationWebSocket                        // wrap in WebSocket frames over TCP+TLS
	ObfuscationReality                          // Reality TLS transport (xray-core REALITY protocol)
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
	case "reality":
		return ObfuscationReality
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
	case ObfuscationReality:
		return "reality"
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

	// TLSSni: Server Name Indication for the TLS ClientHello. When non-empty,
	// the TLS handshake sends this SNI, making the connection look like normal
	// HTTPS traffic to the configured domain. Used only in WebSocket+TLS mode.
	TLSSni string

	// TLSFingerprint: which browser ClientHello to mimic ("chrome", "firefox",
	// "safari", "edge", "ios", "android"). Defaults to "chrome" when empty.
	// Used only in WebSocket+TLS mode.
	TLSFingerprint string

	// IsClient controls WebSocket frame masking. When true, outbound frames
	// are masked per RFC 6455 (client side). When false, frames are unmasked
	// (server side). Used only in WebSocket mode. The registry factory reads
	// this field so that RegisterObfuscator can create the correct variant
	// without a separate parameter.
	IsClient bool
}

// DefaultObfuscationConfig returns a config with AmneziaWG-style defaults
// suitable for basic GFW resistance (v1 level).
func DefaultObfuscationConfig() ObfuscationConfig {
	return ObfuscationConfig{
		H1:          [2]uint32{0x10000000, 0x1FFFFFFF},
		H2:          [2]uint32{0x20000000, 0x2FFFFFFF},
		H3:          [2]uint32{0x30000000, 0x3FFFFFFF},
		H4:          [2]uint32{0x40000000, 0x4FFFFFFF},
		S1:          64,
		S2:          64,
		S3:          32,
		S4:          16,
		Jc:          0, // disabled by default (v2 feature)
		Jmin:        64,
		Jmax:        256,
		PSK:         "",
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

func (noneObfuscator) WrapOutbound(packet []byte) ([]byte, error) { return packet, nil }
func (noneObfuscator) UnwrapInbound(data []byte) ([]byte, error)  { return data, nil }
func (noneObfuscator) Mode() ObfuscationMode                      { return ObfuscationNone }

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
//
//	[4-byte obfuscated type][original packet minus type field][S_n random padding]
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

// --- Obfuscator registry ---

// obfuscatorFactory is a constructor that builds an Obfuscator from a config.
type obfuscatorFactory func(cfg ObfuscationConfig) Obfuscator

// ObfuscatorRegistry is the global registry of obfuscation-mode factories.
// Modes self-register via init() calling RegisterObfuscator. The factory
// lookup replaces the former hard-coded switch statement, so adding a new
// obfuscation mode no longer requires modifying core factory code.
var ObfuscatorRegistry = &obfuscatorRegistry{
	factories: &sync.Map{},
}

// obfuscatorRegistry wraps a sync.Map of mode-name → factory.
type obfuscatorRegistry struct {
	factories *sync.Map
}

// RegisterObfuscator registers a factory for the named obfuscation mode.
// Each mode (none, padded, websocket, etc.) calls this from an init()
// function to self-register. Registering the same name twice panics,
// which catches duplicate registrations at program start.
func RegisterObfuscator(name string, factory obfuscatorFactory) {
	if _, loaded := ObfuscatorRegistry.factories.LoadOrStore(name, factory); loaded {
		panic(fmt.Sprintf("mesh: duplicate obfuscator registration for %q", name))
	}
}

// Get looks up the factory for the named mode. Returns the factory and true
// if found, or nil and false if no mode is registered under that name.
func (r *obfuscatorRegistry) Get(name string) (obfuscatorFactory, bool) {
	v, ok := r.factories.Load(name)
	if !ok {
		return nil, false
	}
	return v.(obfuscatorFactory), true
}

// MustGet is like Get but panics if the mode is not registered. Useful in
// init-time paths where a missing registration indicates a programming error.
func (r *obfuscatorRegistry) MustGet(name string) obfuscatorFactory {
	f, ok := r.Get(name)
	if !ok {
		panic(fmt.Sprintf("mesh: obfuscator mode %q not registered", name))
	}
	return f
}

// Names returns all registered obfuscation mode names. The order is
// non-deterministic (sync.Map iteration).
func (r *obfuscatorRegistry) Names() []string {
	var names []string
	r.factories.Range(func(key, _ any) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}

// --- Obfuscator factory (registry-backed) ---

// NewObfuscator creates an Obfuscator for the given mode with default config.
// The mode is resolved through the ObfuscatorRegistry, so new modes can be
// added by calling RegisterObfuscator without modifying this function.
func NewObfuscator(mode ObfuscationMode) Obfuscator {
	return NewObfuscatorWithConfig(mode, DefaultObfuscationConfig(), true)
}

// NewObfuscatorWithConfig creates an Obfuscator with a specific config.
// For padded mode, the config controls H1-H4/S1-S4/Jc/PSK/jitter.
// For websocket mode, cfg.IsClient controls frame masking.
//
// The mode is resolved through the ObfuscatorRegistry. If the mode has not
// been registered, it falls back to padded mode (fail-safe for GFW resistance).
func NewObfuscatorWithConfig(mode ObfuscationMode, cfg ObfuscationConfig, isClient bool) Obfuscator {
	cfg.IsClient = isClient
	name := mode.String()
	factory, ok := ObfuscatorRegistry.Get(name)
	if !ok {
		// Fail-safe: fall back to padded mode for unrecognized modes.
		factory, ok = ObfuscatorRegistry.Get(ObfuscationPadded.String())
		if !ok {
			panic("mesh: padded obfuscator not registered (init order bug)")
		}
	}
	return factory(cfg)
}

// --- self-registration of built-in obfuscation modes ---

func init() {
	RegisterObfuscator("none", func(cfg ObfuscationConfig) Obfuscator {
		return noneObfuscator{}
	})
}

func init() {
	RegisterObfuscator("padded", func(cfg ObfuscationConfig) Obfuscator {
		return newPaddedObfuscator(cfg)
	})
}

func init() {
	RegisterObfuscator("websocket", func(cfg ObfuscationConfig) Obfuscator {
		return newWebsocketObfuscator(cfg.IsClient)
	})
}

func init() {
	// Reality mode uses a pass-through obfuscator — the TLS wrapping and
	// authentication happen at the transport layer (RealityTransport),
	// not at the packet obfuscation layer. WireGuard packets are sent
	// raw through the established REALITY TLS channel.
	RegisterObfuscator("reality", func(cfg ObfuscationConfig) Obfuscator {
		return noneObfuscator{}
	})
}

// --- Obfuscating Bind (conn.Bind wrapper) ---

// obfuscatingBind wraps a conn.Bind to apply per-peer obfuscation transforms
// on all outbound and inbound packets. This is the integration point between
// the obfuscation shim and wireguard-go's networking layer.
type obfuscatingBind struct {
	inner       conn.Bind
	obfuscators map[string]Obfuscator // keyed by hex public key
	configs     map[string]ObfuscationConfig
	ws          *wsBind       // websocket transport (nil when no peer uses websocket mode)
	reality     *realityBind  // reality TLS transport (nil when no peer uses reality mode)
	mu          sync.RWMutex
	rngMu       sync.Mutex
	rng         *mrand.Rand
}

// NewObfuscatingBind wraps an inner conn.Bind with per-peer obfuscation.
func NewObfuscatingBind(inner conn.Bind) *obfuscatingBind {
	return &obfuscatingBind{
		inner:       inner,
		obfuscators: make(map[string]Obfuscator),
		configs:     make(map[string]ObfuscationConfig),
		rng:         mrand.New(mrand.NewSource(time.Now().UnixNano())),
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
	// Default to ObfuscationNone (pass-through) when no obfuscator is
	// registered for the peer. This is correct for peers configured with
	// obfuscation: "none" and also for the initial handshake before the
	// peer's endpoint address is mapped to a registered obfuscator.
	// Previously this defaulted to ObfuscationPadded, which corrupted
	// WireGuard packets for "none"-mode peers because the obfuscator
	// lookup key (endpoint address from DstToString) did not match the
	// key used at registration (public key).
	return NewObfuscator(ObfuscationNone)
}

// GetConfig returns the obfuscation config for a peer, or the default if unset.
func (b *obfuscatingBind) GetConfig(peerKey string) ObfuscationConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if cfg, ok := b.configs[peerKey]; ok {
		return cfg
	}
	return DefaultObfuscationConfig()
}

// SetWSBind installs a wsBind that handles WebSocket+TLS transport for peers
// configured with ObfuscationWebSocket mode. When set, packets to websocket-mode
// peers are routed through wsBind instead of the inner UDP bind.
func (b *obfuscatingBind) SetWSBind(wb *wsBind) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ws = wb
}

// SetRealityBind installs a realityBind that handles Reality TLS transport for
// peers configured with ObfuscationReality mode. When set, packets to
// reality-mode peers are routed through realityBind instead of the inner UDP bind.
func (b *obfuscatingBind) SetRealityBind(rb *realityBind) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reality = rb
}

// Open delegates to the inner bind. If a wsBind is installed, its listener
// is also opened so that websocket-mode peers can connect.
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

	// Start the websocket listener if configured.
	b.mu.RLock()
	wb := b.ws
	rb := b.reality
	b.mu.RUnlock()
	if wb != nil {
		if err := wb.open(); err != nil {
			return nil, 0, fmt.Errorf("wsBind open: %w", err)
		}
		// Inject websocket-received packets as an additional receive function.
		wrapped = append(wrapped, wb.makeReceiveFunc(b))
	}
	if rb != nil {
		// The realityBind listener is opened separately in MeshNode.Start()
		// because it needs the listen address and context. Here we just
		// inject the receive function for inbound reality packets.
		wrapped = append(wrapped, rb.makeReceiveFunc())
	}

	return wrapped, port, nil
}

// Close delegates to the inner bind.
func (b *obfuscatingBind) Close() error {
	err := b.inner.Close()
	b.mu.RLock()
	wb := b.ws
	rb := b.reality
	b.mu.RUnlock()
	if wb != nil {
		if werr := wb.close(); werr != nil && err == nil {
			err = werr
		}
	}
	if rb != nil {
		if rerr := rb.close(); rerr != nil && err == nil {
			err = rerr
		}
	}
	return err
}

// SetMark delegates to the inner bind.
func (b *obfuscatingBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

// Send applies the peer's obfuscation transform before delegating to inner Send.
// For padded-mode peers with Jc > 0, junk train packets are sent before any
// initiation packet. For websocket-mode peers, packets are routed through the
// wsBind (TCP+TLS) instead of the inner UDP bind. For reality-mode peers,
// packets are routed through the realityBind (REALITY TLS) instead.
func (b *obfuscatingBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	peerKey := endpoint.DstToString()
	o := b.GetObfuscator(peerKey)
	cfg := b.GetConfig(peerKey)

	// Route through websocket transport if the peer is in websocket mode.
	if o.Mode() == ObfuscationWebSocket {
		b.mu.RLock()
		wb := b.ws
		b.mu.RUnlock()
		if wb != nil {
			return wb.send(bufs, endpoint, o)
		}
		// No wsBind installed — fall through to inner send with obfuscation.
	}

	// Route through reality TLS transport if the peer is in reality mode.
	if o.Mode() == ObfuscationReality {
		b.mu.RLock()
		rb := b.reality
		b.mu.RUnlock()
		if rb != nil {
			return rb.send(context.Background(), bufs, endpoint)
		}
		// No realityBind installed — fall through to inner send.
	}

	transformed := make([][]byte, 0, len(bufs))

	// Junk train: when Jc > 0 and the first packet is a handshake initiation,
	// generate and prepend junk packets before the real initiation.
	if cfg.Jc > 0 && len(bufs) > 0 {
		if classifyMessage(bufs[0]) == wgMsgInitiation {
			junk := b.generateJunkTrain(cfg)
			for _, jp := range junk {
				// Obfuscate junk packets the same way as real packets so they
				// are indistinguishable on the wire.
				data, err := o.WrapOutbound(jp.Data)
				if err != nil {
					return fmt.Errorf("obfuscate junk packet: %w", err)
				}
				transformed = append(transformed, data)
			}
		}
	}

	for _, buf := range bufs {
		data, err := o.WrapOutbound(buf)
		if err != nil {
			return fmt.Errorf("obfuscate outbound: %w", err)
		}
		transformed = append(transformed, data)
	}
	return b.inner.Send(transformed, endpoint)
}

// generateJunkTrain is a thread-safe wrapper around GenerateJunkTrain that
// uses the bind's shared RNG.
func (b *obfuscatingBind) generateJunkTrain(cfg ObfuscationConfig) []JunkPacket {
	b.rngMu.Lock()
	defer b.rngMu.Unlock()
	return GenerateJunkTrain(cfg, b.rng)
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
// When useTLS is true, the connection uses utls (github.com/refraction-networking/utls)
// to mimic a browser TLS fingerprint instead of Go's standard crypto/tls, defeating
// JA4-based fingerprinting by the GFW. tlsSni controls the SNI sent in the
// ClientHello; tlsFingerprint selects which browser profile to mimic.
func DialWebSocket(addr string, useTLS bool, tlsSni string, tlsFingerprint string) (*websocketTransport, error) {
	conn, err := dialUTLS(addr, tlsSni, tlsFingerprint, useTLS)
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
		if err != nil {
			return nil, fmt.Errorf("ws TLS listen: %w", err)
		}
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

// --- utls fingerprint helpers ---

// fingerprintToHelloID maps a string fingerprint name to a utls ClientHelloID.
// Defaults to Chrome when empty or unrecognized.
func fingerprintToHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(fp) {
	case "", "chrome":
		return utls.HelloChrome_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	default:
		return utls.HelloChrome_Auto
	}
}

// dialUTLS dials a TCP connection and wraps it in a utls TLS handshake that
// mimics the specified browser ClientHello. If tlsSni is non-empty, it is
// sent as the SNI in the ClientHello. When useTLS is false, a plain TCP
// connection is returned (no TLS wrapping).
func dialUTLS(addr, tlsSni, fingerprint string, useTLS bool) (net.Conn, error) {
	if !useTLS {
		return net.Dial("tcp", addr)
	}

	// Dial the underlying TCP connection first.
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("utls tcp dial: %w", err)
	}

	// Build the utls config with the specified SNI.
	sni := tlsSni
	if sni == "" {
		// Fall back to the host portion of addr.
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			sni = host
		}
	}

	helloID := fingerprintToHelloID(fingerprint)
	tlsConn := utls.UClient(rawConn, &utls.Config{ServerName: sni}, helloID)

	// Perform the utls handshake — this sends the browser-mimicking ClientHello.
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	return tlsConn, nil
}

// --- wsBind: conn.Bind implementation for WebSocket+TLS transport ---
//
// wsBind implements conn.Bind for peers configured with ObfuscationWebSocket
// mode. It maintains a TCP (optionally TLS) listener for inbound connections
// and a pool of outbound websocketTransport connections keyed by peer address.
// WireGuard packets are wrapped/unwrapped in WebSocket binary frames by the
// websocketObfuscator, while the wsBind handles the connection lifecycle.
//
// The wsBind is used in conjunction with the obfuscatingBind: when a peer's
// obfuscation mode is ObfuscationWebSocket, obfuscatingBind.Send routes
// packets through wsBind.send() instead of the inner UDP bind.

// wsBind implements conn.Bind for WebSocket+TLS transport.
type wsBind struct {
	addr           string // listen address (e.g. ":443" or "0.0.0.0:8443")
	useTLS         bool
	certFile       string
	keyFile        string
	tlsSni         string // SNI sent in the TLS ClientHello (client-side dialing)
	tlsFingerprint string // browser fingerprint to mimic ("chrome", "firefox", etc.)

	listener *wsListener

	// Outbound connection pool, keyed by peer endpoint string (host:port).
	connMu sync.Mutex
	conns  map[string]*websocketTransport

	// Inbound packet queue: received websocket frames are deobfuscated and
	// placed here for delivery via makeReceiveFunc.
	recvMu    sync.Mutex
	recvQueue [][]byte
	recvEPs   []conn.Endpoint

	// peerKeyLookup maps a remote address (host:port) to a WireGuard peer key.
	// This lets us resolve the correct obfuscator for inbound packets.
	peerKeyLookup map[string]string

	closed bool
}

// NewWSBind creates a new wsBind listener with TLS configuration.
// tlsSni and tlsFingerprint control the utls ClientHello used for outbound
// TLS connections (client-side). The server-side listener uses crypto/tls
// with the provided cert/key files.
func NewWSBind(addr string, useTLS bool, certFile, keyFile string, tlsSni string, tlsFingerprint string) *wsBind {
	return &wsBind{
		addr:           addr,
		useTLS:         useTLS,
		certFile:       certFile,
		keyFile:        keyFile,
		tlsSni:         tlsSni,
		tlsFingerprint: tlsFingerprint,
		conns:          make(map[string]*websocketTransport),
		peerKeyLookup:  make(map[string]string),
	}
}

// open starts the websocket listener. Safe to call once.
func (wb *wsBind) open() error {
	if wb.addr == "" {
		return nil // no listen address configured; wsBind will only do outbound
	}
	l, err := ListenWebSocket(wb.addr, wb.useTLS, wb.certFile, wb.keyFile)
	if err != nil {
		return err
	}
	wb.listener = l
	// Start accept loop.
	go wb.acceptLoop()
	return nil
}

// close shuts down the listener and all connections.
func (wb *wsBind) close() error {
	wb.connMu.Lock()
	wb.closed = true
	wb.connMu.Unlock()

	var err error
	if wb.listener != nil {
		err = wb.listener.Close()
	}
	// Close all outbound connections.
	wb.connMu.Lock()
	for _, t := range wb.conns {
		t.conn.Close()
	}
	wb.conns = make(map[string]*websocketTransport)
	wb.connMu.Unlock()
	return err
}

// acceptLoop accepts inbound websocket connections and reads frames.
func (wb *wsBind) acceptLoop() {
	for {
		t, err := wb.listener.Accept()
		if err != nil {
			return
		}
		go wb.handleWSConn(t)
	}
}

// handleWSConn reads frames from an accepted websocket transport and enqueues
// the deobfuscated packets for delivery to the wireguard device.
func (wb *wsBind) handleWSConn(t *websocketTransport) {
	defer t.conn.Close()
	// The peer key is unknown at this point (we only have the remote address).
	// Inbound packets are deobfuscated by the obfuscatingBind's receive path
	// using the peer key resolved from the endpoint. Here we just enqueue raw
	// websocket-framed payloads and let the bind's receive func handle them.
	// However, since we need a peer key to look up the obfuscator, we use
	// a default server-side websocket obfuscator for the initial unwrap.
	serverObf := newWebsocketObfuscator(false)
	for {
		payload, err := t.wsConn.ReadFrame()
		if err != nil {
			return
		}
		// payload is the raw WireGuard packet extracted from the WS frame.
		// We already have the deobfuscated packet (ReadFrame strips WS framing).
		// No further unwrapping needed — the websocketObfuscator.WrapOutbound/
		// UnwrapInbound is handled at the obfuscatingBind level. We just enqueue
		// the packet with the remote address as the endpoint.
		_ = serverObf // server-side unwrapping is handled by obfuscatingBind
		remoteAddr := t.conn.RemoteAddr().String()
		wb.enqueueInbound(payload, remoteAddr)
	}
}

// enqueueInbound adds a received packet to the queue for delivery to the
// wireguard device via makeReceiveFunc.
func (wb *wsBind) enqueueInbound(packet []byte, remoteAddr string) {
	ep := &wsEndpoint{addr: remoteAddr}
	wb.recvMu.Lock()
	wb.recvQueue = append(wb.recvQueue, packet)
	wb.recvEPs = append(wb.recvEPs, ep)
	wb.recvMu.Unlock()
}

// getOrCreateConn returns an existing websocketTransport for the peer, or
// dials a new one.
func (wb *wsBind) getOrCreateConn(addr string) (*websocketTransport, error) {
	wb.connMu.Lock()
	if t, ok := wb.conns[addr]; ok {
		wb.connMu.Unlock()
		return t, nil
	}
	wb.connMu.Unlock()

	// Dial a new connection outside the lock to avoid blocking other sends.
	t, err := DialWebSocket(addr, wb.useTLS, wb.tlsSni, wb.tlsFingerprint)
	if err != nil {
		return nil, err
	}
	wb.connMu.Lock()
	if wb.closed {
		wb.connMu.Unlock()
		t.conn.Close()
		return nil, fmt.Errorf("wsBind closed")
	}
	wb.conns[addr] = t
	wb.connMu.Unlock()
	return t, nil
}

// send writes WireGuard packets through a websocket transport connection,
// wrapping them in WebSocket binary frames.
func (wb *wsBind) send(bufs [][]byte, endpoint conn.Endpoint, o Obfuscator) error {
	addr := endpoint.DstToString()
	t, err := wb.getOrCreateConn(addr)
	if err != nil {
		return fmt.Errorf("wsBind dial %s: %w", addr, err)
	}
	for _, buf := range bufs {
		// Wrap the WireGuard packet in a WebSocket binary frame.
		frame, err := o.WrapOutbound(buf)
		if err != nil {
			return fmt.Errorf("wsBind wrap: %w", err)
		}
		if _, err := t.conn.Write(frame); err != nil {
			// Connection might be stale — drop it and retry once.
			wb.connMu.Lock()
			delete(wb.conns, addr)
			wb.connMu.Unlock()
			t.conn.Close()
			return fmt.Errorf("wsBind write: %w", err)
		}
	}
	return nil
}

// makeReceiveFunc returns a conn.ReceiveFunc that drains the inbound
// websocket packet queue, delivering deobfuscated packets to the wireguard
// device.
func (wb *wsBind) makeReceiveFunc(b *obfuscatingBind) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		wb.recvMu.Lock()
		if len(wb.recvQueue) == 0 {
			wb.recvMu.Unlock()
			// Block briefly — the wireguard device expects ReceiveFuncs to
			// block until packets are available. We sleep and retry.
			time.Sleep(10 * time.Millisecond)
			return 0, nil
		}
		n := len(wb.recvQueue)
		if n > len(packets) {
			n = len(packets)
		}
		for i := 0; i < n; i++ {
			pkt := wb.recvQueue[i]
			ep := wb.recvEPs[i]
			// Copy packet data into the provided buffer.
			copy(packets[i], pkt)
			sizes[i] = len(pkt)
			if eps != nil && i < len(eps) {
				eps[i] = ep
			}
		}
		// Drain the consumed entries.
		wb.recvQueue = wb.recvQueue[n:]
		wb.recvEPs = wb.recvEPs[n:]
		wb.recvMu.Unlock()
		return n, nil
	}
}

// --- wsEndpoint: conn.Endpoint for websocket transport ---

// wsEndpoint implements conn.Endpoint for websocket transport peers.
// It carries the remote address (host:port) used to look up obfuscators
// and route packets.
type wsEndpoint struct {
	addr string // remote host:port
}

func (e *wsEndpoint) ClearSrc()           {}
func (e *wsEndpoint) SrcToString() string { return "" }
func (e *wsEndpoint) DstToString() string { return e.addr }
func (e *wsEndpoint) DstToBytes() []byte  { return []byte(e.addr) }
func (e *wsEndpoint) DstIP() netip.Addr {
	host, _, _ := net.SplitHostPort(e.addr)
	ip, _ := netip.ParseAddr(host)
	return ip
}
func (e *wsEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// ParseEndpoint creates a wsEndpoint from a string address.
func (wb *wsBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &wsEndpoint{addr: s}, nil
}

// BatchSize returns the max number of packets per batch for websocket transport.
func (wb *wsBind) BatchSize() int { return 1 }

// SetMark is a no-op for websocket transport (no kernel socket mark).
func (wb *wsBind) SetMark(mark uint32) error { return nil }

// --- realityBind: conn.Bind implementation for Reality TLS transport ---
//
// realityBind implements conn.Bind for peers configured with ObfuscationReality
// mode. It maintains a TCP+TLS (REALITY) listener for inbound connections
// and a pool of outbound REALITY connections keyed by peer address.
// WireGuard packets are sent raw through the established REALITY TLS channel
// — no packet-level obfuscation is needed because the TLS layer provides
// encryption and GFW resistance.
//
// The realityBind is used in conjunction with the obfuscatingBind: when a
// peer's obfuscation mode is ObfuscationReality, obfuscatingBind.Send routes
// packets through realityBind.send() instead of the inner UDP bind.
type realityBind struct {
	// transport is the RealityTransport used for outbound connections.
	transport Transport

	// listener is the inbound REALITY TLS listener (server-side).
	listener net.Listener

	// Outbound connection pool, keyed by peer endpoint string (host:port).
	connMu sync.Mutex
	conns  map[string]net.Conn

	// Inbound packet queue: received REALITY frames are placed here
	// for delivery via makeReceiveFunc.
	recvMu    sync.Mutex
	recvQueue [][]byte
	recvEPs   []conn.Endpoint

	closed bool
}

// newRealityBind creates a new realityBind with the given outbound transport.
// The transport must be a RealityTransport configured with the server's
// public key, short ID, and SNI for client-side REALITY handshakes.
func newRealityBind(transport Transport) *realityBind {
	return &realityBind{
		transport: transport,
		conns:     make(map[string]net.Conn),
	}
}

// open starts the inbound REALITY listener. Only called when this node
// is a relay/shared node accepting Reality connections.
// The listener address and reality config come from the transport's config.
func (rb *realityBind) open(ctx context.Context, addr string) error {
	if addr == "" {
		return nil // no listen address; outbound-only
	}
	l, err := rb.transport.Listen(ctx, addr)
	if err != nil {
		return fmt.Errorf("realityBind listen %s: %w", addr, err)
	}
	rb.listener = l
	go rb.acceptLoop()
	return nil
}

// close shuts down the listener and all connections.
func (rb *realityBind) close() error {
	rb.connMu.Lock()
	rb.closed = true
	rb.connMu.Unlock()

	var err error
	if rb.listener != nil {
		err = rb.listener.Close()
	}
	rb.connMu.Lock()
	for _, c := range rb.conns {
		c.Close()
	}
	rb.conns = make(map[string]net.Conn)
	rb.connMu.Unlock()
	return err
}

// acceptLoop accepts inbound REALITY connections and reads packets.
func (rb *realityBind) acceptLoop() {
	for {
		conn, err := rb.listener.Accept()
		if err != nil {
			return
		}
		go rb.handleConn(conn)
	}
}

// handleConn reads WireGuard packets from an accepted REALITY connection
// and enqueues them for delivery to the wireguard device.
func (rb *realityBind) handleConn(c net.Conn) {
	defer c.Close()
	remoteAddr := c.RemoteAddr().String()
	buf := make([]byte, 1500) // WireGuard max packet size
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			rb.enqueueInbound(pkt, remoteAddr)
		}
	}
}

// enqueueInbound adds a received packet to the queue for delivery to the
// wireguard device via makeReceiveFunc.
func (rb *realityBind) enqueueInbound(packet []byte, remoteAddr string) {
	ep := &wsEndpoint{addr: remoteAddr} // reuse wsEndpoint — same interface
	rb.recvMu.Lock()
	rb.recvQueue = append(rb.recvQueue, packet)
	rb.recvEPs = append(rb.recvEPs, ep)
	rb.recvMu.Unlock()
}

// getOrCreateConn returns an existing REALITY connection for the peer,
// or dials a new one.
func (rb *realityBind) getOrCreateConn(ctx context.Context, addr string) (net.Conn, error) {
	rb.connMu.Lock()
	if c, ok := rb.conns[addr]; ok {
		rb.connMu.Unlock()
		return c, nil
	}
	rb.connMu.Unlock()

	pc, err := rb.transport.Connect(ctx, addr)
	if err != nil {
		return nil, err
	}
	conn := pc // PeerConn satisfies net.Conn

	rb.connMu.Lock()
	if rb.closed {
		rb.connMu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("realityBind closed")
	}
	rb.conns[addr] = conn
	rb.connMu.Unlock()
	return conn, nil
}

// send writes WireGuard packets through a REALITY TLS connection.
// Packets are sent raw — the TLS channel provides encryption.
func (rb *realityBind) send(ctx context.Context, bufs [][]byte, endpoint conn.Endpoint) error {
	addr := endpoint.DstToString()
	conn, err := rb.getOrCreateConn(ctx, addr)
	if err != nil {
		return fmt.Errorf("realityBind dial %s: %w", addr, err)
	}
	for _, buf := range bufs {
		if _, err := conn.Write(buf); err != nil {
			// Connection might be stale — drop it and retry once.
			rb.connMu.Lock()
			delete(rb.conns, addr)
			rb.connMu.Unlock()
			conn.Close()
			return fmt.Errorf("realityBind write: %w", err)
		}
	}
	return nil
}

// makeReceiveFunc returns a conn.ReceiveFunc that drains the inbound
// REALITY packet queue, delivering packets to the wireguard device.
func (rb *realityBind) makeReceiveFunc() conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		rb.recvMu.Lock()
		if len(rb.recvQueue) == 0 {
			rb.recvMu.Unlock()
			// Block briefly — the wireguard device expects ReceiveFuncs to
			// block until packets are available.
			time.Sleep(10 * time.Millisecond)
			return 0, nil
		}
		n := len(rb.recvQueue)
		if n > len(packets) {
			n = len(packets)
		}
		for i := 0; i < n; i++ {
			pkt := rb.recvQueue[i]
			ep := rb.recvEPs[i]
			copy(packets[i], pkt)
			sizes[i] = len(pkt)
			if eps != nil && i < len(eps) {
				eps[i] = ep
			}
		}
		rb.recvQueue = rb.recvQueue[n:]
		rb.recvEPs = rb.recvEPs[n:]
		rb.recvMu.Unlock()
		return n, nil
	}
}
