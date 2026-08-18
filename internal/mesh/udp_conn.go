package mesh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────
// UDPStreamConn — a reliable net.Conn over UDP datagrams.
//
// smux requires a reliable, ordered byte stream. UDP is neither, so we
// add a lightweight ARQ layer (sequence numbers + cumulative ACK +
// timeout retransmit) with a sliding window. This is a simplified
// KCP-style reliability layer, purpose-built for the mesh hole-punch
// data plane — no third-party deps.
//
// Frame format (all integers big-endian):
//   [0]     type   (0x01=DATA, 0x02=ACK, 0x03=FIN)
//   [1:5]   seq    (uint32, for DATA)
//   [5:9]   ack    (uint32, cumulative ACK — highest contiguous seq)
//   [9:11]  len    (uint16 payload length, DATA only)
//   [11:]   payload
// ──────────────────────────────────────────────────────────────────────────

const (
	udpFrameTypeData = 0x01
	udpFrameTypeAck  = 0x02
	udpFrameTypeFin  = 0x03

	udpFrameHeaderLen = 11
	// udpMaxPayload is the conservative floor for the payload size —
	// the txcloud↔Oracle path drops UDP datagrams above ~60B (11B
	// header + 40B payload = 51B). The *actual* payload size is
	// discovered at runtime (see payloadSize below) and may be much
	// larger on paths without that restriction.
	udpMaxPayload = 40

	// udpPayloadLarge is the optimistic payload size used after path
	// MTU discovery succeeds. 11B header + 1200B = 1211B — well under
	// the 1500B Ethernet MTU and the 1400B TUN MTU. On a 257ms link
	// with a 128-frame window this gives ~4.8Mbps (vs ~300kbps at 40B).
	udpPayloadLarge = 1200

	// udpPayloadProbeInterval is how often the sender retries a large
	// payload probe after a failure (the link may have improved).
	udpPayloadProbeInterval = 60 * time.Second

	udpWindowSize = 128 // sliding window (in-flight frames)
	// 32→128 (v1.6.3): the WAN RTT (txcloud↔Oracle ~257ms) × 40B
	// payload bounded throughput at ~40kbps (BDP = window × frame /
	// RTT). 128 frames × 40B / 0.257s ≈ 20KB/s ≈ 160kbps. Safe with
	// the adaptive RTO (RFC 6298 SRTT/RTTVAR): a bigger window only
	// matters when ACKs flow, and retransmits are per-frame.
	udpMaxSeq = uint32(1 << 30)

	// udpWriteTimeout bounds how long Write waits for the sliding
	// window to drain before giving up (dead peer → error → caller
	// falls back to TCP). 30s ≈ 150 RTO retransmits.
	// 10s write timeout: on lossy links the kx should fall back to
	// relay quickly instead of wedging Write for 30s.
	udpWriteTimeout = 10 * time.Second
)

var (
	errUDPClosed = errors.New("udp stream: closed")
)

// udpStreamConn implements net.Conn over a UDP socket with ARQ
// reliability. Each instance is bound to one remote address.
type udpStreamConn struct {
	conn *net.UDPConn
	peer *net.UDPAddr

	// send side
	sendMu   sync.Mutex
	nextSeq  uint32
	baseSeq  uint32 // lowest unacked seq
	inflight map[uint32]udpInflightFrame
	ackRecv  chan uint32
	rtoNs    atomic.Int64 // adaptive retransmit timeout, nanoseconds
	srttNs   atomic.Int64 // smoothed RTT, nanoseconds
	rttvarNs atomic.Int64 // RTT variance (TCP rttvar), nanoseconds
	closed   bool

	// Path MTU discovery: payloadSize starts conservative (udpMaxPayload)
	// and probes upward. If a large frame is ACKed, payloadSize upgrades
	// for the rest of the connection. If the probe times out (RTO), it
	// stays conservative and retries after udpPayloadProbeInterval.
	payloadSize  int       // current payload size (guarded by sendMu)
	lastProbeAt  time.Time // last time we probed with a large frame
	probePending bool      // a large probe frame is inflight

	// recv side
	recvMu    sync.Mutex
	recvBuf   map[uint32][]byte // out-of-order frames
	recvNext  uint32            // next expected seq
	recvReady chan struct{}
	readBuf   []byte
	readErr   error

	// Delayed ACK: instead of sending an ACK for every DATA frame
	// (doubling packet count), we wait for either 2 frames or a 5ms
	// timer — whichever comes first — then send one cumulative ACK.
	// This halves ACK traffic on streaming workloads and reduces
	// per-frame overhead on the return path.
	ackPending uint32 // highest contiguous seq waiting to be ACKed
	ackCount   int    // frames received since last ACK send
	ackTimer   *time.Timer

	finRecv chan struct{}
	once    sync.Once
	done    chan struct{}

	// handlePacketHook is a test-only instrumentation hook.
	handlePacketHook func(ftype byte)
}

// udpInflightFrame is an unacknowledged sent frame plus its send time
// (used for adaptive RTT sampling).
type udpInflightFrame struct {
	data   []byte
	sentAt time.Time
}

const (
	// udpRTOMin bounds the adaptive RTO from below. The mesh data
	// plane rides real WAN links (txcloud↔Oracle RTT ~257ms steady,
	// but spikes to 1.5s+ under loss), and a too-short RTO
	// retransmits every frame before its ACK arrives — flooding the
	// window, wedging Write, and starving smux keepalive until the
	// session dies. RTO = srtt + 4×rttvar (TCP standard) with this
	// floor keeps retransmits honest on jittery links.
	udpRTOMin = 500 * time.Millisecond
	udpRTOMax = 5 * time.Second
)

// rto returns the current adaptive retransmit timeout.
func (sc *udpStreamConn) rto() time.Duration {
	return time.Duration(sc.rtoNs.Load())
}

// sampleRTT updates the smoothed RTT and variance (TCP SRTT/RTTVAR,
// RFC 6298) and the adaptive RTO = srtt + 4×rttvar, clamped to
// [udpRTOMin, udpRTOMax]. Called on every ACK that acknowledges at
// least one inflight frame.
func (sc *udpStreamConn) sampleRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	const (
		alpha = 0.125 // SRTT EWMA (RFC 6298)
		beta  = 0.25  // RTTVAR EWMA
	)
	prevSrtt := time.Duration(sc.srttNs.Load())
	var srtt time.Duration
	if prevSrtt == 0 {
		srtt = rtt
	} else {
		srtt = time.Duration(float64(prevSrtt)*(1-alpha) + float64(rtt)*alpha)
	}
	sc.srttNs.Store(int64(srtt))
	// RTTVAR = (1-β)×RTTVAR + β×|SRTT - RTT|
	rttvar := time.Duration(float64(time.Duration(sc.rttvarNs.Load()))*(1-beta) + float64(absDur(rtt-srtt))*beta)
	sc.rttvarNs.Store(int64(rttvar))

	rto := srtt + 4*rttvar
	if rto < udpRTOMin {
		rto = udpRTOMin
	}
	if rto > udpRTOMax {
		rto = udpRTOMax
	}
	sc.rtoNs.Store(int64(rto))
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// newUDPStreamConn creates a reliable stream for the given peer on the
// shared UDP socket. The socket must be connected (DialUDP) or the
// caller must use WriteToUDP semantics — we use a connected socket so
// ReadFrom/WriteTo are simple.
func newUDPStreamConn(conn *net.UDPConn, peer *net.UDPAddr) *udpStreamConn {
	sc := &udpStreamConn{
		conn:      conn,
		peer:      peer,
		inflight:  make(map[uint32]udpInflightFrame),
		ackRecv:   make(chan uint32, 4096),
		recvBuf:   make(map[uint32][]byte),
		recvReady: make(chan struct{}, 1),
		finRecv:   make(chan struct{}),
		done:      make(chan struct{}),

		payloadSize: udpMaxPayload, // start conservative
		ackPending:  0,             // will be set on first received frame
	}
	sc.rtoNs.Store(int64(udpRTOMin))
	go sc.recvLoop()
	go sc.retransmitLoop()
	return sc
}

// Write implements net.Conn. Frames the data and retransmits until ACKed.
func (sc *udpStreamConn) Write(p []byte) (int, error) {
	sc.sendMu.Lock()
	defer sc.sendMu.Unlock()
	if sc.closed {
		return 0, errUDPClosed
	}

	total := 0
	for len(p) > 0 {
		// Path MTU discovery: if we haven't probed yet (or retry
		// interval elapsed) AND there's enough buffered data to fill
		// a large frame, bump the chunk size for this one frame. If
		// the ACK comes back, payloadSize upgrades permanently. If
		// it times out (RTO), the retransmit uses the conservative
		// size.
		//
		// CRITICAL: probe ONLY when len(p) >= udpPayloadLarge. A
		// small write (e.g. the 160B kx msg1) must be SPLIT into
		// ≤40B ARQ frames — sending it as one oversized frame would
		// be dropped by restricted paths (Oracle security group drops
		// >60B) and the kx never completes. The probe exists to test
		// the path, not to change framing of small messages.
		chunkSize := sc.payloadSize
		// After a successful MTU upgrade, large buffers still use the
		// big payload; small writes (kx frames, smux headers) must
		// ALWAYS split into ≤40B frames — restricted paths (Oracle
		// >60B security group) drop oversized single frames and the
		// kx never completes. Only messages that can fill the large
		// frame benefit from the upgrade.
		if len(p) < udpPayloadLarge {
			chunkSize = udpMaxPayload
		}
		if chunkSize < udpPayloadLarge && !sc.probePending && len(p) >= udpPayloadLarge {
			if time.Since(sc.lastProbeAt) >= udpPayloadProbeInterval || sc.lastProbeAt.IsZero() {
				chunkSize = udpPayloadLarge
				sc.probePending = true
				sc.lastProbeAt = time.Now()
			}
		}
		chunk := p
		if len(chunk) > chunkSize {
			chunk = chunk[:chunkSize]
		}
		seq := sc.nextSeq
		sc.nextSeq = (sc.nextSeq + 1) % udpMaxSeq
		if seq < 4 && sc.probePending { // debug
			log.Printf("[udpstream] probing large payload (%dB) seq=%d to %s", chunkSize, seq, sc.peer)
		}

		frame := make([]byte, udpFrameHeaderLen+len(chunk))
		frame[0] = udpFrameTypeData
		binary.BigEndian.PutUint32(frame[1:5], seq)
		binary.BigEndian.PutUint32(frame[5:9], sc.baseSeq)
		binary.BigEndian.PutUint16(frame[9:11], uint16(len(chunk)))
		copy(frame[udpFrameHeaderLen:], chunk)

		sentAt := time.Now()
		sc.inflight[seq] = udpInflightFrame{data: frame, sentAt: sentAt}
		if _, err := sc.conn.WriteToUDP(frame, sc.peer); err != nil {
			return total, err
		}
		if seq < 4 { // debug: first frames
			log.Printf("[udpstream] write seq=%d to %s len=%d", seq, sc.peer, len(frame))
		}
		total += len(chunk)
		p = p[len(chunk):]

		// Block when the window is full until ACKs drain it. Bound the
		// wait: a peer that stopped ACKing (dead endpoint, network
		// partition) must not wedge Write forever — the caller (TUN
		// forwarder) needs the error to fall back to the TCP path.
		windowWaitStart := time.Now()
		for len(sc.inflight) >= udpWindowSize {
			if time.Since(windowWaitStart) > udpWriteTimeout {
				return total, fmt.Errorf("udp stream: write timeout (%d frames unacked)", len(sc.inflight))
			}
			select {
			case ack := <-sc.ackRecv:
				// Inline advanceBase — we already hold sendMu, and
				// advanceBase would re-Lock (non-reentrant) → deadlock.
				sc.ackLocked(ack)
			case <-sc.done:
				return total, errUDPClosed
			case <-time.After(sc.rto()):
				sc.retransmitLocked()
			}
		}
	}
	return total, nil
}

// Read implements net.Conn. Returns ordered bytes from the ARQ stream.
func (sc *udpStreamConn) Read(p []byte) (int, error) {
	for {
		sc.recvMu.Lock()
		if len(sc.readBuf) > 0 {
			n := copy(p, sc.readBuf)
			sc.readBuf = sc.readBuf[n:]
			sc.recvMu.Unlock()
			return n, nil
		}
		if sc.readErr != nil {
			err := sc.readErr
			sc.recvMu.Unlock()
			return 0, err
		}
		// Peek next in-order frame.
		if data, ok := sc.recvBuf[sc.recvNext]; ok {
			if len(data) == 0 {
				// Zero-length frame (e.g. the TUN UDP auth
				// handshake frame). Consume it and continue —
				// returning (0, nil) violates io.Reader and
				// would make callers treat it as EOF-ish.
				delete(sc.recvBuf, sc.recvNext)
				sc.recvNext = (sc.recvNext + 1) % udpMaxSeq
				sc.recvMu.Unlock()
				sc.signalReady()
				continue
			}
			n := copy(p, data)
			if n < len(data) {
				sc.readBuf = data[n:]
			} else {
				delete(sc.recvBuf, sc.recvNext)
			}
			sc.recvNext = (sc.recvNext + 1) % udpMaxSeq
			sc.recvMu.Unlock()
			sc.signalReady()
			return n, nil
		}
		sc.recvMu.Unlock()

		select {
		case <-sc.recvReady:
		case <-sc.done:
			return 0, errUDPClosed
		case <-sc.finRecv:
			return 0, io.EOF
		}
	}
}

// Close implements net.Conn.
func (sc *udpStreamConn) Close() error {
	sc.once.Do(func() {
		// Read baseSeq under sendMu — advanceBase() (recvLoop) writes
		// it under the same lock; a lock-free read here is a data race.
		sc.sendMu.Lock()
		sc.closed = true
		seq := sc.baseSeq
		sc.sendMu.Unlock()
		// Send FIN best-effort.
		frame := make([]byte, udpFrameHeaderLen)
		frame[0] = udpFrameTypeFin
		binary.BigEndian.PutUint32(frame[5:9], seq)
		sc.conn.WriteToUDP(frame, sc.peer)
		close(sc.done)
	})
	return nil
}

// LocalAddr / RemoteAddr / deadlines (deadlines not enforced for UDP).
func (sc *udpStreamConn) LocalAddr() net.Addr                { return sc.conn.LocalAddr() }
func (sc *udpStreamConn) RemoteAddr() net.Addr               { return sc.peer }
func (sc *udpStreamConn) SetDeadline(t time.Time) error      { return nil }
func (sc *udpStreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (sc *udpStreamConn) SetWriteDeadline(t time.Time) error { return nil }

// handlePacket feeds a received datagram into the ARQ state machine.
// Called by the shared UDP listen loop.
func (sc *udpStreamConn) handlePacket(data []byte) {
	if len(data) < udpFrameHeaderLen {
		return
	}
	ftype := data[0]
	seq := binary.BigEndian.Uint32(data[1:5])
	ack := binary.BigEndian.Uint32(data[5:9])
	if sc.handlePacketHook != nil {
		sc.handlePacketHook(ftype)
	}

	switch ftype {
	case udpFrameTypeData:
		plen := int(binary.BigEndian.Uint16(data[9:11]))
		if plen > len(data)-udpFrameHeaderLen {
			return
		}
		payload := make([]byte, plen)
		copy(payload, data[udpFrameHeaderLen:udpFrameHeaderLen+plen])

		// Single recvMu critical section: store payload + update
		// delayed-ACK state together (was three lock/unlock pairs).
		sc.recvMu.Lock()
		if !seqBefore(seq, sc.recvNext) {
			if _, dup := sc.recvBuf[seq]; !dup {
				sc.recvBuf[seq] = payload
			}
		}
		if seqBefore(sc.ackPending, seq) {
			sc.ackPending = seq
		}
		sc.ackCount++
		needAck := sc.ackCount >= 2
		var ackSeq uint32
		if needAck {
			sc.ackCount = 0
			ackSeq = sc.ackPending
		}
		sc.recvMu.Unlock()
		sc.signalReady()

		if needAck {
			sc.sendAck(ackSeq)
		} else {
			sc.armAckTimer()
		}

	case udpFrameTypeAck:
		select {
		case sc.ackRecv <- ack:
		default:
		}

	case udpFrameTypeFin:
		select {
		case <-sc.finRecv:
		default:
			close(sc.finRecv)
		}
	}
}

func (sc *udpStreamConn) sendAck(seq uint32) {
	frame := make([]byte, udpFrameHeaderLen)
	frame[0] = udpFrameTypeAck
	binary.BigEndian.PutUint32(frame[5:9], seq)
	sc.conn.WriteToUDP(frame, sc.peer)
}

// armAckTimer starts (or resets) the delayed-ACK timer. When it fires,
// a cumulative ACK is sent for whatever seq is in ackPending. This
// ensures a single DATA frame doesn't wait indefinitely for its ACK
// (the 2-frame trigger would never fire for sparse traffic).
func (sc *udpStreamConn) armAckTimer() {
	sc.recvMu.Lock()
	defer sc.recvMu.Unlock()
	if sc.ackTimer != nil {
		sc.ackTimer.Stop()
	}
	sc.ackTimer = time.AfterFunc(5*time.Millisecond, func() {
		// Guard against firing after Close: sendAck on a closed
		// conn writes to a dead UDP socket (harmless error log but
		// noisy). Check done first.
		select {
		case <-sc.done:
			return
		default:
		}
		sc.recvMu.Lock()
		ackSeq := sc.ackPending
		sc.ackCount = 0
		sc.recvMu.Unlock()
		sc.sendAck(ackSeq)
	})
}

// ackLocked processes a cumulative ACK while holding sendMu: removes
// acknowledged frames, advances baseSeq, and samples RTT for the
// adaptive RTO. The ack that releases the OLDEST frame's send time is
// the cleanest RTT sample; we use the newest acknowledged frame's
// send time (closest to the ack's arrival) for the RTT estimate.
func (sc *udpStreamConn) ackLocked(ack uint32) {
	var newest time.Time
	for seq, f := range sc.inflight {
		if !seqBefore(ack, seq) {
			// Path MTU discovery: if this ACK covers a probe frame
			// (payload > udpMaxPayload), upgrade the payload size.
			if sc.probePending && len(f.data) > udpFrameHeaderLen+udpMaxPayload {
				sc.payloadSize = udpPayloadLarge
				sc.probePending = false
				log.Printf("[udpstream] path MTU upgrade: payload %d→%d (%s)",
					udpMaxPayload, udpPayloadLarge, sc.peer)
			}
			delete(sc.inflight, seq)
			if f.sentAt.After(newest) {
				newest = f.sentAt
			}
		}
	}
	if !seqBefore(ack, sc.baseSeq) {
		sc.baseSeq = (ack + 1) % udpMaxSeq
	}
	if !newest.IsZero() {
		sc.sampleRTT(time.Since(newest))
	}
}

// advanceBase removes acknowledged frames from the inflight window and
// advances the base sequence. Also samples RTT for the adaptive RTO.
func (sc *udpStreamConn) advanceBase(ack uint32) {
	sc.sendMu.Lock()
	defer sc.sendMu.Unlock()
	sc.ackLocked(ack)
}

func (sc *udpStreamConn) retransmitLocked() {
	now := time.Now()
	rto := sc.rto()
	for seq, f := range sc.inflight {
		if now.Sub(f.sentAt) >= rto {
			// Path MTU discovery: if a probe frame times out, the
			// large payload was dropped by the link. Downgrade to
			// conservative framing — resend with the same seq so no
			// new hole is created. If the receiver already advanced
			// past this seq (probe was the first frame and the
			// receiver saw it), this retransmit is dropped by ARQ
			// dedup; the data loss is bounded to one frame and the
			// upper layer's stream framing detects the gap (better
			// than silently corrupting the stream).
			if sc.probePending && len(f.data) > udpFrameHeaderLen+udpMaxPayload {
				sc.probePending = false
				log.Printf("[udpstream] path MTU probe failed: downgrading to %dB payload (%s)",
					udpMaxPayload, sc.peer)
				payload := f.data[udpFrameHeaderLen:]
				if len(payload) > udpMaxPayload {
					payload = payload[:udpMaxPayload]
				}
				frame := make([]byte, udpFrameHeaderLen+len(payload))
				copy(frame, f.data[:udpFrameHeaderLen])
				binary.BigEndian.PutUint16(frame[9:11], uint16(len(payload)))
				copy(frame[udpFrameHeaderLen:], payload)
				f.data = frame
			}
			sc.conn.WriteToUDP(f.data, sc.peer)
			f.sentAt = now
			sc.inflight[seq] = f
		}
		_ = seq
	}
}

const (
	// udpIdleTimeout is how long a UDP stream can go without any
	// data activity (send or receive) before it self-terminates.
	// This prevents zombie streams from leaking goroutines when the
	// peer disappears silently (NAT mapping expires, peer restarts
	// without sending FIN, etc.). 120s is long enough that an active
	// session with sparse traffic (keepalive every 30s) stays alive,
	// but short enough to reclaim leaked streams in minutes not hours.
	udpIdleTimeout = 120 * time.Second
)

func (sc *udpStreamConn) retransmitLoop() {
	// Dynamic tick: retransmit checks should happen at ~RTO/4 so
	// retransmits fire promptly after RTO elapses, but without
	// busy-spinning when RTO is large (e.g. 2s on a jittery mobile
	// link → 500ms tick, not 250ms). Recalculate each iteration so
	// the loop tracks the adaptive RTO as RTT samples arrive.
	for {
		tick := sc.rto() / 4
		if tick < 50*time.Millisecond {
			tick = 50 * time.Millisecond
		}
		if tick > 500*time.Millisecond {
			tick = 500 * time.Millisecond
		}
		timer := time.NewTimer(tick)
		select {
		case <-sc.done:
			timer.Stop()
			return
		case <-timer.C:
			sc.sendMu.Lock()
			if len(sc.inflight) > 0 {
				sc.retransmitLocked()
			}
			sc.sendMu.Unlock()
		}
	}
}

func (sc *udpStreamConn) recvLoop() {
	// The shared UDP socket delivers packets to handlePacket directly
	// (called from udpListenLoop's routing). This goroutine exists to
	// drain ackRecv into advanceBase so Write's window check proceeds.
	// It also tracks last-activity for the idle-timeout watchdog in
	// retransmitLoop: a non-empty ackRecv means the peer is alive.
	idleTimer := time.NewTimer(udpIdleTimeout)
	defer idleTimer.Stop()
	for {
		select {
		case ack := <-sc.ackRecv:
			sc.advanceBase(ack)
			idleTimer.Reset(udpIdleTimeout)
		case <-sc.done:
			return
		case <-idleTimer.C:
			// No ACKs for a long period → peer is gone.
			sc.Close()
			return
		}
	}
}

func (sc *udpStreamConn) signalReady() {
	select {
	case sc.recvReady <- struct{}{}:
	default:
	}
}

// seqBefore reports whether a is strictly before b in the modulo space
// (a was sent earlier than b). Equal values are NOT before each other.
func seqBefore(a, b uint32) bool {
	// Go's % keeps the sign of the dividend — normalize into [0, max).
	// diff = (b - a): positive small means b is ahead of a (a is older).
	diff := (int64(b) - int64(a)) % int64(udpMaxSeq)
	if diff < 0 {
		diff += int64(udpMaxSeq)
	}
	return diff != 0 && diff < int64(udpMaxSeq)/2
}
