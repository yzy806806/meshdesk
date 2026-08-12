package mesh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
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
	udpMaxPayload     = 1200 // fits typical MTU with room for smux frames

	udpWindowSize = 32 // sliding window (in-flight frames)
	udpMaxSeq     = uint32(1 << 30)

	// udpWriteTimeout bounds how long Write waits for the sliding
	// window to drain before giving up (dead peer → error → caller
	// falls back to TCP). 30s ≈ 150 RTO retransmits.
	udpWriteTimeout = 30 * time.Second
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
	inflight map[uint32][]byte
	ackRecv  chan uint32
	rto      time.Duration
	closed   bool

	// recv side
	recvMu    sync.Mutex
	recvBuf   map[uint32][]byte // out-of-order frames
	recvNext  uint32            // next expected seq
	recvReady chan struct{}
	readBuf   []byte
	readErr   error

	finRecv chan struct{}
	once    sync.Once
	done    chan struct{}

	// handlePacketHook is a test-only instrumentation hook.
	handlePacketHook func(ftype byte)
}

// newUDPStreamConn creates a reliable stream for the given peer on the
// shared UDP socket. The socket must be connected (DialUDP) or the
// caller must use WriteToUDP semantics — we use a connected socket so
// ReadFrom/WriteTo are simple.
func newUDPStreamConn(conn *net.UDPConn, peer *net.UDPAddr) *udpStreamConn {
	sc := &udpStreamConn{
		conn:      conn,
		peer:      peer,
		inflight:  make(map[uint32][]byte),
		ackRecv:   make(chan uint32, 4096),
		rto:       200 * time.Millisecond,
		recvBuf:   make(map[uint32][]byte),
		recvReady: make(chan struct{}, 1),
		finRecv:   make(chan struct{}),
		done:      make(chan struct{}),
	}
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
		chunk := p
		if len(chunk) > udpMaxPayload {
			chunk = chunk[:udpMaxPayload]
		}
		seq := sc.nextSeq
		sc.nextSeq = (sc.nextSeq + 1) % udpMaxSeq

		frame := make([]byte, udpFrameHeaderLen+len(chunk))
		frame[0] = udpFrameTypeData
		binary.BigEndian.PutUint32(frame[1:5], seq)
		binary.BigEndian.PutUint32(frame[5:9], sc.baseSeq)
		binary.BigEndian.PutUint16(frame[9:11], uint16(len(chunk)))
		copy(frame[udpFrameHeaderLen:], chunk)

		sc.inflight[seq] = frame
		if _, err := sc.conn.WriteToUDP(frame, sc.peer); err != nil {
			return total, err
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
				for seq := range sc.inflight {
					if !seqBefore(ack, seq) {
						delete(sc.inflight, seq)
					}
				}
				if !seqBefore(ack, sc.baseSeq) {
					sc.baseSeq = (ack + 1) % udpMaxSeq
				}
			case <-sc.done:
				return total, errUDPClosed
			case <-time.After(sc.rto):
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

		sc.recvMu.Lock()
		// Only accept frames >= recvNext (drop duplicates/old).
		if !seqBefore(seq, sc.recvNext) {
			if _, dup := sc.recvBuf[seq]; !dup {
				sc.recvBuf[seq] = payload
			}
			sc.recvMu.Unlock()
			sc.signalReady()
		} else {
			sc.recvMu.Unlock()
		}
		// Always ACK the received seq (cumulative ack = highest contiguous).
		sc.sendAck(seq)

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

func (sc *udpStreamConn) advanceBase(ack uint32) {
	sc.sendMu.Lock()
	defer sc.sendMu.Unlock()
	// Remove all frames <= ack.
	for seq := range sc.inflight {
		if !seqBefore(ack, seq) {
			delete(sc.inflight, seq)
		}
	}
	if !seqBefore(ack, sc.baseSeq) {
		sc.baseSeq = (ack + 1) % udpMaxSeq
	}
}

func (sc *udpStreamConn) retransmitLocked() {
	// Retransmit all unacked frames (simplified — full window retransmit
	// on timeout, adequate for low-latency mesh links).
	for seq, frame := range sc.inflight {
		sc.conn.WriteToUDP(frame, sc.peer)
		_ = seq
	}
}

func (sc *udpStreamConn) retransmitLoop() {
	ticker := time.NewTicker(sc.rto)
	defer ticker.Stop()
	for {
		select {
		case <-sc.done:
			return
		case <-ticker.C:
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
	for {
		select {
		case ack := <-sc.ackRecv:
			sc.advanceBase(ack)
		case <-sc.done:
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
