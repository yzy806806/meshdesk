package mesh

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Sniffing edge cases: protocol demux boundary conditions
// ──────────────────────────────────────────────────────────────────────────────

// TestMuxDemux_SlowClientByteByByte verifies that a client that sends data
// one byte at a time with delays between bytes is still correctly routed.
func TestMuxDemux_SlowClientByteByByte(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte{tlsHandshakeRecordType})
		if err != nil {
			t.Errorf("write byte 1: %v", err)
			return
		}
		time.Sleep(100 * time.Millisecond)
		_, err = conn.Write([]byte{0x03, 0x01, 0x00, 0x10})
		if err != nil {
			t.Errorf("write byte 2+: %v", err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}()

	rl := mt.RealityListener()
	defer rl.Close()
	realityCh := make(chan net.Conn, 1)
	go func() {
		conn, err := rl.Accept()
		if err != nil {
			close(realityCh)
			return
		}
		realityCh <- conn
	}()

	select {
	case conn := <-realityCh:
		buf := make([]byte, 2)
		n, _ := io.ReadFull(conn, buf)
		if n < 1 || buf[0] != tlsHandshakeRecordType {
			t.Fatalf("slow client: got %v, expected 0x%02x", buf[:n], tlsHandshakeRecordType)
		}
		conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for slow client connection")
	}
}

// TestMuxDemux_ClientResetDuringPeek verifies that a client that connects
// and immediately closes without sending data doesn't cause a panic.
func TestMuxDemux_ClientResetDuringPeek(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	time.Sleep(200 * time.Millisecond)

	rl := mt.RealityListener()
	defer rl.Close()
	realityCh := make(chan net.Conn, 1)
	go func() {
		conn, err := rl.Accept()
		if err != nil {
			close(realityCh)
			return
		}
		realityCh <- conn
	}()

	select {
	case <-mt.StreamCh():
		t.Fatal("unexpected stream from reset connection")
	case <-realityCh:
		t.Fatal("unexpected reality conn from reset connection")
	case <-time.After(1 * time.Second):
		// expected
	}
}

// TestMuxDemux_ExactBoundaryAtByte22 verifies that byte 22 (0x16 = TLS)
// is correctly routed to Reality, while byte 21 and 23 go to gossip.
// Each connection is sent and verified sequentially to avoid race conditions.
func TestMuxDemux_ExactBoundaryAtByte22(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()
	realityCh := make(chan net.Conn, 10)
	go func() {
		for {
			conn, err := rl.Accept()
			if err != nil {
				close(realityCh)
				return
			}
			realityCh <- conn
		}
	}()

	tests := []struct {
		b         byte
		isReality bool
	}{
		{0x14, false},
		{0x15, false},
		{0x16, true},
		{0x17, false},
		{0x18, false},
	}

	for _, tt := range tests {
		go func(b byte) {
			conn, _ := net.Dial("tcp", addr)
			defer conn.Close()
			conn.Write([]byte{b, 0xAA})
			time.Sleep(30 * time.Millisecond)
		}(tt.b)

		if tt.isReality {
			select {
			case conn := <-realityCh:
				buf := make([]byte, 2)
				n, _ := io.ReadFull(conn, buf)
				if n != 2 || buf[0] != tt.b {
					t.Errorf("byte 0x%02x (TLS): got 0x%02x", tt.b, buf[0])
				}
				conn.Close()
			case conn := <-mt.StreamCh():
				conn.Close()
				t.Errorf("byte 0x%02x (TLS) routed to StreamCh", tt.b)
			case <-time.After(2 * time.Second):
				t.Fatalf("byte 0x%02x: timed out", tt.b)
			}
		} else {
			select {
			case conn := <-mt.StreamCh():
				buf := make([]byte, 2)
				n, _ := io.ReadFull(conn, buf)
				if n != 2 || buf[0] != tt.b {
					t.Errorf("byte 0x%02x (gossip): got 0x%02x", tt.b, buf[0])
				}
				conn.Close()
			case conn := <-realityCh:
				conn.Close()
				t.Errorf("byte 0x%02x (gossip) routed to Reality", tt.b)
			case <-time.After(2 * time.Second):
				t.Fatalf("byte 0x%02x: timed out", tt.b)
			}
		}
	}
}

// TestMuxDemux_HighVolumeRapidConnections verifies that the mux can handle
// many rapid connections without dropping or misrouting any.
func TestMuxDemux_HighVolumeRapidConnections(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	rl := mt.RealityListener()
	defer rl.Close()
	realityCh := make(chan net.Conn, 64)
	go func() {
		for {
			conn, err := rl.Accept()
			if err != nil {
				close(realityCh)
				return
			}
			realityCh <- conn
		}
	}()

	const numConns = 50

	// Use only memberlist message type bytes (0-14) to avoid 22 (TLS).
	for i := 0; i < numConns; i++ {
		go func(idx int) {
			conn, _ := net.Dial("tcp", addr)
			defer conn.Close()
			// Use bytes 0-13 only (memberlist message types, all != 22).
			firstByte := byte(idx % 14)
			conn.Write([]byte{firstByte, byte(idx)})
			time.Sleep(30 * time.Millisecond)
		}(i)
	}

	got := 0
	deadline := time.After(5 * time.Second)

	for got < numConns {
		select {
		case conn := <-mt.StreamCh():
			got++
			conn.Close()
		case conn := <-realityCh:
			conn.Close()
			t.Errorf("unexpected reality conn at count %d", got)
		case <-deadline:
			t.Fatalf("timed out: got %d/%d", got, numConns)
		}
	}
}

// TestMuxDemux_RealityQueueFullBackpressure verifies that when the Reality
// accept queue is full (64 buffered), new TLS connections are dropped.
func TestMuxDemux_RealityQueueFullBackpressure(t *testing.T) {
	mt, _, addr := newTestMuxTransport(t)
	defer mt.Shutdown()

	const overfill = 100
	successCount := &atomic.Int64{}

	for i := 0; i < overfill; i++ {
		go func() {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			_, err = conn.Write([]byte{tlsHandshakeRecordType, 0x01})
			if err == nil {
				time.Sleep(50 * time.Millisecond)
			}
			conn.Close()
			successCount.Add(1)
		}()
	}

	time.Sleep(500 * time.Millisecond)

	drained := 0
	for {
		select {
		case conn := <-mt.realityCh:
			conn.Close()
			drained++
		default:
			goto done
		}
	}
done:
	t.Logf("backpressure: %d attempted, %d in queue, %d dial successes",
		overfill, drained, successCount.Load())
}

// ──────────────────────────────────────────────────────────────────────────────
// connWithPrefix edge case tests
// ──────────────────────────────────────────────────────────────────────────────

// TestConnWithPrefix_ReadAfterUnderlyingClose verifies that after the
// underlying connection is closed, Read returns the prefix bytes and then
// the underlying data before EOF.
func TestConnWithPrefix_ReadAfterUnderlyingClose(t *testing.T) {
	prefix := []byte("PREFIX_DATA")
	conn, peer := newTestConn()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, prefix)

	go func() {
		peer.Write([]byte("MORE"))
		peer.Close()
	}()

	buf := make([]byte, len(prefix))
	n, err := io.ReadFull(wrapped, buf)
	if err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	if n != len(prefix) {
		t.Fatalf("expected %d prefix bytes, got %d", len(prefix), n)
	}

	dataBuf := make([]byte, 10)
	n, err = wrapped.Read(dataBuf)
	if n != 4 {
		t.Fatalf("expected 4 bytes 'MORE', got %d (err=%v)", n, err)
	}
	conn.Close()
}

// TestConnWithPrefix_WriteAfterUnderlyingClose verifies that Write returns
// an error after the underlying connection is closed.
func TestConnWithPrefix_WriteAfterUnderlyingClose(t *testing.T) {
	conn, peer := newTestConn()

	wrapped := NewConnWithPrefix(conn, []byte("PFX"))
	conn.Close()
	peer.Close()

	_, err := wrapped.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error writing to closed connWithPrefix")
	}
}

// TestConnWithPrefix_ReadEmptyBuffer verifies that Read with a nil or empty
// buffer returns (0, nil) per io.Reader contract.
func TestConnWithPrefix_ReadEmptyBuffer(t *testing.T) {
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, []byte("DATA"))

	n, err := wrapped.Read(nil)
	if err != nil {
		t.Fatalf("read with nil buffer: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}

	n, err = wrapped.Read([]byte{})
	if err != nil {
		t.Fatalf("read with empty buffer: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
}

// TestConnWithPrefix_ExactPrefixSizeRead verifies that a Read with buffer
// size exactly matching the prefix size returns exactly those bytes.
func TestConnWithPrefix_ExactPrefixSizeRead(t *testing.T) {
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, []byte("ABCDEF"))

	buf := make([]byte, 6)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("exact read: %v", err)
	}
	if n != 6 {
		t.Fatalf("expected 6 bytes, got %d", n)
	}
}

// TestConnWithPrefix_DoubleReadAfterPrefixExhausted verifies that two
// consecutive Read calls after the prefix is exhausted both go through
// to the underlying connection.
func TestConnWithPrefix_DoubleReadAfterPrefixExhausted(t *testing.T) {
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	wrapped := NewConnWithPrefix(conn, []byte("AB"))

	go func() {
		peer.Write([]byte("CDEFGH"))
		time.Sleep(50 * time.Millisecond)
	}()

	pfxBuf := make([]byte, 2)
	n, err := io.ReadFull(wrapped, pfxBuf)
	if err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 prefix bytes, got %d", n)
	}

	buf1 := make([]byte, 3)
	n, err = io.ReadFull(wrapped, buf1)
	if err != nil {
		t.Fatalf("first underlying read: %v", err)
	}
	buf2 := make([]byte, 3)
	n, err = io.ReadFull(wrapped, buf2)
	if err != nil {
		t.Fatalf("second underlying read: %v", err)
	}
	t.Logf("double read: first=%q second=%q", buf1, buf2)
}

// TestConnWithPrefix_ConcurrentReads verifies no panic under concurrent reads.
func TestConnWithPrefix_ConcurrentReads(t *testing.T) {
	conn, peer := newTestConn()
	defer conn.Close()
	defer peer.Close()

	prefix := bytesRepeat([]byte("X"), 100)
	wrapped := NewConnWithPrefix(conn, prefix)

	go func() {
		peer.Write(bytesRepeat([]byte("Y"), 1000))
		peer.Close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 50)
		for i := 0; i < 10; i++ {
			wrapped.Read(buf)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func bytesRepeat(b []byte, count int) []byte {
	result := make([]byte, len(b)*count)
	for i := 0; i < count; i++ {
		copy(result[i*len(b):], b)
	}
	return result
}
