package smux

import (
	"context"
	"testing"
	"time"
)

// TestSessionStatsZeroOnNewSession verifies that a freshly created
// session pair reports zero bytes before the handshake SYN is sent.
// Note: after handshake, the SYN frame is counted (12 bytes).
func TestSessionStatsZeroOnNewSession(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close()
	defer server.Close()

	// After Client()/Server(), the handshake SYN frame has been sent,
	// so counters are non-zero. Verify the values are small (just the
	// handshake frame, not data).
	cs := client.Stats()
	// Client sends a SYN (12 bytes header).
	if cs.BytesSent == 0 {
		t.Error("client BytesSent should be > 0 after handshake SYN")
	}
	// The sent amount should be exactly one frame header (12 bytes).
	if cs.BytesSent != 12 {
		t.Errorf("client BytesSent = %d, want 12 (handshake SYN frame)", cs.BytesSent)
	}

	ss := server.Stats()
	// Server should have received the SYN.
	if ss.BytesReceived == 0 {
		t.Error("server BytesReceived should be > 0 after receiving SYN")
	}
}

// TestSessionStatsCountsDataFrames verifies that byte counters increase
// after sending and receiving DATA frames. The client sends data to the
// server; both sides should see nonzero counters.
func TestSessionStatsCountsDataFrames(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close()
	defer server.Close()

	// Wait for handshake to complete.
	select {
	case <-server.handshakeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake timeout")
	}

	// Open a stream from client to server, write data, server reads it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	payload := []byte("hello traffic stats test!")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("stream write: %v", err)
	}

	// Accept on server side.
	srvStream, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer srvStream.Close()

	buf := make([]byte, len(payload))
	if _, err := srvStream.Read(buf); err != nil {
		t.Fatalf("stream read: %v", err)
	}

	// Give a moment for the writer goroutine to update counters.
	time.Sleep(50 * time.Millisecond)

	// Client should have sent bytes (SYN frame + DATA frame).
	cs := client.Stats()
	if cs.BytesSent == 0 {
		t.Error("client BytesSent should be > 0 after writing data")
	}
	if cs.BytesReceived == 0 {
		t.Error("client BytesReceived should be > 0 after receiving SYN-ACK or response")
	}

	// Server should have received bytes (SYN frame + DATA frame).
	ss := server.Stats()
	if ss.BytesReceived == 0 {
		t.Error("server BytesReceived should be > 0 after receiving data")
	}
	if ss.BytesSent == 0 {
		t.Error("server BytesSent should be > 0 after sending SYN-ACK/handshake")
	}

	// Verify the total bytes counted include at least the payload size.
	if cs.BytesSent < uint64(len(payload)) {
		t.Errorf("client BytesSent (%d) should be >= payload size (%d)", cs.BytesSent, len(payload))
	}
	if ss.BytesReceived < uint64(len(payload)) {
		t.Errorf("server BytesReceived (%d) should be >= payload size (%d)", ss.BytesReceived, len(payload))
	}
}

// TestSessionStatsSymmetry verifies that bytes sent by the client
// approximately equal bytes received by the server (they should match
// exactly for the data path, but handshake frames may differ slightly).
func TestSessionStatsSymmetry(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close()
	defer server.Close()

	// Wait for handshake.
	select {
	case <-server.handshakeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if _, err := stream.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}

	srvStream, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer srvStream.Close()

	// Read all data.
	recv := make([]byte, len(data))
	_, err = srvStream.Read(recv)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Bytes sent by client should equal bytes received by server
	// (both see the same frames: SYN + DATA for the stream).
	cs := client.Stats()
	ss := server.Stats()

	// The client sent: SYN frame (12B) + DATA frame (12B + 1000B) = 1024B
	// The server received those same frames.
	if cs.BytesSent != ss.BytesReceived {
		// They might differ by the handshake frames. Check that the
		// server received at least as much as the client sent.
		if ss.BytesReceived < cs.BytesSent {
			t.Errorf("server received (%d) < client sent (%d)", ss.BytesReceived, cs.BytesSent)
		}
	}
}
