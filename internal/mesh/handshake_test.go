package mesh

import (
	"strings"
	"testing"
	"time"
)

// TestParsePeerHandshake_EmptyOutput verifies that parsing an empty
// IpcGet output returns an empty map without panicking.
func TestParsePeerHandshake_EmptyOutput(t *testing.T) {
	result := parsePeerHandshake("")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

// TestParsePeerHandshake_NoPeers verifies parsing output with only
// device-level fields (no peer blocks).
func TestParsePeerHandshake_NoPeers(t *testing.T) {
	input := "private_key=abcdef0123456789\nlisten_port=51820\n"
	result := parsePeerHandshake(input)
	if len(result) != 0 {
		t.Errorf("expected 0 peers, got %d", len(result))
	}
}

// TestParsePeerHandshake_SinglePeer verifies parsing a single peer with
// a completed handshake.
func TestParsePeerHandshake_SinglePeer(t *testing.T) {
	pubKey := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	input := strings.Join([]string{
		"private_key=someprivatekey",
		"listen_port=51820",
		"public_key=" + pubKey,
		"preshared_key=0000000000000000000000000000000000000000000000000000000000000000",
		"protocol_version=1",
		"endpoint=1.2.3.4:51820",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=500000000",
		"tx_bytes=1024",
		"rx_bytes=2048",
		"persistent_keepalive_interval=10",
		"allowed_ip=10.10.1.1/32",
		"",
	}, "\n")

	result := parsePeerHandshake(input)
	if len(result) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(result))
	}

	info, ok := result[pubKey]
	if !ok {
		t.Fatalf("peer %s not found", pubKey)
	}

	if info.PublicKey != pubKey {
		t.Errorf("PublicKey = %s, want %s", info.PublicKey, pubKey)
	}
	if info.LastHandshakeNano != 1700000000*int64(time.Second)+500000000 {
		t.Errorf("LastHandshakeNano = %d, want %d",
			info.LastHandshakeNano, 1700000000*int64(time.Second)+500000000)
	}
	if info.TxBytes != 1024 {
		t.Errorf("TxBytes = %d, want 1024", info.TxBytes)
	}
	if info.RxBytes != 2048 {
		t.Errorf("RxBytes = %d, want 2048", info.RxBytes)
	}
	if info.PersistentKeepalive != 10 {
		t.Errorf("PersistentKeepalive = %d, want 10", info.PersistentKeepalive)
	}

	// Verify the handshake time was reconstructed correctly.
	expected := time.Unix(1700000000, 500000000)
	if !info.LastHandshakeTime.Equal(expected) {
		t.Errorf("LastHandshakeTime = %v, want %v", info.LastHandshakeTime, expected)
	}
}

// TestParsePeerHandshake_NoHandshake verifies parsing a peer that has
// never completed a handshake (sec=0, nsec=0).
func TestParsePeerHandshake_NoHandshake(t *testing.T) {
	pubKey := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	input := strings.Join([]string{
		"public_key=" + pubKey,
		"protocol_version=1",
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"tx_bytes=0",
		"rx_bytes=0",
		"",
	}, "\n")

	result := parsePeerHandshake(input)
	info, ok := result[pubKey]
	if !ok {
		t.Fatalf("peer not found")
	}
	if info.LastHandshakeNano != 0 {
		t.Errorf("LastHandshakeNano = %d, want 0", info.LastHandshakeNano)
	}
	if !info.LastHandshakeTime.IsZero() {
		t.Errorf("LastHandshakeTime = %v, want zero", info.LastHandshakeTime)
	}
}

// TestParsePeerHandshake_MultiplePeers verifies parsing multiple peers
// in a single IpcGet output.
func TestParsePeerHandshake_MultiplePeers(t *testing.T) {
	pub1 := "aaaaaa000000000000000000000000000000000000000000000000000000000001"
	pub2 := "bbbbbb111111111111111111111111111111111111111111111111111111111102"

	input := strings.Join([]string{
		"listen_port=51820",
		"public_key=" + pub1,
		"last_handshake_time_sec=1700000100",
		"last_handshake_time_nsec=0",
		"tx_bytes=100",
		"rx_bytes=200",
		"allowed_ip=10.10.1.1/32",
		"public_key=" + pub2,
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"tx_bytes=300",
		"rx_bytes=400",
		"allowed_ip=10.10.2.2/32",
		"",
	}, "\n")

	result := parsePeerHandshake(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(result))
	}

	info1 := result[pub1]
	if info1.TxBytes != 100 {
		t.Errorf("peer1 TxBytes = %d, want 100", info1.TxBytes)
	}
	if info1.LastHandshakeNano != 1700000100*int64(time.Second) {
		t.Errorf("peer1 LastHandshakeNano = %d, want %d",
			info1.LastHandshakeNano, 1700000100*int64(time.Second))
	}

	info2 := result[pub2]
	if info2.TxBytes != 300 {
		t.Errorf("peer2 TxBytes = %d, want 300", info2.TxBytes)
	}
	if info2.LastHandshakeNano != 0 {
		t.Errorf("peer2 LastHandshakeNano = %d, want 0", info2.LastHandshakeNano)
	}
}

// TestParsePeerHandshake_MalformedLines verifies that malformed lines
// are skipped gracefully.
func TestParsePeerHandshake_MalformedLines(t *testing.T) {
	input := strings.Join([]string{
		"listen_port=51820",
		"not_a_key_value_line",
		"",
		"public_key=abc",
		"=no_key",
		"last_handshake_time_sec=not_a_number",
		"tx_bytes=100",
		"",
	}, "\n")

	result := parsePeerHandshake(input)
	if len(result) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(result))
	}
	info := result["abc"]
	if info == nil {
		t.Fatal("peer 'abc' not found")
	}
	// The malformed nsec line should have left TxBytes parsed.
	if info.TxBytes != 100 {
		t.Errorf("TxBytes = %d, want 100", info.TxBytes)
	}
}

// TestIsPeerHandshaked_NilInfo verifies that nil info returns false.
func TestIsPeerHandshaked_NilInfo(t *testing.T) {
	if isPeerHandshaked(nil, 2*time.Minute) {
		t.Error("expected false for nil info")
	}
}

// TestIsPeerHandshaked_NeverHandshaked verifies that a zero handshake
// time (never handshaked) returns false.
func TestIsPeerHandshaked_NeverHandshaked(t *testing.T) {
	info := &PeerHandshakeInfo{LastHandshakeNano: 0}
	if isPeerHandshaked(info, 2*time.Minute) {
		t.Error("expected false for never-handshaked peer")
	}
}

// TestIsPeerHandshaked_Recent verifies that a recent handshake returns true.
func TestIsPeerHandshaked_Recent(t *testing.T) {
	info := &PeerHandshakeInfo{
		LastHandshakeNano: time.Now().Add(-30 * time.Second).UnixNano(),
		LastHandshakeTime: time.Now().Add(-30 * time.Second),
	}
	if !isPeerHandshaked(info, 2*time.Minute) {
		t.Error("expected true for recent handshake")
	}
}

// TestIsPeerHandshaked_Stale verifies that a stale handshake returns false.
func TestIsPeerHandshaked_Stale(t *testing.T) {
	info := &PeerHandshakeInfo{
		LastHandshakeNano: time.Now().Add(-5 * time.Minute).UnixNano(),
		LastHandshakeTime: time.Now().Add(-5 * time.Minute),
	}
	if isPeerHandshaked(info, 2*time.Minute) {
		t.Error("expected false for stale handshake")
	}
}
